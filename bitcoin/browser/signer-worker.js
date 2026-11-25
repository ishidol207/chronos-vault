const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });
const hex = bytes => Array.from(new Uint8Array(bytes), b => b.toString(16).padStart(2, '0')).join('');
const digest = async text => hex(await crypto.subtle.digest('SHA-256', encoder.encode(text)));

function makeEngine(module) {
  const { exports } = new WebAssembly.Instance(module, { chronos: {
    random_fill(ptr, length) {
      const out = new Uint8Array(exports.memory.buffer, ptr, length);
      for (let i = 0; i < length; i += 65536) crypto.getRandomValues(out.subarray(i, i + 65536));
    },
  } });
  return request => {
    const bytes = encoder.encode(JSON.stringify(request));
    const ptr = exports.input_buffer(bytes.length);
    new Uint8Array(exports.memory.buffer, ptr, bytes.length).set(bytes);
    bytes.fill(0);
    const len = exports.process();
    const result = JSON.parse(decoder.decode(new Uint8Array(exports.memory.buffer, exports.output_buffer(), len)));
    if (result.error) throw new Error(result.error);
    return result.value;
  };
}

// The native v1 envelope authenticates the format, big-endian party ID and compressed wallet key.
async function openParty(files, party, peer, publicKey) {
  const { envelope, aesKey, identity } = files;
  const metadata = JSON.parse(await identity.text());
  if (metadata.party_id !== party || metadata.peer_id !== peer || metadata.public_key !== publicKey)
    throw new Error('Wrong wallet, local party or peer identity file');
  const data = new Uint8Array(await envelope.arrayBuffer());
  const magic = Uint8Array.of(67, 86, 80, 65, 82, 84, 0, 1);
  if (data.length < 36 || !magic.every((byte, i) => data[i] === byte))
    throw new Error('Invalid encrypted party file');
  const raw = new Uint8Array(await aesKey.arrayBuffer());
  let key;
  try {
    if (raw.length !== 32) throw new Error('Expected a 32-byte AES key file');
    key = await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['decrypt']);
  } finally { raw.fill(0); }
  const aad = new Uint8Array(49);
  aad.set(magic);
  new DataView(aad.buffer).setBigUint64(8, BigInt(party));
  aad.set(publicKey.match(/../g).map(pair => parseInt(pair, 16)), 16);
  let clear;
  try {
    clear = new Uint8Array(await crypto.subtle.decrypt({
      name: 'AES-GCM', iv: data.subarray(8, 20), additionalData: aad, tagLength: 128,
    }, key, data.subarray(20)));
    return { identity: metadata, secrets: decoder.decode(clear) };
  } catch {
    throw new Error('Party file could not be decrypted with this AES key and wallet identity');
  } finally { clear?.fill(0); }
}

async function claim(ids) {
  const db = await new Promise((resolve, reject) => {
    const req = indexedDB.open('chronos-bitcoin-signer', 1);
    req.onupgradeneeded = () => req.result.createObjectStore('spent');
    req.onerror = () => reject(req.error);
    req.onsuccess = () => resolve(req.result);
  });
  try {
    await new Promise((resolve, reject) => {
      const tx = db.transaction('spent', 'readwrite', { durability: 'strict' });
      tx.oncomplete = resolve;
      tx.onabort = () => reject(new Error('Session or presigning nonce already used, or browser storage unavailable'));
      for (const id of ids) tx.objectStore('spent').add(true, id);
    });
  } finally { db.close(); }
}

function requireIds(ids, count) {
  if (!Array.isArray(ids) || ids.length !== count || new Set(ids).size !== count ||
      !ids.every(s => typeof s === 'string' && /^(0|[1-9][0-9]{0,19})$/.test(s) && BigInt(s) < (1n << 64n)))
    throw new Error('Invalid signing session identifiers');
}

function requirePair(pkg, party, peer) {
  if (pkg.signers.length !== 2 || !pkg.signers.includes(party) || !pkg.signers.includes(peer))
    throw new Error('Transaction signers do not match the selected purpose');
}

async function exchange(url, ticket, step, messages) {
  const body = JSON.stringify({ step, messages });
  for (let attempt = 0; ; attempt++) {
    let response;
    try {
      response = await fetch(url, { method: 'POST', credentials: 'omit', redirect: 'error',
        headers: { Authorization: 'Bearer ' + ticket, 'Content-Type': 'application/json' }, body,
        cache: 'no-store', signal: AbortSignal.timeout(60000) });
      if (response.ok) return await response.json();
    } catch (err) {
      if (attempt >= 3) throw err;
    }
    if (response && !response.ok && (response.status !== 429 || attempt >= 3))
      throw new Error('S signing server returned HTTP ' + response.status);
    await new Promise(resolve => setTimeout(resolve, 200 * 2 ** attempt));
  }
}

async function signRemote(args, local, pkg, count) {
  const { packageJson, purpose, ticket } = args;
  if (!['normal_sign', 'recovery', 'inheritance'].includes(purpose) || typeof ticket !== 'string' || !ticket)
    throw new Error('Missing purpose or signing ticket');
  // The app's same-origin proxy owns routing. No external redirect can receive the ticket.
  const url = new URL(args.stepsUrl ?? '/v1/signing/steps', self.location.origin);
  if (url.origin !== self.location.origin || url.username || url.password || url.hash || url.search)
    throw new Error('Use a same-origin signing endpoint');
  const party = purpose === 'normal_sign' ? 1 : 3;
  requirePair(pkg, party, 2);
  const material = await openParty(args.files, party, 2, pkg.public_key);
  const hash = await digest(packageJson);
  let ids;
  const send = async (step, messages) => {
    const reply = await exchange(url, ticket, step, messages);
    if (reply.step !== step || reply.purpose !== purpose || reply.package_sha256 !== hash)
      throw new Error('S returned a different transaction, purpose or step');
    requireIds(reply.session_ids, count);
    if (ids && !ids.every((id, i) => id === reply.session_ids[i])) throw new Error('Session changed during signing');
    ids = reply.session_ids;
    return reply.packet;
  };
  let theirs = await send(0, []);
  await claim(ids.map(id => 'session:' + id));
  let ours = local({ op: 'start', package: packageJson, ids, ...material });
  material.secrets = '';
  for (let step = 1; step <= count * 3; step++) {
    if (!Array.isArray(ours.messages) || !Array.isArray(theirs?.messages))
      throw new Error('Expected round messages');
    const outgoing = ours.messages;
    ours = local({ op: 'advance', messages: theirs.messages });
    theirs = await send(step, outgoing);
  }
  if (!ours.nonce_ids || !theirs?.share) throw new Error('Missing final signature share');
  await claim(ours.nonce_ids);
  return local({ op: 'combine', package: packageJson, a: local({ op: 'release' }), b: theirs.share });
}

async function signOffline(args, user, recovery, pkg, count) {
  requirePair(pkg, 1, 3);
  const ids = Array.from({ length: count }, () => crypto.getRandomValues(new BigUint64Array(1))[0].toString());
  requireIds(ids, count);
  await claim(ids.map(id => 'session:' + id));
  const start = { op: 'start', package: args.packageJson, ids };
  let u = user({ ...start, ...await openParty(args.userFiles, 1, 3, pkg.public_key) });
  let r = recovery({ ...start, ...await openParty(args.recoveryFiles, 3, 1, pkg.public_key) });
  for (let step = 0; step < count * 3; step++) {
    const userMessages = u.messages;
    u = user({ op: 'advance', messages: r.messages });
    r = recovery({ op: 'advance', messages: userMessages });
  }
  if (!u.nonce_ids || !r.nonce_ids || JSON.stringify(u.nonce_ids) !== JSON.stringify(r.nonce_ids))
    throw new Error('Participants disagree about the signing nonces');
  await claim(u.nonce_ids);
  return user({ op: 'combine', package: args.packageJson, a: user({ op: 'release' }), b: recovery({ op: 'release' }) });
}

self.onmessage = async ({ data }) => {
  try {
    const asset = await fetch(new URL('./chronos_signer.wasm', import.meta.url));
    if (!asset.ok) throw new Error('Could not load signing WASM');
    const module = await WebAssembly.compile(await asset.arrayBuffer());
    const engine = makeEngine(module);
    const review = engine({ op: 'review', package: data.packageJson });
    if (data.op === 'review') { self.postMessage({ value: review }); return; }
    const pkg = JSON.parse(data.packageJson);
    const count = review.input_sighashes.length;
    let signed;
    if (data.op === 'server') signed = await signRemote(data, engine, pkg, count);
    else if (data.op === 'offline') signed = await signOffline(data, engine, makeEngine(module), pkg, count);
    else throw new Error('Unknown signer operation');
    self.postMessage({ value: signed });
  } catch (err) {
    self.postMessage({ error: err?.message || err?.name || 'Browser signing failed' });
  }
};
