import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import {
  authorizeFaceAndIssueTicket,
  createChallengeStore,
  fetchSigningContext,
  parsePgVector
} from '../../biometrics/server/signing-session.mjs';

const prefix = '/api/vault/face/';
const localWallet = new URL('../../bitcoin/party-local-test/public-key.json', import.meta.url);
const maxBodyBytes = 1024 * 1024;

function reply(response, status, body) {
  response.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store'
  });
  response.end(JSON.stringify(body));
}

export function createFaceChallengeMiddleware({
  signerUrl = process.env.CHRONOS_SIGNER_URL || 'http://127.0.0.1:8787',
  fetchImpl = fetch,
  walletKeyFile = process.env.CHRONOS_TEST_WALLET_PUBLIC_KEY_PATH || localWallet,
  privateKeyPath = process.env.CHRONOS_AUTH_PRIVATE_KEY_PATH ||
    (process.env.LOCALAPPDATA && join(process.env.LOCALAPPDATA, 'chronos-vault-test-auth.pem'))
} = {}) {
  const challenges = createChallengeStore({ ttlSeconds: 120 });
  let enrollment;
  const signerFetch = (url, options) =>
    fetchImpl(url, { ...options, redirect: 'error', signal: AbortSignal.timeout(3000) });

  return async (request, response, next) => {
    const action = request.url?.split('?')[0].slice(prefix.length);
    if (!request.url?.startsWith(prefix) || !['challenge', 'enroll', 'verify'].includes(action)) return next();
    if (request.method !== 'POST') {
      response.setHeader('Allow', 'POST');
      return reply(response, 405, { error: 'POST 요청이 필요합니다.' });
    }
    if (request.headers['content-type']?.split(';')[0].trim() !== 'application/json') {
      return reply(response, 415, { error: 'JSON 요청이 필요합니다.' });
    }
    if (action !== 'challenge' && !['http://127.0.0.1:5181', 'http://localhost:5181'].includes(request.headers.origin)) {
      return reply(response, 403, { error: '로컬 테스트 화면에서만 사용할 수 있습니다.' });
    }

    let packageJson;
    let payment;
    let payload;
    try {
      const chunks = [];
      let size = 0;
      for await (const chunk of request) {
        size += chunk.length;
        if (size > maxBodyBytes) return reply(response, 413, { error: '거래 파일이 너무 큽니다.' });
        chunks.push(chunk);
      }
      ({ packageJson, payload } = JSON.parse(Buffer.concat(chunks).toString('utf8')));
      if (typeof packageJson !== 'string') throw new Error('Missing transaction text');
      payment = JSON.parse(packageJson);
    } catch {
      return reply(response, 400, { error: '거래 JSON을 읽을 수 없습니다.' });
    }

    const { public_key: key, signers } = payment ?? {};
    if (typeof key !== 'string' || !/^(02|03)[a-f0-9]{64}$/i.test(key) ||
        !Array.isArray(signers) || signers.length !== 2 ||
        !signers.includes(1) || !signers.includes(2)) {
      return reply(response, 400, { error: 'U+S 일반 송금 거래 파일이 필요합니다.' });
    }

    let context;
    try {
      context = await fetchSigningContext(signerUrl, signerFetch);
    } catch {
      return reply(response, 503, { error: '서명 서버에 연결할 수 없습니다.' });
    }
    if (key.toLowerCase() !== context.publicKey.toLowerCase()) {
      return reply(response, 409, { error: '거래와 서명 서버의 지갑이 일치하지 않습니다.' });
    }
    const vaultId = context.publicKey.toLowerCase();
    if (action !== 'challenge') {
      let testKey;
      try {
        const raw = (await readFile(walletKeyFile, 'utf8')).trim();
        testKey = (raw.startsWith('"') ? JSON.parse(raw) : raw).toLowerCase();
      } catch {
        return reply(response, 503, { error: '로컬 테스트 지갑을 읽을 수 없습니다.' });
      }
      if (testKey !== vaultId || payload?.vaultId !== vaultId || payload?.role !== 'owner') {
        return reply(response, 403, { error: '로컬 테스트 지갑의 소유자 인증만 지원합니다.' });
      }
      if (action === 'enroll') {
        if (enrollment) return reply(response, 409, { error: '이미 등록되었습니다. 등록을 초기화하려면 웹 개발 서버를 다시 시작하세요.' });
        try {
          enrollment = { vaultId, embedding: parsePgVector(payload.embedding) };
        } catch {
          return reply(response, 400, { error: '얼굴 등록 데이터를 읽을 수 없습니다.' });
        }
        return reply(response, 200, { enrolled: true });
      }
      if (enrollment?.vaultId !== vaultId) {
        return reply(response, 409, { error: '먼저 테스트 지갑 소유자 얼굴을 등록하세요.' });
      }
      if (payload.purpose !== 'normal_sign' || payload.publicKey !== vaultId ||
          typeof payload.signingPackageHash !== 'string') {
        return reply(response, 400, { error: '일반 송금 인증 데이터가 올바르지 않습니다.' });
      }
      let privateKey;
      try {
        privateKey = await readFile(privateKeyPath);
      } catch {
        return reply(response, 503, { error: '로컬 인증 키를 읽을 수 없습니다.' });
      }
      try {
        const result = await authorizeFaceAndIssueTicket({
          ...context, signerUrl, packageJson, payload, privateKey,
          challengeStore: {
            consume(nonce, expected) {
              const record = challenges.consume(nonce, expected);
              if (record.instanceId !== context.instanceId) throw new Error('Signing server restarted');
              return record;
            }
          },
          storedEmbedding: enrollment.embedding, fetchImpl: signerFetch
        });
        return reply(response, result.verified ? 200 : 403, result.verified ? result : {
          error: '등록된 얼굴과 일치하지 않습니다. 다시 시도해 주세요.'
        });
      } catch {
        return reply(response, 400, { error: '인증 번호를 확인할 수 없거나 서명 티켓 발급에 실패했습니다. 다시 시도해 주세요.' });
      } finally {
        privateKey.fill(0);
      }
    }
    if (challenges.size() >= 100) {
      return reply(response, 429, { error: '잠시 후 다시 시도해 주세요.' });
    }
    const challenge = challenges.issue({
      ...context,
      vaultId,
      packageJson,
      purpose: 'normal_sign',
      role: 'owner'
    });
    return reply(response, 200, challenge);
  };
}
