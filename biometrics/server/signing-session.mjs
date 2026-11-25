// Server-side only. verification is the authentication handler's verified record for this transaction.
import { createHash, randomBytes, sign } from 'node:crypto';

export const EMBEDDING_DIM = 128;
export const RECOMMENDED_VAULT_THRESHOLD = 0.4;
export const SIGNING_AUDIENCE = 'chronos-vault:testnet4:signing:v1';

const MAX_AUTHORIZATION_TTL_SECONDS = 120;

export function sha256Hex(text) {
  return createHash('sha256').update(text, 'utf8').digest('hex');
}

export function buildSigningSessionRequest(packageJson, verification, privateKey) {
  const digest = sha256Hex(packageJson);
  if (digest !== verification.packageSha256) {
    throw new Error('Transaction differs from the one presented for authentication');
  }
  const authorization = JSON.stringify({
    audience: SIGNING_AUDIENCE,
    instance_id: verification.instanceId,
    public_key: verification.publicKey,
    package_sha256: digest,
    purpose: verification.purpose,
    role: verification.role,
    face_verified: verification.faceVerified,
    inheritance_evidence: verification.inheritanceEvidence ?? null,
    expires_at: verification.expiresAt,
  });
  return {
    package_json: packageJson,
    authorization,
    signature: sign(null, Buffer.from(authorization, 'utf8'), privateKey).toString('hex'),
  };
}

export function parsePgVector(input) {
  let values;
  if (typeof input === 'string') {
    const trimmed = input.trim();
    if (!trimmed.startsWith('[') || !trimmed.endsWith(']')) {
      throw new Error('Invalid pgvector literal: expected "[v0,v1,...,v127]"');
    }
    const inner = trimmed.slice(1, -1).trim();
    if (inner.length === 0) {
      throw new Error(`Invalid pgvector literal: expected ${EMBEDDING_DIM} values, got 0`);
    }
    values = inner.split(',').map((part) => Number(part.trim()));
  } else if (ArrayBuffer.isView(input) || Array.isArray(input)) {
    values = Array.from(input, Number);
  } else {
    throw new Error('Embedding must be a pgvector string or numeric array');
  }

  if (values.length !== EMBEDDING_DIM) {
    throw new Error(`Expected ${EMBEDDING_DIM}-D face embedding, got ${values.length}`);
  }

  const out = new Float64Array(EMBEDDING_DIM);
  let normSq = 0;
  for (let i = 0; i < EMBEDDING_DIM; i += 1) {
    const v = values[i];
    if (!Number.isFinite(v)) {
      throw new Error(`Face embedding contains non-finite value at index ${i}`);
    }
    out[i] = v;
    normSq += v * v;
  }
  if (normSq === 0) {
    throw new Error('Face embedding cannot be the zero vector');
  }
  return out;
}

export function verifyFaceEmbedding(
  probeEmbedding,
  storedEmbedding,
  threshold = RECOMMENDED_VAULT_THRESHOLD,
) {
  if (!Number.isFinite(threshold) || threshold < -1 || threshold > 1) {
    throw new Error(`Invalid similarity threshold: ${threshold}`);
  }
  const probe = parsePgVector(probeEmbedding);
  const stored = parsePgVector(storedEmbedding);
  let dot = 0;
  let normProbe = 0;
  let normStored = 0;
  for (let i = 0; i < EMBEDDING_DIM; i += 1) {
    dot += probe[i] * stored[i];
    normProbe += probe[i] * probe[i];
    normStored += stored[i] * stored[i];
  }
  const rawSimilarity = dot / (Math.sqrt(normProbe) * Math.sqrt(normStored));
  const similarity = Math.max(-1, Math.min(1, rawSimilarity));
  return {
    matched: similarity >= threshold,
    similarity,
    distance: 1 - similarity,
    threshold,
  };
}

export function createChallengeStore({ ttlSeconds = 120, now = () => Date.now() } = {}) {
  if (!Number.isFinite(ttlSeconds) || ttlSeconds <= 0) {
    throw new Error('ttlSeconds must be a positive number');
  }
  const entries = new Map();

  function sweep(nowMs) {
    for (const [nonce, record] of entries) {
      if (record.expiresAtMs <= nowMs) {
        entries.delete(nonce);
      }
    }
  }

  return {
    issue({ vaultId, publicKey, instanceId, packageJson, purpose, role }) {
      const nowMs = now();
      sweep(nowMs);
      if (typeof vaultId !== 'string' || vaultId.trim().length === 0) {
        throw new Error('vaultId is required to issue a challenge');
      }
      if (typeof packageJson !== 'string' || packageJson.length === 0) {
        throw new Error('packageJson is required to issue a challenge');
      }
      const normalizedPublicKey = typeof publicKey === 'string' ? publicKey.trim().toLowerCase() : undefined;
      const packageSha256 = sha256Hex(packageJson);
      const challengeNonce = randomBytes(24).toString('base64url');
      const expiresAtMs = nowMs + ttlSeconds * 1000;
      const expiresAt = Math.floor(expiresAtMs / 1000);
      entries.set(challengeNonce, {
        challengeNonce,
        vaultId,
        publicKey: normalizedPublicKey,
        instanceId,
        packageSha256,
        purpose,
        role,
        expiresAt,
        expiresAtMs,
      });
      return { challengeNonce, packageSha256, expiresAt };
    },

    consume(nonce, expected = {}) {
      const nowMs = now();
      if (typeof nonce !== 'string' || nonce.trim().length === 0) {
        throw new Error('Missing challengeNonce');
      }
      const record = entries.get(nonce);
      entries.delete(nonce);
      if (!record) {
        throw new Error('Unknown or already consumed challengeNonce');
      }
      if (record.expiresAtMs <= nowMs) {
        throw new Error('challengeNonce has expired');
      }
      if (expected.vaultId !== undefined && record.vaultId !== expected.vaultId) {
        throw new Error('challengeNonce does not match vaultId');
      }
      if (
        expected.publicKey !== undefined &&
        record.publicKey !== undefined &&
        record.publicKey !== expected.publicKey.trim().toLowerCase()
      ) {
        throw new Error('challengeNonce does not match publicKey');
      }
      if (expected.packageSha256 !== undefined && record.packageSha256 !== expected.packageSha256.toLowerCase()) {
        throw new Error('challengeNonce does not match transaction packageSha256');
      }
      if (expected.purpose !== undefined && record.purpose !== undefined && record.purpose !== expected.purpose) {
        throw new Error('challengeNonce does not match purpose');
      }
      if (expected.role !== undefined && record.role !== undefined && record.role !== expected.role) {
        throw new Error('challengeNonce does not match role');
      }
      return {
        challengeNonce: record.challengeNonce,
        vaultId: record.vaultId,
        publicKey: record.publicKey,
        instanceId: record.instanceId,
        packageSha256: record.packageSha256,
        purpose: record.purpose,
        role: record.role,
        expiresAt: record.expiresAt,
      };
    },

    size() {
      sweep(now());
      return entries.size;
    },
  };
}

function normalizeBaseUrl(signerUrl) {
  if (typeof signerUrl !== 'string' || signerUrl.trim().length === 0) {
    throw new Error('signerUrl is required');
  }
  return signerUrl.trim().replace(/\/+$/, '');
}

async function readErrorBody(response) {
  try {
    return (await response.text()).trim();
  } catch {
    return '';
  }
}

export async function fetchSigningContext(signerUrl, fetchImpl = globalThis.fetch) {
  const baseUrl = normalizeBaseUrl(signerUrl);
  const res = await fetchImpl(`${baseUrl}/v1/signing/context`, {
    method: 'GET',
    headers: { Accept: 'application/json' },
  });
  if (!res.ok) {
    const detail = await readErrorBody(res);
    throw new Error(`Failed to fetch signing context (${res.status})${detail ? `: ${detail}` : ''}`);
  }
  const data = await res.json();
  if (typeof data?.instance_id !== 'string' || typeof data?.public_key !== 'string') {
    throw new Error('Signing server returned an invalid /v1/signing/context payload');
  }
  return {
    instanceId: data.instance_id,
    publicKey: data.public_key,
  };
}

export async function issueSigningTicket(
  signerUrl,
  packageJson,
  verification,
  privateKey,
  fetchImpl = globalThis.fetch,
) {
  const baseUrl = normalizeBaseUrl(signerUrl);
  const body = buildSigningSessionRequest(packageJson, verification, privateKey);
  const res = await fetchImpl(`${baseUrl}/v1/signing/sessions`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json',
    },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const detail = await readErrorBody(res);
    throw new Error(`Signing server rejected session request (${res.status})${detail ? `: ${detail}` : ''}`);
  }
  const data = await res.json();
  if (typeof data?.ticket !== 'string' || data.ticket.length === 0) {
    throw new Error('Signing server response did not include a session ticket');
  }
  return {
    ticket: data.ticket,
    expiresInSeconds: typeof data.expires_in_seconds === 'number' ? data.expires_in_seconds : undefined,
  };
}

export async function authorizeFaceAndIssueTicket({
  signerUrl,
  packageJson,
  payload,
  storedEmbedding,
  privateKey,
  threshold = RECOMMENDED_VAULT_THRESHOLD,
  instanceId,
  publicKey,
  challengeStore,
  inheritanceEvidence = null,
  ttlSeconds = 60,
  fetchImpl = globalThis.fetch,
  now = () => Date.now(),
}) {
  if (!Number.isFinite(ttlSeconds) || ttlSeconds <= 0 || ttlSeconds > MAX_AUTHORIZATION_TTL_SECONDS) {
    throw new Error(`ttlSeconds must be between 1 and ${MAX_AUTHORIZATION_TTL_SECONDS}`);
  }
  if (!payload || typeof payload !== 'object') {
    throw new Error('FaceVerifyPayload is required');
  }

  let resolvedInstanceId = instanceId;
  let resolvedPublicKey = publicKey;
  if (!resolvedInstanceId || !resolvedPublicKey) {
    const ctx = await fetchSigningContext(signerUrl, fetchImpl);
    resolvedInstanceId = resolvedInstanceId ?? ctx.instanceId;
    resolvedPublicKey = resolvedPublicKey ?? ctx.publicKey;
  }

  const normalizedPublicKey = resolvedPublicKey.trim().toLowerCase();
  const packageSha256 = sha256Hex(packageJson);

  if (payload.signingPackageHash !== undefined && payload.signingPackageHash.toLowerCase() !== packageSha256) {
    throw new Error('Payload signingPackageHash does not match packageJson');
  }
  if (payload.publicKey !== undefined && payload.publicKey.trim().toLowerCase() !== normalizedPublicKey) {
    throw new Error('Payload publicKey does not match signing server publicKey');
  }

  if (challengeStore) {
    challengeStore.consume(payload.challengeNonce, {
      vaultId: payload.vaultId,
      publicKey: normalizedPublicKey,
      packageSha256,
      purpose: payload.purpose,
      role: payload.role,
    });
  }

  const match = verifyFaceEmbedding(payload.embedding, storedEmbedding, threshold);
  if (!match.matched) {
    return {
      verified: false,
      similarity: match.similarity,
      reason: 'face_mismatch',
    };
  }

  if (payload.purpose === 'inheritance' && !inheritanceEvidence) {
    throw new Error("inheritanceEvidence ('death_verified' | 'inactivity_elapsed') is required for inheritance");
  }

  const expiresAt = Math.floor(now() / 1000) + Math.floor(ttlSeconds);
  const { ticket, expiresInSeconds } = await issueSigningTicket(
    signerUrl,
    packageJson,
    {
      instanceId: resolvedInstanceId,
      publicKey: normalizedPublicKey,
      packageSha256,
      purpose: payload.purpose,
      role: payload.role,
      faceVerified: true,
      inheritanceEvidence: payload.purpose === 'inheritance' ? inheritanceEvidence : null,
      expiresAt,
    },
    privateKey,
    fetchImpl,
  );

  return {
    verified: true,
    similarity: match.similarity,
    ticket,
    expiresInSeconds,
  };
}
