import { generateKeyPairSync, verify as cryptoVerify } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  BiometricsApiError,
  EMBEDDING_DIM,
  RECOMMENDED_VAULT_THRESHOLD,
  enrollFaceWithServer,
  extractSigningPackageMetadata,
  hashSigningPackage,
  toPgVectorLiteral,
  verifyTransactionWithFace,
  type BiometricsEngineLike,
  type EnrollResult,
  type VerifyCaptureResult,
} from '../src/index';
import {
  SIGNING_AUDIENCE,
  authorizeFaceAndIssueTicket,
  buildSigningSessionRequest,
  createChallengeStore,
  fetchSigningContext,
  issueSigningTicket,
  parsePgVector,
  sha256Hex,
  verifyFaceEmbedding,
} from '../server/signing-session.mjs';

const MASTER_PUBKEY = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';

function makeUnitVector(seed: number): Float32Array {
  const vec = new Float32Array(EMBEDDING_DIM);
  let normSq = 0;
  for (let i = 0; i < EMBEDDING_DIM; i += 1) {
    const val = Math.sin((i + 1) * (seed + 1.37));
    vec[i] = val;
    normSq += val * val;
  }
  const inv = 1 / Math.sqrt(normSq);
  for (let i = 0; i < EMBEDDING_DIM; i += 1) {
    vec[i] *= inv;
  }
  return vec;
}

function makeOrthogonalVector(index: number): Float32Array {
  const vec = new Float32Array(EMBEDDING_DIM);
  vec[index] = 1;
  return vec;
}

function makePackageJson(signers: [number, number] = [1, 2]): string {
  return JSON.stringify({
    public_key: MASTER_PUBKEY,
    signers,
    unsigned_tx_hex: '020000000001',
    request: { amount: { type: 'sweep' }, fee_rate_sat_vb: 1 },
  });
}

function makeMockEnrollResult(seed = 1): EnrollResult {
  const vector = makeUnitVector(seed);
  return {
    vector,
    pgVector: toPgVectorLiteral(vector),
    samplesUsed: 5,
    minSampleConsistency: 0.92,
    liveness: {
      status: 'passed',
      steps: ['blink', 'turn_left'],
      currentStep: 2,
      blinkCount: 1,
      startedAt: 1000,
      finishedAt: 3400,
    },
  };
}

function makeMockVerifyResult(seed = 1): VerifyCaptureResult {
  const vector = makeUnitVector(seed);
  return {
    vector,
    pgVector: toPgVectorLiteral(vector),
    samplesUsed: 2,
    liveness: {
      status: 'passed',
      steps: ['turn_right', 'blink'],
      currentStep: 2,
      blinkCount: 1,
      startedAt: 2000,
      finishedAt: 4100,
    },
  };
}

describe('server/signing-session.mjs helpers', () => {
  it('buildSigningSessionRequest signs exact authorization JSON with Ed25519 and rejects tampered tx', () => {
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    const pkg = makePackageJson([1, 2]);
    const digest = sha256Hex(pkg);

    const req = buildSigningSessionRequest(
      pkg,
      {
        instanceId: 'inst-123',
        publicKey: MASTER_PUBKEY,
        packageSha256: digest,
        purpose: 'normal_sign',
        role: 'owner',
        faceVerified: true,
        inheritanceEvidence: null,
        expiresAt: 1_800_000_000,
      },
      privateKey.export({ type: 'pkcs8', format: 'pem' }),
    );

    expect(req.package_json).toBe(pkg);
    const parsedAuth = JSON.parse(req.authorization);
    expect(parsedAuth.audience).toBe(SIGNING_AUDIENCE);
    expect(parsedAuth.package_sha256).toBe(digest);
    expect(parsedAuth.inheritance_evidence).toBeNull();

    const sigOk = cryptoVerify(
      null,
      Buffer.from(req.authorization, 'utf8'),
      publicKey,
      Buffer.from(req.signature, 'hex'),
    );
    expect(sigOk).toBe(true);

    expect(() =>
      buildSigningSessionRequest(
        pkg + ' ',
        {
          instanceId: 'inst-123',
          publicKey: MASTER_PUBKEY,
          packageSha256: digest,
          purpose: 'normal_sign',
          role: 'owner',
          faceVerified: true,
          expiresAt: 1_800_000_000,
        },
        privateKey,
      ),
    ).toThrow(/Transaction differs/);
  });

  it('parsePgVector and verifyFaceEmbedding match identical vectors and reject orthogonal or invalid ones', () => {
    const vA = makeOrthogonalVector(0);
    const vB = makeOrthogonalVector(1);
    const litA = toPgVectorLiteral(vA);
    const litB = toPgVectorLiteral(vB);

    expect(parsePgVector(litA).length).toBe(EMBEDDING_DIM);
    expect(() => parsePgVector('[0.1,0.2]')).toThrow(/128-D/);
    expect(() => parsePgVector('not-a-vector')).toThrow(/Invalid pgvector/);

    const same = verifyFaceEmbedding(litA, litA);
    expect(same.matched).toBe(true);
    expect(same.similarity).toBeCloseTo(1, 5);
    expect(same.distance).toBeCloseTo(0, 5);
    expect(same.threshold).toBe(RECOMMENDED_VAULT_THRESHOLD);

    const diff = verifyFaceEmbedding(litA, litB);
    expect(diff.matched).toBe(false);
    expect(diff.similarity).toBeCloseTo(0, 5);
  });

  it('createChallengeStore enforces single-use, expiry, and transaction binding', () => {
    let clockMs = 1_700_000_000_000;
    const store = createChallengeStore({ ttlSeconds: 30, now: () => clockMs });
    const pkg = makePackageJson([2, 3]);

    const issued = store.issue({
      vaultId: 'vault-1',
      publicKey: MASTER_PUBKEY,
      instanceId: 'inst-1',
      packageJson: pkg,
      purpose: 'inheritance',
      role: 'heir',
    });

    expect(store.size()).toBe(1);
    const consumed = store.consume(issued.challengeNonce, {
      vaultId: 'vault-1',
      publicKey: MASTER_PUBKEY,
      packageSha256: issued.packageSha256,
      purpose: 'inheritance',
      role: 'heir',
    });
    expect(consumed.packageSha256).toBe(sha256Hex(pkg));
    expect(store.size()).toBe(0);

    // Replay must fail
    expect(() => store.consume(issued.challengeNonce, { vaultId: 'vault-1' })).toThrow(
      /Unknown or already consumed/,
    );

    // Expiry must fail
    const issued2 = store.issue({
      vaultId: 'vault-1',
      packageJson: pkg,
      purpose: 'normal_sign',
    });
    clockMs += 31_000;
    expect(() => store.consume(issued2.challengeNonce, { vaultId: 'vault-1' })).toThrow(/expired/);

    // Mismatched transaction hash must fail and consume the nonce
    const issued3 = store.issue({
      vaultId: 'vault-1',
      packageJson: pkg,
      purpose: 'normal_sign',
    });
    expect(() =>
      store.consume(issued3.challengeNonce, {
        vaultId: 'vault-1',
        packageSha256: '0'.repeat(64),
      }),
    ).toThrow(/packageSha256/);
    expect(store.size()).toBe(0);
  });

  it('fetchSigningContext, issueSigningTicket, and authorizeFaceAndIssueTicket wire the full server flow', async () => {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    const pkg = makePackageJson([1, 2]);
    const pkgHash = sha256Hex(pkg);
    const enrolled = toPgVectorLiteral(makeUnitVector(7));
    const impostor = toPgVectorLiteral(makeOrthogonalVector(5));

    const calls: Array<{ url: string; method: string; body?: string }> = [];
    const mockFetch: typeof fetch = async (input, init) => {
      const url = String(input);
      const method = init?.method ?? 'GET';
      const body = typeof init?.body === 'string' ? init.body : undefined;
      calls.push({ url, method, body });

      if (url.endsWith('/v1/signing/context') && method === 'GET') {
        return new Response(JSON.stringify({ instance_id: 'inst-abc', public_key: MASTER_PUBKEY }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }
      if (url.endsWith('/v1/signing/sessions') && method === 'POST') {
        const parsed = JSON.parse(body ?? '{}');
        const sigOk = cryptoVerify(
          null,
          Buffer.from(parsed.authorization, 'utf8'),
          publicKey,
          Buffer.from(parsed.signature, 'hex'),
        );
        expect(sigOk).toBe(true);
        return new Response(JSON.stringify({ ticket: 'tkt-xyz-999', expires_in_seconds: 600 }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }
      return new Response('not found', { status: 404 });
    };

    const ctx = await fetchSigningContext('http://127.0.0.1:8080/', mockFetch);
    expect(ctx).toEqual({ instanceId: 'inst-abc', publicKey: MASTER_PUBKEY });

    const directTicket = await issueSigningTicket(
      'http://127.0.0.1:8080',
      pkg,
      {
        instanceId: ctx.instanceId,
        publicKey: ctx.publicKey,
        packageSha256: pkgHash,
        purpose: 'normal_sign',
        role: 'owner',
        faceVerified: true,
        expiresAt: Math.floor(Date.now() / 1000) + 60,
      },
      privateKey,
      mockFetch,
    );
    expect(directTicket).toEqual({ ticket: 'tkt-xyz-999', expiresInSeconds: 600 });

    const store = createChallengeStore({ ttlSeconds: 60 });
    const challenge = store.issue({
      vaultId: 'vault-42',
      publicKey: MASTER_PUBKEY,
      instanceId: 'inst-abc',
      packageJson: pkg,
      purpose: 'normal_sign',
      role: 'owner',
    });

    const authorized = await authorizeFaceAndIssueTicket({
      signerUrl: 'http://127.0.0.1:8080',
      packageJson: pkg,
      payload: {
        vaultId: 'vault-42',
        role: 'owner',
        purpose: 'normal_sign',
        embedding: enrolled,
        liveness: { steps: ['blink'], blinkCount: 1, durationMs: 1200 },
        publicKey: MASTER_PUBKEY,
        challengeNonce: challenge.challengeNonce,
        signingPackageHash: pkgHash,
        signers: [1, 2],
      },
      storedEmbedding: enrolled,
      privateKey,
      challengeStore: store,
      fetchImpl: mockFetch,
    });
    expect(authorized.verified).toBe(true);
    expect(authorized.ticket).toBe('tkt-xyz-999');
    expect(authorized.similarity).toBeCloseTo(1, 5);

    // Mismatched face should NOT call /v1/signing/sessions
    const sessionCallsBefore = calls.filter((c) => c.url.endsWith('/v1/signing/sessions')).length;
    const rejected = await authorizeFaceAndIssueTicket({
      signerUrl: 'http://127.0.0.1:8080',
      packageJson: pkg,
      payload: {
        vaultId: 'vault-42',
        role: 'owner',
        purpose: 'normal_sign',
        embedding: impostor,
        liveness: { steps: ['blink'], blinkCount: 1, durationMs: 1200 },
        publicKey: MASTER_PUBKEY,
        signingPackageHash: pkgHash,
      },
      storedEmbedding: enrolled,
      privateKey,
      instanceId: 'inst-abc',
      publicKey: MASTER_PUBKEY,
      fetchImpl: mockFetch,
    });
    expect(rejected.verified).toBe(false);
    expect(rejected.ticket).toBeUndefined();
    expect(calls.filter((c) => c.url.endsWith('/v1/signing/sessions')).length).toBe(sessionCallsBefore);
  });
});

describe('src/client.ts frontend one-call helpers', () => {
  const fakeVideo = {} as HTMLVideoElement;

  it('extractSigningPackageMetadata parses public_key and signers safely', () => {
    const meta = extractSigningPackageMetadata(makePackageJson([2, 3]));
    expect(meta).toEqual({ publicKey: MASTER_PUBKEY, signers: [2, 3] });
    expect(extractSigningPackageMetadata('not-json')).toEqual({});
  });

  it('enrollFaceWithServer runs enroll() and POSTs FaceEnrollPayload', async () => {
    const enrollResult = makeMockEnrollResult(3);
    const engine: BiometricsEngineLike = {
      enroll: async () => enrollResult,
      verify: async () => makeMockVerifyResult(3),
    };

    let sentBody = '';
    const mockFetch: typeof fetch = async (_url, init) => {
      sentBody = String(init?.body ?? '');
      return new Response(JSON.stringify({ ok: true, enrolledAt: '2026-11-25T00:00:00Z' }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    };

    const result = await enrollFaceWithServer<{ ok: boolean }>({
      engine,
      video: fakeVideo,
      vaultId: 'vault-9',
      role: 'owner',
      enrollUrl: '/api/vault/face/enroll',
      publicKey: MASTER_PUBKEY,
      challengeNonce: 'nonce-1',
      fetchImpl: mockFetch,
    });

    expect(result.response.ok).toBe(true);
    expect(JSON.parse(sentBody)).toEqual(result.payload);
    expect(result.payload.publicKey).toBe(MASTER_PUBKEY);
    expect(result.payload.challengeNonce).toBe('nonce-1');
  });

  it('verifyTransactionWithFace hashes packageJson, auto-extracts metadata, and returns ticket', async () => {
    const pkg = makePackageJson([2, 3]);
    const expectedHash = await hashSigningPackage(pkg);
    const engine: BiometricsEngineLike = {
      enroll: async () => makeMockEnrollResult(4),
      verify: async () => makeMockVerifyResult(4),
    };

    let receivedPayload: Record<string, unknown> = {};
    const mockFetch: typeof fetch = async (_url, init) => {
      receivedPayload = JSON.parse(String(init?.body ?? '{}'));
      return new Response(
        JSON.stringify({ verified: true, similarity: 0.74, ticket: 'session-ticket-123' }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      );
    };

    const res = await verifyTransactionWithFace({
      engine,
      video: fakeVideo,
      vaultId: 'vault-9',
      role: 'heir',
      purpose: 'inheritance',
      packageJson: pkg,
      verifyUrl: '/api/vault/face/verify',
      challengeNonce: 'nonce-2',
      fetchImpl: mockFetch,
    });

    expect(res.ticket).toBe('session-ticket-123');
    expect(res.response.verified).toBe(true);
    expect(receivedPayload.signingPackageHash).toBe(expectedHash);
    expect(receivedPayload.publicKey).toBe(MASTER_PUBKEY);
    expect(receivedPayload.signers).toEqual([2, 3]);
    expect(receivedPayload.challengeNonce).toBe('nonce-2');
  });

  it('verifyTransactionWithFace throws BiometricsApiError when server returns verified:true without ticket', async () => {
    const pkg = makePackageJson([1, 2]);
    const engine: BiometricsEngineLike = {
      enroll: async () => makeMockEnrollResult(4),
      verify: async () => makeMockVerifyResult(4),
    };

    const mockFetch: typeof fetch = async () =>
      new Response(JSON.stringify({ verified: true, similarity: 0.8 }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });

    await expect(
      verifyTransactionWithFace({
        engine,
        video: fakeVideo,
        vaultId: 'vault-9',
        role: 'owner',
        purpose: 'normal_sign',
        packageJson: pkg,
        verifyUrl: '/api/vault/face/verify',
        fetchImpl: mockFetch,
      }),
    ).rejects.toBeInstanceOf(BiometricsApiError);
  });
});
