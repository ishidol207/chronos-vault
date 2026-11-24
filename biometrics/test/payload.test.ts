import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { EMBEDDING_DIM, PARTY_ID, RECOMMENDED_VAULT_THRESHOLD } from '../src/config';
import { buildEnrollPayload, buildVerifyPayload, hashSigningPackage } from '../src/session';
import type { EnrollResult, VerifyCaptureResult } from '../src/types';
import { l2Normalize, toPgVectorLiteral } from '../src/vector';

const SAMPLE_MASTER_PK = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';

function makeVector(): Float32Array {
  const arr = new Float32Array(EMBEDDING_DIM);
  for (let i = 0; i < EMBEDDING_DIM; i++) {
    arr[i] = Math.cos(i + 1);
  }
  return l2Normalize(arr);
}

function makeEnrollResult(): EnrollResult {
  const vector = makeVector();
  return {
    vector,
    pgVector: toPgVectorLiteral(vector),
    samplesUsed: 5,
    minSampleConsistency: 0.87,
    liveness: {
      status: 'passed',
      steps: ['blink', 'turn_left'],
      currentStep: 2,
      blinkCount: 1,
      startedAt: 1000,
      finishedAt: 3840,
    },
  };
}

function makeVerifyResult(): VerifyCaptureResult {
  const vector = makeVector();
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
      finishedAt: 5120,
    },
  };
}

describe('payload builders and threshold wallet bindings', () => {
  it('exports canonical party IDs and recommended vault threshold', () => {
    expect(PARTY_ID).toEqual({ USER: 1, SERVER: 2, RECOVERY: 3 });
    expect(RECOMMENDED_VAULT_THRESHOLD).toBe(0.4);
  });

  it('keeps legacy 3-arg buildEnrollPayload and 4-arg buildVerifyPayload backward compatible', () => {
    const enroll = buildEnrollPayload('vault-1', 'owner', makeEnrollResult());
    expect(enroll.vaultId).toBe('vault-1');
    expect(enroll.role).toBe('owner');
    expect(enroll.liveness.durationMs).toBe(2840);
    expect('publicKey' in enroll).toBe(false);
    expect('challengeNonce' in enroll).toBe(false);

    const verify = buildVerifyPayload('vault-1', 'heir', 'inheritance', makeVerifyResult());
    expect(verify.vaultId).toBe('vault-1');
    expect(verify.role).toBe('heir');
    expect(verify.purpose).toBe('inheritance');
    expect(verify.liveness.durationMs).toBe(3120);
    expect('publicKey' in verify).toBe(false);
    expect('signingPackageHash' in verify).toBe(false);
    expect('signers' in verify).toBe(false);
  });

  it('binds publicKey, challengeNonce, signingPackageHash, and signers cleanly', async () => {
    const packageJson = JSON.stringify({
      public_key: SAMPLE_MASTER_PK,
      signers: [PARTY_ID.SERVER, PARTY_ID.RECOVERY],
      unsigned_tx_hex: '0200000000',
    });
    const pkgHash = await hashSigningPackage(packageJson);
    const expectedHash = createHash('sha256').update(packageJson, 'utf8').digest('hex');
    expect(pkgHash).toBe(expectedHash);

    const enroll = buildEnrollPayload('vault-1', 'owner', makeEnrollResult(), {
      publicKey: SAMPLE_MASTER_PK.toUpperCase(),
      challengeNonce: 'nonce-enroll-001',
    });
    expect(enroll.publicKey).toBe(SAMPLE_MASTER_PK);
    expect(enroll.challengeNonce).toBe('nonce-enroll-001');

    const verify = buildVerifyPayload('vault-1', 'heir', 'inheritance', makeVerifyResult(), {
      publicKey: SAMPLE_MASTER_PK,
      challengeNonce: 'nonce-verify-002',
      signingPackageHash: pkgHash.toUpperCase(),
      signers: [PARTY_ID.SERVER, PARTY_ID.RECOVERY],
    });
    expect(verify.publicKey).toBe(SAMPLE_MASTER_PK);
    expect(verify.challengeNonce).toBe('nonce-verify-002');
    expect(verify.signingPackageHash).toBe(expectedHash);
    expect(verify.signers).toEqual([2, 3]);
  });

  it('rejects malformed publicKey, signingPackageHash, nonce, and signers', () => {
    const verifyRes = makeVerifyResult();

    expect(() =>
      buildVerifyPayload('v', 'owner', 'normal_sign', verifyRes, {
        publicKey: '04' + 'a'.repeat(64),
      }),
    ).toThrow(/compressed SEC1/i);

    expect(() =>
      buildVerifyPayload('v', 'owner', 'normal_sign', verifyRes, {
        publicKey: '02deadbeef',
      }),
    ).toThrow(/compressed SEC1/i);

    expect(() =>
      buildVerifyPayload('v', 'owner', 'normal_sign', verifyRes, {
        signingPackageHash: 'not-a-sha256',
      }),
    ).toThrow(/SHA-256/i);

    expect(() =>
      buildVerifyPayload('v', 'owner', 'normal_sign', verifyRes, {
        challengeNonce: '   ',
      }),
    ).toThrow(/challengeNonce/i);

    expect(() =>
      buildVerifyPayload('v', 'owner', 'normal_sign', verifyRes, {
        signers: [2, 2],
      }),
    ).toThrow(/distinct party IDs/i);
  });
});
