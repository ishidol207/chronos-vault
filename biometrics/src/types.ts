/**
 * Integration types shared with the frontend and auth/signing server.
 *
 * Chronos Vault uses 2-of-3 CGGMP20 threshold ECDSA (`bitcoin/` + `threshold-online/`):
 *   - Party 1 (U): user device
 *   - Party 2 (S): auth & co-signing server (holds encrypted `secrets.cvparty` locally)
 *   - Party 3 (R): recovery / designated heir share holder
 *
 * Facial recognition never acts as a key share or seed itself, and Party 2 (S) never
 * transmits its long-term key share to the client. This module produces a normalized
 * 128-D face vector after on-device liveness verification so the server can decide
 * whether Party 2 should co-sign a reviewed `SigningPackage` and return a partial
 * ECDSA signature (`PartyResponse`) or short-lived signer approval token.
 */

import type { ChallengeStep, LivenessReport } from './liveness';
import type { FrameMetrics, QualityIssue } from './quality';
import type { FaceVector } from './vector';

/** Threshold ECDSA participant ID matching `bitcoin/` (`1 = U, 2 = S, 3 = R`). */
export type PartyId = 1 | 2 | 3;

/** Two distinct participants forming a 2-of-3 signing quorum (e.g. `[1, 2]` or `[2, 3]`). */
export type SigningQuorum = readonly [PartyId, PartyId];

export type SubjectRole = 'owner' | 'heir';

export type AuthPurpose = 'normal_sign' | 'recovery' | 'inheritance';

/** Optional wallet and anti-replay bindings for `buildEnrollPayload`. */
export interface EnrollPayloadOptions {
  /** 33-byte compressed SEC1 hex master public key (`public-key.json` from `bitcoin/`). */
  publicKey?: string;
  /** Server-issued one-time challenge nonce to prevent replay. */
  challengeNonce?: string;
}

/** Optional wallet, transaction, and anti-replay bindings for `buildVerifyPayload`. */
export interface VerifyPayloadOptions {
  /** 33-byte compressed SEC1 hex master public key (`public-key.json` from `bitcoin/`). */
  publicKey?: string;
  /** Server-issued one-time challenge nonce to prevent replay. */
  challengeNonce?: string;
  /**
   * Lowercase 64-hex SHA-256 fingerprint of the reviewed `SigningPackage` JSON
   * (binds face approval to one exact transaction, matching `exchange-<hash>` in `bitcoin/`).
   */
  signingPackageHash?: string;
  /** Two-party signing quorum from `SigningPackage.signers` (e.g. `[1, 2]` for U+S, `[2, 3]` for S+R). */
  signers?: SigningQuorum;
}

/** Payload sent by the frontend when registering an owner or heir face vector. */
export interface FaceEnrollPayload {
  vaultId: string;
  role: SubjectRole;
  /** Unit-length 128-D vector formatted as a pgvector literal "[v0,v1,...]". */
  embedding: string;
  /** Client-side liveness metadata (informational; server still enforces policy). */
  liveness: {
    steps: ChallengeStep[];
    blinkCount: number;
    durationMs: number;
  };
  /** 33-byte compressed SEC1 hex master public key (`public-key.json` from `bitcoin/`). */
  publicKey?: string;
  /** Server-issued one-time challenge nonce to prevent replay. */
  challengeNonce?: string;
}

/** Payload sent by the frontend when requesting Party 2 (server S) co-signing authorization. */
export interface FaceVerifyPayload {
  vaultId: string;
  role: SubjectRole;
  purpose: AuthPurpose;
  /** Unit-length 128-D vector formatted as a pgvector literal "[v0,v1,...]". */
  embedding: string;
  liveness: {
    steps: ChallengeStep[];
    blinkCount: number;
    durationMs: number;
  };
  /** 33-byte compressed SEC1 hex master public key (`public-key.json` from `bitcoin/`). */
  publicKey?: string;
  /** Server-issued one-time challenge nonce to prevent replay. */
  challengeNonce?: string;
  /**
   * Lowercase 64-hex SHA-256 fingerprint of the reviewed `SigningPackage` JSON
   * (binds face approval to one exact transaction).
   */
  signingPackageHash?: string;
  /** Two-party signing quorum from `SigningPackage.signers` (e.g. `[1, 2]` for U+S, `[2, 3]` for S+R). */
  signers?: SigningQuorum;
}

/** Expected response shape from the auth / Party 2 signing server after cosine comparison. */
export interface FaceVerifyServerResponse {
  verified: boolean;
  similarity: number;
  /**
   * Serialized `PartyResponse` JSON (`{ party_id: 2, inputs: [{ sighash, partial }] }`)
   * returned when the server executes Party 2's `sign-share` / `signShare` directly.
   * Party 2 never transmits its long-term encrypted key share (`secrets.cvparty`).
   */
  partyResponse?: string;
  /**
   * Short-lived single-use approval token for Party 2's signer adapter
   * (`testnet4 send` / `threshold-runner presign`) when auth and signing are separate services.
   */
  approvalToken?: string;
  /**
   * @deprecated Legacy field from the earlier Shamir design. Under CGGMP20 (`bitcoin/`),
   * Party 2 (S) keeps its encrypted key share on the server and returns `partyResponse` or
   * `approvalToken` instead.
   */
  shareS?: string;
  reason?: string;
}

export interface EnrollResult {
  vector: FaceVector;
  /** Ready to send directly to Supabase / PostgreSQL pgvector. */
  pgVector: string;
  samplesUsed: number;
  /** Lowest similarity between any accepted sample and the final averaged template. */
  minSampleConsistency: number;
  liveness: LivenessReport;
}

export interface VerifyCaptureResult {
  vector: FaceVector;
  /** Ready to send directly to the auth server for Party 2 (server S) co-signing verification. */
  pgVector: string;
  samplesUsed: number;
  liveness: LivenessReport;
}

export type SessionStage = 'liveness' | 'capturing' | 'done' | 'failed';

export interface SessionProgress {
  stage: SessionStage;
  /** Localized prompt for the user. */
  message: string;
  liveness: LivenessReport | null;
  qualityIssues: QualityIssue[];
  metrics: FrameMetrics | null;
  samplesCollected: number;
  samplesTarget: number;
}
