/**
 * Integration types shared with the frontend and auth server.
 *
 * Chronos Vault uses three threshold ECDSA shares (2-of-3):
 *   - U: user device
 *   - S: auth server
 *   - R: emergency card / file
 *
 * Facial recognition never acts as a key share itself. It only produces a
 * normalized 128-D vector after on-device liveness verification so the server
 * can decide whether S participates in signing.
 */

import type { ChallengeStep, LivenessReport } from './liveness';
import type { FrameMetrics, QualityIssue } from './quality';
import type { FaceVector } from './vector';

export type SubjectRole = 'owner' | 'heir';

export type AuthPurpose = 'normal_sign' | 'recovery' | 'inheritance';

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
}

/** Payload sent by the frontend when requesting a signing session with S. */
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
}

/** Expected response shape from the auth server after cosine comparison. */
export interface FaceVerifyServerResponse {
  verified: boolean;
  similarity: number;
  /** Transaction-scoped ticket issued by S once the server has verified all required conditions. */
  ticket?: string;
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
  /** Ready to send directly to the auth server for share S verification. */
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
