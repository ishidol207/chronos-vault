import type { KeyLike } from 'node:crypto';
import type { AuthPurpose, FaceVerifyPayload, FaceVerifyServerResponse, SubjectRole } from '../src/types';

export declare const EMBEDDING_DIM = 128;
export declare const RECOMMENDED_VAULT_THRESHOLD = 0.4;
export declare const SIGNING_AUDIENCE = 'chronos-vault:testnet4:signing:v1';

export type InheritanceEvidence = 'death_verified' | 'inactivity_elapsed';

export interface SigningVerificationRecord {
  instanceId: string;
  publicKey: string;
  packageSha256: string;
  purpose: AuthPurpose;
  role: SubjectRole;
  faceVerified: boolean;
  inheritanceEvidence?: InheritanceEvidence | null;
  /** Unix timestamp in seconds (must be within 120 seconds of issuance for threshold-runner). */
  expiresAt: number;
}

export interface SigningSessionRequestBody {
  package_json: string;
  authorization: string;
  signature: string;
}

export interface FaceEmbeddingMatch {
  matched: boolean;
  similarity: number;
  distance: number;
  threshold: number;
}

export interface IssuedChallenge {
  challengeNonce: string;
  packageSha256: string;
  expiresAt: number;
}

export interface ConsumedChallenge extends IssuedChallenge {
  vaultId: string;
  publicKey?: string;
  instanceId?: string;
  purpose?: AuthPurpose;
  role?: SubjectRole;
}

export interface ChallengeIssueInput {
  vaultId: string;
  packageJson: string;
  publicKey?: string;
  instanceId?: string;
  purpose?: AuthPurpose;
  role?: SubjectRole;
}

export interface ChallengeConsumeExpected {
  vaultId?: string;
  publicKey?: string;
  packageSha256?: string;
  purpose?: AuthPurpose;
  role?: SubjectRole;
}

export interface ChallengeStore {
  issue(input: ChallengeIssueInput): IssuedChallenge;
  consume(nonce: string | undefined, expected?: ChallengeConsumeExpected): ConsumedChallenge;
  size(): number;
}

export interface SigningContext {
  instanceId: string;
  publicKey: string;
}

export interface SigningTicketResult {
  ticket: string;
  expiresInSeconds?: number;
}

export interface AuthorizeFaceAndIssueTicketOptions {
  signerUrl: string;
  packageJson: string;
  payload: FaceVerifyPayload;
  storedEmbedding: string | ArrayLike<number>;
  privateKey: KeyLike | string | Uint8Array;
  threshold?: number;
  instanceId?: string;
  publicKey?: string;
  challengeStore?: ChallengeStore;
  inheritanceEvidence?: InheritanceEvidence | null;
  ttlSeconds?: number;
  fetchImpl?: typeof fetch;
  now?: () => number;
}

export interface AuthorizeFaceTicketResponse extends FaceVerifyServerResponse {
  expiresInSeconds?: number;
}

export declare function sha256Hex(text: string): string;

export declare function buildSigningSessionRequest(
  packageJson: string,
  verification: SigningVerificationRecord,
  privateKey: KeyLike | string | Uint8Array,
): SigningSessionRequestBody;

export declare function parsePgVector(input: string | ArrayLike<number>): Float64Array;

export declare function verifyFaceEmbedding(
  probeEmbedding: string | ArrayLike<number>,
  storedEmbedding: string | ArrayLike<number>,
  threshold?: number,
): FaceEmbeddingMatch;

export declare function createChallengeStore(options?: {
  ttlSeconds?: number;
  now?: () => number;
}): ChallengeStore;

export declare function fetchSigningContext(
  signerUrl: string,
  fetchImpl?: typeof fetch,
): Promise<SigningContext>;

export declare function issueSigningTicket(
  signerUrl: string,
  packageJson: string,
  verification: SigningVerificationRecord,
  privateKey: KeyLike | string | Uint8Array,
  fetchImpl?: typeof fetch,
): Promise<SigningTicketResult>;

export declare function authorizeFaceAndIssueTicket(
  options: AuthorizeFaceAndIssueTicketOptions,
): Promise<AuthorizeFaceTicketResponse>;
