/**
 * Drop-in frontend client helpers that combine on-device biometrics capture
 * (`BiometricsEngine`) with backend HTTP calls for enrollment and transaction-bound
 * signing ticket acquisition.
 */

import {
  buildEnrollPayload,
  buildVerifyPayload,
  hashSigningPackage,
  type BiometricsEngine,
  type EnrollSessionOptions,
  type VerifySessionOptions,
} from './session';
import type {
  AuthPurpose,
  EnrollResult,
  FaceEnrollPayload,
  FaceVerifyPayload,
  FaceVerifyServerResponse,
  PartyId,
  SigningQuorum,
  SubjectRole,
  VerifyCaptureResult,
} from './types';

export type BiometricsEngineLike = Pick<BiometricsEngine, 'enroll' | 'verify'>;

export class BiometricsApiError extends Error {
  constructor(
    public readonly status: number,
    message: string,
    public readonly body?: unknown,
  ) {
    super(message);
    this.name = 'BiometricsApiError';
  }
}

export interface SigningPackageMetadata {
  publicKey?: string;
  signers?: SigningQuorum;
}

const VALID_PARTY_IDS = new Set<number>([1, 2, 3]);

/**
 * Reads optional `public_key` and `signers` fields from a serialized `SigningPackage` JSON
 * string without mutating or re-serializing the original payload.
 */
export function extractSigningPackageMetadata(packageJson: string): SigningPackageMetadata {
  try {
    const parsed = JSON.parse(packageJson) as Record<string, unknown>;
    const meta: SigningPackageMetadata = {};
    if (typeof parsed.public_key === 'string' && parsed.public_key.trim().length > 0) {
      meta.publicKey = parsed.public_key.trim();
    }
    if (
      Array.isArray(parsed.signers) &&
      parsed.signers.length === 2 &&
      typeof parsed.signers[0] === 'number' &&
      typeof parsed.signers[1] === 'number' &&
      VALID_PARTY_IDS.has(parsed.signers[0]) &&
      VALID_PARTY_IDS.has(parsed.signers[1]) &&
      parsed.signers[0] !== parsed.signers[1]
    ) {
      meta.signers = [parsed.signers[0] as PartyId, parsed.signers[1] as PartyId];
    }
    return meta;
  } catch {
    return {};
  }
}

export interface EnrollFaceWithServerOptions extends EnrollSessionOptions {
  engine: BiometricsEngineLike;
  video: HTMLVideoElement;
  vaultId: string;
  role: SubjectRole;
  /** Backend endpoint accepting `FaceEnrollPayload` via HTTP POST. */
  enrollUrl: string;
  publicKey?: string;
  challengeNonce?: string;
  headers?: HeadersInit;
  credentials?: RequestCredentials;
  extraBody?: Record<string, unknown>;
  fetchImpl?: typeof fetch;
}

export interface EnrollFaceWithServerResult<TResponse = unknown> {
  capture: EnrollResult;
  payload: FaceEnrollPayload;
  response: TResponse;
}

export interface VerifyTransactionWithFaceOptions extends VerifySessionOptions {
  engine: BiometricsEngineLike;
  video: HTMLVideoElement;
  vaultId: string;
  role: SubjectRole;
  purpose: AuthPurpose;
  /** Exact raw `SigningPackage` JSON string returned by `prepareTransaction` / `payment.json`. */
  packageJson: string;
  /** Backend endpoint accepting `FaceVerifyPayload` via HTTP POST and returning `FaceVerifyServerResponse`. */
  verifyUrl: string;
  /** Optional override; auto-extracted from `packageJson.public_key` when omitted. */
  publicKey?: string;
  challengeNonce?: string;
  /** Optional override; auto-extracted from `packageJson.signers` when omitted. */
  signers?: SigningQuorum;
  /** When true, includes the raw `packageJson` field alongside `FaceVerifyPayload` in the POST body. */
  includePackageJson?: boolean;
  /** Require `response.ticket` when `response.verified === true` (default: `true`). */
  requireTicket?: boolean;
  headers?: HeadersInit;
  credentials?: RequestCredentials;
  extraBody?: Record<string, unknown>;
  fetchImpl?: typeof fetch;
}

export interface VerifyTransactionWithFaceResult {
  capture: VerifyCaptureResult;
  payload: FaceVerifyPayload;
  response: FaceVerifyServerResponse;
  /** Transaction-scoped signing ticket ready to pass to `signWithServer(signerUrl, ticket, packageJson, ...)`. */
  ticket?: string;
}

async function postJson<TResponse>(
  url: string,
  body: Record<string, unknown>,
  options: {
    headers?: HeadersInit;
    credentials?: RequestCredentials;
    signal?: AbortSignal;
    fetchImpl?: typeof fetch;
  },
): Promise<TResponse> {
  const fetchFn = options.fetchImpl ?? globalThis.fetch;
  const headers = new Headers(options.headers);
  if (!headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }
  if (!headers.has('Accept')) {
    headers.set('Accept', 'application/json');
  }

  const res = await fetchFn(url, {
    method: 'POST',
    headers,
    credentials: options.credentials,
    signal: options.signal,
    body: JSON.stringify(body),
  });

  const text = await res.text();
  let parsed: unknown;
  if (text.length > 0) {
    try {
      parsed = JSON.parse(text);
    } catch {
      parsed = text;
    }
  }

  if (!res.ok) {
    const detail =
      typeof parsed === 'object' && parsed !== null && 'reason' in parsed
        ? String((parsed as { reason: unknown }).reason)
        : typeof parsed === 'string' && parsed.length > 0
          ? parsed
          : `HTTP ${res.status}`;
    throw new BiometricsApiError(res.status, `Biometrics request failed (${res.status}): ${detail}`, parsed);
  }

  return parsed as TResponse;
}

/**
 * One-call frontend helper for face enrollment:
 * runs `engine.enroll()`, builds `FaceEnrollPayload`, and POSTs it to `enrollUrl`.
 */
export async function enrollFaceWithServer<TResponse = unknown>(
  options: EnrollFaceWithServerOptions,
): Promise<EnrollFaceWithServerResult<TResponse>> {
  const {
    engine,
    video,
    vaultId,
    role,
    enrollUrl,
    publicKey,
    challengeNonce,
    headers,
    credentials,
    extraBody,
    fetchImpl,
    ...sessionOptions
  } = options;

  const capture = await engine.enroll(video, sessionOptions);
  const payload = buildEnrollPayload(vaultId, role, capture, {
    publicKey,
    challengeNonce,
  });
  const body = extraBody ? { ...extraBody, ...payload } : { ...payload };
  const response = await postJson<TResponse>(enrollUrl, body, {
    headers,
    credentials,
    signal: sessionOptions.signal,
    fetchImpl,
  });

  return { capture, payload, response };
}

/**
 * One-call frontend helper for transaction-bound face verification:
 * hashes the exact raw `packageJson`, runs `engine.verify()`, builds `FaceVerifyPayload`,
 * POSTs it to `verifyUrl`, and returns the signing `ticket` ready for `signWithServer()`.
 */
export async function verifyTransactionWithFace(
  options: VerifyTransactionWithFaceOptions,
): Promise<VerifyTransactionWithFaceResult> {
  const {
    engine,
    video,
    vaultId,
    role,
    purpose,
    packageJson,
    verifyUrl,
    publicKey,
    challengeNonce,
    signers,
    includePackageJson = false,
    requireTicket = true,
    headers,
    credentials,
    extraBody,
    fetchImpl,
    ...sessionOptions
  } = options;

  const signingPackageHash = await hashSigningPackage(packageJson);
  const pkgMeta = extractSigningPackageMetadata(packageJson);
  const capture = await engine.verify(video, sessionOptions);
  const payload = buildVerifyPayload(vaultId, role, purpose, capture, {
    publicKey: publicKey ?? pkgMeta.publicKey,
    challengeNonce,
    signingPackageHash,
    signers: signers ?? pkgMeta.signers,
  });

  const body: Record<string, unknown> = {
    ...(extraBody ?? {}),
    ...payload,
    ...(includePackageJson ? { packageJson } : {}),
  };

  const response = await postJson<FaceVerifyServerResponse>(verifyUrl, body, {
    headers,
    credentials,
    signal: sessionOptions.signal,
    fetchImpl,
  });

  if (typeof response?.verified !== 'boolean') {
    throw new BiometricsApiError(502, 'Auth server returned an invalid FaceVerifyServerResponse', response);
  }

  if (response.verified && requireTicket && !response.ticket) {
    throw new BiometricsApiError(
      502,
      'Auth server verified face but did not return a signing ticket',
      response,
    );
  }

  return {
    capture,
    payload,
    response,
    ticket: response.verified ? response.ticket : undefined,
  };
}
