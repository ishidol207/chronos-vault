import { EMBEDDING_DIM } from './config';

/** A face vector: Float32Array of length EMBEDDING_DIM with unit L2 norm. */
export type FaceVector = Float32Array;

export class VectorError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'VectorError';
  }
}

export function l2Norm(v: ArrayLike<number>): number {
  let sum = 0;
  for (let i = 0; i < v.length; i++) sum += v[i] * v[i];
  return Math.sqrt(sum);
}

/** Returns a new unit-length copy of `v`. Throws on zero, NaN or Infinity. */
export function l2Normalize(v: ArrayLike<number>): FaceVector {
  const norm = l2Norm(v);
  if (!Number.isFinite(norm) || norm === 0) {
    throw new VectorError('Cannot normalize a zero or non-finite vector');
  }
  const out = new Float32Array(v.length);
  for (let i = 0; i < v.length; i++) out[i] = v[i] / norm;
  return out;
}

/** Throws unless `v` has EMBEDDING_DIM finite entries and unit norm (within tolerance). */
export function assertFaceVector(v: ArrayLike<number>, tolerance = 1e-3): asserts v is FaceVector {
  if (v.length !== EMBEDDING_DIM) {
    throw new VectorError(`Expected ${EMBEDDING_DIM} dimensions, got ${v.length}`);
  }
  for (let i = 0; i < v.length; i++) {
    if (!Number.isFinite(v[i])) throw new VectorError(`Non-finite value at index ${i}`);
  }
  const norm = l2Norm(v);
  if (Math.abs(norm - 1) > tolerance) {
    throw new VectorError(`Vector is not unit length (norm = ${norm.toFixed(6)})`);
  }
}

/**
 * Cosine similarity in [-1, 1]. For unit vectors this is the dot product.
 * Matches pgvector: similarity = 1 - (a <=> b).
 */
export function cosineSimilarity(a: ArrayLike<number>, b: ArrayLike<number>): number {
  if (a.length !== b.length) {
    throw new VectorError(`Length mismatch: ${a.length} vs ${b.length}`);
  }
  let dot = 0;
  let na = 0;
  let nb = 0;
  for (let i = 0; i < a.length; i++) {
    dot += a[i] * b[i];
    na += a[i] * a[i];
    nb += b[i] * b[i];
  }
  if (na === 0 || nb === 0) throw new VectorError('Cosine similarity of a zero vector');
  return dot / (Math.sqrt(na) * Math.sqrt(nb));
}

/** Element-wise mean of several vectors, re-normalized to unit length. */
export function meanVector(vectors: ArrayLike<number>[]): FaceVector {
  if (vectors.length === 0) throw new VectorError('meanVector needs at least one vector');
  const dim = vectors[0].length;
  const acc = new Float64Array(dim);
  for (const v of vectors) {
    if (v.length !== dim) throw new VectorError('meanVector: inconsistent dimensions');
    for (let i = 0; i < dim; i++) acc[i] += v[i];
  }
  return l2Normalize(acc);
}

/**
 * Serializes to the pgvector text format, e.g. "[0.1,-0.2,...]".
 * This is what the API expects when the vector is sent as a string.
 */
export function toPgVectorLiteral(v: FaceVector): string {
  assertFaceVector(v);
  return '[' + Array.from(v, (x) => x.toPrecision(8)).join(',') + ']';
}

/** Parses the pgvector text format back into a FaceVector (validated). */
export function fromPgVectorLiteral(s: string): FaceVector {
  const trimmed = s.trim();
  if (!trimmed.startsWith('[') || !trimmed.endsWith(']')) {
    throw new VectorError('Not a pgvector literal');
  }
  const body = trimmed.slice(1, -1).trim();
  const parts = body.length === 0 ? [] : body.split(',');
  const v = new Float32Array(parts.length);
  for (let i = 0; i < parts.length; i++) {
    const x = Number(parts[i]);
    if (!Number.isFinite(x)) throw new VectorError(`Invalid number at index ${i}`);
    v[i] = x;
  }
  assertFaceVector(v);
  return v;
}

/** Overwrites a buffer with zeros. Use on raw pixel buffers and temporary vectors. */
export function wipe(buf: Float32Array | Float64Array | Uint8Array | Uint8ClampedArray): void {
  buf.fill(0);
}
