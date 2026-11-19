import { describe, expect, it } from 'vitest';
import { EMBEDDING_DIM } from '../src/config';
import {
  VectorError,
  assertFaceVector,
  cosineSimilarity,
  fromPgVectorLiteral,
  l2Norm,
  l2Normalize,
  meanVector,
  toPgVectorLiteral,
  wipe,
} from '../src/vector';

function makeUnit(seed: number): Float32Array {
  const raw = new Float32Array(EMBEDDING_DIM);
  for (let i = 0; i < EMBEDDING_DIM; i++) {
    raw[i] = Math.sin((i + 1) * seed) + Math.cos(i * 0.37 + seed);
  }
  return l2Normalize(raw);
}

describe('vector utilities', () => {
  it('normalizes vectors to unit L2 norm', () => {
    const v = l2Normalize([3, 4]);
    expect(l2Norm(v)).toBeCloseTo(1, 6);
    expect(v[0]).toBeCloseTo(0.6, 6);
    expect(v[1]).toBeCloseTo(0.8, 6);
  });

  it('rejects zero or non-finite vectors', () => {
    expect(() => l2Normalize([0, 0, 0])).toThrow(VectorError);
    expect(() => l2Normalize([1, Number.NaN])).toThrow(VectorError);
    expect(() => l2Normalize([1, Number.POSITIVE_INFINITY])).toThrow(VectorError);
  });

  it('validates 128-D unit face vectors', () => {
    const good = makeUnit(1.5);
    expect(() => assertFaceVector(good)).not.toThrow();

    expect(() => assertFaceVector(new Float32Array(64))).toThrow(VectorError);

    const unnormalized = new Float32Array(EMBEDDING_DIM).fill(1);
    expect(() => assertFaceVector(unnormalized)).toThrow(VectorError);

    const withNan = new Float32Array(good);
    withNan[10] = Number.NaN;
    expect(() => assertFaceVector(withNan)).toThrow(VectorError);
  });

  it('computes cosine similarity correctly', () => {
    const a = makeUnit(2.1);
    const negA = new Float32Array(a.map((x) => -x));
    expect(cosineSimilarity(a, a)).toBeCloseTo(1, 6);
    expect(cosineSimilarity(a, negA)).toBeCloseTo(-1, 6);

    const ortho1 = new Float32Array(EMBEDDING_DIM);
    const ortho2 = new Float32Array(EMBEDDING_DIM);
    ortho1[0] = 1;
    ortho2[1] = 1;
    expect(cosineSimilarity(ortho1, ortho2)).toBeCloseTo(0, 6);
  });

  it('averages multiple vectors and re-normalizes', () => {
    const a = makeUnit(1.1);
    const b = l2Normalize(a.map((x, i) => x + (i % 2 === 0 ? 0.01 : -0.01)));
    const m = meanVector([a, b]);
    expect(l2Norm(m)).toBeCloseTo(1, 6);
    expect(cosineSimilarity(m, a)).toBeCloseTo(cosineSimilarity(m, b), 5);
    expect(cosineSimilarity(m, a)).toBeGreaterThan(cosineSimilarity(a, b));
    expect(() => meanVector([])).toThrow(VectorError);
  });

  it('round-trips pgvector text literals', () => {
    const v = makeUnit(4.2);
    const literal = toPgVectorLiteral(v);
    expect(literal.startsWith('[')).toBe(true);
    expect(literal.endsWith(']')).toBe(true);
    expect(literal.split(',').length).toBe(EMBEDDING_DIM);

    const parsed = fromPgVectorLiteral(literal);
    expect(cosineSimilarity(v, parsed)).toBeCloseTo(1, 6);

    expect(() => fromPgVectorLiteral('not-a-vector')).toThrow(VectorError);
    expect(() => fromPgVectorLiteral('[1,2,3]')).toThrow(VectorError);
  });

  it('wipes typed array buffers with zeros', () => {
    const v = makeUnit(3.3);
    wipe(v);
    expect(Array.from(v).every((x) => x === 0)).toBe(true);
  });
});
