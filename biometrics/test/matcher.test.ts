import { describe, expect, it } from 'vitest';
import { EMBEDDING_DIM, SFACE_COSINE_THRESHOLD } from '../src/config';
import { calibrateThreshold, verifyVector } from '../src/matcher';
import { l2Normalize } from '../src/vector';

function makeUnit(seed: number): Float32Array {
  const arr = new Float32Array(EMBEDDING_DIM);
  for (let i = 0; i < EMBEDDING_DIM; i++) {
    arr[i] = Math.sin((i + 1) * seed) + Math.cos((i + 2) * seed * 0.5);
  }
  return l2Normalize(arr);
}

describe('verifyVector', () => {
  it('accepts identical and close vectors and reports pgvector-compatible distance', () => {
    const ref = makeUnit(1.0);
    const same = verifyVector(ref, ref);
    expect(same.matched).toBe(true);
    expect(same.similarity).toBeCloseTo(1, 6);
    expect(same.distance).toBeCloseTo(0, 6);
    expect(same.threshold).toBe(SFACE_COSINE_THRESHOLD);
  });

  it('rejects unrelated vectors below threshold', () => {
    const a = makeUnit(1.0);
    const b = makeUnit(9.7);
    const res = verifyVector(a, b, 0.5);
    expect(res.matched).toBe(false);
    expect(res.similarity + res.distance).toBeCloseTo(1, 6);
  });
});

describe('calibrateThreshold', () => {
  it('finds EER = 0 for linearly separable genuine/impostor scores', () => {
    const genuine = [0.55, 0.62, 0.68, 0.71, 0.79];
    const impostor = [-0.1, 0.05, 0.14, 0.21, 0.28];

    const res = calibrateThreshold(genuine, impostor);
    expect(res.eer).toBe(0);
    expect(res.far).toBe(0);
    expect(res.frr).toBe(0);
    expect(res.threshold).toBeGreaterThan(0.28);
    expect(res.threshold).toBeLessThan(0.55);
  });

  it('enforces targetFar on overlapping score distributions', () => {
    const genuine = [0.35, 0.45, 0.52, 0.60, 0.65, 0.70, 0.75, 0.80];
    const impostor = [0.05, 0.10, 0.15, 0.20, 0.25, 0.30, 0.38, 0.42];

    const res = calibrateThreshold(genuine, impostor, { targetFar: 0 });
    expect(res.far).toBe(0);
    expect(res.threshold).toBeGreaterThan(0.42);
    expect(res.frr).toBeGreaterThan(0);
  });
});
