import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { ALIGNED_SIZE } from '../src/align';
import { EMBEDDING_DIM } from '../src/config';
import { FaceEmbedder } from '../src/embedder';
import { buildEnrollPayload, buildVerifyPayload } from '../src/session';
import {
  assertFaceVector,
  cosineSimilarity,
  fromPgVectorLiteral,
  toPgVectorLiteral,
} from '../src/vector';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SFACE_PATH = path.resolve(__dirname, '..', 'models', 'face_recognition_sface_2021dec.onnx');
const hasModel = fs.existsSync(SFACE_PATH);

function makePatternTensor(seed: number): Float32Array {
  const len = 3 * ALIGNED_SIZE * ALIGNED_SIZE;
  const out = new Float32Array(len);
  for (let i = 0; i < len; i++) {
    out[i] = ((Math.sin(i * 0.013 + seed) + 1) * 127.5);
  }
  return out;
}

describe.skipIf(!hasModel)('SFace ONNX integration', () => {
  it('runs real inference, produces a unit 128-D vector, and wipes input tensor', async () => {
    const modelBytes = new Uint8Array(fs.readFileSync(SFACE_PATH));
    const embedder = await FaceEmbedder.create({ modelBuffer: modelBytes });
    try {
      const t1 = makePatternTensor(1.0);
      const t1Copy = new Float32Array(t1);
      const t2 = makePatternTensor(7.5);

      const v1 = await embedder.embedTensor(t1, true);
      const v1Repeat = await embedder.embedTensor(t1Copy, true);
      const v2 = await embedder.embedTensor(t2, true);

      // Input buffers wiped
      expect(Array.from(t1).every((x) => x === 0)).toBe(true);
      expect(Array.from(t2).every((x) => x === 0)).toBe(true);

      // Valid unit 128-D vectors
      expect(v1.length).toBe(EMBEDDING_DIM);
      expect(() => assertFaceVector(v1)).not.toThrow();

      // Deterministic on same input, distinct on different input
      expect(cosineSimilarity(v1, v1Repeat)).toBeCloseTo(1, 5);
      expect(cosineSimilarity(v1, v2)).toBeLessThan(0.99);

      // End-to-end payload formatting and pgvector round-trip
      const pg = toPgVectorLiteral(v1);
      expect(cosineSimilarity(fromPgVectorLiteral(pg), v1)).toBeCloseTo(1, 6);

      const enrollPayload = buildEnrollPayload('vault-123', 'owner', {
        vector: v1,
        pgVector: pg,
        samplesUsed: 5,
        minSampleConsistency: 0.85,
        liveness: {
          status: 'passed',
          steps: ['blink', 'turn_left'],
          currentStep: 2,
          blinkCount: 1,
          startedAt: 1000,
          finishedAt: 3400,
        },
      });
      expect(enrollPayload.role).toBe('owner');
      expect(enrollPayload.liveness.durationMs).toBe(2400);

      const verifyPayload = buildVerifyPayload('vault-123', 'heir', 'inheritance', {
        vector: v2,
        pgVector: toPgVectorLiteral(v2),
        samplesUsed: 2,
        liveness: {
          status: 'passed',
          steps: ['turn_right', 'blink'],
          currentStep: 2,
          blinkCount: 1,
          startedAt: 5000,
          finishedAt: 7250,
        },
      });
      expect(verifyPayload.purpose).toBe('inheritance');
      expect(verifyPayload.liveness.durationMs).toBe(2250);
    } finally {
      await embedder.dispose();
    }
  }, 20000);
});
