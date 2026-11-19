/**
 * Face vector comparison and threshold calibration utilities.
 *
 * Cosine similarity here matches pgvector's cosine distance operator (<=>):
 *   distance = 1 - similarity
 *   similarity >= threshold  <==>  (a <=> b) <= (1 - threshold)
 */

import { SFACE_COSINE_THRESHOLD } from './config';
import { assertFaceVector, cosineSimilarity, type FaceVector } from './vector';

export interface MatchResult {
  matched: boolean;
  /** Cosine similarity in [-1, 1]. Higher means closer. */
  similarity: number;
  /** Cosine distance (1 - similarity), matching pgvector's `<=>`. */
  distance: number;
  threshold: number;
}

export function verifyVector(
  probe: FaceVector,
  reference: FaceVector,
  threshold: number = SFACE_COSINE_THRESHOLD,
): MatchResult {
  assertFaceVector(probe);
  assertFaceVector(reference);
  if (!Number.isFinite(threshold) || threshold < -1 || threshold > 1) {
    throw new Error(`Invalid similarity threshold: ${threshold}`);
  }
  const raw = cosineSimilarity(probe, reference);
  const similarity = Math.max(-1, Math.min(1, raw));
  const distance = 1 - similarity;
  return {
    matched: similarity >= threshold,
    similarity,
    distance,
    threshold,
  };
}

export interface ScoreSummary {
  count: number;
  min: number;
  max: number;
  mean: number;
}

export interface CalibrationOptions {
  /**
   * Maximum acceptable False Accept Rate in [0, 1].
   * When set, `threshold` is chosen as the lowest threshold with FAR <= targetFar.
   * When omitted, `threshold` equals `eerThreshold`.
   */
  targetFar?: number;
}

export interface CalibrationResult {
  /** Recommended cosine similarity threshold. */
  threshold: number;
  /** False Accept Rate at `threshold` (fraction of impostors accepted). */
  far: number;
  /** False Reject Rate at `threshold` (fraction of genuine pairs rejected). */
  frr: number;
  /** Equal Error Rate where FAR and FRR are closest. */
  eer: number;
  /** Threshold at EER. */
  eerThreshold: number;
  genuine: ScoreSummary;
  impostor: ScoreSummary;
}

function summarize(scores: readonly number[]): ScoreSummary {
  let min = Infinity;
  let max = -Infinity;
  let sum = 0;
  for (const s of scores) {
    if (!Number.isFinite(s)) throw new Error('Calibration scores must be finite numbers');
    if (s < min) min = s;
    if (s > max) max = s;
    sum += s;
  }
  return { count: scores.length, min, max, mean: sum / scores.length };
}

function ratesAt(genuine: readonly number[], impostor: readonly number[], t: number): { far: number; frr: number } {
  let fa = 0;
  for (const s of impostor) if (s >= t) fa++;
  let fr = 0;
  for (const s of genuine) if (s < t) fr++;
  return { far: fa / impostor.length, frr: fr / genuine.length };
}

/**
 * Computes FAR/FRR/EER and selects a cosine similarity threshold from labeled
 * genuine (same person) and impostor (different people) similarity scores.
 */
export function calibrateThreshold(
  genuineScores: readonly number[],
  impostorScores: readonly number[],
  options: CalibrationOptions = {},
): CalibrationResult {
  if (genuineScores.length === 0 || impostorScores.length === 0) {
    throw new Error('calibrateThreshold needs at least one genuine and one impostor score');
  }

  const genuine = summarize(genuineScores);
  const impostor = summarize(impostorScores);

  const unique = Array.from(new Set([...genuineScores, ...impostorScores])).sort((a, b) => a - b);
  const candidates: number[] = [];
  candidates.push(Math.max(-1, unique[0] - 1e-4));
  for (let i = 0; i < unique.length; i++) {
    candidates.push(unique[i]);
    if (i + 1 < unique.length) {
      candidates.push((unique[i] + unique[i + 1]) / 2);
    }
  }
  candidates.push(Math.min(1, unique[unique.length - 1] + 1e-4));

  let bestEerDiff = Infinity;
  let eerThreshold = candidates[0];
  let eer = 1;

  for (const t of candidates) {
    const { far, frr } = ratesAt(genuineScores, impostorScores, t);
    const diff = Math.abs(far - frr);
    const avg = (far + frr) / 2;
    if (diff < bestEerDiff || (diff === bestEerDiff && avg < eer)) {
      bestEerDiff = diff;
      eerThreshold = t;
      eer = avg;
    }
  }

  let threshold = eerThreshold;
  if (options.targetFar !== undefined) {
    if (options.targetFar < 0 || options.targetFar > 1) {
      throw new Error(`targetFar must be in [0, 1], got ${options.targetFar}`);
    }
    let chosen: number | null = null;
    for (const t of candidates) {
      const { far } = ratesAt(genuineScores, impostorScores, t);
      if (far <= options.targetFar) {
        chosen = t;
        break;
      }
    }
    threshold = chosen ?? 1;
  }

  const { far, frr } = ratesAt(genuineScores, impostorScores, threshold);
  return {
    threshold,
    far,
    frr,
    eer,
    eerThreshold,
    genuine,
    impostor,
  };
}
