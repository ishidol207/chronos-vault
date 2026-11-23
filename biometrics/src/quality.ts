/**
 * Frame quality gating before running the embedding model.
 * Keeps blurry/side-profile/blinking/multi-face frames out of the enrollment average
 * and probe vector. Pure math on MediaPipe landmarks, no DOM access.
 */

import { DEFAULT_QUALITY, type QualityConfig } from './config';
import {
  eyeState,
  fivePoints,
  headPose,
  interOcularDistance,
  type FrameSize,
  type Landmark,
} from './geometry';

export type QualityIssue =
  | 'no_face'
  | 'multiple_faces'
  | 'face_cropped'
  | 'face_too_small'
  | 'yaw_too_large'
  | 'pitch_too_large'
  | 'eyes_closed';

export interface FrameMetrics {
  faceCount: number;
  interOcularPx: number;
  yaw: number;
  pitch: number;
  roll: number;
  earLeft: number;
  earRight: number;
}

export interface QualityResult {
  ok: boolean;
  reasons: QualityIssue[];
  metrics: FrameMetrics | null;
}

const BORDER_MARGIN = 0.02;

/**
 * Default size ratio for `dominantFace`: the main face's inter-ocular distance must be at
 * least this many times every other face's (a bystander or a face on a poster behind).
 */
export const DEFAULT_DOMINANCE_RATIO = 1.6;

/**
 * Index of the face that clearly dominates the frame, judged by inter-ocular distance, or -1
 * when no single face is at least `ratio` times larger than all the others (two people of
 * similar size: the caller should still reject the image).
 */
export function dominantFace(
  faces: Landmark[][],
  size: FrameSize,
  ratio: number = DEFAULT_DOMINANCE_RATIO,
): number {
  if (faces.length === 0) return -1;
  if (faces.length === 1) return 0;
  const sizes = faces.map((f) => interOcularDistance(f, size));
  let best = 0;
  for (let i = 1; i < sizes.length; i++) if (sizes[i] > sizes[best]) best = i;
  return sizes.every((s, i) => i === best || sizes[best] >= ratio * s) ? best : -1;
}

export function assessFrameQuality(
  faces: Landmark[][],
  size: FrameSize,
  cfg: Partial<QualityConfig> = {},
): QualityResult {
  if (faces.length === 0) {
    return { ok: false, reasons: ['no_face'], metrics: null };
  }
  if (faces.length > 1) {
    return { ok: false, reasons: ['multiple_faces'], metrics: null };
  }

  const q: QualityConfig = { ...DEFAULT_QUALITY, ...cfg };
  const lms = faces[0];
  const eyes = eyeState(lms, size);
  const pose = headPose(lms, size);
  const iod = interOcularDistance(lms, size);
  const pts = fivePoints(lms, size);

  const reasons: QualityIssue[] = [];

  const minX = size.width * BORDER_MARGIN;
  const maxX = size.width * (1 - BORDER_MARGIN);
  const minY = size.height * BORDER_MARGIN;
  const maxY = size.height * (1 - BORDER_MARGIN);
  for (const p of pts) {
    if (p.x < minX || p.x > maxX || p.y < minY || p.y > maxY) {
      reasons.push('face_cropped');
      break;
    }
  }

  if (iod < q.minInterOcularPx) reasons.push('face_too_small');
  if (Math.abs(pose.yaw) > q.maxYawDeg) reasons.push('yaw_too_large');
  if (Math.abs(pose.pitch) > q.maxPitchDeg) reasons.push('pitch_too_large');
  if (Math.min(eyes.left, eyes.right) < q.minEarForCapture) reasons.push('eyes_closed');

  return {
    ok: reasons.length === 0,
    reasons,
    metrics: {
      faceCount: 1,
      interOcularPx: iod,
      yaw: pose.yaw,
      pitch: pose.pitch,
      roll: pose.roll,
      earLeft: eyes.left,
      earRight: eyes.right,
    },
  };
}

export function qualityHint(issue: QualityIssue, lang: 'en' | 'ko' = 'en'): string {
  const table: Record<QualityIssue, [string, string]> = {
    no_face: ['Center your face in the frame', '얼굴을 화면 중앙에 맞춰 주세요'],
    multiple_faces: ['Only one face should be visible', '화면에 한 사람만 나오도록 해 주세요'],
    face_cropped: ['Keep your whole face inside the frame', '얼굴 전체가 화면 안에 들어오게 해 주세요'],
    face_too_small: ['Move closer to the camera', '카메라에 조금 더 가까이 와 주세요'],
    yaw_too_large: ['Look straight at the camera', '카메라를 정면으로 바라봐 주세요'],
    pitch_too_large: ['Keep your head level', '고개를 수평으로 유지해 주세요'],
    eyes_closed: ['Keep your eyes open', '눈을 뜬 상태로 유지해 주세요'],
  };
  return table[issue][lang === 'ko' ? 1 : 0];
}
