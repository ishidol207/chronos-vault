import { describe, expect, it } from 'vitest';
import { LM, MIN_LANDMARKS, type FrameSize, type Landmark } from '../src/geometry';
import { assessFrameQuality, qualityHint } from '../src/quality';

const SIZE: FrameSize = { width: 640, height: 480 };

function makeFace(opts: {
  cx?: number;
  scale?: number;
  eyeH?: number;
  yawZ?: number;
  pitchZ?: number;
} = {}): Landmark[] {
  const cx = opts.cx ?? 0.5;
  const s = opts.scale ?? 1;
  const eyeH = (opts.eyeH ?? 0.015) * s;
  const yawZ = opts.yawZ ?? 0;
  const pitchZ = opts.pitchZ ?? 0;

  const lms: Landmark[] = Array.from({ length: MIN_LANDMARKS + 10 }, () => ({
    x: cx,
    y: 0.5,
    z: 0,
  }));
  const hw = 0.03 * s;
  const lx = cx - 0.1 * s;
  const rx = cx + 0.1 * s;

  lms[LM.eyeImageLeft[0]] = { x: lx - hw, y: 0.42, z: -yawZ / 2 };
  lms[LM.eyeImageLeft[1]] = { x: lx - hw * 0.4, y: 0.42 - eyeH, z: -yawZ / 2 };
  lms[LM.eyeImageLeft[2]] = { x: lx + hw * 0.4, y: 0.42 - eyeH, z: -yawZ / 2 };
  lms[LM.eyeImageLeft[3]] = { x: lx + hw, y: 0.42, z: -yawZ / 2 };
  lms[LM.eyeImageLeft[4]] = { x: lx + hw * 0.4, y: 0.42 + eyeH, z: -yawZ / 2 };
  lms[LM.eyeImageLeft[5]] = { x: lx - hw * 0.4, y: 0.42 + eyeH, z: -yawZ / 2 };

  lms[LM.eyeImageRight[0]] = { x: rx + hw, y: 0.42, z: yawZ / 2 };
  lms[LM.eyeImageRight[1]] = { x: rx + hw * 0.4, y: 0.42 - eyeH, z: yawZ / 2 };
  lms[LM.eyeImageRight[2]] = { x: rx - hw * 0.4, y: 0.42 - eyeH, z: yawZ / 2 };
  lms[LM.eyeImageRight[3]] = { x: rx - hw, y: 0.42, z: yawZ / 2 };
  lms[LM.eyeImageRight[4]] = { x: rx - hw * 0.4, y: 0.42 + eyeH, z: yawZ / 2 };
  lms[LM.eyeImageRight[5]] = { x: rx + hw * 0.4, y: 0.42 + eyeH, z: yawZ / 2 };

  lms[LM.noseTip] = { x: cx, y: 0.52, z: -0.04 };
  lms[LM.mouthImageLeft] = { x: cx - 0.06 * s, y: 0.62, z: 0 };
  lms[LM.mouthImageRight] = { x: cx + 0.06 * s, y: 0.62, z: 0 };
  lms[LM.forehead] = { x: cx, y: 0.25, z: -pitchZ / 2 };
  lms[LM.chin] = { x: cx, y: 0.75, z: pitchZ / 2 };
  return lms;
}

describe('assessFrameQuality', () => {
  it('accepts a clean centered frontal face', () => {
    const res = assessFrameQuality([makeFace()], SIZE);
    expect(res.ok).toBe(true);
    expect(res.reasons).toEqual([]);
    expect(res.metrics?.interOcularPx).toBeCloseTo(128, 2);
  });

  it('rejects empty and multi-face frames', () => {
    expect(assessFrameQuality([], SIZE).reasons).toEqual(['no_face']);
    expect(assessFrameQuality([makeFace(), makeFace()], SIZE).reasons).toEqual(['multiple_faces']);
  });

  it('flags faces that are too small, cropped, turned, or blinking', () => {
    expect(assessFrameQuality([makeFace({ scale: 0.3 })], SIZE).reasons).toContain('face_too_small');
    expect(assessFrameQuality([makeFace({ cx: 0.05 })], SIZE).reasons).toContain('face_cropped');
    expect(assessFrameQuality([makeFace({ yawZ: 0.25 })], SIZE).reasons).toContain('yaw_too_large');
    expect(assessFrameQuality([makeFace({ pitchZ: 0.25 })], SIZE).reasons).toContain('pitch_too_large');
    expect(assessFrameQuality([makeFace({ eyeH: 0.002 })], SIZE).reasons).toContain('eyes_closed');
  });

  it('provides localized hints in Korean and English', () => {
    expect(qualityHint('face_too_small', 'ko')).toContain('가까이');
    expect(qualityHint('yaw_too_large', 'en')).toContain('straight');
  });
});
