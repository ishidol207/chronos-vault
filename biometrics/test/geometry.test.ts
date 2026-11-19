import { describe, expect, it } from 'vitest';
import {
  ARCFACE_TEMPLATE_112,
  LM,
  MIN_LANDMARKS,
  alignmentError,
  applySimilarity,
  estimateSimilarity,
  eyeState,
  fivePoints,
  headPose,
  interOcularDistance,
  type FrameSize,
  type Landmark,
} from '../src/geometry';

const SIZE: FrameSize = { width: 640, height: 480 };

/** Builds a synthetic frontal 478-point landmark array with controllable eye openness & pose. */
function makeSyntheticFace(opts: {
  eyeHeightNorm?: number;
  yawOffsetZ?: number;
  pitchOffsetZ?: number;
  rollOffsetY?: number;
  scale?: number;
} = {}): Landmark[] {
  const s = opts.scale ?? 1;
  const eyeH = (opts.eyeHeightNorm ?? 0.015) * s;
  const yawZ = opts.yawOffsetZ ?? 0;
  const pitchZ = opts.pitchOffsetZ ?? 0;
  const rollY = opts.rollOffsetY ?? 0;

  const lms: Landmark[] = Array.from({ length: MIN_LANDMARKS + 10 }, () => ({
    x: 0.5,
    y: 0.5,
    z: 0,
  }));

  // Image-left eye around (0.4, 0.42), width 0.06 * s
  const lx = 0.5 - 0.1 * s;
  const ly = 0.42 - rollY;
  const hw = 0.03 * s;
  lms[LM.eyeImageLeft[0]] = { x: lx - hw, y: ly, z: -yawZ / 2 };
  lms[LM.eyeImageLeft[1]] = { x: lx - hw * 0.4, y: ly - eyeH, z: -yawZ / 2 };
  lms[LM.eyeImageLeft[2]] = { x: lx + hw * 0.4, y: ly - eyeH, z: -yawZ / 2 };
  lms[LM.eyeImageLeft[3]] = { x: lx + hw, y: ly, z: -yawZ / 2 };
  lms[LM.eyeImageLeft[4]] = { x: lx + hw * 0.4, y: ly + eyeH, z: -yawZ / 2 };
  lms[LM.eyeImageLeft[5]] = { x: lx - hw * 0.4, y: ly + eyeH, z: -yawZ / 2 };

  // Image-right eye around (0.6, 0.42)
  const rx = 0.5 + 0.1 * s;
  const ry = 0.42 + rollY;
  lms[LM.eyeImageRight[0]] = { x: rx + hw, y: ry, z: yawZ / 2 };
  lms[LM.eyeImageRight[1]] = { x: rx + hw * 0.4, y: ry - eyeH, z: yawZ / 2 };
  lms[LM.eyeImageRight[2]] = { x: rx - hw * 0.4, y: ry - eyeH, z: yawZ / 2 };
  lms[LM.eyeImageRight[3]] = { x: rx - hw, y: ry, z: yawZ / 2 };
  lms[LM.eyeImageRight[4]] = { x: rx - hw * 0.4, y: ry + eyeH, z: yawZ / 2 };
  lms[LM.eyeImageRight[5]] = { x: rx + hw * 0.4, y: ry + eyeH, z: yawZ / 2 };

  // Nose, mouth, forehead, chin
  lms[LM.noseTip] = { x: 0.5, y: 0.52, z: -0.04 };
  lms[LM.mouthImageLeft] = { x: 0.5 - 0.06 * s, y: 0.62, z: 0 };
  lms[LM.mouthImageRight] = { x: 0.5 + 0.06 * s, y: 0.62, z: 0 };
  lms[LM.forehead] = { x: 0.5, y: 0.25, z: -pitchZ / 2 };
  lms[LM.chin] = { x: 0.5, y: 0.75, z: pitchZ / 2 };

  return lms;
}

describe('geometry', () => {
  it('computes open vs closed EAR accurately in pixel space', () => {
    const openFace = makeSyntheticFace({ eyeHeightNorm: 0.015 });
    const closedFace = makeSyntheticFace({ eyeHeightNorm: 0.003 });

    const openEar = eyeState(openFace, SIZE);
    const closedEar = eyeState(closedFace, SIZE);

    expect(openEar.left).toBeCloseTo(openEar.right, 5);
    expect(openEar.mean).toBeGreaterThan(0.3);
    expect(closedEar.mean).toBeLessThan(0.1);
  });

  it('estimates head pose yaw, pitch, and roll signs consistently', () => {
    const center = headPose(makeSyntheticFace(), SIZE);
    expect(Math.abs(center.yaw)).toBeLessThan(1e-6);
    expect(Math.abs(center.pitch)).toBeLessThan(1e-6);
    expect(Math.abs(center.roll)).toBeLessThan(1e-6);

    const turnLeft = headPose(makeSyntheticFace({ yawOffsetZ: 0.12 }), SIZE);
    expect(turnLeft.yaw).toBeGreaterThan(15);

    const turnRight = headPose(makeSyntheticFace({ yawOffsetZ: -0.12 }), SIZE);
    expect(turnRight.yaw).toBeLessThan(-15);

    const lookUp = headPose(makeSyntheticFace({ pitchOffsetZ: 0.12 }), SIZE);
    expect(lookUp.pitch).toBeGreaterThan(10);

    const rolled = headPose(makeSyntheticFace({ rollOffsetY: 0.03 }), SIZE);
    expect(rolled.roll).toBeGreaterThan(5);
  });

  it('computes inter-ocular distance in pixels', () => {
    const face = makeSyntheticFace({ scale: 1 });
    // Eye centers at 0.4*640 = 256 and 0.6*640 = 384 -> distance = 128 px
    expect(interOcularDistance(face, SIZE)).toBeCloseTo(128, 3);
  });

  it('extracts five alignment points in canonical order', () => {
    const pts = fivePoints(makeSyntheticFace(), SIZE);
    expect(pts).toHaveLength(5);
    expect(pts[0].x).toBeLessThan(pts[1].x); // image-left eye < image-right eye
    expect(pts[2].y).toBeGreaterThan(pts[0].y); // nose below eyes
    expect(pts[3].x).toBeLessThan(pts[4].x); // left mouth < right mouth
  });

  it('recovers an exact 2D similarity transform (rotation + scale + translation)', () => {
    const angle = 0.42;
    const scale = 1.75;
    const tx = 140;
    const ty = 85;
    const forward = {
      a: scale * Math.cos(angle),
      b: scale * Math.sin(angle),
      tx,
      ty,
    };

    const src = ARCFACE_TEMPLATE_112.map((p) => applySimilarity(forward, p));
    const recovered = estimateSimilarity(src, ARCFACE_TEMPLATE_112);
    const err = alignmentError(recovered, src, ARCFACE_TEMPLATE_112);

    expect(err).toBeLessThan(1e-9);
  });
});
