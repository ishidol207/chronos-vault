/**
 * Pure geometry on MediaPipe Face Landmarker output (478 landmarks).
 * No DOM access here so everything can be unit tested in Node.
 *
 * Coordinates from MediaPipe are normalized: x in [0,1] of image width, y in [0,1]
 * of image height, z is depth on roughly the same scale as x (smaller = closer to camera).
 * All functions below first convert to pixel space so aspect ratio does not distort results.
 */

export interface Landmark {
  x: number;
  y: number;
  z: number;
}

export interface Point2 {
  x: number;
  y: number;
}

interface Point3 {
  x: number;
  y: number;
  z: number;
}

/**
 * Landmark indices used by this module (MediaPipe canonical face mesh).
 * "Image-left" means the left side of the un-mirrored camera image,
 * which is the subject's right side.
 */
export const LM = {
  /** Eye contour points p1..p6 for EAR, ordered: outer corner, top, top, inner corner, bottom, bottom. */
  eyeImageLeft: [33, 160, 158, 133, 153, 144] as const,
  eyeImageRight: [263, 387, 385, 362, 380, 373] as const,
  noseTip: 1,
  mouthImageLeft: 61,
  mouthImageRight: 291,
  forehead: 10,
  chin: 152,
} as const;

export const MIN_LANDMARKS = 468;

export interface FrameSize {
  width: number;
  height: number;
}

function px(l: Landmark, size: FrameSize): Point3 {
  return { x: l.x * size.width, y: l.y * size.height, z: l.z * size.width };
}

function dist2(a: Point2, b: Point2): number {
  return Math.hypot(a.x - b.x, a.y - b.y);
}

function mid(a: Point2, b: Point2): Point2 {
  return { x: (a.x + b.x) / 2, y: (a.y + b.y) / 2 };
}

function requireLandmarks(lms: Landmark[]): void {
  if (lms.length < MIN_LANDMARKS) {
    throw new Error(`Expected at least ${MIN_LANDMARKS} landmarks, got ${lms.length}`);
  }
}

/**
 * Eye Aspect Ratio (Soukupova and Cech, 2016):
 *   EAR = (|p2 - p6| + |p3 - p5|) / (2 |p1 - p4|)
 * Roughly 0.25-0.35 for an open eye, below about 0.2 when closed.
 */
export function eyeAspectRatio(
  lms: Landmark[],
  idx: readonly [number, number, number, number, number, number],
  size: FrameSize,
): number {
  const [p1, p2, p3, p4, p5, p6] = idx.map((i) => px(lms[i], size));
  const horizontal = dist2(p1, p4);
  if (horizontal === 0) return 0;
  return (dist2(p2, p6) + dist2(p3, p5)) / (2 * horizontal);
}

export interface EyeState {
  left: number;
  right: number;
  /** Mean of both eyes. */
  mean: number;
}

export function eyeState(lms: Landmark[], size: FrameSize): EyeState {
  requireLandmarks(lms);
  const left = eyeAspectRatio(lms, LM.eyeImageLeft, size);
  const right = eyeAspectRatio(lms, LM.eyeImageRight, size);
  return { left, right, mean: (left + right) / 2 };
}

export interface HeadPose {
  /** Degrees. Positive = subject turned toward their own left. */
  yaw: number;
  /** Degrees. Positive = chin moved away from the camera (looking up). */
  pitch: number;
  /** Degrees. In-plane rotation of the eye line. Positive = clockwise in the image. */
  roll: number;
}

const RAD = 180 / Math.PI;

/**
 * Approximate head pose from 3D landmarks.
 * Yaw: depth difference across the eye axis. Pitch: depth difference along the
 * forehead-chin axis. Roll: angle of the eye axis in the image plane.
 * Accurate enough for quality gating and the turn challenge; not a calibrated pose estimator.
 */
export function headPose(lms: Landmark[], size: FrameSize): HeadPose {
  requireLandmarks(lms);
  const a = px(lms[LM.eyeImageLeft[0]], size);
  const b = px(lms[LM.eyeImageRight[0]], size);
  const top = px(lms[LM.forehead], size);
  const bottom = px(lms[LM.chin], size);

  const ex = b.x - a.x;
  const ey = b.y - a.y;
  const ez = b.z - a.z;
  const ux = bottom.x - top.x;
  const uy = bottom.y - top.y;
  const uz = bottom.z - top.z;

  return {
    yaw: Math.atan2(ez, Math.hypot(ex, ey)) * RAD,
    pitch: Math.atan2(uz, Math.hypot(ux, uy)) * RAD,
    roll: Math.atan2(ey, ex) * RAD,
  };
}

export function interOcularDistance(lms: Landmark[], size: FrameSize): number {
  requireLandmarks(lms);
  const [l, r] = eyeCenters(lms, size);
  return dist2(l, r);
}

function eyeCenters(lms: Landmark[], size: FrameSize): [Point2, Point2] {
  const l = mid(px(lms[LM.eyeImageLeft[0]], size), px(lms[LM.eyeImageLeft[3]], size));
  const r = mid(px(lms[LM.eyeImageRight[0]], size), px(lms[LM.eyeImageRight[3]], size));
  return [l, r];
}

/**
 * The five points used for alignment, in the same order as ARCFACE_TEMPLATE_112:
 * image-left eye center, image-right eye center, nose tip, image-left mouth corner,
 * image-right mouth corner. Pixel coordinates.
 */
export function fivePoints(lms: Landmark[], size: FrameSize): Point2[] {
  requireLandmarks(lms);
  const [le, re] = eyeCenters(lms, size);
  const n = px(lms[LM.noseTip], size);
  const ml = px(lms[LM.mouthImageLeft], size);
  const mr = px(lms[LM.mouthImageRight], size);
  return [le, re, { x: n.x, y: n.y }, { x: ml.x, y: ml.y }, { x: mr.x, y: mr.y }];
}

/**
 * Standard 112x112 five-point template (InsightFace / OpenCV FaceRecognizerSF alignCrop).
 * SFace was trained on crops aligned to these positions.
 */
export const ARCFACE_TEMPLATE_112: readonly Point2[] = [
  { x: 38.2946, y: 51.6963 },
  { x: 73.5318, y: 51.5014 },
  { x: 56.0252, y: 71.7366 },
  { x: 41.5493, y: 92.3655 },
  { x: 70.7299, y: 92.2041 },
];

/**
 * 2D similarity transform (rotation + uniform scale + translation):
 *   x' = a*x - b*y + tx
 *   y' = b*x + a*y + ty
 * Canvas equivalent: ctx.setTransform(a, b, -b, a, tx, ty).
 */
export interface Similarity {
  a: number;
  b: number;
  tx: number;
  ty: number;
}

export function applySimilarity(t: Similarity, p: Point2): Point2 {
  return { x: t.a * p.x - t.b * p.y + t.tx, y: t.b * p.x + t.a * p.y + t.ty };
}

/** Least-squares similarity transform mapping `src` onto `dst` (closed form, 2D Umeyama). */
export function estimateSimilarity(src: readonly Point2[], dst: readonly Point2[]): Similarity {
  if (src.length !== dst.length || src.length < 2) {
    throw new Error('estimateSimilarity needs two point lists of equal length >= 2');
  }
  const n = src.length;
  let sx = 0, sy = 0, dx = 0, dy = 0;
  for (let i = 0; i < n; i++) {
    sx += src[i].x; sy += src[i].y; dx += dst[i].x; dy += dst[i].y;
  }
  sx /= n; sy /= n; dx /= n; dy /= n;

  let num1 = 0, num2 = 0, den = 0;
  for (let i = 0; i < n; i++) {
    const px0 = src[i].x - sx;
    const py0 = src[i].y - sy;
    const qx = dst[i].x - dx;
    const qy = dst[i].y - dy;
    num1 += px0 * qx + py0 * qy;
    num2 += px0 * qy - py0 * qx;
    den += px0 * px0 + py0 * py0;
  }
  if (den === 0) throw new Error('estimateSimilarity: degenerate source points');
  const a = num1 / den;
  const b = num2 / den;
  return { a, b, tx: dx - (a * sx - b * sy), ty: dy - (b * sx + a * sy) };
}

/** Mean distance (pixels in template space) between transformed src points and dst. */
export function alignmentError(t: Similarity, src: readonly Point2[], dst: readonly Point2[]): number {
  let e = 0;
  for (let i = 0; i < src.length; i++) e += dist2(applySimilarity(t, src[i]), dst[i]);
  return e / src.length;
}
