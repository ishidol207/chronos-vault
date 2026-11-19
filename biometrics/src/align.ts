/**
 * Face alignment to the 112x112 ArcFace/SFace canonical crop and NCHW tensor packing.
 *
 * Matches OpenCV FaceRecognizerSF::alignCrop + FaceRecognizerSF::feature:
 *   - 5-point similarity warp to ARCFACE_TEMPLATE_112 on a 112x112 canvas
 *   - RGB planar NCHW float32 tensor [1, 3, 112, 112] in range [0, 255]
 *     (SFace performs mean/std normalization inside the ONNX graph).
 *
 * Raw RGBA pixel data and the temporary canvas are cleared right after tensor packing.
 */

import {
  ARCFACE_TEMPLATE_112,
  alignmentError,
  estimateSimilarity,
  fivePoints,
  type FrameSize,
  type Landmark,
  type Similarity,
} from './geometry';
import { wipe } from './vector';

export const ALIGNED_SIZE = 112;

export type DrawableImage =
  | HTMLVideoElement
  | HTMLCanvasElement
  | HTMLImageElement
  | ImageBitmap
  | OffscreenCanvas;

export interface AlignedCrop {
  /** Planar RGB float32 tensor of shape [1, 3, 112, 112] with values in [0, 255]. */
  tensorData: Float32Array;
  transform: Similarity;
  /** Mean landmark alignment residual in pixels on the 112x112 grid. */
  errorPx: number;
}

/**
 * Packs 112x112 RGBA uint8 pixel data into planar RGB float32 NCHW [1, 3, 112, 112].
 * Values stay in [0, 255] because SFace normalizes internally (cv::dnn::blobFromImage
 * with scalefactor=1, mean=0, swapRB=true on BGR -> RGB [0, 255]).
 */
export function rgbaToRgbNchw112(rgba: Uint8ClampedArray | Uint8Array): Float32Array {
  const pixels = ALIGNED_SIZE * ALIGNED_SIZE;
  if (rgba.length !== pixels * 4) {
    throw new Error(`Expected ${pixels * 4} RGBA bytes, got ${rgba.length}`);
  }
  const out = new Float32Array(3 * pixels);
  const gOffset = pixels;
  const bOffset = 2 * pixels;
  for (let i = 0; i < pixels; i++) {
    const p = i * 4;
    out[i] = rgba[p];
    out[gOffset + i] = rgba[p + 1];
    out[bOffset + i] = rgba[p + 2];
  }
  return out;
}

function createScratchCanvas(): {
  canvas: OffscreenCanvas | HTMLCanvasElement;
  ctx: OffscreenCanvasRenderingContext2D | CanvasRenderingContext2D;
} {
  if (typeof OffscreenCanvas !== 'undefined') {
    const canvas = new OffscreenCanvas(ALIGNED_SIZE, ALIGNED_SIZE);
    const ctx = canvas.getContext('2d', { willReadFrequently: true });
    if (ctx) return { canvas, ctx };
  }
  if (typeof document !== 'undefined') {
    const canvas = document.createElement('canvas');
    canvas.width = ALIGNED_SIZE;
    canvas.height = ALIGNED_SIZE;
    const ctx = canvas.getContext('2d', { willReadFrequently: true });
    if (ctx) return { canvas, ctx };
  }
  throw new Error('No 2D canvas implementation available in this environment');
}

export function getDrawableSize(source: DrawableImage): FrameSize {
  if (typeof HTMLVideoElement !== 'undefined' && source instanceof HTMLVideoElement) {
    return { width: source.videoWidth, height: source.videoHeight };
  }
  if (typeof HTMLImageElement !== 'undefined' && source instanceof HTMLImageElement) {
    return { width: source.naturalWidth || source.width, height: source.naturalHeight || source.height };
  }
  return { width: source.width, height: source.height };
}

/**
 * Warps the detected face from `source` onto a 112x112 aligned crop and packs
 * the RGB NCHW tensor. Wipes the temporary RGBA buffer and clears the scratch canvas.
 */
export function alignFaceToTensor(
  source: DrawableImage,
  landmarks: Landmark[],
  size: FrameSize = getDrawableSize(source),
): AlignedCrop {
  if (size.width <= 0 || size.height <= 0) {
    throw new Error(`Invalid source frame dimensions: ${size.width}x${size.height}`);
  }
  const srcPts = fivePoints(landmarks, size);
  const transform = estimateSimilarity(srcPts, ARCFACE_TEMPLATE_112);
  const errorPx = alignmentError(transform, srcPts, ARCFACE_TEMPLATE_112);

  const { ctx } = createScratchCanvas();
  ctx.imageSmoothingEnabled = true;
  ctx.imageSmoothingQuality = 'high';
  ctx.setTransform(1, 0, 0, 1, 0, 0);
  ctx.fillStyle = '#000000';
  ctx.fillRect(0, 0, ALIGNED_SIZE, ALIGNED_SIZE);

  // Canvas setTransform(a, b, c, d, e, f): x' = a*x + c*y + e, y' = b*x + d*y + f
  ctx.setTransform(transform.a, transform.b, -transform.b, transform.a, transform.tx, transform.ty);
  ctx.drawImage(source as CanvasImageSource, 0, 0);

  ctx.setTransform(1, 0, 0, 1, 0, 0);
  const imageData = ctx.getImageData(0, 0, ALIGNED_SIZE, ALIGNED_SIZE);
  try {
    const tensorData = rgbaToRgbNchw112(imageData.data);
    return { tensorData, transform, errorPx };
  } finally {
    wipe(imageData.data);
    ctx.clearRect(0, 0, ALIGNED_SIZE, ALIGNED_SIZE);
  }
}
