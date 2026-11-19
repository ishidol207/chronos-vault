/**
 * Wrapper around MediaPipe FaceLandmarker for both video streams and single images.
 *
 * Uses `numFaces: 2` by default so the caller can detect and reject frames where
 * more than one person is in front of the camera.
 */

import { FaceLandmarker, FilesetResolver, type ImageSource } from '@mediapipe/tasks-vision';
import { DEFAULT_MODEL_PATHS, type ModelPaths } from './config';
import type { Landmark } from './geometry';

export interface FaceDetectorOptions {
  paths?: Partial<Pick<ModelPaths, 'mediapipeWasmBaseUrl' | 'faceLandmarkerModelUrl'>>;
  /** Optional pre-fetched model bytes (avoids network fetch in bundled environments). */
  modelBuffer?: Uint8Array;
  runningMode?: 'VIDEO' | 'IMAGE';
  /** Defaults to 2 so multi-face frames can be detected and rejected. */
  numFaces?: number;
  minFaceDetectionConfidence?: number;
  minFacePresenceConfidence?: number;
  minTrackingConfidence?: number;
  /** Defaults to GPU with automatic fallback to CPU if GPU initialization fails. */
  delegate?: 'GPU' | 'CPU';
}

export class FaceDetector {
  private lastVideoTs = -1;
  private disposed = false;

  private constructor(
    private readonly landmarker: FaceLandmarker,
    private mode: 'VIDEO' | 'IMAGE',
  ) {}

  static async create(options: FaceDetectorOptions = {}): Promise<FaceDetector> {
    const wasmBase = options.paths?.mediapipeWasmBaseUrl ?? DEFAULT_MODEL_PATHS.mediapipeWasmBaseUrl;
    const modelUrl = options.paths?.faceLandmarkerModelUrl ?? DEFAULT_MODEL_PATHS.faceLandmarkerModelUrl;
    const runningMode = options.runningMode ?? 'VIDEO';
    const numFaces = options.numFaces ?? 2;

    const vision = await FilesetResolver.forVisionTasks(wasmBase);

    const makeOptions = (delegate: 'GPU' | 'CPU') => ({
      baseOptions: options.modelBuffer
        ? { modelAssetBuffer: options.modelBuffer, delegate }
        : { modelAssetPath: modelUrl, delegate },
      runningMode,
      numFaces,
      minFaceDetectionConfidence: options.minFaceDetectionConfidence ?? 0.5,
      minFacePresenceConfidence: options.minFacePresenceConfidence ?? 0.5,
      minTrackingConfidence: options.minTrackingConfidence ?? 0.5,
      outputFaceBlendshapes: false,
      outputFacialTransformationMatrixes: false,
    });

    if (options.delegate) {
      const lm = await FaceLandmarker.createFromOptions(vision, makeOptions(options.delegate));
      return new FaceDetector(lm, runningMode);
    }

    try {
      const lm = await FaceLandmarker.createFromOptions(vision, makeOptions('GPU'));
      return new FaceDetector(lm, runningMode);
    } catch {
      const lm = await FaceLandmarker.createFromOptions(vision, makeOptions('CPU'));
      return new FaceDetector(lm, runningMode);
    }
  }

  async setRunningMode(mode: 'VIDEO' | 'IMAGE'): Promise<void> {
    this.ensureAlive();
    if (this.mode === mode) return;
    await this.landmarker.setOptions({ runningMode: mode });
    this.mode = mode;
    if (mode === 'VIDEO') this.lastVideoTs = -1;
  }

  /**
   * Runs landmark detection on a video frame. Timestamps are clamped to be strictly
   * increasing because MediaPipe throws if two video frames share a timestamp.
   */
  detectVideo(frame: ImageSource, timestampMs: number): Landmark[][] {
    this.ensureAlive();
    if (this.mode !== 'VIDEO') {
      throw new Error('FaceDetector is in IMAGE mode; call setRunningMode("VIDEO") first');
    }
    const ts = timestampMs > this.lastVideoTs ? timestampMs : this.lastVideoTs + 1;
    this.lastVideoTs = ts;
    const res = this.landmarker.detectForVideo(frame, ts);
    return res.faceLandmarks;
  }

  /** Runs landmark detection on a static image. */
  detectImage(image: ImageSource): Landmark[][] {
    this.ensureAlive();
    if (this.mode !== 'IMAGE') {
      throw new Error('FaceDetector is in VIDEO mode; call setRunningMode("IMAGE") first');
    }
    const res = this.landmarker.detect(image);
    return res.faceLandmarks;
  }

  dispose(): void {
    if (this.disposed) return;
    this.disposed = true;
    this.landmarker.close();
  }

  private ensureAlive(): void {
    if (this.disposed) throw new Error('FaceDetector has been disposed');
  }
}
