/**
 * High-level session orchestrator for enrollment and verification.
 *
 * Typical flow:
 *   const engine = await BiometricsEngine.create({ paths: ... });
 *   const enrolled = await engine.enroll(videoEl, { lang: 'ko', onProgress });
 *   // Send enrolled.pgVector to server when registering owner or heir.
 *
 *   const probe = await engine.verify(videoEl, { lang: 'ko', onProgress });
 *   // Send probe.pgVector to auth server to request share S.
 */

import { getDrawableSize, type DrawableImage } from './align';
import {
  DEFAULT_ENROLLMENT,
  DEFAULT_LIVENESS,
  DEFAULT_QUALITY,
  SFACE_COSINE_THRESHOLD,
  type EnrollmentConfig,
  type LivenessConfig,
  type ModelPaths,
  type QualityConfig,
} from './config';
import { FaceEmbedder, type FaceEmbedderOptions } from './embedder';
import { eyeState, headPose } from './geometry';
import { FaceDetector, type FaceDetectorOptions } from './landmarker';
import { LivenessChallenge, randomChallenge, type ChallengeStep } from './liveness';
import { verifyVector, type MatchResult } from './matcher';
import { assessFrameQuality, DEFAULT_DOMINANCE_RATIO, dominantFace, qualityHint } from './quality';
import type {
  AuthPurpose,
  EnrollResult,
  FaceEnrollPayload,
  FaceVerifyPayload,
  SessionProgress,
  SubjectRole,
  VerifyCaptureResult,
} from './types';
import {
  cosineSimilarity,
  meanVector,
  toPgVectorLiteral,
  wipe,
  type FaceVector,
} from './vector';

export interface BiometricsEngineOptions {
  paths?: Partial<ModelPaths>;
  detector?: Omit<FaceDetectorOptions, 'paths'>;
  embedder?: Omit<FaceEmbedderOptions, 'paths'>;
}

export interface CaptureSessionOptions {
  lang?: 'en' | 'ko';
  /** Fixed liveness steps (defaults to a random blink + head-turn sequence). */
  livenessSteps?: ChallengeStep[];
  /** Skip active liveness (for automated tests only; do not disable in production). */
  skipLiveness?: boolean;
  liveness?: Partial<LivenessConfig>;
  quality?: Partial<QualityConfig>;
  /** Time limit for collecting quality frames after liveness passes (ms). Default: 15000. */
  captureTimeoutMs?: number;
  signal?: AbortSignal;
  onProgress?: (progress: SessionProgress) => void;
}

export interface EnrollSessionOptions extends CaptureSessionOptions {
  enrollment?: Partial<EnrollmentConfig>;
}

export interface VerifySessionOptions extends CaptureSessionOptions {
  /** Number of frames averaged into the probe vector. Defaults to 2. */
  samples?: number;
  minSampleIntervalMs?: number;
}

export interface LocalVerifyResult extends VerifyCaptureResult {
  match: MatchResult;
}

export interface ExtractImageOptions {
  /**
   * Static images only (live sessions always reject extra faces). When true, an image with
   * more than one face is accepted if one face is clearly the largest (see `dominantFace`),
   * and only that face is used. Two faces of similar size are still rejected. Default false.
   */
  allowBackgroundFaces?: boolean;
  /** Size ratio for `allowBackgroundFaces`. Default `DEFAULT_DOMINANCE_RATIO` (1.6). */
  dominanceRatio?: number;
}

export class BiometricsSessionError extends Error {
  constructor(
    public readonly code:
      | 'aborted'
      | 'liveness_failed'
      | 'capture_timeout'
      | 'inconsistent_samples'
      | 'video_not_ready'
      | 'no_face'
      | 'multiple_faces',
    message: string,
  ) {
    super(message);
    this.name = 'BiometricsSessionError';
  }
}

function nextFrame(signal?: AbortSignal): Promise<number> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(new BiometricsSessionError('aborted', 'Biometrics session aborted'));
      return;
    }
    const onAbort = () => {
      cancelAnimationFrame(id);
      reject(new BiometricsSessionError('aborted', 'Biometrics session aborted'));
    };
    const id = requestAnimationFrame((ts) => {
      signal?.removeEventListener('abort', onAbort);
      resolve(ts);
    });
    signal?.addEventListener('abort', onAbort, { once: true });
  });
}

export class BiometricsEngine {
  private disposed = false;

  constructor(
    private readonly detector: FaceDetector,
    private readonly embedder: FaceEmbedder,
  ) {}

  static async create(options: BiometricsEngineOptions = {}): Promise<BiometricsEngine> {
    const [detector, embedder] = await Promise.all([
      FaceDetector.create({ ...options.detector, paths: options.paths, runningMode: 'VIDEO' }),
      FaceEmbedder.create({ ...options.embedder, paths: options.paths }),
    ]);
    return new BiometricsEngine(detector, embedder);
  }

  /**
   * Runs liveness + multi-frame capture to create a stable enrollment template
   * for either the wallet owner or a designated heir.
   */
  async enroll(
    video: HTMLVideoElement,
    options: EnrollSessionOptions = {},
  ): Promise<EnrollResult> {
    this.ensureAlive();
    const eCfg: EnrollmentConfig = { ...DEFAULT_ENROLLMENT, ...options.enrollment };
    const capture = await this.runSession(video, {
      ...options,
      samples: eCfg.samples,
      minSampleIntervalMs: eCfg.minSampleIntervalMs,
      minConsistency: eCfg.minSampleConsistency,
    });
    return {
      vector: capture.vector,
      pgVector: toPgVectorLiteral(capture.vector),
      samplesUsed: capture.samplesUsed,
      minSampleConsistency: capture.minConsistency,
      liveness: capture.liveness,
    };
  }

  /**
   * Runs liveness + capture to produce a probe vector for server-side verification
   * (to authorize S to co-sign a transfer, recovery, or inheritance transaction).
   */
  async verify(
    video: HTMLVideoElement,
    options: VerifySessionOptions = {},
  ): Promise<VerifyCaptureResult> {
    this.ensureAlive();
    const capture = await this.runSession(video, {
      ...options,
      samples: options.samples ?? 2,
      minSampleIntervalMs: options.minSampleIntervalMs ?? 150,
      minConsistency: 0.4,
    });
    return {
      vector: capture.vector,
      pgVector: toPgVectorLiteral(capture.vector),
      samplesUsed: capture.samplesUsed,
      liveness: capture.liveness,
    };
  }

  /** Convenience helper for local verification / demo without a backend. */
  async verifyLocal(
    video: HTMLVideoElement,
    reference: FaceVector,
    options: VerifySessionOptions & { threshold?: number } = {},
  ): Promise<LocalVerifyResult> {
    const capture = await this.verify(video, options);
    const match = verifyVector(capture.vector, reference, options.threshold ?? SFACE_COSINE_THRESHOLD);
    return { ...capture, match };
  }

  /**
   * Extracts a single 128-D face vector from a static image or canvas.
   * Rejects images with zero or multiple faces. Does not run liveness.
   */
  async extractFromImage(
    image: DrawableImage,
    qualityCfg?: Partial<QualityConfig>,
    options: ExtractImageOptions = {},
  ): Promise<FaceVector> {
    this.ensureAlive();
    await this.detector.setRunningMode('IMAGE');
    try {
      const size = getDrawableSize(image);
      let faces = this.detector.detectImage(image as Parameters<FaceDetector['detectImage']>[0]);
      if (faces.length === 0) {
        throw new BiometricsSessionError('no_face', 'No face detected in image');
      }
      if (faces.length > 1) {
        const main = options.allowBackgroundFaces
          ? dominantFace(faces, size, options.dominanceRatio ?? DEFAULT_DOMINANCE_RATIO)
          : -1;
        if (main < 0) {
          throw new BiometricsSessionError('multiple_faces', 'Multiple faces detected in image');
        }
        faces = [faces[main]];
      }
      if (qualityCfg) {
        const q = assessFrameQuality(faces, size, qualityCfg);
        if (!q.ok) {
          throw new BiometricsSessionError(
            'inconsistent_samples',
            `Image failed quality check: ${q.reasons.join(', ')}`,
          );
        }
      }
      return await this.embedder.embedFace(image, faces[0], size);
    } finally {
      await this.detector.setRunningMode('VIDEO');
    }
  }

  async dispose(): Promise<void> {
    if (this.disposed) return;
    this.disposed = true;
    this.detector.dispose();
    await this.embedder.dispose();
  }

  private async runSession(
    video: HTMLVideoElement,
    cfg: CaptureSessionOptions & {
      samples: number;
      minSampleIntervalMs: number;
      minConsistency: number;
    },
  ) {
    if (video.readyState < 2 || video.videoWidth === 0 || video.videoHeight === 0) {
      throw new BiometricsSessionError('video_not_ready', 'Video element has no active frames');
    }

    await this.detector.setRunningMode('VIDEO');
    const lang = cfg.lang ?? 'ko';
    const steps = cfg.livenessSteps ?? randomChallenge();
    const liveness = new LivenessChallenge(steps, { ...DEFAULT_LIVENESS, ...cfg.liveness });
    const qualityCfg = { ...DEFAULT_QUALITY, ...cfg.quality };
    const captureTimeoutMs = cfg.captureTimeoutMs ?? 15000;

    let stage: 'liveness' | 'capturing' = cfg.skipLiveness ? 'capturing' : 'liveness';
    let captureStartedAt = cfg.skipLiveness ? performance.now() : 0;
    let lastSampleAt = -Infinity;

    const collected: FaceVector[] = [];

    try {
      while (true) {
        const ts = await nextFrame(cfg.signal);
        const size = { width: video.videoWidth, height: video.videoHeight };
        if (size.width === 0 || size.height === 0) continue;

        const faces = this.detector.detectVideo(video, ts);
        const q = assessFrameQuality(faces, size, qualityCfg);

        if (stage === 'liveness') {
          const eyes = faces.length === 1 ? eyeState(faces[0], size) : { left: 0, right: 0, mean: 0 };
          const pose = faces.length === 1 ? headPose(faces[0], size) : { yaw: 0, pitch: 0, roll: 0 };
          const report = liveness.update({ t: ts, eyes, pose, faceCount: faces.length });

          if (report.status === 'failed') {
            cfg.onProgress?.({
              stage: 'failed',
              message: liveness.instruction(lang),
              liveness: report,
              qualityIssues: q.reasons,
              metrics: q.metrics,
              samplesCollected: 0,
              samplesTarget: cfg.samples,
            });
            throw new BiometricsSessionError(
              'liveness_failed',
              `Liveness check failed (${report.reason ?? 'unknown'})`,
            );
          }

          if (report.status === 'passed') {
            stage = 'capturing';
            captureStartedAt = ts;
            cfg.onProgress?.({
              stage: 'capturing',
              message:
                lang === 'ko'
                  ? '정면을 바라보고 잠시 유지해 주세요'
                  : 'Look straight ahead and hold still',
              liveness: report,
              qualityIssues: q.reasons,
              metrics: q.metrics,
              samplesCollected: 0,
              samplesTarget: cfg.samples,
            });
            continue;
          }

          cfg.onProgress?.({
            stage: 'liveness',
            message: liveness.instruction(lang),
            liveness: report,
            qualityIssues: q.reasons,
            metrics: q.metrics,
            samplesCollected: 0,
            samplesTarget: cfg.samples,
          });
          continue;
        }

        // Stage === 'capturing'
        if (ts - captureStartedAt > captureTimeoutMs) {
          cfg.onProgress?.({
            stage: 'failed',
            message: lang === 'ko' ? '촬영 시간이 초과되었습니다' : 'Capture timed out',
            liveness: liveness.state,
            qualityIssues: q.reasons,
            metrics: q.metrics,
            samplesCollected: collected.length,
            samplesTarget: cfg.samples,
          });
          throw new BiometricsSessionError('capture_timeout', 'Timed out waiting for quality face frames');
        }

        if (q.ok && ts - lastSampleAt >= cfg.minSampleIntervalMs) {
          const vec = await this.embedder.embedFace(video, faces[0], size);
          collected.push(vec);
          lastSampleAt = ts;
        }

        const hintMsg = q.ok
          ? lang === 'ko'
            ? `얼굴 벡터 추출 중 (${collected.length}/${cfg.samples})`
            : `Capturing face (${collected.length}/${cfg.samples})`
          : qualityHint(q.reasons[0], lang);

        cfg.onProgress?.({
          stage: 'capturing',
          message: hintMsg,
          liveness: liveness.state,
          qualityIssues: q.reasons,
          metrics: q.metrics,
          samplesCollected: collected.length,
          samplesTarget: cfg.samples,
        });

        if (collected.length >= cfg.samples) {
          const avg = meanVector(collected);
          let minSim = 1;
          for (const v of collected) {
            const sim = cosineSimilarity(v, avg);
            if (sim < minSim) minSim = sim;
          }

          if (minSim < cfg.minConsistency) {
            wipe(avg);
            throw new BiometricsSessionError(
              'inconsistent_samples',
              `Captured frames were inconsistent (min similarity ${minSim.toFixed(3)} < ${cfg.minConsistency})`,
            );
          }

          const finalReport = liveness.state ?? {
            status: 'passed' as const,
            steps: [],
            currentStep: 0,
            blinkCount: 0,
            startedAt: captureStartedAt,
            finishedAt: ts,
          };

          cfg.onProgress?.({
            stage: 'done',
            message: lang === 'ko' ? '완료되었습니다' : 'Complete',
            liveness: finalReport,
            qualityIssues: [],
            metrics: q.metrics,
            samplesCollected: collected.length,
            samplesTarget: cfg.samples,
          });

          return {
            vector: avg,
            samplesUsed: collected.length,
            minConsistency: minSim,
            liveness: finalReport,
          };
        }
      }
    } finally {
      for (const v of collected) wipe(v);
    }
  }

  private ensureAlive(): void {
    if (this.disposed) throw new Error('BiometricsEngine has been disposed');
  }
}

/** Formats an EnrollResult into the JSON payload expected by the auth server. */
export function buildEnrollPayload(
  vaultId: string,
  role: SubjectRole,
  result: EnrollResult,
): FaceEnrollPayload {
  const durationMs =
    result.liveness.finishedAt !== undefined
      ? Math.max(0, Math.round(result.liveness.finishedAt - result.liveness.startedAt))
      : 0;
  return {
    vaultId,
    role,
    embedding: result.pgVector,
    liveness: {
      steps: [...result.liveness.steps],
      blinkCount: result.liveness.blinkCount,
      durationMs,
    },
  };
}

/** Formats a VerifyCaptureResult into the JSON payload expected by the auth server. */
export function buildVerifyPayload(
  vaultId: string,
  role: SubjectRole,
  purpose: AuthPurpose,
  result: VerifyCaptureResult,
): FaceVerifyPayload {
  const durationMs =
    result.liveness.finishedAt !== undefined
      ? Math.max(0, Math.round(result.liveness.finishedAt - result.liveness.startedAt))
      : 0;
  return {
    vaultId,
    role,
    purpose,
    embedding: result.pgVector,
    liveness: {
      steps: [...result.liveness.steps],
      blinkCount: result.liveness.blinkCount,
      durationMs,
    },
  };
}
