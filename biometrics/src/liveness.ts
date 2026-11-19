/**
 * Active liveness check: the user has to blink and turn their head in a random order.
 *
 * This is a state machine fed one frame at a time, so it is independent of the camera
 * and of MediaPipe and can be tested with synthetic sequences.
 *
 * What it does protect against: holding a printed photo or a still image in front of the camera.
 * What it does NOT protect against: a replayed video of the user doing the same actions,
 * a 3D mask, or a modified client that skips this check entirely. See the security notes
 * in "[facial recognition].md".
 */

import { DEFAULT_LIVENESS, type LivenessConfig } from './config';
import type { EyeState, HeadPose } from './geometry';

export type ChallengeStep = 'blink' | 'turn_left' | 'turn_right';

export interface LivenessFrame {
  /** Monotonic timestamp in milliseconds (performance.now() or video time). */
  t: number;
  eyes: EyeState;
  pose: HeadPose;
  /** Number of faces detected in this frame. */
  faceCount: number;
}

export type LivenessStatus = 'in_progress' | 'passed' | 'failed';

export interface LivenessReport {
  status: LivenessStatus;
  steps: ChallengeStep[];
  /** Index of the step currently expected (equals steps.length when passed). */
  currentStep: number;
  blinkCount: number;
  /** Set when status is 'failed'. */
  reason?: 'timeout' | 'multiple_faces' | 'no_face';
  startedAt: number;
  finishedAt?: number;
}

/**
 * Blink detector using EAR with hysteresis:
 *   open -> closed when EAR < earClosed
 *   closed -> open when EAR > earOpen
 * A blink is counted when the closed period lasts between minBlinkMs and maxBlinkMs.
 */
export class BlinkDetector {
  private closedSince: number | null = null;
  private count = 0;

  constructor(private readonly cfg: Pick<LivenessConfig, 'earClosed' | 'earOpen' | 'minBlinkMs' | 'maxBlinkMs'>) {
    if (cfg.earOpen <= cfg.earClosed) {
      throw new Error('earOpen must be greater than earClosed');
    }
  }

  get blinks(): number {
    return this.count;
  }

  /** Feeds one frame. Returns true on the frame where a blink completes. */
  update(t: number, ear: number): boolean {
    if (this.closedSince === null) {
      if (ear < this.cfg.earClosed) this.closedSince = t;
      return false;
    }
    if (ear > this.cfg.earOpen) {
      const duration = t - this.closedSince;
      this.closedSince = null;
      if (duration >= this.cfg.minBlinkMs && duration <= this.cfg.maxBlinkMs) {
        this.count++;
        return true;
      }
    }
    return false;
  }

  /** Cancels an in-progress closed-eye interval without recording a blink. */
  cancelPending(): void {
    this.closedSince = null;
  }

  reset(): void {
    this.closedSince = null;
    this.count = 0;
  }
}

/** Shuffles a copy of the array using the provided random source. */
function shuffle<T>(arr: readonly T[], random: () => number): T[] {
  const out = arr.slice();
  for (let i = out.length - 1; i > 0; i--) {
    const j = Math.floor(random() * (i + 1));
    [out[i], out[j]] = [out[j], out[i]];
  }
  return out;
}

/** Cryptographically random float in [0, 1). Falls back to Math.random outside browsers/Node 19+. */
function secureRandom(): number {
  const c = globalThis.crypto;
  if (c && typeof c.getRandomValues === 'function') {
    const buf = new Uint32Array(1);
    c.getRandomValues(buf);
    return buf[0] / 2 ** 32;
  }
  return Math.random();
}

/** Builds a random challenge: one blink plus one head turn, in random order. */
export function randomChallenge(random: () => number = secureRandom): ChallengeStep[] {
  const turn: ChallengeStep = random() < 0.5 ? 'turn_left' : 'turn_right';
  return shuffle<ChallengeStep>(['blink', turn], random);
}

export class LivenessChallenge {
  private readonly cfg: LivenessConfig;
  private readonly blink: BlinkDetector;
  private report: LivenessReport | null = null;
  /** A turn step only completes after the head came back near the center first. */
  private wasCentered = false;

  constructor(
    readonly steps: ChallengeStep[] = randomChallenge(),
    cfg: Partial<LivenessConfig> = {},
  ) {
    if (steps.length === 0) throw new Error('Challenge needs at least one step');
    this.cfg = { ...DEFAULT_LIVENESS, ...cfg };
    this.blink = new BlinkDetector(this.cfg);
  }

  get state(): LivenessReport | null {
    return this.report ? { ...this.report, steps: [...this.report.steps] } : null;
  }

  /** Human readable instruction for the current step, for the UI. */
  instruction(lang: 'en' | 'ko' = 'en'): string {
    const r = this.report;
    if (r && r.status === 'passed') return lang === 'ko' ? '확인 완료' : 'Done';
    if (r && r.status === 'failed') return lang === 'ko' ? '다시 시도해 주세요' : 'Please try again';
    const step = this.steps[r ? r.currentStep : 0];
    const text: Record<ChallengeStep, [string, string]> = {
      blink: ['Blink once', '눈을 한 번 깜빡여 주세요'],
      turn_left: ['Turn your head to your left', '고개를 왼쪽으로 돌려 주세요'],
      turn_right: ['Turn your head to your right', '고개를 오른쪽으로 돌려 주세요'],
    };
    return text[step][lang === 'ko' ? 1 : 0];
  }

  update(frame: LivenessFrame): LivenessReport {
    if (!this.report) {
      this.report = {
        status: 'in_progress',
        steps: [...this.steps],
        currentStep: 0,
        blinkCount: 0,
        startedAt: frame.t,
      };
    }
    const r = this.report;
    if (r.status !== 'in_progress') return this.state!;

    if (frame.t - r.startedAt > this.cfg.timeoutMs) {
      return this.fail('timeout', frame.t);
    }
    if (frame.faceCount > 1) return this.fail('multiple_faces', frame.t);
    if (frame.faceCount === 0) {
      // Losing the face resets any partial blink so it cannot be faked by covering the camera.
      this.blink.cancelPending();
      return this.state!;
    }

    const blinked = this.blink.update(frame.t, frame.eyes.mean);
    r.blinkCount = this.blink.blinks;

    const yaw = frame.pose.yaw;
    if (Math.abs(yaw) < this.cfg.turnYawDeg / 2) this.wasCentered = true;

    const step = this.steps[r.currentStep];
    let done = false;
    if (step === 'blink') {
      done = blinked;
    } else if (step === 'turn_left') {
      done = this.wasCentered && yaw >= this.cfg.turnYawDeg;
    } else if (step === 'turn_right') {
      done = this.wasCentered && yaw <= -this.cfg.turnYawDeg;
    }

    if (done) {
      r.currentStep++;
      this.wasCentered = false;
      if (r.currentStep >= this.steps.length) {
        r.status = 'passed';
        r.finishedAt = frame.t;
      }
    }
    return this.state!;
  }

  reset(): void {
    this.report = null;
    this.wasCentered = false;
    this.blink.reset();
  }

  private fail(reason: NonNullable<LivenessReport['reason']>, t: number): LivenessReport {
    const r = this.report!;
    r.status = 'failed';
    r.reason = reason;
    r.finishedAt = t;
    return this.state!;
  }
}
