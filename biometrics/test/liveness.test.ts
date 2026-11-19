import { describe, expect, it } from 'vitest';
import {
  BlinkDetector,
  LivenessChallenge,
  randomChallenge,
  type LivenessFrame,
} from '../src/liveness';

function frame(t: number, ear: number, yaw = 0, faceCount = 1): LivenessFrame {
  return {
    t,
    eyes: { left: ear, right: ear, mean: ear },
    pose: { yaw, pitch: 0, roll: 0 },
    faceCount,
  };
}

describe('BlinkDetector', () => {
  const cfg = { earClosed: 0.18, earOpen: 0.24, minBlinkMs: 40, maxBlinkMs: 500 };

  it('counts a valid blink and respects hysteresis', () => {
    const d = new BlinkDetector(cfg);
    expect(d.update(0, 0.3)).toBe(false);
    expect(d.update(50, 0.15)).toBe(false); // closed at 50
    expect(d.update(100, 0.21)).toBe(false); // in deadband, still closed
    expect(d.update(180, 0.28)).toBe(true); // opened after 130ms -> blink!
    expect(d.blinks).toBe(1);
  });

  it('ignores single-frame noise shorter than minBlinkMs', () => {
    const d = new BlinkDetector(cfg);
    d.update(0, 0.3);
    d.update(10, 0.12);
    expect(d.update(30, 0.3)).toBe(false); // 20ms < 40ms
    expect(d.blinks).toBe(0);
  });

  it('ignores eyes held shut longer than maxBlinkMs', () => {
    const d = new BlinkDetector(cfg);
    d.update(0, 0.3);
    d.update(100, 0.12);
    expect(d.update(800, 0.3)).toBe(false); // 700ms > 500ms
    expect(d.blinks).toBe(0);
  });
});

describe('LivenessChallenge', () => {
  it('passes a blink + turn_left challenge in order', () => {
    const c = new LivenessChallenge(['blink', 'turn_left'], { timeoutMs: 5000 });
    expect(c.instruction('ko')).toContain('깜빡');
    expect(c.instruction('en')).toContain('Blink');

    // Step 1: blink
    c.update(frame(0, 0.3, 0));
    c.update(frame(100, 0.14, 0));
    const afterBlink = c.update(frame(240, 0.3, 0));
    expect(afterBlink.status).toBe('in_progress');
    expect(afterBlink.currentStep).toBe(1);
    expect(afterBlink.blinkCount).toBe(1);
    expect(c.instruction('ko')).toContain('왼쪽');

    // Step 2: must be centered first, then turn left (yaw >= 18)
    c.update(frame(300, 0.3, 2)); // centered
    const mid = c.update(frame(400, 0.3, 12)); // not far enough yet
    expect(mid.status).toBe('in_progress');

    const passed = c.update(frame(500, 0.3, 22));
    expect(passed.status).toBe('passed');
    expect(passed.finishedAt).toBe(500);
  });

  it('requires head to be centered before accepting a turn step', () => {
    const c = new LivenessChallenge(['turn_right']);
    // Starts already turned right (e.g. tilted static photo) -> should NOT pass
    const r1 = c.update(frame(0, 0.3, -25));
    expect(r1.status).toBe('in_progress');
    const r2 = c.update(frame(100, 0.3, -25));
    expect(r2.status).toBe('in_progress');

    // Return to center, then turn right -> passes
    c.update(frame(200, 0.3, 0));
    const r3 = c.update(frame(300, 0.3, -20));
    expect(r3.status).toBe('passed');
  });

  it('fails on timeout', () => {
    const c = new LivenessChallenge(['blink'], { timeoutMs: 1000 });
    c.update(frame(100, 0.3, 0));
    const r = c.update(frame(1200, 0.3, 0));
    expect(r.status).toBe('failed');
    expect(r.reason).toBe('timeout');
  });

  it('fails immediately when multiple faces appear', () => {
    const c = new LivenessChallenge(['blink']);
    c.update(frame(0, 0.3, 0, 1));
    const r = c.update(frame(50, 0.3, 0, 2));
    expect(r.status).toBe('failed');
    expect(r.reason).toBe('multiple_faces');
  });

  it('cannot fake a blink by hiding the face from the camera', () => {
    const c = new LivenessChallenge(['blink']);
    c.update(frame(0, 0.3, 0, 1));
    c.update(frame(100, 0.12, 0, 1)); // eyes closed
    c.update(frame(180, 0, 0, 0)); // face disappears -> resets partial blink
    const r = c.update(frame(250, 0.3, 0, 1)); // reappears open
    expect(r.status).toBe('in_progress');
    expect(r.blinkCount).toBe(0);
  });

  it('generates valid random challenges with one blink and one turn', () => {
    const steps = randomChallenge(() => 0.1);
    expect(steps).toHaveLength(2);
    expect(steps).toContain('blink');
    expect(steps.some((s) => s === 'turn_left' || s === 'turn_right')).toBe(true);
  });
});
