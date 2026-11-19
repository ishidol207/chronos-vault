import { describe, expect, it } from 'vitest';
import { ALIGNED_SIZE, rgbaToRgbNchw112 } from '../src/align';

describe('rgbaToRgbNchw112', () => {
  it('packs RGBA uint8 into planar RGB float32 [0, 255] NCHW', () => {
    const pixels = ALIGNED_SIZE * ALIGNED_SIZE;
    const rgba = new Uint8ClampedArray(pixels * 4);
    // Pixel 0: (10, 20, 30, 255)
    rgba[0] = 10;
    rgba[1] = 20;
    rgba[2] = 30;
    rgba[3] = 255;
    // Last pixel: (200, 150, 100, 128)
    const last = (pixels - 1) * 4;
    rgba[last] = 200;
    rgba[last + 1] = 150;
    rgba[last + 2] = 100;
    rgba[last + 3] = 128;

    const tensor = rgbaToRgbNchw112(rgba);
    expect(tensor.length).toBe(3 * pixels);
    expect(tensor[0]).toBe(10);
    expect(tensor[pixels]).toBe(20);
    expect(tensor[2 * pixels]).toBe(30);
    expect(tensor[pixels - 1]).toBe(200);
    expect(tensor[2 * pixels - 1]).toBe(150);
    expect(tensor[3 * pixels - 1]).toBe(100);
  });

  it('rejects wrong byte lengths', () => {
    expect(() => rgbaToRgbNchw112(new Uint8ClampedArray(16))).toThrow();
  });
});
