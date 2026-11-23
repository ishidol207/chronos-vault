/**
 * LFW pair evaluation of the real pipeline: MediaPipe landmarks -> 5-point alignment -> SFace.
 * Serves images from LFW_DIR (see vite.config.ts); results land on `window.__lfw`.
 * Usage: open /?split=train (or test) on the eval dev server; add &bg=1 to accept images
 * with smaller background faces (`allowBackgroundFaces`).
 */
import { BiometricsEngine, BiometricsSessionError } from '../src/session';
import { cosineSimilarity } from '../src/vector';

interface PairLabel { i: number; same: number; ext: string }
interface PairResult { i: number; same: boolean; sim: number | null; error?: string }

const log = document.getElementById('log')!;
const params = new URLSearchParams(location.search);
const split = params.get('split') ?? 'train';
const allowBackgroundFaces = params.get('bg') === '1';

function loadImage(url: string): Promise<HTMLImageElement> {
  return new Promise((resolve, reject) => {
    const img = new Image();
    img.onload = () => resolve(img);
    img.onerror = () => reject(new Error(`cannot load ${url}`));
    img.src = url;
  });
}

async function main(): Promise<void> {
  const engine = await BiometricsEngine.create({
    paths: {
      mediapipeWasmBaseUrl: '/mp-wasm',
      faceLandmarkerModelUrl: '/models/face_landmarker.task',
      embeddingModelUrl: '/models/face_recognition_sface_2021dec.onnx',
      onnxWasmBaseUrl: '/ort-wasm/',
    },
  });
  const labels: PairLabel[] = await (await fetch(`/lfw/${split}/labels.json`)).json();
  const results: PairResult[] = [];
  const t0 = performance.now();
  for (const p of labels) {
    try {
      const [a, b] = await Promise.all([0, 1].map((k) => loadImage(`/lfw/${split}/${p.i}_${k}.${p.ext}`)));
      const va = await engine.extractFromImage(a, undefined, { allowBackgroundFaces });
      const vb = await engine.extractFromImage(b, undefined, { allowBackgroundFaces });
      results.push({ i: p.i, same: p.same === 1, sim: cosineSimilarity(va, vb) });
    } catch (e) {
      const code = e instanceof BiometricsSessionError ? e.code : 'error';
      results.push({ i: p.i, same: p.same === 1, sim: null, error: code });
    }
    if (results.length % 100 === 0) log.textContent = `${results.length}/${labels.length}`;
  }
  (window as unknown as { __lfw: unknown }).__lfw = { split, allowBackgroundFaces, ms: performance.now() - t0, results };
  log.textContent = `done ${results.length} pairs`;
  await engine.dispose();
}

main().catch((e) => {
  (window as unknown as { __lfw: unknown }).__lfw = { error: String(e) };
  log.textContent = String(e);
});
