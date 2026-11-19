#!/usr/bin/env node
/**
 * Downloads the MediaPipe Face Landmarker and SFace ONNX models into biometrics/models/
 * and verifies their SHA-256 checksums.
 *
 * Usage:
 *   npm run fetch-models
 *   npm run fetch-models -- --force
 */

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const MODELS_DIR = path.resolve(__dirname, '..', 'models');

const MODELS = [
  {
    name: 'face_landmarker.task',
    url: 'https://storage.googleapis.com/mediapipe-models/face_landmarker/face_landmarker/float16/1/face_landmarker.task',
    sha256: '64184e229b263107bc2b804c6625db1341ff2bb731874b0bcc2fe6544e0bc9ff',
  },
  {
    name: 'face_recognition_sface_2021dec.onnx',
    url: 'https://github.com/opencv/opencv_zoo/raw/main/models/face_recognition_sface/face_recognition_sface_2021dec.onnx',
    sha256: '0ba9fbfa01b5270c96627c4ef784da859931e02f04419c829e83484087c34e79',
  },
];

const force = process.argv.includes('--force');

function sha256File(filePath) {
  const hash = crypto.createHash('sha256');
  hash.update(fs.readFileSync(filePath));
  return hash.digest('hex');
}

async function downloadModel(model) {
  const dest = path.join(MODELS_DIR, model.name);

  if (!force && fs.existsSync(dest)) {
    const actual = sha256File(dest);
    if (actual === model.sha256) {
      console.log(`[skip] ${model.name} already present and checksum matches.`);
      return;
    }
    console.log(`[warn] ${model.name} checksum mismatch (${actual}), re-downloading.`);
  }

  console.log(`[fetch] ${model.name} <- ${model.url}`);
  const res = await fetch(model.url);
  if (!res.ok) {
    throw new Error(`Failed to download ${model.name}: HTTP ${res.status} ${res.statusText}`);
  }

  const buf = Buffer.from(await res.arrayBuffer());
  const actual = crypto.createHash('sha256').update(buf).digest('hex');
  if (actual !== model.sha256) {
    throw new Error(
      `Checksum mismatch for ${model.name}: expected ${model.sha256}, got ${actual}`,
    );
  }

  fs.mkdirSync(MODELS_DIR, { recursive: true });
  const tmp = dest + '.tmp';
  fs.writeFileSync(tmp, buf);
  fs.renameSync(tmp, dest);
  console.log(`[ok] ${model.name} (${(buf.length / (1024 * 1024)).toFixed(2)} MB)`);
}

async function main() {
  for (const model of MODELS) {
    await downloadModel(model);
  }
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
});
