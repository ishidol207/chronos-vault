#!/usr/bin/env node
/**
 * Copies everything the browser needs at runtime into another project's static folder:
 *   <dest>/models/   face_landmarker.task, face_recognition_sface_2021dec.onnx
 *   <dest>/ort-wasm/ onnxruntime-web wasm files
 *   <dest>/mp-wasm/  MediaPipe tasks-vision wasm files
 * These match the paths used in the integration guide (`/models`, `/ort-wasm/`, `/mp-wasm`).
 *
 * Usage (run inside biometrics/ after `npm install` and `npm run fetch-models`):
 *   npm run copy-assets -- ../my-app/public
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const destArg = process.argv[2];
if (!destArg) {
  console.error('Usage: npm run copy-assets -- <static folder of your app, e.g. ../my-app/public>');
  process.exit(1);
}
const dest = path.resolve(process.cwd(), destArg);

const groups = [
  { from: 'models', to: 'models', match: (f) => f.endsWith('.onnx') || f.endsWith('.task'), hint: 'run "npm run fetch-models" first' },
  { from: 'node_modules/onnxruntime-web/dist', to: 'ort-wasm', match: (f) => f.endsWith('.wasm') || f.endsWith('.mjs'), hint: 'run "npm install" first' },
  { from: 'node_modules/@mediapipe/tasks-vision/wasm', to: 'mp-wasm', match: () => true, hint: 'run "npm install" first' },
];

let copied = 0;
for (const g of groups) {
  const src = path.join(root, g.from);
  const files = fs.existsSync(src) ? fs.readdirSync(src).filter((f) => g.match(f) && fs.statSync(path.join(src, f)).isFile()) : [];
  if (files.length === 0) {
    console.error(`[missing] ${g.from}: ${g.hint}`);
    process.exit(1);
  }
  const out = path.join(dest, g.to);
  fs.mkdirSync(out, { recursive: true });
  for (const f of files) {
    fs.copyFileSync(path.join(src, f), path.join(out, f));
    copied++;
  }
  console.log(`[ok] ${files.length} file(s) -> ${path.relative(process.cwd(), out) || out}`);
}
console.log(`Copied ${copied} file(s). Serve "${destArg}" as your app's static root.`);
