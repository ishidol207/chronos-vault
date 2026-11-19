import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { defineConfig, type Plugin } from 'vite';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const pkgRoot = path.resolve(__dirname, '..');

const MIME: Record<string, string> = {
  '.wasm': 'application/wasm',
  '.mjs': 'application/javascript',
  '.js': 'application/javascript',
  '.onnx': 'application/octet-stream',
  '.task': 'application/octet-stream',
};

/** Serves local model files and runtime wasm assets during `vite demo`. */
function serveBiometricsAssets(): Plugin {
  const mounts: Array<{ prefix: string; dir: string }> = [
    { prefix: '/models/', dir: path.join(pkgRoot, 'models') },
    { prefix: '/ort-wasm/', dir: path.join(pkgRoot, 'node_modules/onnxruntime-web/dist') },
    { prefix: '/mp-wasm/', dir: path.join(pkgRoot, 'node_modules/@mediapipe/tasks-vision/wasm') },
  ];

  return {
    name: 'serve-biometrics-assets',
    configureServer(server) {
      server.middlewares.use((req, res, next) => {
        const rawUrl = req.url?.split('?')[0] ?? '';
        for (const m of mounts) {
          if (!rawUrl.startsWith(m.prefix)) continue;
          const rel = rawUrl.slice(m.prefix.length);
          const full = path.resolve(m.dir, rel);
          if (!full.startsWith(m.dir) || !fs.existsSync(full) || !fs.statSync(full).isFile()) {
            res.statusCode = 404;
            res.end(`Not found: ${rawUrl}. Did you run "npm run fetch-models"?`);
            return;
          }
          const ext = path.extname(full);
          res.setHeader('Content-Type', MIME[ext] ?? 'application/octet-stream');
          fs.createReadStream(full).pipe(res);
          return;
        }
        next();
      });
    },
  };
}

export default defineConfig({
  plugins: [serveBiometricsAssets()],
  optimizeDeps: {
    exclude: ['onnxruntime-web', '@mediapipe/tasks-vision'],
  },
  server: {
    port: 5179,
    fs: {
      allow: [pkgRoot],
    },
  },
  build: {
    outDir: path.join(__dirname, 'dist'),
    emptyOutDir: true,
  },
});
