import { fileURLToPath } from 'node:url';
import { readFile } from 'node:fs/promises';
import demoConfig from '../biometrics/demo/vite.config.ts';
import { createFaceChallengeMiddleware } from './server/face-challenge.mjs';

const root = fileURLToPath(new URL('.', import.meta.url));
const signerRoot = new URL('../bitcoin/browser/', import.meta.url);
const signerAssets = new Map([
  ['/browser-signer/signer.js', 'text/javascript'],
  ['/browser-signer/signer-worker.js', 'text/javascript'],
  ['/browser-signer/chronos_signer.wasm', 'application/wasm']
]);

const serveSignerAssets = {
  name: 'serve-chronos-signer',
  configureServer(server) {
    server.middlewares.use(async (request, response, next) => {
      const path = request.url?.split('?')[0];
      const contentType = signerAssets.get(path);
      if (!contentType) return next();
      try {
        const body = await readFile(new URL(path.slice('/browser-signer/'.length), signerRoot));
        response.setHeader('Content-Type', contentType);
        response.end(body);
      } catch (error) {
        next(error);
      }
    });
  }
};

export default {
  ...demoConfig,
  root,
  plugins: [
    ...demoConfig.plugins,
    serveSignerAssets,
    {
      name: 'chronos-face-challenge',
      configureServer(server) {
        server.middlewares.use(createFaceChallengeMiddleware());
      }
    }
  ],
  server: {
    ...demoConfig.server,
    host: '127.0.0.1',
    port: 5181,
    strictPort: true,
    proxy: {
      '^/v1/signing/steps$': process.env.CHRONOS_SIGNER_URL || 'http://127.0.0.1:8787',
      '^/api/testnet4/tx(?:/[a-fA-F0-9]{64}/status)?$': {
        target: 'https://mempool.space',
        changeOrigin: true,
        rewrite: path => path.replace('/api/testnet4/', '/testnet4/api/')
      }
    },
    fs: { allow: [root, ...demoConfig.server.fs.allow] }
  }
};
