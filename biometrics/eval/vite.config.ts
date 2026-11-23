import fs from 'node:fs';
import path from 'node:path';
import { defineConfig, mergeConfig, type Plugin } from 'vite';
import demoConfig from '../demo/vite.config';

/** Serves LFW pair images from $LFW_DIR at /lfw/ (never bundled or committed). */
function serveLfw(): Plugin {
  const dir = path.resolve(process.env.LFW_DIR ?? '');
  return {
    name: 'serve-lfw',
    configureServer(server) {
      server.middlewares.use((req, res, next) => {
        const url = req.url?.split('?')[0] ?? '';
        if (!url.startsWith('/lfw/')) return next();
        const full = path.resolve(dir, url.slice(5));
        if (!process.env.LFW_DIR || !full.startsWith(dir) || !fs.existsSync(full)) {
          res.statusCode = 404;
          res.end('Set LFW_DIR to the extracted pair images');
          return;
        }
        res.setHeader('Content-Type', full.endsWith('.json') ? 'application/json' : 'image/jpeg');
        fs.createReadStream(full).pipe(res);
      });
    },
  };
}

export default mergeConfig(demoConfig, defineConfig({ plugins: [serveLfw()], server: { port: 5180 } }));
