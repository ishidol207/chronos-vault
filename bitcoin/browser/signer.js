// Load from your application's own origin. Each call gets a fresh crypto worker.
function run(op, options) {
  const { signal, ...args } = options;
  if (signal?.aborted) return Promise.reject(signal.reason);
  const worker = new Worker(new URL('./signer-worker.js', import.meta.url), { type: 'module' });
  return new Promise((resolve, reject) => {
    const end = (settle, value) => {
      worker.terminate();
      signal?.removeEventListener('abort', abort);
      settle(value);
    };
    const abort = () => end(reject, signal.reason);
    signal?.addEventListener('abort', abort, { once: true });
    worker.onmessage = ({ data }) => Object.hasOwn(data, 'error')
      ? end(reject, new Error(data.error)) : end(resolve, data.value);
    worker.onerror = () => end(reject, new Error('Browser signing worker failed'));
    worker.onmessageerror = () => end(reject, new Error('Invalid signing worker response'));
    try { worker.postMessage({ ...args, op }); } catch (err) { end(reject, err); }
  });
}

export function reviewPayment(packageJson) {
  return run('review', { packageJson });
}

export function signWithServer(options) {
  return run('server', options);
}

export function signOffline(options) {
  return run('offline', options);
}
