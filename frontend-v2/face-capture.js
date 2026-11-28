import {
  BiometricsEngine, buildEnrollPayload, buildVerifyPayload, hashSigningPackage,
  openCamera, stopCamera, wipe
} from '../biometrics/src/index.ts';

async function postFace(action, body, signal) {
  const response = await fetch(`/api/vault/face/${action}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
    signal
  });
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || '서버 요청에 실패했습니다.');
  return result;
}

export async function captureFace(video, signal, onProgress, { action, packageJson } = {}) {
  let stream;
  let engine;
  const releaseCamera = () => stopCamera(video, stream);
  signal.addEventListener('abort', releaseCamera, { once: true });
  try {
    signal.throwIfAborted();
    stream = await openCamera(video);
    signal.throwIfAborted();
    onProgress('얼굴 인증 모델을 불러오는 중입니다.');
    engine = await BiometricsEngine.create({
      paths: {
        mediapipeWasmBaseUrl: '/mp-wasm',
        faceLandmarkerModelUrl: '/models/face_landmarker.task',
        embeddingModelUrl: '/models/face_recognition_sface_2021dec.onnx',
        onnxWasmBaseUrl: '/ort-wasm/'
      }
    });
    signal.throwIfAborted();
    const challenge = packageJson && action === 'verify'
      ? await postFace('challenge', { packageJson }, signal)
      : undefined;
    const options = {
      lang: 'ko',
      signal,
      onProgress: progress => onProgress(progress.message)
    };
    const capture = await (action === 'enroll' ? engine.enroll(video, options) : engine.verify(video, options));
    try {
      if (!packageJson) return;
      const { public_key, signers } = JSON.parse(packageJson);
      const publicKey = public_key.toLowerCase();
      const vaultId = publicKey;
      if (action === 'enroll') {
        const payload = buildEnrollPayload(vaultId, 'owner', capture, { publicKey });
        return await postFace('enroll', { packageJson, payload }, signal);
      }
      const payload = buildVerifyPayload(vaultId, 'owner', 'normal_sign', capture, {
        publicKey, challengeNonce: challenge.challengeNonce, signers, signingPackageHash: await hashSigningPackage(packageJson)
      });
      return await postFace('verify', { packageJson, payload }, signal);
    } finally {
      wipe(capture.vector);
    }
  } finally {
    signal.removeEventListener('abort', releaseCamera);
    releaseCamera();
    await engine?.dispose();
  }
}
