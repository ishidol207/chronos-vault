import {
  BiometricsEngine,
  PARTY_ID,
  RECOMMENDED_VAULT_THRESHOLD,
  buildEnrollPayload,
  buildVerifyPayload,
  openCamera,
  stopCamera,
  wipe,
  type FaceVector,
  type SessionProgress,
  type SubjectRole,
} from '../src/index';

const video = document.getElementById('video') as HTMLVideoElement;
const promptEl = document.getElementById('prompt') as HTMLDivElement;
const btnInit = document.getElementById('btn-init') as HTMLButtonElement;
const btnEnrollOwner = document.getElementById('btn-enroll-owner') as HTMLButtonElement;
const btnEnrollHeir = document.getElementById('btn-enroll-heir') as HTMLButtonElement;
const btnVerify = document.getElementById('btn-verify') as HTMLButtonElement;
const btnCancel = document.getElementById('btn-cancel') as HTMLButtonElement;
const roleSelect = document.getElementById('role-select') as HTMLSelectElement;
const thresholdInput = document.getElementById('threshold-input') as HTMLInputElement;
const ownerStatus = document.getElementById('owner-status') as HTMLSpanElement;
const heirStatus = document.getElementById('heir-status') as HTMLSpanElement;
const matchStatus = document.getElementById('match-status') as HTMLSpanElement;
const metricsText = document.getElementById('metrics-text') as HTMLSpanElement;
const payloadOut = document.getElementById('payload-out') as HTMLPreElement;

let engine: BiometricsEngine | null = null;
let stream: MediaStream | null = null;
let activeAbort: AbortController | null = null;

const templates: Record<SubjectRole, FaceVector | null> = {
  owner: null,
  heir: null,
};

thresholdInput.value = String(RECOMMENDED_VAULT_THRESHOLD);

function setBusy(busy: boolean): void {
  const ready = engine !== null;
  btnInit.disabled = ready || busy;
  btnEnrollOwner.disabled = !ready || busy;
  btnEnrollHeir.disabled = !ready || busy;
  btnVerify.disabled = !ready || busy;
  btnCancel.disabled = !busy;
}

function handleProgress(p: SessionProgress): void {
  promptEl.textContent = `[${p.stage}] ${p.message}`;
  if (p.metrics) {
    metricsText.textContent =
      `yaw=${p.metrics.yaw.toFixed(1)} pitch=${p.metrics.pitch.toFixed(1)} ` +
      `ear=${((p.metrics.earLeft + p.metrics.earRight) / 2).toFixed(2)} ` +
      `iod=${p.metrics.interOcularPx.toFixed(0)}px`;
  } else {
    metricsText.textContent = 'no single face';
  }
}

btnInit.addEventListener('click', async () => {
  setBusy(true);
  promptEl.textContent = 'Opening camera and loading MediaPipe + SFace ONNX models...';
  try {
    stream = await openCamera(video, { width: 640, height: 480 });
    engine = await BiometricsEngine.create({
      paths: {
        mediapipeWasmBaseUrl: '/mp-wasm',
        faceLandmarkerModelUrl: '/models/face_landmarker.task',
        embeddingModelUrl: '/models/face_recognition_sface_2021dec.onnx',
        onnxWasmBaseUrl: '/ort-wasm/',
      },
    });
    promptEl.textContent = 'Models loaded. Choose Enroll Owner, Enroll Heir, or Verify.';
  } catch (err) {
    promptEl.textContent = `Init failed: ${err instanceof Error ? err.message : String(err)}`;
    stopCamera(video, stream);
    stream = null;
  } finally {
    setBusy(false);
  }
});

async function runEnroll(role: SubjectRole): Promise<void> {
  if (!engine) return;
  activeAbort = new AbortController();
  setBusy(true);
  try {
    const res = await engine.enroll(video, {
      lang: 'ko',
      signal: activeAbort.signal,
      onProgress: handleProgress,
    });
    if (templates[role]) wipe(templates[role]!);
    templates[role] = res.vector;

    const badge = role === 'owner' ? ownerStatus : heirStatus;
    badge.textContent = `enrolled (consistency ${res.minSampleConsistency.toFixed(3)})`;
    badge.className = 'badge ok';

    const payload = buildEnrollPayload('demo-vault-001', role, res);
    payloadOut.textContent = JSON.stringify(
      { ...payload, embedding: `${payload.embedding.slice(0, 72)}... (${res.vector.length} dims)` },
      null,
      2,
    );
    promptEl.textContent = `Enrolled ${role} template (${res.samplesUsed} samples).`;
  } catch (err) {
    promptEl.textContent = `Enroll failed: ${err instanceof Error ? err.message : String(err)}`;
  } finally {
    activeAbort = null;
    setBusy(false);
  }
}

btnEnrollOwner.addEventListener('click', () => void runEnroll('owner'));
btnEnrollHeir.addEventListener('click', () => void runEnroll('heir'));

btnVerify.addEventListener('click', async () => {
  if (!engine) return;
  const role = roleSelect.value as SubjectRole;
  const reference = templates[role];
  if (!reference) {
    promptEl.textContent = `Enroll ${role} first before running local verification.`;
    return;
  }

  activeAbort = new AbortController();
  setBusy(true);
  try {
    const threshold = Number(thresholdInput.value) || RECOMMENDED_VAULT_THRESHOLD;
    const purpose = role === 'owner' ? 'recovery' : 'inheritance';
    const res = await engine.verifyLocal(video, reference, {
      lang: 'ko',
      threshold,
      signal: activeAbort.signal,
      onProgress: handleProgress,
    });

    matchStatus.textContent = `${res.match.matched ? 'MATCH' : 'REJECT'} (sim=${res.match.similarity.toFixed(3)}, dist=${res.match.distance.toFixed(3)})`;
    matchStatus.className = `badge ${res.match.matched ? 'ok' : 'err'}`;

    const payload = buildVerifyPayload('demo-vault-001', role, purpose, res, {
      signers: [PARTY_ID.SERVER, PARTY_ID.RECOVERY],
    });
    payloadOut.textContent = JSON.stringify(
      {
        requestPayload: {
          ...payload,
          embedding: `${payload.embedding.slice(0, 72)}... (${res.vector.length} dims)`,
        },
        localMatch: res.match,
      },
      null,
      2,
    );
    promptEl.textContent = res.match.matched
      ? `Verified ${role} (similarity ${res.match.similarity.toFixed(3)} >= ${threshold}). Ready to authorize Party 2 (S) co-signing.`
      : `Rejected ${role} (similarity ${res.match.similarity.toFixed(3)} < ${threshold}).`;
  } catch (err) {
    promptEl.textContent = `Verify failed: ${err instanceof Error ? err.message : String(err)}`;
  } finally {
    activeAbort = null;
    setBusy(false);
  }
});

btnCancel.addEventListener('click', () => {
  activeAbort?.abort();
});

window.addEventListener('beforeunload', () => {
  activeAbort?.abort();
  stopCamera(video, stream);
  if (templates.owner) wipe(templates.owner);
  if (templates.heir) wipe(templates.heir);
  void engine?.dispose();
});
