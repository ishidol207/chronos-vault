/**
 * Shared configuration for the biometrics module.
 *
 * Values here are the single source of truth for the client side. If you change
 * EMBEDDING_DIM or the matching threshold, the database column type and the
 * server-side RPC have to be updated as well (see "[facial recognition].md").
 */

/** Dimension of the face vector. Must match `vector(128)` in the database. */
export const EMBEDDING_DIM = 128;

/**
 * Cosine similarity threshold that the bundled SFace model was evaluated with.
 * OpenCV publishes 0.363 for SFace (cosine) on LFW. This is a property of the model,
 * not of the system; a different model needs a different threshold.
 */
export const SFACE_COSINE_THRESHOLD = 0.363;

/**
 * Recommended starting threshold for Chronos Vault Party 2 (server S) authorization.
 * Achieved 0.00% FAR across both LFW 1,000-pair and 2,200-pair evaluations while
 * keeping FRR under 1.5%. Calibrate further with `calibrateThreshold` on real device pairs.
 */
export const RECOMMENDED_VAULT_THRESHOLD = 0.4;

/**
 * Threshold written in the project architecture document (tau = 0.85).
 * Kept here for reference only. It does not fit the SFace score distribution:
 * genuine SFace pairs rarely reach 0.85, so using it would reject the real owner.
 * Use `calibrateThreshold` with your own genuine/impostor pairs before deciding.
 */
export const ARCHITECTURE_DOC_TAU = 0.85;

/**
 * Threshold ECDSA party IDs matching `bitcoin/` (`PARTIES = [1, 2, 3]`).
 * Party 2 (SERVER) keeps its encrypted key share (`secrets.cvparty`) on the server
 * and returns a partial signature (`PartyResponse`), never its long-term share.
 */
export const PARTY_ID = {
  /** Party 1: user device (U). */
  USER: 1,
  /** Party 2: auth & co-signing server (S). */
  SERVER: 2,
  /** Party 3: recovery / designated heir share holder (R). */
  RECOVERY: 3,
} as const;

export interface ModelPaths {
  /** Base URL of the MediaPipe tasks-vision wasm files. */
  mediapipeWasmBaseUrl: string;
  /** URL of the MediaPipe face_landmarker.task model. */
  faceLandmarkerModelUrl: string;
  /** URL of the face embedding ONNX model. */
  embeddingModelUrl: string;
  /** Base URL for onnxruntime-web wasm files. Leave undefined to use the bundler default. */
  onnxWasmBaseUrl?: string;
}

export const DEFAULT_MODEL_PATHS: ModelPaths = {
  mediapipeWasmBaseUrl: 'https://cdn.jsdelivr.net/npm/@mediapipe/tasks-vision@1.2.3/wasm',
  faceLandmarkerModelUrl: '/models/face_landmarker.task',
  embeddingModelUrl: '/models/face_recognition_sface_2021dec.onnx',
};

export interface QualityConfig {
  /** Minimum distance between the two eye centers in source pixels. */
  minInterOcularPx: number;
  /** Maximum absolute yaw (degrees) accepted for a capture frame. */
  maxYawDeg: number;
  /** Maximum absolute pitch (degrees) accepted for a capture frame. */
  maxPitchDeg: number;
  /** Frames where either eye is below this EAR are treated as blinking and skipped. */
  minEarForCapture: number;
}

export const DEFAULT_QUALITY: QualityConfig = {
  minInterOcularPx: 60,
  maxYawDeg: 20,
  maxPitchDeg: 20,
  minEarForCapture: 0.2,
};

export interface LivenessConfig {
  /** EAR below this value counts as "eye closed". */
  earClosed: number;
  /** EAR above this value counts as "eye open" (hysteresis). */
  earOpen: number;
  /** A closed period shorter than this (ms) is treated as noise. */
  minBlinkMs: number;
  /** A closed period longer than this (ms) is not a blink (eyes held shut). */
  maxBlinkMs: number;
  /** Yaw (degrees) the user must reach for a head-turn step. */
  turnYawDeg: number;
  /** Time limit for the whole challenge (ms). */
  timeoutMs: number;
}

export const DEFAULT_LIVENESS: LivenessConfig = {
  earClosed: 0.18,
  earOpen: 0.24,
  minBlinkMs: 40,
  maxBlinkMs: 500,
  turnYawDeg: 18,
  timeoutMs: 15000,
};

export interface EnrollmentConfig {
  /** Number of accepted frames averaged into the enrollment template. */
  samples: number;
  /** Minimum time between two accepted samples (ms), so samples are not identical frames. */
  minSampleIntervalMs: number;
  /** Each sample must reach at least this similarity to the averaged template. */
  minSampleConsistency: number;
}

export const DEFAULT_ENROLLMENT: EnrollmentConfig = {
  samples: 5,
  minSampleIntervalMs: 200,
  minSampleConsistency: 0.5,
};
