/**
 * On-device 128-D face embedding extractor powered by SFace (ONNX Runtime Web).
 *
 * Input:  float32 NCHW [1, 3, 112, 112], RGB order, range [0, 255]
 * Output: unit-normalized 128-D Float32Array (FaceVector)
 *
 * Temporary tensor buffers are zero-filled right after inference completes.
 */

import * as ort from 'onnxruntime-web';
import { ALIGNED_SIZE, alignFaceToTensor, type DrawableImage } from './align';
import { DEFAULT_MODEL_PATHS, EMBEDDING_DIM, type ModelPaths } from './config';
import type { FrameSize, Landmark } from './geometry';
import { assertFaceVector, l2Normalize, wipe, type FaceVector } from './vector';

export interface FaceEmbedderOptions {
  paths?: Partial<Pick<ModelPaths, 'embeddingModelUrl' | 'onnxWasmBaseUrl'>>;
  /** Optional pre-loaded ONNX model bytes (also used by Node tests). */
  modelBuffer?: Uint8Array;
  /** Execution providers forwarded to onnxruntime-web. Defaults to ['wasm']. */
  executionProviders?: ort.InferenceSession.ExecutionProviderConfig[];
  /** Number of WASM threads (browser only; ignored if SharedArrayBuffer is unavailable). */
  numThreads?: number;
}

export class FaceEmbedder {
  private readonly inputName: string;
  private readonly outputName: string;
  private disposed = false;

  private constructor(private readonly session: ort.InferenceSession) {
    if (session.inputNames.length === 0 || session.outputNames.length === 0) {
      throw new Error('ONNX model has no inputs or outputs');
    }
    this.inputName = session.inputNames[0];
    this.outputName = session.outputNames[0];
  }

  static async create(options: FaceEmbedderOptions = {}): Promise<FaceEmbedder> {
    if (options.paths?.onnxWasmBaseUrl) {
      ort.env.wasm.wasmPaths = options.paths.onnxWasmBaseUrl;
    }
    if (options.numThreads !== undefined) {
      ort.env.wasm.numThreads = options.numThreads;
    }

    const sessionOptions: ort.InferenceSession.SessionOptions = {
      executionProviders: options.executionProviders ?? ['wasm'],
      graphOptimizationLevel: 'all',
      logSeverityLevel: 3,
    };

    const session = options.modelBuffer
      ? await ort.InferenceSession.create(options.modelBuffer, sessionOptions)
      : await ort.InferenceSession.create(
          options.paths?.embeddingModelUrl ?? DEFAULT_MODEL_PATHS.embeddingModelUrl,
          sessionOptions,
        );

    return new FaceEmbedder(session);
  }

  /**
   * Runs inference on an aligned [1, 3, 112, 112] planar RGB float32 buffer.
   * When `wipeInput` is true (default), `tensorData` is zeroed before returning.
   */
  async embedTensor(tensorData: Float32Array, wipeInput = true): Promise<FaceVector> {
    this.ensureAlive();
    const expectedLen = 3 * ALIGNED_SIZE * ALIGNED_SIZE;
    if (tensorData.length !== expectedLen) {
      throw new Error(`Expected tensor of length ${expectedLen}, got ${tensorData.length}`);
    }

    const input = new ort.Tensor('float32', tensorData, [1, 3, ALIGNED_SIZE, ALIGNED_SIZE]);
    try {
      const outputs = await this.session.run({ [this.inputName]: input });
      const outTensor = outputs[this.outputName];
      const raw = outTensor.data;
      if (!(raw instanceof Float32Array) || raw.length !== EMBEDDING_DIM) {
        throw new Error(`Unexpected embedding output: length=${raw.length}`);
      }
      try {
        const vec = l2Normalize(raw);
        assertFaceVector(vec);
        return vec;
      } finally {
        wipe(raw);
      }
    } finally {
      if (wipeInput) wipe(tensorData);
    }
  }

  /** Aligns the face from `source` using its landmarks, then extracts its 128-D vector. */
  async embedFace(
    source: DrawableImage,
    landmarks: Landmark[],
    size?: FrameSize,
  ): Promise<FaceVector> {
    this.ensureAlive();
    const { tensorData } = alignFaceToTensor(source, landmarks, size);
    return this.embedTensor(tensorData, true);
  }

  async dispose(): Promise<void> {
    if (this.disposed) return;
    this.disposed = true;
    await this.session.release();
  }

  private ensureAlive(): void {
    if (this.disposed) throw new Error('FaceEmbedder has been disposed');
  }
}
