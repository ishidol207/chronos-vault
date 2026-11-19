/**
 * Thin browser webcam helper. Keeps getUserMedia constraints and cleanup in one place.
 */

export interface CameraOptions {
  width?: number;
  height?: number;
  facingMode?: 'user' | 'environment';
}

export async function openCamera(
  video: HTMLVideoElement,
  options: CameraOptions = {},
): Promise<MediaStream> {
  if (typeof navigator === 'undefined' || !navigator.mediaDevices?.getUserMedia) {
    throw new Error('Camera access (navigator.mediaDevices.getUserMedia) is unavailable');
  }

  const stream = await navigator.mediaDevices.getUserMedia({
    audio: false,
    video: {
      facingMode: options.facingMode ?? 'user',
      width: { ideal: options.width ?? 640 },
      height: { ideal: options.height ?? 480 },
    },
  });

  video.srcObject = stream;
  video.muted = true;
  video.playsInline = true;

  await new Promise<void>((resolve, reject) => {
    const onLoaded = () => {
      cleanup();
      resolve();
    };
    const onError = () => {
      cleanup();
      reject(new Error('Failed to load webcam stream into video element'));
    };
    const cleanup = () => {
      video.removeEventListener('loadedmetadata', onLoaded);
      video.removeEventListener('error', onError);
    };
    if (video.readyState >= 1 && video.videoWidth > 0) {
      resolve();
      return;
    }
    video.addEventListener('loadedmetadata', onLoaded);
    video.addEventListener('error', onError);
  });

  await video.play();
  return stream;
}

export function stopCamera(video: HTMLVideoElement | null, stream?: MediaStream | null): void {
  const active = stream ?? (video?.srcObject instanceof MediaStream ? video.srcObject : null);
  if (active) {
    for (const track of active.getTracks()) track.stop();
  }
  if (video) {
    video.pause();
    video.srcObject = null;
  }
}
