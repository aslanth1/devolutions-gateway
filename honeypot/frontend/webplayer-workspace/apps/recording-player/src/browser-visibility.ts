import { emitPlayerTelemetry, playerActiveMode, playerFallbackStarted } from './telemetry';

const BROWSER_VISIBILITY_SAMPLE_INTERVAL_MS = 300;
const BROWSER_VISIBILITY_MIN_VALID_SAMPLES = 2;
const BROWSER_VISIBILITY_VISIBLE_THRESHOLD_PER_MILLE = 10;
const BROWSER_VISIBILITY_SPARSE_THRESHOLD_PER_MILLE = 1;
const BROWSER_VISIBILITY_CANVAS_WIDTH = 64;
const BROWSER_VISIBILITY_CANVAS_HEIGHT = 36;

const BROWSER_VISIBILITY_WINDOWS = [
  { phase: 'startup', durationMs: 1500 },
  { phase: 'stabilize', durationMs: 3000 },
  { phase: 'steady', durationMs: 4500 },
] as const;

type BrowserVisibilityPhase = typeof BROWSER_VISIBILITY_WINDOWS[number]['phase'];
type BrowserPlayerMode = 'active_live' | 'static_fallback' | 'unknown';
type BrowserSampleStatus =
  | 'ready'
  | 'no_video_element'
  | 'no_decodable_frame'
  | 'readback_error'
  | 'insufficient_samples'
  | 'transitional';
type BrowserVisibilityVerdict = 'visible_frame' | 'sparse_pixels' | 'all_black' | 'inconclusive';

type BrowserVisibilitySample = {
  mode: BrowserPlayerMode;
  status: BrowserSampleStatus;
  readyState?: number;
  currentTimeMs?: number;
  videoWidth?: number;
  videoHeight?: number;
  nonBlackRatioPerMille?: number;
  meanNonBlackRatioPerMille?: number;
  transitionObserved: boolean;
  detail?: string;
};

const canvas = document.createElement('canvas');
canvas.width = BROWSER_VISIBILITY_CANVAS_WIDTH;
canvas.height = BROWSER_VISIBILITY_CANVAS_HEIGHT;
const context = canvas.getContext('2d', { willReadFrequently: true });

let browserVisibilityProbeStarted = false;
let lastResolvedMode: BrowserPlayerMode | null = null;

function sleep(durationMs: number) {
  return new Promise((resolve) => {
    window.setTimeout(resolve, durationMs);
  });
}

function classifyNonBlackRatioPerMille(nonBlackRatioPerMille: number): BrowserVisibilityVerdict {
  if (nonBlackRatioPerMille >= BROWSER_VISIBILITY_VISIBLE_THRESHOLD_PER_MILLE) {
    return 'visible_frame';
  }

  if (nonBlackRatioPerMille >= BROWSER_VISIBILITY_SPARSE_THRESHOLD_PER_MILLE) {
    return 'sparse_pixels';
  }

  return 'all_black';
}

function roundRatioPerMille(value: number) {
  return Math.max(0, Math.min(1000, Math.round(value)));
}

function average(values: number[]) {
  if (values.length === 0) {
    return undefined;
  }

  return values.reduce((sum, value) => sum + value, 0) / values.length;
}

function representativeValue<T>(values: T[]) {
  if (values.length === 0) {
    return undefined;
  }

  return values[Math.floor(values.length / 2)];
}

function formatNetworkStateDetail(networkState: number) {
  switch (networkState) {
    case HTMLMediaElement.NETWORK_EMPTY:
      return 'networkState=empty';
    case HTMLMediaElement.NETWORK_IDLE:
      return 'networkState=idle';
    case HTMLMediaElement.NETWORK_LOADING:
      return 'networkState=loading';
    case HTMLMediaElement.NETWORK_NO_SOURCE:
      return 'networkState=no_source';
    default:
      return `networkState=${networkState}`;
  }
}

function formatBufferedDetail(video: HTMLVideoElement) {
  if (video.buffered.length === 0) {
    return 'bufferedRanges=0';
  }

  const bufferedEndMs = Math.round(video.buffered.end(video.buffered.length - 1) * 1000);
  return `bufferedRanges=${video.buffered.length} bufferedEndMs=${bufferedEndMs}`;
}

function formatPlaybackStateDetail(
  video: HTMLVideoElement,
  readyState: number,
  currentTimeMs: number | undefined,
  videoWidth: number | undefined,
  videoHeight: number | undefined,
) {
  const currentTimeDetail =
    currentTimeMs === undefined ? 'currentTimeMs=unavailable' : `currentTimeMs=${currentTimeMs}`;
  const videoWidthDetail = videoWidth === undefined ? 'videoWidth=unavailable' : `videoWidth=${videoWidth}`;
  const videoHeightDetail =
    videoHeight === undefined ? 'videoHeight=unavailable' : `videoHeight=${videoHeight}`;
  const pausedDetail = `paused=${video.paused}`;
  const endedDetail = `ended=${video.ended}`;
  const seekingDetail = `seeking=${video.seeking}`;
  const networkStateDetail = formatNetworkStateDetail(video.networkState);
  const bufferedDetail = formatBufferedDetail(video);

  return `${pausedDetail} ${endedDetail} ${seekingDetail} ${networkStateDetail} ${bufferedDetail} readyState=${readyState} ${currentTimeDetail} ${videoWidthDetail} ${videoHeightDetail}`;
}

function resolvePlayerVideo() {
  const activePlayer = document.querySelector('shadow-player') as HTMLElement & {
    shadowRoot?: ShadowRoot | null;
  } | null;
  const activeVideo = activePlayer?.shadowRoot?.querySelector('video') as HTMLVideoElement | null;
  const staticVideo = document.querySelector('multi-video-player video') as HTMLVideoElement | null;
  const fallbackVideo = document.querySelector('video') as HTMLVideoElement | null;

  let mode: BrowserPlayerMode = 'unknown';
  let video: HTMLVideoElement | null = null;

  if (activeVideo && playerActiveMode()) {
    mode = 'active_live';
    video = activeVideo;
  } else if (staticVideo && playerFallbackStarted()) {
    mode = 'static_fallback';
    video = staticVideo;
  } else if (activeVideo) {
    mode = 'active_live';
    video = activeVideo;
  } else if (staticVideo) {
    mode = 'static_fallback';
    video = staticVideo;
  } else if (fallbackVideo) {
    video = fallbackVideo;
  }

  const transitionObserved = lastResolvedMode !== null && mode !== 'unknown' && lastResolvedMode !== mode;
  if (mode !== 'unknown') {
    lastResolvedMode = mode;
  }

  return { mode, video, transitionObserved };
}

function samplePlayerVideo(): BrowserVisibilitySample {
  const { mode, video, transitionObserved } = resolvePlayerVideo();

  if (!video) {
    return {
      mode,
      status: 'no_video_element',
      transitionObserved,
      detail: 'no player video element was available for browser visibility sampling',
    };
  }

  const readyState = video.readyState;
  const currentTimeMs = Number.isFinite(video.currentTime) ? Math.round(video.currentTime * 1000) : undefined;
  const videoWidth = video.videoWidth || undefined;
  const videoHeight = video.videoHeight || undefined;

  if (readyState < HTMLMediaElement.HAVE_CURRENT_DATA || !videoWidth || !videoHeight) {
    return {
      mode,
      status: 'no_decodable_frame',
      readyState,
      currentTimeMs,
      videoWidth,
      videoHeight,
      transitionObserved,
      detail: `video did not have a decodable frame available yet (${formatPlaybackStateDetail(
        video,
        readyState,
        currentTimeMs,
        videoWidth,
        videoHeight,
      )})`,
    };
  }

  if (!context) {
    return {
      mode,
      status: 'readback_error',
      readyState,
      currentTimeMs,
      videoWidth,
      videoHeight,
      transitionObserved,
      detail: '2d canvas context was unavailable',
    };
  }

  try {
    context.drawImage(video, 0, 0, BROWSER_VISIBILITY_CANVAS_WIDTH, BROWSER_VISIBILITY_CANVAS_HEIGHT);
    const pixels = context.getImageData(0, 0, BROWSER_VISIBILITY_CANVAS_WIDTH, BROWSER_VISIBILITY_CANVAS_HEIGHT).data;
    const totalPixels = pixels.length / 4;
    let nonBlackPixels = 0;
    let lumaSum = 0;

    for (let index = 0; index < pixels.length; index += 4) {
      const red = pixels[index];
      const green = pixels[index + 1];
      const blue = pixels[index + 2];
      const luma = Math.round(0.2126 * red + 0.7152 * green + 0.0722 * blue);
      lumaSum += luma;
      if (red > 8 || green > 8 || blue > 8) {
        nonBlackPixels += 1;
      }
    }

    const nonBlackRatioPerMille = roundRatioPerMille((nonBlackPixels / totalPixels) * 1000);
    const meanLumaPerMille = roundRatioPerMille((lumaSum / totalPixels / 255) * 1000);

    return {
      mode,
      status: transitionObserved ? 'transitional' : 'ready',
      readyState,
      currentTimeMs,
      videoWidth,
      videoHeight,
      nonBlackRatioPerMille,
      meanNonBlackRatioPerMille: meanLumaPerMille,
      transitionObserved,
    };
  } catch (error) {
    return {
      mode,
      status: 'readback_error',
      readyState,
      currentTimeMs,
      videoWidth,
      videoHeight,
      transitionObserved,
      detail: error instanceof Error ? error.message : String(error),
    };
  }
}

async function collectBrowserVisibilityWindow(windowIndex: number, phase: BrowserVisibilityPhase, durationMs: number) {
  const windowStartAtUnixMs = Date.now();
  const samples: BrowserVisibilitySample[] = [];
  const sampleAttempts = Math.max(1, Math.floor(durationMs / BROWSER_VISIBILITY_SAMPLE_INTERVAL_MS));

  for (let attempt = 0; attempt < sampleAttempts; attempt += 1) {
    samples.push(samplePlayerVideo());

    if (attempt + 1 < sampleAttempts) {
      await sleep(BROWSER_VISIBILITY_SAMPLE_INTERVAL_MS);
    }
  }

  const windowEndAtUnixMs = Date.now();
  const validSamples = samples.filter((sample) => sample.status === 'ready');
  const transitionObserved = samples.some((sample) => sample.transitionObserved);
  const modes = samples
    .map((sample) => sample.mode)
    .filter((mode) => mode !== 'unknown');
  const dominantMode = representativeValue(modes) ?? 'unknown';
  const currentTimes = validSamples
    .map((sample) => sample.currentTimeMs)
    .filter((value): value is number => value !== undefined)
    .sort((left, right) => left - right);
  const maxNonBlackRatioPerMille = validSamples.reduce<number | undefined>((currentMax, sample) => {
    if (sample.nonBlackRatioPerMille === undefined) {
      return currentMax;
    }

    if (currentMax === undefined) {
      return sample.nonBlackRatioPerMille;
    }

    return Math.max(currentMax, sample.nonBlackRatioPerMille);
  }, undefined);
  const meanNonBlackRatioPerMille = average(
    validSamples
      .map((sample) => sample.nonBlackRatioPerMille)
      .filter((value): value is number => value !== undefined),
  );
  const representativeCurrentTimeMs = representativeValue(currentTimes);
  const representativeVideo = validSamples[validSamples.length - 1];
  const representativeStatus = samples[samples.length - 1];

  let sampleStatus: BrowserSampleStatus = representativeStatus?.status ?? 'no_video_element';
  let visibilityVerdict: BrowserVisibilityVerdict = 'inconclusive';
  let detail = representativeStatus?.detail;

  if (transitionObserved) {
    sampleStatus = 'transitional';
    detail = 'player mode changed while the browser visibility window was sampled';
  } else if (validSamples.length < BROWSER_VISIBILITY_MIN_VALID_SAMPLES) {
    sampleStatus = 'insufficient_samples';
    detail = detail ?? 'not enough valid browser samples were captured for this window';
  } else if (maxNonBlackRatioPerMille !== undefined) {
    sampleStatus = 'ready';
    visibilityVerdict = classifyNonBlackRatioPerMille(maxNonBlackRatioPerMille);
    detail = `window captured ${validSamples.length} valid browser samples`;
  }

  emitPlayerTelemetry({
    kind: 'browser_visibility_window',
    playerMode: dominantMode,
    windowIndex,
    windowPhase: phase,
    windowStartAtUnixMs,
    windowEndAtUnixMs,
    sampleCount: samples.length,
    validSampleCount: validSamples.length,
    sampleStatus,
    visibilityVerdict,
    representativeCurrentTimeMs,
    videoWidth: representativeVideo?.videoWidth,
    videoHeight: representativeVideo?.videoHeight,
    maxNonBlackRatioPerMille,
    meanNonBlackRatioPerMille:
      meanNonBlackRatioPerMille === undefined ? undefined : roundRatioPerMille(meanNonBlackRatioPerMille),
    transitionObserved,
    detail,
  });
}

async function runBrowserVisibilityProbe() {
  for (const [windowIndex, window] of BROWSER_VISIBILITY_WINDOWS.entries()) {
    await collectBrowserVisibilityWindow(windowIndex, window.phase, window.durationMs);
  }
}

export function startBrowserVisibilityProbe() {
  if (browserVisibilityProbeStarted) {
    return;
  }

  browserVisibilityProbeStarted = true;
  void runBrowserVisibilityProbe();
}
