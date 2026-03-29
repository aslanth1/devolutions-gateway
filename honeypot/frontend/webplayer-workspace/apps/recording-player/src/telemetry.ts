import type { GatewayAccessApi } from './gateway';

const PLAYER_TELEMETRY_SCHEMA_VERSION = 1;

type PlayerTelemetryEvent = {
  kind: string;
  observedAtUnixMs?: number;
  websocketUrl?: string;
  requestUrl?: string;
  httpStatus?: number;
  openedAtUnixMs?: number;
  firstMessageAtUnixMs?: number;
  closedAtUnixMs?: number;
  elapsedMsSinceOpen?: number;
  rawCloseCode?: number;
  rawCloseReason?: string;
  transformedCloseCode?: number;
  transformedCloseReason?: string;
  deliveryKind?: string;
  activeMode?: boolean;
  fallbackStarted?: boolean;
  wasClean?: boolean;
  detail?: string;
};

type PlayerTelemetryState = {
  gatewayAccessApi: GatewayAccessApi;
  isActiveSession: boolean;
  fallbackStarted: boolean;
};

let telemetryState: PlayerTelemetryState | null = null;

export function configurePlayerTelemetry(gatewayAccessApi: GatewayAccessApi, isActiveSession: boolean) {
  telemetryState = {
    gatewayAccessApi,
    isActiveSession,
    fallbackStarted: !isActiveSession,
  };

  emitPlayerTelemetry({
    kind: 'player_mode_configured',
    detail: isActiveSession
      ? 'recording-player configured active playback intent'
      : 'recording-player configured static playback intent',
  });
}

export function markStaticPlaybackStarted() {
  if (!telemetryState || telemetryState.fallbackStarted) {
    return;
  }

  telemetryState.fallbackStarted = true;
  emitPlayerTelemetry({
    kind: 'static_playback_started',
    detail: 'recording-player invoked static playback while the page was originally active',
  });
}

export function playerActiveMode() {
  return Boolean(telemetryState?.isActiveSession) && !telemetryState?.fallbackStarted;
}

export function playerFallbackStarted() {
  return Boolean(telemetryState?.fallbackStarted);
}

export function emitPlayerTelemetry(event: PlayerTelemetryEvent) {
  if (!telemetryState) {
    return;
  }

  const payload = {
    schemaVersion: PLAYER_TELEMETRY_SCHEMA_VERSION,
    sessionId: telemetryState.gatewayAccessApi.sessionId,
    observedAtUnixMs: event.observedAtUnixMs ?? Date.now(),
    kind: event.kind,
    websocketUrl: event.websocketUrl,
    requestUrl: event.requestUrl,
    httpStatus: event.httpStatus,
    openedAtUnixMs: event.openedAtUnixMs,
    firstMessageAtUnixMs: event.firstMessageAtUnixMs,
    closedAtUnixMs: event.closedAtUnixMs,
    elapsedMsSinceOpen: event.elapsedMsSinceOpen,
    rawCloseCode: event.rawCloseCode,
    rawCloseReason: event.rawCloseReason,
    transformedCloseCode: event.transformedCloseCode,
    transformedCloseReason: event.transformedCloseReason,
    deliveryKind: event.deliveryKind,
    activeMode: event.activeMode ?? playerActiveMode(),
    fallbackStarted: event.fallbackStarted ?? playerFallbackStarted(),
    wasClean: event.wasClean,
    detail: event.detail,
  };
  const body = JSON.stringify(payload);

  void fetch(telemetryState.gatewayAccessApi.playerTelemetryUrl(), {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body,
    keepalive: true,
  }).catch(() => undefined);
}
