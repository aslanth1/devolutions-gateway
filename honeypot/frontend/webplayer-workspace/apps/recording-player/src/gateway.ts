import { emitPlayerTelemetry } from './telemetry';

export class GatewayAccessApi {
  recordingInfo = null;
  gatewayAccessUrl: string;
  token: string;
  sessionId: string;

  constructor(gatewayAccessUrl, token, sessionId) {
    this.gatewayAccessUrl = gatewayAccessUrl;
    this.token = token;
    this.sessionId = sessionId;
  }

  static builder() {
    return new GatewayAccessApiBuilder();
  }

  async fetchRecordingInfo() {
    const requestUrl = this.videoSrcInfoUrl();
    emitPlayerTelemetry({
      kind: 'recording_info_fetch_started',
      requestUrl,
      detail: 'recording-player requested recording.json',
    });

    let response;
    try {
      response = await fetch(requestUrl);
    } catch (error) {
      emitPlayerTelemetry({
        kind: 'recording_info_fetch_failed',
        requestUrl,
        detail: error instanceof Error ? error.message : String(error),
      });
      throw error;
    }

    if (!response.ok) {
      emitPlayerTelemetry({
        kind: 'recording_info_fetch_failed',
        requestUrl,
        httpStatus: response.status,
        detail: `request failed with status ${response.status}`,
      });
      throw new Error(`Request failed. Returned status of ${response.status}`);
    }

    emitPlayerTelemetry({
      kind: 'recording_info_fetch_succeeded',
      requestUrl,
      httpStatus: response.status,
      detail: 'recording-player loaded recording.json successfully',
    });
    this.recordingInfo = await response.json();
    return this.recordingInfo;
  }

  info() {
    return {
      gatewayAccessUrl: this.gatewayAccessUrl,
      token: this.token,
      sessionId: this.sessionId,
      recordingInfo: this.recordingInfo,
    };
  }

  videoSrcInfoUrl() {
    return `${this.gatewayAccessUrl}/jet/jrec/pull/${this.sessionId}/recording.json?token=${this.token}`;
  }

  staticRecordingUrl(fileName) {
    return `${this.gatewayAccessUrl}/jet/jrec/pull/${this.sessionId}/${fileName}?token=${this.token}`;
  }

  sessionShadowingUrl() {
    return `${this.gatewayAccessUrl.replace('http://', 'ws://').replace('https://', 'wss://')}/jet/jrec/shadow/${this.sessionId}?token=${this.token}`;
  }

  playerResourceUrl(path: string) {
    return `${this.gatewayAccessUrl}/jet/jrec/play/${path}`;
  }

  playerTelemetryUrl() {
    return `${this.gatewayAccessUrl}/jet/jrec/telemetry/${this.sessionId}?token=${this.token}`;
  }
}

class GatewayAccessApiBuilder {
  _gatewayAccessUrl: string | null;
  _token: string | null;
  _sessionId: string | null;

  constructor() {
    this._gatewayAccessUrl = null;
    this._token = null;
    this._sessionId = null;
  }

  gatewayAccessUrl(gatewayAccessUrl) {
    this._gatewayAccessUrl = gatewayAccessUrl;
    return this;
  }

  token(token) {
    this._token = token;
    return this;
  }

  sessionId(sessionId) {
    this._sessionId = sessionId;
    return this;
  }

  build() {
    return new GatewayAccessApi(this._gatewayAccessUrl, this._token, this._sessionId);
  }
}
