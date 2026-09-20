/**
 * AegisAI WebSocket Client
 * Implements exponential backoff reconnection as per rules.md §4.
 */

const getWsUrl = () => {
  if (import.meta.env.VITE_WS_URL) {
    return import.meta.env.VITE_WS_URL.replace(/\/+$/, '');
  }
  if (import.meta.env.VITE_API_URL) {
    return import.meta.env.VITE_API_URL.replace(/^http/, 'ws').replace(/\/+$/, '');
  }
  if (typeof window !== "undefined") {
    if (window.location.host.includes("amplifyapp.com")) {
      return "wss://aegisai-backend-l0zn.onrender.com";
    }
    const proto = window.location.protocol === "https:" ? "wss://" : "ws://";
    return `${proto}${window.location.host}`;
  }
  return "wss://aegisai-backend-l0zn.onrender.com";
};

export const WS_URL = getWsUrl();


class AegisWebSocket {
  constructor() {
    this.ws = null;
    this.listeners = new Set();
    this.retryDelay = 1000;
    this.maxRetryDelay = 30000;
    this.shouldReconnect = false;
    this._pingInterval = null;
  }

  isConnected() {
    return this.ws !== null && this.ws.readyState === WebSocket.OPEN;
  }

  connect(token) {
    this.shouldReconnect = true;
    if (this.ws && (this.ws.readyState === WebSocket.OPEN || this.ws.readyState === WebSocket.CONNECTING)) {
      if (this.ws.readyState === WebSocket.OPEN) {
        this._emit({ type: "connected" });
      }
      return;
    }
    this._connect(token);
  }

  _connect(token) {
    const url = token
      ? `${WS_URL}/ws/telemetry?token=${token}`
      : `${WS_URL}/ws/telemetry`;

    try {
      this.ws = new WebSocket(url);

      this.ws.onopen = () => {
        console.log("[AegisWS] Connected");
        this.retryDelay = 1000; // reset backoff on success
        this._startPing();
        this._emit({ type: "connected" });
      };

      this.ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          this._emit(data);
        } catch (e) {
          console.warn("[AegisWS] Failed to parse message", e);
        }
      };

      this.ws.onerror = (err) => {
        console.warn("[AegisWS] Error", err);
      };

      this.ws.onclose = () => {
        console.log("[AegisWS] Disconnected");
        this._stopPing();
        this._emit({ type: "disconnected" });
        if (this.shouldReconnect) {
          console.log(`[AegisWS] Reconnecting in ${this.retryDelay}ms...`);
          setTimeout(() => this._connect(token), this.retryDelay);
          // Exponential backoff with jitter
          this.retryDelay = Math.min(
            this.retryDelay * 2 + Math.random() * 500,
            this.maxRetryDelay
          );
        }
      };
    } catch (e) {
      console.error("[AegisWS] Failed to create WebSocket", e);
    }
  }

  _startPing() {
    this._pingInterval = setInterval(() => {
      if (this.ws?.readyState === WebSocket.OPEN) {
        this.ws.send("ping");
      }
    }, 25000);
  }

  _stopPing() {
    if (this._pingInterval) clearInterval(this._pingInterval);
  }

  subscribe(listener) {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  _emit(data) {
    this.listeners.forEach((fn) => fn(data));
  }

  disconnect() {
    this.shouldReconnect = false;
    this._stopPing();
    this.ws?.close();
  }
}

export const aegisWS = new AegisWebSocket();
