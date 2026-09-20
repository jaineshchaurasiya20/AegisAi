/**
 * AegisAI API Client — Axios-free fetch wrapper for REST endpoints.
 */

const getBaseUrl = () => {
  if (import.meta.env.VITE_API_URL) {
    return import.meta.env.VITE_API_URL.replace(/\/+$/, '');
  }
  if (typeof window !== "undefined") {
    if (window.location.host.includes("amplifyapp.com")) {
      return "https://aegisai-backend-l0zn.onrender.com";
    }
    return window.location.origin.replace(/\/+$/, '');
  }
  return "https://aegisai-backend-l0zn.onrender.com";
};

export const BASE_URL = getBaseUrl();


let _token = null;

export function setToken(token) {
  _token = token;
  if (token) localStorage.setItem("aegis_token", token);
  else localStorage.removeItem("aegis_token");
}

export function getToken() {
  if (_token) return _token;
  _token = localStorage.getItem("aegis_token");
  return _token;
}

const _authListeners = new Set();

export function onUnauthorized(callback) {
  _authListeners.add(callback);
  return () => _authListeners.delete(callback);
}

function handleUnauthorized() {
  setToken(null);
  _authListeners.forEach((cb) => {
    try { cb(); } catch (e) { console.error(e); }
  });
}

async function request(path, options = {}) {
  const token = getToken();
  const headers = {
    "Content-Type": "application/json",
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...options.headers,
  };
  const res = await fetch(`${BASE_URL}${path}`, { ...options, headers });
  if (!res.ok) {
    if (res.status === 401) {
      handleUnauthorized();
    }
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || "Request failed");
  }
  return res.json();
}

export const api = {
  login: async (username, password) => {
    const body = new URLSearchParams({ username, password });
    const res = await fetch(`${BASE_URL}/api/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body,
    });
    const data = await res.json().catch(() => ({ detail: "Authentication request failed" }));
    if (!res.ok) {
      throw new Error(data.detail || "Invalid security credentials");
    }
    return data;
  },
  getHostMetrics: () => request("/api/telemetry/host"),
  getStatus: () => request("/api/telemetry/status"),
  getThreats: (params = {}) => {
    const qs = new URLSearchParams(params).toString();
    return request(`/api/threats/${qs ? "?" + qs : ""}`);
  },
  getThreatStats: () => request("/api/threats/stats"),
  triggerScan:    () => request("/api/threats/scan", { method: "POST" }),
  triggerReplay:  (count = 4, delay = 1.0) =>
    request("/api/threats/replay", {
      method: "POST",
      body: JSON.stringify({ count, delay }),
    }),
  getThreatExplanation: (id) => request(`/api/threats/${id}/explain`),

  // ── Containment Action Engine ──────────────────────────────────────────
  /** POST /api/action/contain — Execute manual or autonomous containment */
  containAction: (payload) =>
    request("/api/action/contain", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  /** GET /api/action/audit — Fetch the containment action audit trail */
  getAuditLog: () => request("/api/action/audit"),

  /** GET /api/settings/policy — Fetch current engine policy */
  getPolicy: () => request("/api/settings/policy"),

  /** POST /api/settings/policy — Persist updated engine policy */
  savePolicy: (settings) =>
    request("/api/settings/policy", {
      method: "POST",
      body: JSON.stringify(settings),
    }),

  // ── ONNX Model Telemetry & ML Config ───────────────────────────────────
  /** GET /api/model/telemetry — Fetch live ONNX edge runtime telemetry */
  getModelTelemetry: () => request("/api/model/telemetry"),

  /** GET /api/model/config — Fetch active ML operational thresholds */
  getModelConfig: () => request("/api/model/config"),

  /** POST /api/model/config — Hot-reload ML operational thresholds */
  saveModelConfig: (config) =>
    request("/api/model/config", {
      method: "POST",
      body: JSON.stringify(config),
    }),

  // ── Deception & Honeypot Engine ────────────────────────────────────────
  /** GET /api/deception/traps — Fetch segregated honeypot payload captures */
  getDeceptionTraps: (params = {}) => {
    const qs = new URLSearchParams(params).toString();
    return request(`/api/deception/traps${qs ? "?" + qs : ""}`);
  },

  /** GET /api/deception/stats — Fetch honeypot deception stats & decoy paths */
  getDeceptionStats: () => request("/api/deception/stats"),
  /** GET /api/deception/config — Fetch decoy configuration for UI */
  getDeceptionConfig: () => request("/api/deception/config"),

  /** POST /api/deception/simulate — Trigger a simulated honeypot trap redirection */
  simulateHoneypotTrap: (payload = {}) =>
    request("/api/deception/simulate", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  // ── Cryptographic Action Quorum ─────────────────────────────────────────
  /** POST /api/quorum/authorize — Operator approval or rejection */
  authorizeQuorum: (payload) =>
    request("/api/quorum/authorize", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  /** GET /api/quorum/pending — Fetch active pending quorum requests */
  getPendingQuorumActions: () => request("/api/quorum/pending"),

  // ── NIST CSF 2.0 & GDPR Article 33 Audit Generator ─────────────────────
  /** Export audit report as 1-click file download (JSON or Markdown) */
  exportAuditReport: async (threatId, format = "json") => {
    const token = getToken();
    const headers = {
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    };
    const res = await fetch(`${BASE_URL}/api/audit/export/${threatId}?format=${format}&download=true`, {
      headers,
    });
    if (!res.ok) {
      throw new Error(`Export failed: ${res.statusText}`);
    }
    const text = await res.text();
    let vaultStatus = null;
    let reportData = null;

    if (format === "json") {
      try {
        reportData = JSON.parse(text);
        vaultStatus = reportData.aws_vault_status || null;
      } catch (e) {
        console.warn("Could not parse JSON audit report response:", e);
      }
    }

    const blob = new Blob([text], {
      type: format === "markdown" ? "text/markdown;charset=utf-8" : "application/json;charset=utf-8",
    });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `aegisai_audit_${(threatId || "report").slice(0, 8)}.${format === "markdown" ? "md" : "json"}`;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);

    return {
      success: true,
      report: reportData,
      aws_vault_status: vaultStatus,
      vault_header_status: res.headers.get("X-AWS-Vault-Status"),
      vault_uri: res.headers.get("X-AWS-Vault-URI") || vaultStatus?.s3_uri,
    };
  },

  /** GET /api/audit/export/{threat_id} directly as JSON data */
  getAuditReport: (threatId, format = "json") =>
    request(`/api/audit/export/${threatId}?format=${format}&download=false`),

  /** GET /api/audit/sandbox/status */
  getSandboxStatus: () => request("/api/audit/sandbox/status"),

  /** POST /api/audit/sandbox/wipe */
  wipeSandbox: () => request("/api/audit/sandbox/wipe", { method: "POST" }),
};
