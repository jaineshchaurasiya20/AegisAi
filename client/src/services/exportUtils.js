/**
 * exportUtils.js — Client-side log export engine for AegisAI Threat Logs.
 * Supports three industry-standard formats: CSV, JSON, CEF (SIEM syslog).
 * Zero server dependency — all blob generation happens in-browser.
 */

/** Map internal severity string → CEF numeric severity 0–10 */
const CEF_SEVERITY_MAP = { critical: 10, high: 7, medium: 5, low: 2 };

/** Safely format an ISO timestamp for display */
function fmtTs(iso) {
  try {
    return new Date(iso).toLocaleString("sv-SE").replace("T", " ");
  } catch {
    return iso;
  }
}

/** Trigger a file download via an invisible anchor tag */
function triggerDownload(content, filename, mime) {
  const blob = new Blob([content], { type: mime });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement("a");
  a.href     = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

/** Sanitize a single CSV cell value (escape commas/quotes/newlines) */
function csvCell(val) {
  const str = val === null || val === undefined ? "" : String(val);
  if (str.includes(",") || str.includes('"') || str.includes("\n")) {
    return `"${str.replace(/"/g, '""')}"`;
  }
  return str;
}

// ─── CSV ──────────────────────────────────────────────────────────────────────

export function exportCSV(threats) {
  const HEADERS = [
    "Timestamp",
    "Event ID",
    "Threat Type",
    "Severity",
    "Risk Score (%)",
    "Source IP",
    "Source Port",
    "Destination IP",
    "Destination Port",
    "Action Taken",
    "Process Name",
  ];

  const rows = threats.map((t) => [
    fmtTs(t.timestamp),
    t.id,
    t.threat_type,
    t.severity,
    ((t.threat_score ?? 0) * 100).toFixed(2),
    t.source_ip,
    t.source_port ?? t.port ?? "",
    t.destination_ip ?? "",
    t.port ?? "",
    (t.action_taken ?? "").replace(/_/g, " "),
    t.process_name ?? "",
  ]);

  const csv = [HEADERS, ...rows].map((r) => r.map(csvCell).join(",")).join("\n");
  const ts  = new Date().toISOString().slice(0, 10);
  triggerDownload(csv, `aegisai_threat_logs_${ts}.csv`, "text/csv");
}

// ─── JSON ─────────────────────────────────────────────────────────────────────

export function exportJSON(threats) {
  const payload = {
    exported_at: new Date().toISOString(),
    source: "AegisAI Edge Detection Engine v1.0",
    total: threats.length,
    threats,
  };
  const json = JSON.stringify(payload, null, 2);
  const ts   = new Date().toISOString().slice(0, 10);
  triggerDownload(json, `aegisai_threat_logs_${ts}.json`, "application/json");
}

// ─── CEF ─────────────────────────────────────────────────────────────────────
// Format: CEF:0|Vendor|Product|Version|EventID|Name|Severity|Extensions
// https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors/cef-implementation-standard/

export function exportCEF(threats) {
  const lines = threats.map((t) => {
    const sevNum = CEF_SEVERITY_MAP[t.severity] ?? 5;
    const act    = (t.action_taken ?? "logged").replace(/_/g, "-");
    const score  = ((t.threat_score ?? 0) * 100).toFixed(1);
    const eventId = (t.threat_type ?? "UNKNOWN").toUpperCase().replace(/\s+/g, "_");

    // Extension key=value pairs (no pipes, no newlines in values)
    const ext = [
      `rt=${new Date(t.timestamp).getTime()}`,
      `src=${t.source_ip ?? "0.0.0.0"}`,
      `dst=${t.destination_ip ?? "0.0.0.0"}`,
      `spt=${t.source_port ?? t.port ?? 0}`,
      `dpt=${t.port ?? 0}`,
      `act=${act}`,
      `cs1=${score}`,
      `cs1Label=RiskScorePct`,
      `cs2=${t.id}`,
      `cs2Label=EventID`,
    ].join(" ");

    return `CEF:0|AegisAI|ThreatEngine|1.0|${eventId}|${t.threat_type}|${sevNum}|${ext}`;
  });

  const cef = lines.join("\n");
  const ts  = new Date().toISOString().slice(0, 10);
  triggerDownload(cef, `aegisai_threat_logs_${ts}.cef`, "text/plain");
}
