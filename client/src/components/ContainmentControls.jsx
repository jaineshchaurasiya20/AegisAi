/**
 * ContainmentControls — Manual remediation action buttons.
 * Renders inside ThreatDetailModal (Remediation tab).
 *
 * Actions:
 *   ISOLATE_HOST   — Crimson  — Requires confirmation
 *   KILL_PROCESS   — Red      — Requires confirmation
 *   QUARANTINE_FILE— Amber    — Requires confirmation
 *   WHITELIST      — Emerald  — No confirmation needed
 */
import React, { useState } from "react";
import {
  WifiOff, Skull, Package, ShieldCheck,
  AlertTriangle, CheckCircle2, Loader2, ChevronRight,
} from "lucide-react";
import { useEngine } from "../context/EngineContext";

/* ─── Action definitions ───────────────────────────────────────────────── */
const ACTIONS = [
  {
    type: "ISOLATE_HOST",
    label: "Isolate Host",
    sublabel: "Disable NIC / block via firewall",
    Icon: WifiOff,
    color: "#ef4444",
    bg: "rgba(239,68,68,0.08)",
    border: "rgba(239,68,68,0.25)",
    hoverBg: "rgba(239,68,68,0.15)",
    destructive: true,
    confirmMsg: (t) =>
      `This will add a firewall BLOCK rule for ${t?.source_ip ?? "the source IP"}, cutting off all outbound connections to that host. Continue?`,
  },
  {
    type: "KILL_PROCESS",
    label: "Kill Process",
    sublabel: "Force-terminate the flagged PID",
    Icon: Skull,
    color: "#f87171",
    bg: "rgba(248,113,113,0.08)",
    border: "rgba(248,113,113,0.25)",
    hoverBg: "rgba(248,113,113,0.15)",
    destructive: true,
    confirmMsg: (t, tel) =>
      `This will execute ${
        tel?.pid ? `taskkill /F /PID ${tel.pid}` : "a SIGKILL"
      } against "${tel?.processName ?? "unknown"}". The process will be immediately terminated. Continue?`,
  },
  {
    type: "QUARANTINE_FILE",
    label: "Quarantine File",
    sublabel: "Move binary to isolated sandbox",
    Icon: Package,
    color: "#f59e0b",
    bg: "rgba(245,158,11,0.08)",
    border: "rgba(245,158,11,0.25)",
    hoverBg: "rgba(245,158,11,0.15)",
    destructive: true,
    confirmMsg: (t, tel) =>
      `"${tel?.processName ?? "unknown"}" will be moved to the AegisAI quarantine directory and prevented from executing. Continue?`,
  },
  {
    type: "WHITELIST",
    label: "Whitelist Event",
    sublabel: "Mark as false positive",
    Icon: ShieldCheck,
    color: "#10b981",
    bg: "rgba(16,185,129,0.08)",
    border: "rgba(16,185,129,0.25)",
    hoverBg: "rgba(16,185,129,0.15)",
    destructive: false,
    confirmMsg: null,
  },
];

/* ─── Inline confirmation dialog ──────────────────────────────────────── */
function ConfirmDialog({ action, threat, telemetry, onConfirm, onCancel }) {
  return (
    <div
      className="rounded-xl border p-4 animate-fade-in"
      style={{
        background: `${action.color}08`,
        borderColor: action.border,
      }}
    >
      <div className="flex items-start gap-3">
        <AlertTriangle size={15} style={{ color: action.color, flexShrink: 0, marginTop: 1 }} />
        <div className="flex-1">
          <p className="text-white text-xs font-semibold mb-1">Confirm: {action.label}</p>
          <p className="text-slate-400 text-[11px] leading-relaxed mb-3">
            {action.confirmMsg(threat, telemetry)}
          </p>
          <div className="flex gap-2">
            <button
              id={`confirm-action-${action.type.toLowerCase()}-btn`}
              onClick={onConfirm}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-bold transition"
              style={{
                background: action.color,
                color: "#fff",
              }}
            >
              <ChevronRight size={11} />
              Execute
            </button>
            <button
              onClick={onCancel}
              className="px-3 py-1.5 rounded-lg text-xs font-semibold text-slate-400 hover:text-white hover:bg-slate-700 transition"
            >
              Cancel
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

/* ─── Single action button ─────────────────────────────────────────────── */
function ActionButton({ def, threat, telemetry, onTrigger, result, busy }) {
  const [hovered, setHovered] = useState(false);

  const done    = result?.type === def.type && result?.done;
  const running = busy === def.type;

  return (
    <div className="space-y-1.5">
      <button
        id={`action-btn-${def.type.toLowerCase()}`}
        onClick={() => onTrigger(def)}
        disabled={running || done}
        onMouseEnter={() => setHovered(true)}
        onMouseLeave={() => setHovered(false)}
        className="flex items-center gap-3 w-full rounded-xl px-4 py-3.5 border text-left transition-all duration-150 disabled:cursor-not-allowed relative overflow-hidden"
        style={{
          background: done
            ? "rgba(16,185,129,0.08)"
            : running
            ? "rgba(6,182,212,0.08)"
            : hovered
            ? def.hoverBg
            : def.bg,
          borderColor: done ? "rgba(16,185,129,0.4)" : running ? "rgba(6,182,212,0.4)" : def.border,
          opacity: 1,
        }}
      >
        {/* Icon */}
        <div
          className="w-9 h-9 rounded-lg flex items-center justify-center flex-shrink-0"
          style={{
            background: done ? "rgba(16,185,129,0.2)" : running ? "rgba(6,182,212,0.2)" : `${def.color}15`,
          }}
        >
          {running ? (
            <Loader2 size={16} className="animate-spin text-cyan-400" />
          ) : done ? (
            <CheckCircle2 size={16} className="text-emerald-400" />
          ) : (
            <def.Icon size={16} style={{ color: def.color }} />
          )}
        </div>

        {/* Labels & States */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <p
              className="text-sm font-semibold"
              style={{ color: done ? "#10b981" : running ? "#06b6d4" : def.color }}
            >
              {def.label}
            </p>
            {/* Execution State Badge */}
            <span
              className="text-[9px] font-bold px-2 py-0.5 rounded-full uppercase tracking-wider"
              style={{
                background: done
                  ? "rgba(16,185,129,0.15)"
                  : running
                  ? "rgba(6,182,212,0.15)"
                  : "rgba(100,116,139,0.15)",
                color: done ? "#10b981" : running ? "#06b6d4" : "#94a3b8",
                border: `1px solid ${
                  done ? "rgba(16,185,129,0.3)" : running ? "rgba(6,182,212,0.3)" : "rgba(100,116,139,0.3)"
                }`,
              }}
            >
              {done ? "Executed Successfully" : running ? "Executing..." : "Idle"}
            </span>
          </div>

          <p className="text-slate-400 text-[11px] mt-0.5 truncate">
            {done ? result.detail : running ? "Dispatching kernel instruction..." : def.sublabel}
          </p>
        </div>

        {/* Destructive tag */}
        {def.destructive && !done && !running && (
          <span
            className="text-[9px] font-bold px-1.5 py-0.5 rounded flex-shrink-0"
            style={{
              background: `${def.color}18`,
              color: def.color,
              border: `1px solid ${def.color}30`,
            }}
          >
            DESTRUCTIVE
          </span>
        )}
      </button>

      {/* Kernel Verification Hook Details Box */}
      {done && (
        <div className="mx-2 px-3 py-2 rounded-lg bg-emerald-950/40 border border-emerald-500/30 text-xs flex items-center justify-between animate-fade-in font-mono">
          <div className="flex items-center gap-2 text-emerald-400">
            <CheckCircle2 size={13} className="flex-shrink-0" />
            <span className="text-[11px]">
              {def.type === "KILL_PROCESS"
                ? `Kernel Verified: PID ${result.pid || telemetry?.pid || "N/A"} Terminated`
                : def.type === "QUARANTINE_FILE"
                ? `Quarantined -> ${result.quarantine_path || "server/quarantine/sandbox.bin"}`
                : def.type === "ISOLATE_HOST"
                ? `Firewall Rule Active: ${result.firewall_rule || `AegisAI_Block_${threat?.source_ip}`}`
                : "Rule Applied to Threat Signature"}
            </span>
          </div>
          <span className="text-[10px] text-emerald-500/80 bg-emerald-900/40 px-1.5 py-0.5 rounded">
            VERIFIED
          </span>
        </div>
      )}
    </div>
  );
}

/* ─── Main ContainmentControls ─────────────────────────────────────────── */
export default function ContainmentControls({ threat, telemetry }) {
  const { dispatchAction, policy } = useEngine();
  const [pending, setPending]      = useState(null);    // action def awaiting confirm
  const [busy, setBusy]            = useState(null);    // action type currently running
  const [results, setResults]      = useState([]);      // completed action results

  async function execute(def) {
    setPending(null);
    setBusy(def.type);
    try {
      const res = await dispatchAction({
        threatId:    threat.id,
        pid:         telemetry?.pid,
        processName: telemetry?.processName,
        targetIp:    threat.source_ip,
        actionType:  def.type,
        mode:        "MANUAL",
      });
      setResults((prev) => [
        ...prev.filter((r) => r.type !== def.type),
        {
          type: def.type,
          done: true,
          statusLabel: res.statusLabel,
          detail: res.detail,
          pid: res.pid || telemetry?.pid,
          quarantine_path: res.quarantine_path,
          firewall_rule: res.firewall_rule,
        },
      ]);
    } finally {
      setBusy(null);
    }
  }

  function onTrigger(def) {
    if (def.destructive) {
      setPending(def);
    } else {
      execute(def);
    }
  }

  const isAutonomous = policy.containmentMode === "AUTONOMOUS";

  return (
    <div className="space-y-4">
      {/* Engine mode banner */}
      <div
        className="rounded-xl border p-3.5 flex items-center gap-3"
        style={{
          background: isAutonomous
            ? "rgba(239,68,68,0.06)"
            : "rgba(6,182,212,0.05)",
          borderColor: isAutonomous
            ? "rgba(239,68,68,0.2)"
            : "rgba(6,182,212,0.2)",
        }}
      >
        <div
          className="w-2.5 h-2.5 rounded-full flex-shrink-0 animate-threat-pulse"
          style={{ background: isAutonomous ? "#ef4444" : "#06b6d4" }}
        />
        <div>
          <p
            className="text-xs font-bold"
            style={{ color: isAutonomous ? "#ef4444" : "#06b6d4" }}
          >
            {isAutonomous ? "⚡ Autonomous Containment Mode ACTIVE" : "🛡 Manual Approval Mode"}
          </p>
          <p className="text-slate-500 text-[11px] mt-0.5">
            {isAutonomous
              ? `Engine auto-executes when risk score ≥ ${Math.round(policy.autoContainThreshold * 100)}%`
              : "SOC analyst approval required before executing any action"}
          </p>
        </div>
      </div>

      {/* Confirmation dialog (inline, replaces buttons temporarily) */}
      {pending && (
        <ConfirmDialog
          action={pending}
          threat={threat}
          telemetry={telemetry}
          onConfirm={() => execute(pending)}
          onCancel={() => setPending(null)}
        />
      )}

      {/* Action buttons */}
      <div className="space-y-2.5">
        {ACTIONS.map((def) => {
          const result = results.find((r) => r.type === def.type) ?? null;
          return (
            <ActionButton
              key={def.type}
              def={def}
              threat={threat}
              telemetry={telemetry}
              onTrigger={onTrigger}
              result={result}
              busy={busy}
            />
          );
        })}
      </div>

      {/* Audit note */}
      <p className="text-slate-600 text-[10px] text-center pt-1">
        All actions are audit-logged with timestamp, executor, and outcome.
      </p>
    </div>
  );
}
