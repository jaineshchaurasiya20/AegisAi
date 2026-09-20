/**
 * TelemetryGrid — Process Telemetry panel displayed inside the ThreatDetailModal.
 * Shows: PID, parent process, CPU/RAM, open sockets, and command-line arguments.
 */
import React, { useState } from "react";
import {
  Cpu, MemoryStick, Terminal, Network,
  ChevronDown, ChevronUp, Activity,
} from "lucide-react";

const STATE_COLORS = {
  ESTABLISHED: { bg: "rgba(16,185,129,0.1)", text: "#10b981", border: "rgba(16,185,129,0.3)" },
  LISTEN:      { bg: "rgba(59,130,246,0.1)", text: "#3b82f6", border: "rgba(59,130,246,0.3)" },
  TIME_WAIT:   { bg: "rgba(245,158,11,0.1)", text: "#f59e0b", border: "rgba(245,158,11,0.3)" },
  CLOSE_WAIT:  { bg: "rgba(239,68,68,0.1)",  text: "#ef4444", border: "rgba(239,68,68,0.3)"  },
  SYN_SENT:    { bg: "rgba(168,85,247,0.1)", text: "#a855f7", border: "rgba(168,85,247,0.3)" },
};

function stateStyle(state) {
  return STATE_COLORS[state] || { bg: "rgba(107,114,128,0.1)", text: "#9ca3af", border: "rgba(107,114,128,0.3)" };
}

function StatPill({ label, value, color, Icon }) {
  return (
    <div
      className="flex items-center gap-3 rounded-xl p-3 border"
      style={{
        background: `${color}10`,
        borderColor: `${color}25`,
      }}
    >
      <div
        className="w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0"
        style={{ background: `${color}18` }}
      >
        <Icon size={14} style={{ color }} />
      </div>
      <div>
        <p className="text-slate-500 text-[10px] uppercase tracking-wider">{label}</p>
        <p className="text-white font-bold text-sm mono leading-tight">{value}</p>
      </div>
    </div>
  );
}

export default function TelemetryGrid({ telemetry }) {
  const [socketsExpanded, setSocketsExpanded] = useState(true);

  if (!telemetry) {
    return (
      <div className="text-slate-500 text-sm text-center py-6">
        No process telemetry available for this event.
      </div>
    );
  }

  const cpuColor   = telemetry.cpuUsagePct > 50 ? "#ef4444" : telemetry.cpuUsagePct > 20 ? "#f59e0b" : "#10b981";
  const memColor   = telemetry.memoryUsageMb > 500 ? "#ef4444" : telemetry.memoryUsageMb > 200 ? "#f59e0b" : "#3b82f6";

  return (
    <div className="space-y-4">

      {/* Process identity */}
      <div className="grid grid-cols-2 gap-3">
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-3">
          <p className="text-slate-500 text-[10px] uppercase tracking-wider mb-1">Process</p>
          <p className="text-white font-semibold text-sm mono">{telemetry.processName}</p>
          <p className="text-slate-500 text-[11px] mono mt-0.5">PID {telemetry.pid}</p>
        </div>
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-3">
          <p className="text-slate-500 text-[10px] uppercase tracking-wider mb-1">Parent Process</p>
          <p className="text-white font-semibold text-sm mono">{telemetry.parentProcess}</p>
          <p className="text-slate-500 text-[11px] mono mt-0.5">PID {telemetry.parentPid}</p>
        </div>
      </div>

      {/* CPU / RAM stats */}
      <div className="grid grid-cols-2 gap-3">
        <StatPill
          label="CPU Usage"
          value={`${telemetry.cpuUsagePct.toFixed(1)}%`}
          color={cpuColor}
          Icon={Cpu}
        />
        <StatPill
          label="RAM Usage"
          value={`${telemetry.memoryUsageMb} MB`}
          color={memColor}
          Icon={MemoryStick}
        />
      </div>

      {/* Command-line arguments */}
      <div>
        <div className="flex items-center gap-2 mb-2">
          <Terminal size={12} className="text-cyan-400" />
          <p className="text-slate-400 text-xs font-semibold uppercase tracking-wider">Command Line</p>
        </div>
        <div
          className="rounded-lg border border-slate-700/60 p-3 overflow-x-auto"
          style={{ background: "#0a0e17" }}
        >
          <code
            className="mono text-[11px] leading-relaxed break-all"
            style={{ color: "#06b6d4" }}
          >
            {telemetry.commandLine || "<no arguments>"}
          </code>
        </div>
      </div>

      {/* Open Sockets */}
      <div>
        <button
          className="flex items-center gap-2 mb-2 w-full text-left group"
          onClick={() => setSocketsExpanded((v) => !v)}
          id="sockets-toggle-btn"
        >
          <Network size={12} className="text-purple-400" />
          <p className="text-slate-400 text-xs font-semibold uppercase tracking-wider flex-1">
            Open Sockets
            <span
              className="ml-2 text-[10px] font-normal rounded-full px-1.5 py-0.5"
              style={{
                background: "rgba(168,85,247,0.15)",
                color: "#a855f7",
                border: "1px solid rgba(168,85,247,0.3)",
              }}
            >
              {telemetry.openSockets?.length ?? 0}
            </span>
          </p>
          {socketsExpanded
            ? <ChevronUp size={12} className="text-slate-600 group-hover:text-slate-400 transition" />
            : <ChevronDown size={12} className="text-slate-600 group-hover:text-slate-400 transition" />
          }
        </button>

        {socketsExpanded && (
          <div className="space-y-1.5 max-h-48 overflow-y-auto pr-1">
            {(!telemetry.openSockets || telemetry.openSockets.length === 0) ? (
              <p className="text-slate-600 text-xs text-center py-3">No open connections</p>
            ) : (
              telemetry.openSockets.map((sock, i) => {
                const ss = stateStyle(sock.state);
                return (
                  <div
                    key={i}
                    className="flex items-center gap-2 rounded-lg px-3 py-2 border text-[11px]"
                    style={{ background: "#0d1117", borderColor: "#1e293b" }}
                  >
                    {/* Protocol badge */}
                    <span
                      className="mono font-bold px-1.5 py-0.5 rounded text-[10px] flex-shrink-0"
                      style={{
                        background: sock.protocol === "TCP"
                          ? "rgba(59,130,246,0.12)"
                          : "rgba(245,158,11,0.12)",
                        color: sock.protocol === "TCP" ? "#3b82f6" : "#f59e0b",
                        border: `1px solid ${sock.protocol === "TCP" ? "rgba(59,130,246,0.3)" : "rgba(245,158,11,0.3)"}`,
                      }}
                    >
                      {sock.protocol}
                    </span>

                    {/* Local port */}
                    <span className="text-slate-500 flex-shrink-0">:{sock.localPort}</span>
                    <span className="text-slate-700">→</span>

                    {/* Remote */}
                    <span className="mono text-slate-300 flex-1 truncate">
                      {sock.remoteIp}
                      <span className="text-slate-500">:{sock.remotePort}</span>
                    </span>

                    {/* State badge */}
                    <span
                      className="mono px-1.5 py-0.5 rounded text-[10px] flex-shrink-0 font-semibold"
                      style={{
                        background: ss.bg,
                        color: ss.text,
                        border: `1px solid ${ss.border}`,
                      }}
                    >
                      {sock.state}
                    </span>
                  </div>
                );
              })
            )}
          </div>
        )}
      </div>
    </div>
  );
}
