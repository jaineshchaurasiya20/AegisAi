import React, { useState, useEffect, useRef } from "react";
import {
  Activity, Search, Shield, CheckCircle2, Play, RefreshCw,
  Terminal, ChevronDown, ChevronRight, Zap, ShieldAlert,
  Cpu, Database, Sparkles, Filter, Trash2
} from "lucide-react";
import { api } from "../services/api";

export default function AgentReasoningPipeline({
  agentTraces = [],
  currentTelemetry = null,
  onTriggerReplay = null,
  replaying = false,
  onClear = null,
}) {
  const [filterAgent, setFilterAgent] = useState("ALL");
  const [expandedTraceId, setExpandedTraceId] = useState(null);
  const [autoScroll, setAutoScroll] = useState(true);
  const traceEndRef = useRef(null);
  const containerRef = useRef(null);

  // Auto-scroll to latest trace when new event arrives
  useEffect(() => {
    if (autoScroll && traceEndRef.current) {
      traceEndRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [agentTraces, autoScroll]);

  // Extract latest state per agent
  const latestDetector = agentTraces.filter((t) => t.agent === "Detector Agent").slice(-1)[0];
  const latestInvestigator = agentTraces.filter((t) => t.agent === "Investigator Agent").slice(-1)[0];
  const latestRemediator = agentTraces.filter((t) => t.agent === "Remediator Agent").slice(-1)[0];
  const latestAuditor = agentTraces.filter((t) => t.agent === "Auditor Agent").slice(-1)[0];

  // Honeypot traps & diverted connections
  const honeypotEvents = agentTraces.filter((t) => t.agent === "Decoy Listener" || t.payload?.action_type === "HONEYPOT_REDIRECT" || t.payload?.status === "TRAPPED");
  const divertedTrapsCount = honeypotEvents.length;

  // Dynamic threshold & entropy values
  const currentTau = latestDetector?.payload?.dynamic_threshold ?? currentTelemetry?.threat?.dynamic_threshold ?? 0.65;
  const currentScore = latestDetector?.payload?.threat_score ?? currentTelemetry?.threat?.score ?? 0.0;
  const cpuPercent = currentTelemetry?.cpu_percent ?? 18.4;
  const ramPercent = currentTelemetry?.memory_percent ?? 72.1;

  // Filter traces
  const filteredTraces = filterAgent === "ALL"
    ? agentTraces
    : agentTraces.filter((t) => t.agent.toLowerCase().includes(filterAgent.toLowerCase()));

  const toggleExpand = (id) => {
    setExpandedTraceId((prev) => (prev === id ? null : id));
  };

  return (
    <div className="card p-5 space-y-5 border border-slate-800 bg-[#0c101b]/95 backdrop-blur-xl relative overflow-hidden shadow-2xl">
      {/* Background glow accents */}
      <div className="absolute top-0 right-1/4 w-96 h-32 bg-cyan-500/5 blur-3xl pointer-events-none rounded-full" />
      <div className="absolute bottom-0 right-0 w-64 h-32 bg-purple-500/5 blur-3xl pointer-events-none rounded-full" />

      {/* Header & Controls Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800/80 pb-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500/20 to-blue-600/20 border border-cyan-500/30 flex items-center justify-center shadow-lg shadow-cyan-500/10">
            <Zap size={20} className="text-cyan-400" />
          </div>
          <div>
            <div className="flex items-center gap-2.5 flex-wrap">
              <h2 className="text-white font-bold text-base tracking-tight">
                Autonomous 4-Agent Reasoning Pipeline
              </h2>
              <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[10px] font-bold bg-emerald-500/15 border border-emerald-500/30 text-emerald-400">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-threat-pulse" />
                Live Event Bus Active
              </span>
              <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[10px] font-bold bg-amber-500/15 border border-amber-500/30 text-amber-300 shadow-[0_0_10px_rgba(245,158,11,0.2)]">
                <Zap size={10} className="text-amber-400" />
                ⚡ AWS EventBridge: Fleet Sync (Source: aegisai.deception)
              </span>
            </div>
            <p className="text-slate-400 text-xs mt-0.5">
              Decoupled asynchronous telemetry → XAI attribution → surgical containment → closed-loop verification & AWS EventBridge fleet broadcast
            </p>
          </div>
        </div>

        {/* Action Buttons */}
        <div className="flex items-center gap-2 flex-wrap">
          {onTriggerReplay && (
            <button
              id="trigger-replay-demo-btn"
              onClick={onTriggerReplay}
              disabled={replaying}
              className={`flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-bold transition shadow-lg ${
                replaying
                  ? "bg-purple-600/40 text-purple-200 border border-purple-500/40 cursor-not-allowed"
                  : "bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white border border-purple-400/40 shadow-purple-600/20 active:scale-95"
              }`}
              title="Stream synthetic attack vectors to observe live 4-agent cascade"
            >
              {replaying ? (
                <RefreshCw size={13} className="animate-spin text-purple-300" />
              ) : (
                <Play size={13} className="fill-current text-purple-200" />
              )}
              <span>{replaying ? "Replaying Attacks..." : "Trigger Replay Demo"}</span>
            </button>
          )}

          {onClear && agentTraces.length > 0 && (
            <button
              id="clear-agent-trace-btn"
              onClick={onClear}
              className="p-2 rounded-xl border border-slate-700 bg-slate-800/80 hover:bg-slate-700 text-slate-400 hover:text-white transition"
              title="Clear Trace Stream"
            >
              <Trash2 size={14} />
            </button>
          )}
        </div>
      </div>

      {/* 4 Agent Pipeline Status Cards Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5">
        {/* 1. Detector Agent Card */}
        <div className="rounded-xl p-3.5 border bg-slate-900/60 border-slate-800 flex flex-col justify-between relative overflow-hidden transition-all duration-200 hover:border-cyan-500/40">
          <div className="flex items-start justify-between gap-2">
            <div className="flex items-center gap-2">
              <div className="w-7 h-7 rounded-lg bg-cyan-500/15 border border-cyan-500/30 flex items-center justify-center">
                <Activity size={14} className="text-cyan-400" />
              </div>
              <span className="text-xs font-bold text-white">Detector Agent</span>
            </div>
            <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full uppercase tracking-wider ${
              latestDetector ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 animate-pulse" : "bg-slate-800 text-slate-400"
            }`}>
              {latestDetector ? "Anomaly Flagged" : "Monitoring"}
            </span>
          </div>

          <div className="mt-3 space-y-1.5">
            <div className="flex items-center justify-between text-xs">
              <span className="text-slate-400">Dynamic Threshold τ(t):</span>
              <span className="font-mono font-bold text-cyan-400">
                {currentTau.toFixed(2)}
              </span>
            </div>
            <div className="flex items-center justify-between text-xs">
              <span className="text-slate-400">Host Entropy:</span>
              <span className="font-mono text-slate-300 text-[11px]">
                CPU {cpuPercent?.toFixed(0)}% · RAM {ramPercent?.toFixed(0)}%
              </span>
            </div>
            {latestDetector && (
              <div className="pt-1.5 border-t border-slate-800 text-[11px] text-cyan-300/90 truncate font-mono">
                Anomaly Score: {(currentScore * 100).toFixed(0)}% &gt; τ({currentTau.toFixed(2)})
              </div>
            )}
          </div>
        </div>

        {/* 2. Investigator Agent Card */}
        <div className="rounded-xl p-3.5 border bg-slate-900/60 border-slate-800 flex flex-col justify-between relative overflow-hidden transition-all duration-200 hover:border-purple-500/40">
          <div className="flex items-start justify-between gap-2">
            <div className="flex items-center gap-2">
              <div className="w-7 h-7 rounded-lg bg-purple-500/15 border border-purple-500/30 flex items-center justify-center">
                <Search size={14} className="text-purple-400" />
              </div>
              <span className="text-xs font-bold text-white">Investigator Agent</span>
            </div>
            <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full uppercase tracking-wider ${
              latestInvestigator ? "bg-purple-500/20 text-purple-300 border border-purple-500/40" : "bg-slate-800 text-slate-400"
            }`}>
              {latestInvestigator ? "Attributed" : "Idle"}
            </span>
          </div>

          <div className="mt-3 space-y-1.5">
            <div className="flex items-center justify-between text-xs">
              <span className="text-slate-400">XAI Attribution:</span>
              <span className="font-mono font-semibold text-purple-300 text-[11px] truncate max-w-[130px]">
                {latestInvestigator?.payload?.attribution_method || "DomainAttribution"}
              </span>
            </div>
            <div className="flex items-center justify-between text-xs">
              <span className="text-slate-400">Context:</span>
              <span className="font-mono text-slate-300 text-[11px]">
                {latestInvestigator?.payload?.process_name || (latestInvestigator?.payload?.process_pid ? `PID ${latestInvestigator.payload.process_pid}` : "Read-Only psutil")}
              </span>
            </div>
            {latestInvestigator && (
              <div className="pt-1.5 border-t border-slate-800 text-[11px] text-purple-300/90 truncate font-mono">
                {latestInvestigator.payload?.root_cause || latestInvestigator.message}
              </div>
            )}
          </div>
        </div>

        {/* 3. Remediator Agent Card */}
        <div className="rounded-xl p-3.5 border bg-slate-900/60 border-slate-800 flex flex-col justify-between relative overflow-hidden transition-all duration-200 hover:border-amber-500/40">
          <div className="flex items-start justify-between gap-2">
            <div className="flex items-center gap-2">
              <div className="w-7 h-7 rounded-lg bg-amber-500/15 border border-amber-500/30 flex items-center justify-center">
                <Shield size={14} className="text-amber-400" />
              </div>
              <span className="text-xs font-bold text-white">Remediator Agent</span>
            </div>
            <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full uppercase tracking-wider ${
              latestRemediator?.status === "SUCCESS"
                ? "bg-amber-500/20 text-amber-300 border border-amber-500/40"
                : latestRemediator?.status === "SKIPPED"
                ? "bg-blue-500/20 text-blue-300 border border-blue-500/40"
                : "bg-slate-800 text-slate-400"
            }`}>
              {latestRemediator?.status || "Standby"}
            </span>
          </div>

          <div className="mt-3 space-y-1.5">
            <div className="flex items-center justify-between text-xs">
              <span className="text-slate-400">Containment:</span>
              <span className="font-mono font-bold text-amber-400 text-[11px]">
                {latestRemediator?.payload?.action_type || "PID_KILL / DECOY"}
              </span>
            </div>
            <div className="flex items-center justify-between text-xs">
              <span className="text-slate-400">Deception:</span>
              <span className="font-mono font-bold text-cyan-400 text-[11px]">
                {divertedTrapsCount > 0 ? `${divertedTrapsCount} Diverted Traps` : "4 Decoys Active"}
              </span>
            </div>
            <div className="flex items-center justify-between text-xs">
              <span className="text-slate-400">Guardrails:</span>
              <span className="font-mono text-emerald-400 text-[11px]">
                AegisAI &amp; OS Protected
              </span>
            </div>
            {latestRemediator && (
              <div className="pt-1.5 border-t border-slate-800 text-[11px] text-amber-300/90 truncate font-mono">
                {latestRemediator.payload?.target || latestRemediator.message}
              </div>
            )}
          </div>
        </div>

        {/* 4. Auditor Agent Card */}
        <div className="rounded-xl p-3.5 border bg-slate-900/60 border-slate-800 flex flex-col justify-between relative overflow-hidden transition-all duration-200 hover:border-emerald-500/40">
          <div className="flex items-start justify-between gap-2">
            <div className="flex items-center gap-2">
              <div className="w-7 h-7 rounded-lg bg-emerald-500/15 border border-emerald-500/30 flex items-center justify-center">
                <CheckCircle2 size={14} className="text-emerald-400" />
              </div>
              <span className="text-xs font-bold text-white">Auditor Agent</span>
            </div>
            <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full uppercase tracking-wider ${
              latestAuditor?.status === "SUCCESS"
                ? "bg-emerald-500/20 text-emerald-300 border border-emerald-500/40"
                : "bg-slate-800 text-slate-400"
            }`}>
              {latestAuditor ? "Verified 500ms" : "Ready"}
            </span>
          </div>

          <div className="mt-3 space-y-1.5">
            <div className="flex items-center justify-between text-xs">
              <span className="text-slate-400">Closed-Loop:</span>
              <span className="font-mono font-bold text-emerald-400 text-[11px]">
                {latestAuditor?.status === "SUCCESS" ? "✓ Containment Verified" : "500ms Post-Check"}
              </span>
            </div>
            <div className="flex items-center justify-between text-xs">
              <span className="text-slate-400">Retraining Store:</span>
              <span className="font-mono text-cyan-400 text-[11px]">
                SQLite (Edge Retrained)
              </span>
            </div>
            {latestAuditor && (
              <div className="pt-1.5 border-t border-slate-800 text-[11px] text-emerald-300/90 truncate font-mono">
                Label: {latestAuditor.payload?.retraining_label || "verified threat"}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Sequential Real-Time Trace Terminal Stream */}
      <div className="space-y-2.5">
        <div className="flex items-center justify-between flex-wrap gap-2 text-xs">
          <div className="flex items-center gap-2">
            <Terminal size={14} className="text-slate-400" />
            <span className="font-semibold text-white">Sequential Inter-Agent Execution Feed</span>
            <span className="text-slate-500 font-mono text-[11px]">
              ({filteredTraces.length} events)
            </span>
          </div>

          {/* Filter Pills */}
          <div className="flex items-center gap-1.5 bg-slate-900/80 p-1 rounded-lg border border-slate-800 text-[11px]">
            {["ALL", "Detector", "Investigator", "Remediator", "Decoy", "Auditor"].map((f) => (
              <button
                key={f}
                onClick={() => setFilterAgent(f)}
                className={`px-2 py-0.5 rounded-md font-medium transition ${
                  filterAgent === f
                    ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 font-bold"
                    : "text-slate-400 hover:text-white"
                }`}
              >
                {f}
              </button>
            ))}
          </div>
        </div>

        {/* Console Box */}
        <div
          ref={containerRef}
          className="rounded-xl border border-slate-800 bg-[#080b13] p-3.5 font-mono text-xs max-h-64 overflow-y-auto space-y-2 shadow-inner"
        >
          {filteredTraces.length === 0 ? (
            <div className="py-8 text-center text-slate-500 text-xs space-y-1">
              <p>No agent execution traces captured yet.</p>
              <p className="text-[11px] text-slate-600">
                Click <span className="text-purple-400 font-semibold">"Trigger Replay Demo"</span> above to stream attacks through all 4 agents.
              </p>
            </div>
          ) : (
            filteredTraces.map((trace, idx) => {
              const isExpanded = expandedTraceId === trace.event_id || expandedTraceId === `idx-${idx}`;
              const timeStr = trace.timestamp
                ? new Date(trace.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })
                : "—";

              // Color mappings per agent
              let agentColor = "text-cyan-400 border-cyan-500/30 bg-cyan-950/20";
              let badgeColor = "bg-cyan-500/15 text-cyan-300";
              if (trace.agent.includes("Investigator")) {
                agentColor = "text-purple-400 border-purple-500/30 bg-purple-950/20";
                badgeColor = "bg-purple-500/15 text-purple-300";
              } else if (trace.agent.includes("Remediator")) {
                agentColor = "text-amber-400 border-amber-500/30 bg-amber-950/20";
                badgeColor = "bg-amber-500/15 text-amber-300";
              } else if (trace.agent.includes("Decoy")) {
                agentColor = "text-blue-400 border-blue-500/30 bg-blue-950/20";
                badgeColor = "bg-blue-500/15 text-blue-300";
              } else if (trace.agent.includes("Auditor")) {
                agentColor = "text-emerald-400 border-emerald-500/30 bg-emerald-950/20";
                badgeColor = "bg-emerald-500/15 text-emerald-300";
              }

              const entropyVal = trace.payload?.entropy_score ?? trace.payload?.entropy;

              return (
                <div
                  key={trace.event_id || `idx-${idx}`}
                  className="rounded-lg border border-slate-800/80 bg-slate-900/40 p-2.5 transition-all hover:bg-slate-900/80"
                >
                  <div
                    onClick={() => toggleExpand(trace.event_id || `idx-${idx}`)}
                    className="flex items-start justify-between gap-3 cursor-pointer select-none"
                  >
                    <div className="flex items-start gap-2 min-w-0">
                      <span className="text-slate-500 text-[11px] flex-shrink-0 pt-0.5">
                        {timeStr}
                      </span>
                      <span className={`px-2 py-0.5 rounded font-bold text-[10px] uppercase tracking-wider flex-shrink-0 border ${agentColor}`}>
                        {trace.agent.replace(" Agent", "")}
                      </span>
                      <span className="text-slate-200 text-xs break-words leading-relaxed">
                        {trace.message}
                      </span>
                      {entropyVal !== undefined && (
                        <span className="px-1.5 py-0.5 rounded bg-blue-500/15 text-blue-400 border border-blue-500/30 text-[10px] font-bold flex-shrink-0">
                          Entropy: {entropyVal}
                        </span>
                      )}
                      {(trace.payload?.eventbridge_synced || trace.message?.includes("[AWS EventBridge]")) && (
                        <span className="px-1.5 py-0.5 rounded bg-amber-500/15 text-amber-300 border border-amber-500/30 text-[10px] font-bold flex-shrink-0 flex items-center gap-1">
                          <Zap size={9} className="text-amber-400" />
                          ⚡ EventBridge Synced
                        </span>
                      )}
                    </div>

                    <div className="flex items-center gap-2 flex-shrink-0">
                      <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold uppercase ${badgeColor}`}>
                        {trace.status}
                      </span>
                      {isExpanded ? (
                        <ChevronDown size={13} className="text-slate-400" />
                      ) : (
                        <ChevronRight size={13} className="text-slate-400" />
                      )}
                    </div>
                  </div>

                  {/* Expanded JSON details */}
                  {isExpanded && (
                    <div className="mt-2.5 pt-2.5 border-t border-slate-800 text-[11px] space-y-1.5 animate-fade-in">
                      <div className="flex items-center justify-between text-slate-400">
                        <span>Event ID: <span className="text-slate-300">{trace.event_id || "N/A"}</span></span>
                        <span>Severity: <span className="text-amber-400 uppercase">{trace.severity || "info"}</span></span>
                      </div>
                      {trace.payload && Object.keys(trace.payload).length > 0 && (
                        <pre className="p-2 rounded bg-slate-950 border border-slate-800/80 overflow-x-auto text-slate-300 text-[10px]">
                          {JSON.stringify(trace.payload, null, 2)}
                        </pre>
                      )}
                    </div>
                  )}
                </div>
              );
            })
          )}
          <div ref={traceEndRef} />
        </div>
      </div>
    </div>
  );
}
