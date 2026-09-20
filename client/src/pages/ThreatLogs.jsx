/**
 * ThreatLogs — Full audit log view for AegisAI.
 *
 * Features:
 *  - Real-time search (threat type, IP, severity)
 *  - Multi-filter: Severity, Event Type, Action Taken, Time Range
 *  - Paginated sortable table (LogTable)
 *  - CSV / JSON / CEF export (LogFilterBar → exportUtils)
 *  - Row click → ThreatDetailModal (XAI + Telemetry slide-over)
 *  - Live stats header (total, critical count, avg score)
 */
import React, { useEffect, useState, useMemo, useCallback, useRef } from "react";
import {
  ShieldAlert, AlertTriangle, Activity, AlertOctagon, Target
} from "lucide-react";
import LogFilterBar   from "../components/LogFilterBar";
import LogTable       from "../components/LogTable";
import ThreatDetailModal from "../components/ThreatDetailModal";
import { api } from "../services/api";
import { aegisWS } from "../services/websocket";

/* ─── Time-range filter helper ─────────────────────────────────────────────── */
function withinTimeRange(isoTs, range) {
  if (!range || range === "all") return true;
  const now = Date.now();
  const ms  = { "24h": 864e5, "7d": 6048e5, "30d": 2592e6 }[range];
  if (!ms) return true;
  return now - new Date(isoTs).getTime() <= ms;
}

/* ─── Main page ────────────────────────────────────────────────────────────── */
export default function ThreatLogs() {
  const [threats,         setThreats]       = useState([]);
  const [loading,         setLoading]       = useState(true);
  const [error,           setError]         = useState(null);
  const [selectedThreat, setSelectedThreat] = useState(null);

  // Mouse tracking for premium background spotlight
  const [mousePos, setMousePos] = useState({ x: 0, y: 0 });
  const pageRef = useRef(null);

  // Filter state
  const [search,     setSearch]     = useState("");
  const [severities, setSeverities] = useState([]);   // multi-select array
  const [eventTypes, setEventTypes] = useState([]);
  const [actions,    setActions]    = useState([]);
  const [timeRange,  setTimeRange]  = useState("all");

  // Load Premium Font dynamically
  useEffect(() => {
    const link = document.createElement("link");
    link.href = "https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap";
    link.rel = "stylesheet";
    document.head.appendChild(link);
    return () => {
      if (document.head.contains(link)) document.head.removeChild(link);
    };
  }, []);

  /* ── Mouse move handler for spotlights ──────────────────────────────── */
  const handleMouseMove = (e) => {
    if (!pageRef.current) return;
    const rect = pageRef.current.getBoundingClientRect();
    setMousePos({
      x: e.clientX - rect.left,
      y: e.clientY - rect.top,
    });
  };

  /* ── Data fetch ─────────────────────────────────────────────────────── */
  const load = useCallback(() => {
    setLoading(true);
    setError(null);
    api.getThreats({ limit: 500 })
      .then((data) => {
        setThreats(Array.isArray(data) ? data : []);
      })
      .catch((err) => {
        setError(err.message || "Failed to load threat logs");
      })
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    load();
    const unsub = aegisWS.subscribe((msg) => {
      if ((msg.type === "threat_alert" || msg.type === "THREAT_DETECTED") && (msg.threat || msg.payload)) {
        const item = msg.payload || msg.threat;
        setThreats((prev) => [item, ...prev.filter((existing) => existing.id !== item.id)]);
      } else if (msg.type === "telemetry" && msg.threat?.new_alert) {
        setThreats((prev) => [msg.threat.new_alert, ...prev.filter((item) => item.id !== msg.threat.new_alert.id)]);
      }
    });
    return unsub;
  }, [load]);

  /* ── Filter pipeline ────────────────────────────────────────────────── */
  const filtered = useMemo(() => {
    const q = search.toLowerCase();
    return threats.filter((t) => {
      // Text search
      if (q && !["threat_type","source_ip","destination_ip","severity","action_taken","process_name"]
        .some((k) => (t[k] ?? "").toString().toLowerCase().includes(q))) return false;
      // Severity
      if (severities.length && !severities.includes(t.severity)) return false;
      // Event type
      if (eventTypes.length && !eventTypes.includes(t.threat_type)) return false;
      // Action
      if (actions.length && !actions.includes(t.action_taken)) return false;
      // Time range
      if (!withinTimeRange(t.timestamp, timeRange)) return false;
      return true;
    });
  }, [threats, search, severities, eventTypes, actions, timeRange]);

  /* ── Summary stats ──────────────────────────────────────────────────── */
  const stats = useMemo(() => {
    const criticals  = filtered.filter((t) => t.severity === "critical").length;
    const isolated   = filtered.filter((t) => t.action_taken === "process_isolated").length;
    const trapped    = filtered.filter((t) => t.action_taken === "trapped_in_honeypot" || t.deception_status === "TRAPPED").length;
    const avgScore   = filtered.length
      ? (filtered.reduce((s, t) => s + (t.threat_score ?? 0), 0) / filtered.length * 100).toFixed(1)
      : "0.0";
    return { criticals, isolated, trapped, avgScore };
  }, [filtered]);

  /* ── Clear all filters ──────────────────────────────────────────────── */
  function clearFilters() {
    setSearch(""); setSeverities([]); setEventTypes([]);
    setActions([]); setTimeRange("all");
  }

  /* ─── Render ─────────────────────────────────────────────────────────── */
  return (
    <div 
      ref={pageRef}
      onMouseMove={handleMouseMove}
      className="relative min-h-screen bg-gradient-to-br from-[#02040A] via-[#060918] to-[#0A061C] text-slate-200 overflow-hidden selection:bg-cyan-500/30"
      style={{ fontFamily: "'Plus Jakarta Sans', sans-serif" }}
    >
      {/* Dynamic Background Double Spotlights & Ambient Glows */}
      <div 
        className="pointer-events-none fixed inset-0 z-0 transition-opacity duration-500 ease-out"
        style={{
          background: `
            radial-gradient(800px circle at ${mousePos.x}px ${mousePos.y}px, rgba(139, 92, 246, 0.06), transparent 45%),
            radial-gradient(400px circle at ${mousePos.x}px ${mousePos.y}px, rgba(56, 189, 248, 0.04), transparent 50%)
          `,
        }}
      />
      <div className="absolute top-[-20%] right-[-10%] w-[60vw] h-[60vw] max-w-[800px] max-h-[800px] rounded-full bg-purple-900/10 blur-[130px] pointer-events-none" />
      <div className="absolute bottom-[-15%] left-[-15%] w-[70vw] h-[70vw] max-w-[900px] max-h-[900px] rounded-full bg-blue-900/10 blur-[140px] pointer-events-none" />

      {/* Main Content Area */}
      <div className="relative z-10 p-4 sm:p-6 lg:p-8 space-y-6 max-w-[1600px] mx-auto animate-in fade-in slide-in-from-bottom-6 duration-1000 ease-out">

        {/* ── Page header with inline contextual metrics ───────────────── */}
        <div className="flex flex-col xl:flex-row xl:items-end justify-between gap-5 pb-5 border-b border-white/[0.04]">
          <div>
            <h1 className="text-[1.75rem] font-bold tracking-tight bg-gradient-to-r from-white via-blue-100 to-indigo-300 bg-clip-text text-transparent drop-shadow-sm flex items-center gap-3">
              <ShieldAlert size={28} className="text-cyan-400 drop-shadow-[0_0_8px_rgba(34,211,238,0.5)]" />
              Audit Logs & Telemetry
            </h1>
            <p className="text-slate-400/90 text-[13px] mt-1.5 font-medium tracking-wide">
              Kernel & Socket Event Stream · High-Fidelity Edge History
            </p>
          </div>

          {/* Premium Inline Operational Metrics */}
          <div className="flex items-center gap-3 flex-wrap">
            {/* Total Events */}
            <div className="group relative flex items-center gap-2.5 px-4 py-2 rounded-xl bg-[#090C1A]/80 border border-white/[0.05] backdrop-blur-3xl text-[13px] text-slate-300 shadow-[0_4px_24px_-8px_rgba(0,0,0,0.6)] hover:border-cyan-500/30 transition-all duration-500">
              <Activity size={14} className="text-cyan-400" />
              <span className="text-slate-400">Events:</span>
              <span className="text-white font-bold tracking-wide">{filtered.length}</span>
              <span className="text-slate-500 font-mono text-xs">/ {threats.length}</span>
            </div>

            {/* Critical Threats */}
            <div className="group relative flex items-center gap-2.5 px-4 py-2 rounded-xl bg-[#1A0B14]/80 border border-red-500/20 backdrop-blur-3xl text-[13px] text-red-300 shadow-[0_4px_24px_-8px_rgba(239,68,68,0.15)] hover:border-red-500/40 transition-all duration-500">
              <AlertOctagon size={14} className="text-red-400 animate-pulse" />
              <span className="text-red-400 font-bold tracking-wide">{stats.criticals}</span>
              <span className="text-red-400/70">Critical</span>
            </div>

            {/* Trapped / Honeypot (Conditional) */}
            {stats.trapped > 0 && (
              <div className="group relative flex items-center gap-2.5 px-4 py-2 rounded-xl bg-[#081515]/80 border border-emerald-500/20 backdrop-blur-3xl text-[13px] text-emerald-300 shadow-[0_4px_24px_-8px_rgba(16,185,129,0.15)] hover:border-emerald-500/40 transition-all duration-500">
                <Target size={14} className="text-emerald-400" />
                <span className="text-emerald-400 font-bold tracking-wide">{stats.trapped}</span>
                <span className="text-emerald-400/70">Trapped</span>
              </div>
            )}

            {/* Average Risk Score */}
            <div className="group relative flex items-center gap-2.5 px-4 py-2 rounded-xl bg-[#1A150B]/80 border border-amber-500/20 backdrop-blur-3xl text-[13px] text-amber-300 shadow-[0_4px_24px_-8px_rgba(245,158,11,0.15)] hover:border-amber-500/40 transition-all duration-500">
              <span className="text-amber-400/70">Avg Risk:</span>
              <span className="text-amber-400 font-bold tracking-wide">{stats.avgScore}%</span>
            </div>
          </div>
        </div>

        {/* ── Error Banner ────────────────────────────────────────────── */}
        {error && (
          <div className="relative overflow-hidden rounded-xl bg-[#1A0B14]/80 backdrop-blur-xl border border-red-500/30 p-4 flex items-center justify-between shadow-[0_0_30px_rgba(239,68,68,0.15)] animate-in fade-in slide-in-from-top-4">
            <div className="absolute top-0 left-0 w-1 h-full bg-red-500"></div>
            <div className="flex items-center gap-3 text-red-300 text-[13px] font-medium ml-2">
              <AlertTriangle size={18} className="text-red-400" />
              <span>{error}</span>
            </div>
            <button
              onClick={load}
              className="px-4 py-1.5 rounded-lg bg-red-500/10 hover:bg-red-500/20 border border-red-500/30 hover:border-red-500/50 text-red-300 text-xs font-bold tracking-wide transition-all active:scale-95"
            >
              RETRY
            </button>
          </div>
        )}

        {/* ── Filter Bar Container with Premium Hover Glow ─────────────── */}
        <div className="group relative rounded-2xl transition-all duration-500 hover:shadow-[0_0_40px_rgba(99,102,241,0.08)]">
          <div className="absolute -inset-[1px] bg-gradient-to-br from-indigo-500/20 via-purple-500/10 to-transparent rounded-2xl opacity-0 group-hover:opacity-100 transition duration-700 blur-md"></div>
          <div className="relative bg-[#090C1A]/70 backdrop-blur-3xl border border-white/[0.05] rounded-2xl p-1 overflow-hidden">
            <div className="absolute top-0 left-0 w-full h-[1px] bg-gradient-to-r from-transparent via-indigo-500/30 to-transparent"></div>
            <LogFilterBar
              search={search}         onSearch={setSearch}
              severities={severities}   onSeverities={setSeverities}
              eventTypes={eventTypes}   onEventTypes={setEventTypes}
              actions={actions}         onActions={setActions}
              timeRange={timeRange}     onTimeRange={setTimeRange}
              onClear={clearFilters}
              onRefresh={load}          loading={loading}
              filteredThreats={filtered}
            />
          </div>
        </div>

        {/* ── Data Table Container with Premium Hover Glow ─────────────── */}
        <div className="group relative rounded-2xl transition-all duration-500 hover:shadow-[0_0_40px_rgba(56,189,248,0.08)]">
          <div className="absolute -inset-[1px] bg-gradient-to-tl from-cyan-500/20 via-blue-500/10 to-transparent rounded-2xl opacity-0 group-hover:opacity-100 transition duration-700 blur-md"></div>
          <div className="relative bg-[#090C1A]/70 backdrop-blur-3xl border border-white/[0.05] rounded-2xl overflow-hidden shadow-2xl">
            <div className="absolute top-0 left-0 w-full h-[1px] bg-gradient-to-r from-transparent via-cyan-500/30 to-transparent"></div>
            <LogTable
              threats={filtered}
              loading={loading}
              onRowClick={setSelectedThreat}
            />
          </div>
        </div>

        {/* ── XAI + Telemetry slide-over ──────────────────────────────── */}
        {selectedThreat && (
          <ThreatDetailModal
            threat={selectedThreat}
            onClose={() => setSelectedThreat(null)}
          />
        )}
      </div>
    </div>
  );
}