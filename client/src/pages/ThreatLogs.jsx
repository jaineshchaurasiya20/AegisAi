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
import React, { useEffect, useState, useMemo, useCallback } from "react";
import {
  ShieldAlert, ShieldCheck, Flame, TrendingUp, Database, AlertTriangle,
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
  const [threats,       setThreats]       = useState([]);
  const [loading,       setLoading]       = useState(true);
  const [error,         setError]         = useState(null);
  const [selectedThreat, setSelectedThreat] = useState(null);

  // Filter state
  const [search,     setSearch]     = useState("");
  const [severities, setSeverities] = useState([]);   // multi-select array
  const [eventTypes, setEventTypes] = useState([]);
  const [actions,    setActions]    = useState([]);
  const [timeRange,  setTimeRange]  = useState("all");

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
    <div className="p-6 space-y-5 animate-fade-in">

      {/* ── Page header with inline contextual metrics ───────────────── */}
      <div className="flex items-center justify-between gap-4 flex-wrap pb-2 border-b border-white/[0.06]">
        <div>
          <h1 className="text-white text-xl sm:text-2xl font-bold flex items-center gap-2.5">
            <ShieldAlert size={22} className="text-cyan-400" />
            Log Analysis
          </h1>
          <p className="text-slate-400 text-xs sm:text-sm mt-0.5">
            Kernel & Socket Telemetry Audit Stream · Edge-native event history
          </p>
        </div>

        {/* Inline operational metrics (No duplicate full-width card grid) */}
        <div className="flex items-center gap-2.5 flex-wrap text-xs font-mono">
          <div className="px-3 py-1.5 rounded-lg bg-navy-950/70 border border-white/[0.06] text-slate-300">
            <span className="text-slate-500">Events: </span>
            <span className="text-white font-bold">{filtered.length}</span>
            <span className="text-slate-500"> / {threats.length}</span>
          </div>

          <div className="px-3 py-1.5 rounded-lg bg-navy-950/70 border border-red-500/25 text-red-300">
            <span className="text-red-400 font-bold">{stats.criticals}</span>
            <span className="text-slate-400"> Critical</span>
          </div>

          {stats.trapped > 0 && (
            <div className="px-3 py-1.5 rounded-lg bg-navy-950/70 border border-cyan-500/25 text-cyan-300">
              <span className="text-cyan-400 font-bold">{stats.trapped}</span>
              <span className="text-slate-400"> Honeypot Trapped</span>
            </div>
          )}

          <div className="px-3 py-1.5 rounded-lg bg-navy-950/70 border border-white/[0.06] text-slate-300">
            <span className="text-slate-500">Avg Risk: </span>
            <span className="text-amber-300 font-bold">{stats.avgScore}%</span>
          </div>
        </div>
      </div>

      {/* ── Error Banner ────────────────────────────────────────────── */}
      {error && (
        <div className="bg-red-500/10 border border-red-500/25 rounded-xl p-4 flex items-center justify-between">
          <div className="flex items-center gap-3 text-red-400 text-sm">
            <AlertTriangle size={18} />
            <span>{error}</span>
          </div>
          <button
            onClick={load}
            className="px-3 py-1.5 rounded-lg bg-red-500/20 hover:bg-red-500/30 text-red-300 text-xs font-semibold transition"
          >
            Retry
          </button>
        </div>
      )}

      {/* ── Filter bar ──────────────────────────────────────────────── */}
      <LogFilterBar
        search={search}           onSearch={setSearch}
        severities={severities}   onSeverities={setSeverities}
        eventTypes={eventTypes}   onEventTypes={setEventTypes}
        actions={actions}         onActions={setActions}
        timeRange={timeRange}     onTimeRange={setTimeRange}
        onClear={clearFilters}
        onRefresh={load}          loading={loading}
        filteredThreats={filtered}
      />

      {/* ── Data table ──────────────────────────────────────────────── */}
      <LogTable
        threats={filtered}
        loading={loading}
        onRowClick={setSelectedThreat}
      />

      {/* ── XAI + Telemetry slide-over ──────────────────────────────── */}
      {selectedThreat && (
        <ThreatDetailModal
          threat={selectedThreat}
          onClose={() => setSelectedThreat(null)}
        />
      )}
    </div>
  );
}
