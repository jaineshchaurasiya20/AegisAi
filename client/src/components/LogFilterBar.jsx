/**
 * LogFilterBar — Search, multi-filter controls, time range picker, and export dropdown.
 * Fully controlled: all state lives in the parent ThreatLogs page.
 */
import React, { useState, useRef, useEffect } from "react";
import {
  Search, X, Download, ChevronDown,
  SlidersHorizontal, RefreshCw, FileJson,
  FileText, FileCode2,
} from "lucide-react";
import { exportCSV, exportJSON, exportCEF } from "../services/exportUtils";

/* ─── Static option sets ───────────────────────────────────────────────────── */
const SEVERITY_OPTS = [
  { value: "critical", label: "Critical", color: "#ef4444" },
  { value: "high",     label: "High",     color: "#f59e0b" },
  { value: "medium",   label: "Medium",   color: "#3b82f6" },
  { value: "low",      label: "Low",      color: "#10b981" },
];

const EVENT_TYPE_OPTS = [
  "Port Scan", "SSH Brute Force", "Lateral Movement",
  "Data Exfil", "Anomalous Process", "DNS Tunneling",
  "DDoS", "Privilege Escalation",
];

const ACTION_OPTS = [
  { value: "process_isolated", label: "Auto-Isolated" },
  { value: "logged",           label: "Alert Only" },
  { value: "terminated",       label: "Process Terminated" },
  { value: "whitelisted",      label: "Whitelisted" },
];

const TIME_OPTS = [
  { value: "24h",    label: "Last 24 Hours" },
  { value: "7d",     label: "Last 7 Days"   },
  { value: "30d",    label: "Last 30 Days"  },
  { value: "all",    label: "All Time"      },
];

/* ─── Small reusable dropdown ─────────────────────────────────────────────── */
function Dropdown({ trigger, children, align = "left" }) {
  const [open, setOpen] = useState(false);
  const ref = useRef(null);

  useEffect(() => {
    function onOutside(e) {
      if (ref.current && !ref.current.contains(e.target)) setOpen(false);
    }
    document.addEventListener("mousedown", onOutside);
    return () => document.removeEventListener("mousedown", onOutside);
  }, []);

  return (
    <div className="relative" ref={ref}>
      <div onClick={() => setOpen((v) => !v)}>{trigger}</div>
      {open && (
        <div
          className="absolute z-30 mt-1.5 rounded-xl border border-slate-700/60 shadow-2xl overflow-hidden animate-fade-in"
          style={{
            background: "#0d1117",
            minWidth: 200,
            [align === "right" ? "right" : "left"]: 0,
          }}
          onClick={() => setOpen(false)}
        >
          {children}
        </div>
      )}
    </div>
  );
}

/* ─── Multi-select chip filter ────────────────────────────────────────────── */
function MultiSelectFilter({ label, options, selected, onChange, colorFn }) {
  const allSelected = selected.length === 0;

  function toggle(val) {
    if (selected.includes(val)) onChange(selected.filter((v) => v !== val));
    else onChange([...selected, val]);
  }

  return (
    <Dropdown
      trigger={
        <button
          className="flex items-center gap-1.5 px-3 py-2 rounded-lg border text-xs font-semibold transition"
          style={{
            background: selected.length > 0 ? "rgba(6,182,212,0.08)" : "rgba(30,41,59,0.6)",
            borderColor: selected.length > 0 ? "rgba(6,182,212,0.3)" : "rgba(51,65,85,0.6)",
            color: selected.length > 0 ? "#06b6d4" : "#94a3b8",
          }}
        >
          {label}
          {selected.length > 0 && (
            <span
              className="ml-0.5 px-1.5 py-0.5 rounded-full text-[10px] font-bold"
              style={{ background: "rgba(6,182,212,0.2)", color: "#06b6d4" }}
            >
              {selected.length}
            </span>
          )}
          <ChevronDown size={11} />
        </button>
      }
    >
      <div className="p-1">
        {options.map((opt) => {
          const val   = typeof opt === "string" ? opt : opt.value;
          const lbl   = typeof opt === "string" ? opt : opt.label;
          const color = colorFn?.(val);
          const active = selected.includes(val);
          return (
            <button
              key={val}
              onClick={(e) => { e.stopPropagation(); toggle(val); }}
              className="flex items-center gap-2.5 w-full px-3 py-2 rounded-lg text-xs transition hover:bg-slate-800/60"
              style={{ color: active ? (color || "#06b6d4") : "#94a3b8" }}
            >
              {/* Checkbox */}
              <span
                className="w-3.5 h-3.5 rounded flex items-center justify-center flex-shrink-0 border transition"
                style={{
                  background: active ? (color || "#06b6d4") + "25" : "transparent",
                  borderColor: active ? (color || "#06b6d4") : "#374151",
                }}
              >
                {active && (
                  <svg width="8" height="8" viewBox="0 0 8 8">
                    <polyline points="1,4 3,6 7,2" fill="none" stroke={color || "#06b6d4"} strokeWidth="1.5" strokeLinecap="round" />
                  </svg>
                )}
              </span>
              {color && (
                <span className="w-2 h-2 rounded-full flex-shrink-0" style={{ background: color }} />
              )}
              {lbl}
            </button>
          );
        })}
      </div>
    </Dropdown>
  );
}

/* ─── Export dropdown ─────────────────────────────────────────────────────── */
function ExportMenu({ threats }) {
  const FORMATS = [
    { label: "Export as CSV",  sub: "Excel / Spreadsheet", Icon: FileText,  fn: () => exportCSV(threats),  color: "#10b981" },
    { label: "Export as JSON", sub: "Raw payload + telemetry", Icon: FileJson, fn: () => exportJSON(threats), color: "#3b82f6" },
    { label: "Export as CEF",  sub: "SIEM syslog format", Icon: FileCode2, fn: () => exportCEF(threats),  color: "#a855f7" },
  ];

  return (
    <Dropdown
      align="right"
      trigger={
        <button
          id="export-btn"
          className="flex items-center gap-2 px-3 py-2 rounded-lg border border-slate-700/60 text-xs font-semibold text-slate-300 hover:text-white hover:border-slate-600 transition"
          style={{ background: "rgba(30,41,59,0.6)" }}
        >
          <Download size={13} />
          Export
          <ChevronDown size={11} />
        </button>
      }
    >
      <div className="p-1.5">
        <p className="px-2 py-1 text-[10px] text-slate-500 uppercase tracking-wider mb-1">
          Export {threats.length} filtered events
        </p>
        {FORMATS.map(({ label, sub, Icon, fn, color }) => (
          <button
            key={label}
            id={`export-${label.split(" ").pop().toLowerCase()}-btn`}
            onClick={(e) => { e.stopPropagation(); fn(); }}
            className="flex items-center gap-3 w-full px-3 py-2.5 rounded-lg text-xs transition hover:bg-slate-800/60 group"
          >
            <div
              className="w-7 h-7 rounded-lg flex items-center justify-center flex-shrink-0"
              style={{ background: `${color}18`, border: `1px solid ${color}30` }}
            >
              <Icon size={13} style={{ color }} />
            </div>
            <div className="text-left">
              <p className="text-slate-200 font-semibold group-hover:text-white transition">{label}</p>
              <p className="text-slate-500 text-[10px]">{sub}</p>
            </div>
          </button>
        ))}
      </div>
    </Dropdown>
  );
}

/* ─── Main LogFilterBar ───────────────────────────────────────────────────── */
export default function LogFilterBar({
  search, onSearch,
  severities, onSeverities,
  eventTypes, onEventTypes,
  actions, onActions,
  timeRange, onTimeRange,
  onClear,
  onRefresh, loading,
  filteredThreats,
}) {
  const hasFilters =
    search || severities.length || eventTypes.length || actions.length || timeRange !== "all";

  return (
    <div className="space-y-3">
      {/* Row 1: Search + Export + Refresh */}
      <div className="flex items-center gap-3">
        {/* Search */}
        <div className="relative flex-1 min-w-0">
          <Search size={13} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500 pointer-events-none" />
          <input
            id="log-search-input"
            type="text"
            placeholder="Search threat type, IP, process name..."
            value={search}
            onChange={(e) => onSearch(e.target.value)}
            className="w-full bg-slate-900/80 border border-slate-700/60 rounded-lg pl-9 pr-8 py-2 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500/60 transition"
          />
          {search && (
            <button
              onClick={() => onSearch("")}
              className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300"
            >
              <X size={12} />
            </button>
          )}
        </div>

        {/* Refresh */}
        <button
          id="refresh-logs-btn"
          onClick={onRefresh}
          className="p-2 rounded-lg border border-slate-700/60 text-slate-400 hover:text-white hover:border-slate-600 transition"
          style={{ background: "rgba(30,41,59,0.6)" }}
          title="Refresh logs"
        >
          <RefreshCw size={14} className={loading ? "animate-spin" : ""} />
        </button>

        {/* Export */}
        <ExportMenu threats={filteredThreats} />
      </div>

      {/* Row 2: Filter chips */}
      <div className="flex flex-wrap items-center gap-2">
        <span className="flex items-center gap-1.5 text-slate-500 text-xs">
          <SlidersHorizontal size={12} />
          Filter:
        </span>

        {/* Severity multi-select */}
        <MultiSelectFilter
          label="Severity"
          options={SEVERITY_OPTS}
          selected={severities}
          onChange={onSeverities}
          colorFn={(v) => SEVERITY_OPTS.find((o) => o.value === v)?.color}
        />

        {/* Event Type multi-select */}
        <MultiSelectFilter
          label="Event Type"
          options={EVENT_TYPE_OPTS}
          selected={eventTypes}
          onChange={onEventTypes}
        />

        {/* Action Taken multi-select */}
        <MultiSelectFilter
          label="Action Taken"
          options={ACTION_OPTS}
          selected={actions}
          onChange={onActions}
        />

        {/* Time Range */}
        <Dropdown
          trigger={
            <button
              className="flex items-center gap-1.5 px-3 py-2 rounded-lg border text-xs font-semibold transition"
              style={{
                background: timeRange !== "all" ? "rgba(6,182,212,0.08)" : "rgba(30,41,59,0.6)",
                borderColor: timeRange !== "all" ? "rgba(6,182,212,0.3)" : "rgba(51,65,85,0.6)",
                color: timeRange !== "all" ? "#06b6d4" : "#94a3b8",
              }}
            >
              {TIME_OPTS.find((o) => o.value === timeRange)?.label ?? "Time Range"}
              <ChevronDown size={11} />
            </button>
          }
        >
          <div className="p-1">
            {TIME_OPTS.map((opt) => (
              <button
                key={opt.value}
                onClick={(e) => { e.stopPropagation(); onTimeRange(opt.value); }}
                className="flex items-center gap-2 w-full px-3 py-2 rounded-lg text-xs transition hover:bg-slate-800/60"
                style={{ color: timeRange === opt.value ? "#06b6d4" : "#94a3b8" }}
              >
                {timeRange === opt.value && (
                  <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 flex-shrink-0" />
                )}
                {opt.label}
              </button>
            ))}
          </div>
        </Dropdown>

        {/* Clear filters */}
        {hasFilters && (
          <button
            id="clear-filters-btn"
            onClick={onClear}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-semibold text-red-400 hover:text-red-300 hover:bg-red-500/10 border border-red-500/20 transition"
          >
            <X size={11} />
            Clear filters
          </button>
        )}
      </div>
    </div>
  );
}
