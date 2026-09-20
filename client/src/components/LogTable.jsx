/**
 * LogTable — Paginated, sortable threat log data table with critical row highlighting.
 * Includes inline quick-remediation action dropdowns and modal trigger.
 */
import React, { useState, useRef, useEffect } from "react";
import {
  ChevronUp, ChevronDown, ChevronLeft, ChevronRight,
  ChevronsLeft, ChevronsRight, ExternalLink, ShieldAlert,
  Shield, Crosshair, Skull, WifiOff, Package, ShieldCheck,
  MoreVertical, CheckCircle2, Loader2
} from "lucide-react";
import { useEngine } from "../context/EngineContext";

/* ─── Config ───────────────────────────────────────────────────────────────── */
const PAGE_SIZE_OPTS = [10, 25, 50];

const SEV_CFG = {
  critical: { badge: "badge-critical", color: "#ef4444", Icon: ShieldAlert },
  high:     { badge: "badge-high",     color: "#f59e0b", Icon: ShieldAlert },
  medium:   { badge: "badge-medium",   color: "#3b82f6", Icon: Shield      },
  low:      { badge: "badge-low",      color: "#10b981", Icon: Shield      },
};

const ACTION_CFG = {
  trapped_in_honeypot: { label: "Trapped in Honeypot", color: "#06b6d4", bg: "rgba(6,182,212,0.12)" },
  process_isolated:    { label: "Auto-Isolated",       color: "#ef4444", bg: "rgba(239,68,68,0.1)" },
  logged:              { label: "Alert Only",          color: "#f59e0b", bg: "rgba(245,158,11,0.1)" },
  terminated:          { label: "Process Terminated",  color: "#a855f7", bg: "rgba(168,85,247,0.1)" },
  whitelisted:         { label: "Whitelisted",         color: "#10b981", bg: "rgba(16,185,129,0.1)" },
};

/* ─── Helpers ─────────────────────────────────────────────────────────────── */
function fmtTs(iso) {
  try {
    return new Date(iso).toLocaleString("sv-SE").replace("T", " ");
  } catch { return iso; }
}

function scorePct(score) {
  return Math.round((score ?? 0) * 100);
}

/* ─── Sort icon ───────────────────────────────────────────────────────────── */
function SortIcon({ active, asc }) {
  if (!active) return <span className="w-3 h-3 opacity-0" />;
  return asc
    ? <ChevronUp size={12} className="text-cyan-400" />
    : <ChevronDown size={12} className="text-cyan-400" />;
}

/* ─── Quick Remediation Popover ───────────────────────────────────────────── */
function QuickActionMenu({ threat, onOpenModal }) {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(null);
  const [confirming, setConfirming] = useState(null); // actionType awaiting confirm
  const menuRef = useRef(null);
  const { dispatchAction } = useEngine();

  useEffect(() => {
    function handleClickOutside(e) {
      if (menuRef.current && !menuRef.current.contains(e.target)) {
        setOpen(false);
        setConfirming(null);
      }
    }
    if (open) document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, [open]);

  const targetPid = threat.telemetry?.pid || (threat.port ? ((threat.port * 37 + 1024) % 24000) + 1200 : 8421);

  const executeAction = async (actionType) => {
    setBusy(actionType);
    setConfirming(null);
    try {
      await dispatchAction({
        threatId: threat.id,
        pid: targetPid,
        processName: threat.telemetry?.processName || "malicious_proc.exe",
        targetIp: threat.source_ip,
        actionType,
        mode: "MANUAL",
      });
      setOpen(false);
    } finally {
      setBusy(null);
    }
  };

  const handleTrigger = (e, actionType, isDestructive) => {
    e.stopPropagation();
    if (isDestructive) {
      setConfirming(actionType);
    } else {
      executeAction(actionType);
    }
  };

  return (
    <div className="relative" ref={menuRef} onClick={(e) => e.stopPropagation()}>
      <button
        id={`quick-action-btn-${threat.id}`}
        onClick={() => {
          setOpen((o) => !o);
          setConfirming(null);
        }}
        className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white border border-slate-700 transition"
        title="Quick Containment Actions"
      >
        <Crosshair size={12} className="text-red-400" />
        <span>Remediate</span>
        <ChevronDown size={11} className="text-slate-500" />
      </button>

      {open && (
        <div
          className="absolute right-0 top-full mt-1.5 w-60 rounded-xl bg-[#0e1422] border border-slate-700 shadow-2xl z-50 p-2 space-y-1.5 animate-fade-in font-sans"
          style={{ backdropFilter: "blur(14px)" }}
        >
          <div className="px-2 py-1 border-b border-slate-800 flex items-center justify-between text-[10px] uppercase tracking-wider text-slate-500 font-bold">
            <span>Quick Containment</span>
            <span className="mono text-slate-400 font-normal">ID: {threat.id?.slice(0, 6)}</span>
          </div>

          {/* Inline Confirmation Prompt */}
          {confirming ? (
            <div className="p-2.5 rounded-lg bg-red-500/10 border border-red-500/30 text-xs animate-fade-in">
              <div className="flex items-center gap-1.5 text-red-300 font-bold mb-1">
                <ShieldAlert size={13} className="text-red-400" />
                <span>Confirm {confirming.replace(/_/g, " ")}</span>
              </div>
              <p className="text-slate-400 text-[11px] leading-relaxed mb-2.5">
                {confirming === "KILL_PROCESS"
                  ? `Terminate PID ${targetPid}?`
                  : confirming === "ISOLATE_HOST"
                  ? `Block outbound traffic to ${threat.source_ip}?`
                  : `Move ${threat.telemetry?.processName || "binary"} to quarantine sandbox?`}
              </p>
              <div className="flex items-center gap-1.5">
                <button
                  id={`confirm-quick-${confirming.toLowerCase()}-btn`}
                  onClick={() => executeAction(confirming)}
                  className="flex-1 py-1 px-2 rounded bg-red-500 hover:bg-red-400 text-white font-bold text-[11px] transition text-center shadow-sm"
                >
                  Confirm Execute
                </button>
                <button
                  onClick={() => setConfirming(null)}
                  className="py-1 px-2 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[11px] transition"
                >
                  Cancel
                </button>
              </div>
            </div>
          ) : (
            <>
              {/* Action 1: Kill Process */}
              <button
                id={`quick-kill-process-${threat.id}`}
                onClick={(e) => handleTrigger(e, "KILL_PROCESS", true)}
                disabled={busy !== null}
                className="w-full flex items-center gap-2.5 px-2.5 py-1.5 rounded-lg text-left text-xs font-medium text-red-300 hover:bg-red-500/15 transition disabled:opacity-50 group"
              >
                {busy === "KILL_PROCESS" ? (
                  <Loader2 size={13} className="animate-spin text-red-400" />
                ) : (
                  <Skull size={13} className="text-red-400 flex-shrink-0 group-hover:scale-110 transition-transform" />
                )}
                <div className="flex-1">
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-white">Kill Process</span>
                    <span className="text-[9px] text-red-400/80 bg-red-500/10 px-1 rounded">DESTRUCTIVE</span>
                  </div>
                  <p className="text-[10px] text-slate-500">taskkill /F PID {threat.telemetry?.pid || 4012}</p>
                </div>
              </button>

              {/* Action 2: Isolate Host */}
              <button
                id={`quick-isolate-host-${threat.id}`}
                onClick={(e) => handleTrigger(e, "ISOLATE_HOST", true)}
                disabled={busy !== null}
                className="w-full flex items-center gap-2.5 px-2.5 py-1.5 rounded-lg text-left text-xs font-medium text-amber-300 hover:bg-amber-500/15 transition disabled:opacity-50 group"
              >
                {busy === "ISOLATE_HOST" ? (
                  <Loader2 size={13} className="animate-spin text-amber-400" />
                ) : (
                  <WifiOff size={13} className="text-amber-400 flex-shrink-0 group-hover:scale-110 transition-transform" />
                )}
                <div className="flex-1">
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-white">Isolate Host</span>
                    <span className="text-[9px] text-amber-400/80 bg-amber-500/10 px-1 rounded">DESTRUCTIVE</span>
                  </div>
                  <p className="text-[10px] text-slate-500">Firewall block IP {threat.source_ip}</p>
                </div>
              </button>

              {/* Action 3: Quarantine File */}
              <button
                id={`quick-quarantine-file-${threat.id}`}
                onClick={(e) => handleTrigger(e, "QUARANTINE_FILE", true)}
                disabled={busy !== null}
                className="w-full flex items-center gap-2.5 px-2.5 py-1.5 rounded-lg text-left text-xs font-medium text-purple-300 hover:bg-purple-500/15 transition disabled:opacity-50 group"
              >
                {busy === "QUARANTINE_FILE" ? (
                  <Loader2 size={13} className="animate-spin text-purple-400" />
                ) : (
                  <Package size={13} className="text-purple-400 flex-shrink-0 group-hover:scale-110 transition-transform" />
                )}
                <div className="flex-1">
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-white">Quarantine File</span>
                  </div>
                  <p className="text-[10px] text-slate-500">Move executable to sandbox</p>
                </div>
              </button>

              {/* Action 4: Whitelist Event */}
              <button
                id={`quick-whitelist-${threat.id}`}
                onClick={(e) => handleTrigger(e, "WHITELIST", false)}
                disabled={busy !== null}
                className="w-full flex items-center gap-2.5 px-2.5 py-1.5 rounded-lg text-left text-xs font-medium text-emerald-300 hover:bg-emerald-500/15 transition disabled:opacity-50 group"
              >
                {busy === "WHITELIST" ? (
                  <Loader2 size={13} className="animate-spin text-emerald-400" />
                ) : (
                  <ShieldCheck size={13} className="text-emerald-400 flex-shrink-0 group-hover:scale-110 transition-transform" />
                )}
                <div className="flex-1">
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-white">Whitelist Event</span>
                  </div>
                  <p className="text-[10px] text-slate-500">Suppress false positive alert</p>
                </div>
              </button>
            </>
          )}

          <div className="pt-1.5 border-t border-slate-800">
            <button
              onClick={() => {
                setOpen(false);
                onOpenModal(threat);
              }}
              className="w-full text-center py-1 text-[11px] font-semibold text-cyan-400 hover:text-cyan-300 transition"
            >
              Open Full Containment Tab →
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

/* ─── Column defs ─────────────────────────────────────────────────────────── */
const COLUMNS = [
  { key: "timestamp",    label: "Timestamp",      sortable: true  },
  { key: "threat_type",  label: "Threat Event",   sortable: true  },
  { key: "source_ip",    label: "Source → Target", sortable: true },
  { key: "threat_score", label: "Risk Score",     sortable: true  },
  { key: "action_taken", label: "Action Taken",   sortable: true  },
  { key: "_actions",     label: "Remediation",    sortable: false },
  { key: "_details",     label: "Details",        sortable: false },
];

/* ─── Main component ──────────────────────────────────────────────────────── */
export default function LogTable({ threats, loading, onRowClick }) {
  const [sortKey, setSortKey]   = useState("timestamp");
  const [sortAsc, setSortAsc]   = useState(false);
  const [page, setPage]         = useState(1);
  const [pageSize, setPageSize] = useState(10);

  /* Sorting */
  function handleSort(key) {
    if (!key || key === "_details" || key === "_actions") return;
    if (sortKey === key) setSortAsc((v) => !v);
    else { setSortKey(key); setSortAsc(false); }
  }

  const sorted = [...threats].sort((a, b) => {
    let va = a[sortKey] ?? "";
    let vb = b[sortKey] ?? "";
    if (typeof va === "string") va = va.toLowerCase();
    if (typeof vb === "string") vb = vb.toLowerCase();
    if (va < vb) return sortAsc ? -1 : 1;
    if (va > vb) return sortAsc ? 1 : -1;
    return 0;
  });

  /* Pagination */
  const totalPages  = Math.max(1, Math.ceil(sorted.length / pageSize));
  const safePage    = Math.min(page, totalPages);
  const startIdx    = (safePage - 1) * pageSize;
  const paginated   = sorted.slice(startIdx, startIdx + pageSize);
  const showFrom    = sorted.length === 0 ? 0 : startIdx + 1;
  const showTo      = Math.min(startIdx + pageSize, sorted.length);

  /* Reset to page 1 whenever threats or pageSize changes */
  useEffect(() => { setPage(1); }, [threats.length, pageSize]);

  return (
    <div className="card overflow-hidden flex flex-col">
      {/* ── Table ──────────────────────────────────────────────────────── */}
      <div className="overflow-x-auto flex-1">
        <table className="w-full text-sm border-collapse">
          {/* Head */}
          <thead>
            <tr style={{ background: "#0d1117", borderBottom: "1px solid #1e293b" }}>
              {COLUMNS.map(({ key, label, sortable }) => (
                <th
                  key={key}
                  onClick={() => sortable && handleSort(key)}
                  className={`text-left px-4 py-3 text-xs font-semibold uppercase tracking-wider text-slate-500 select-none ${
                    sortable ? "cursor-pointer hover:text-slate-300 transition" : ""
                  }`}
                >
                  <span className="flex items-center gap-1">
                    {label}
                    {sortable && <SortIcon active={sortKey === key} asc={sortAsc} />}
                  </span>
                </th>
              ))}
            </tr>
          </thead>

          {/* Body */}
          <tbody>
            {loading ? (
              /* Loading skeleton */
              Array.from({ length: 5 }).map((_, i) => (
                <tr key={i} style={{ borderBottom: "1px solid rgba(30,41,59,0.5)" }}>
                  {COLUMNS.map((col) => (
                    <td key={col.key} className="px-4 py-3.5">
                      <div className="h-3 rounded bg-slate-800 animate-pulse" style={{ width: col.key === "_details" ? 28 : "70%" }} />
                    </td>
                  ))}
                </tr>
              ))
            ) : paginated.length === 0 ? (
              <tr>
                <td colSpan={COLUMNS.length} className="text-center py-16 text-slate-500">
                  <ShieldAlert size={32} className="mx-auto mb-3 opacity-30" />
                  <p className="font-medium">No threats match the current filters</p>
                  <p className="text-xs mt-1 text-slate-600">Try adjusting your search or filter criteria</p>
                </td>
              </tr>
            ) : (
              paginated.map((t) => {
                const sev = SEV_CFG[t.severity] || SEV_CFG.low;
                const act = ACTION_CFG[t.action_taken] || {
                  label: (t.action_taken ?? "logged").replace(/_/g, " "),
                  color: "#9ca3af",
                  bg: "rgba(107,114,128,0.1)",
                };
                const pct = scorePct(t.threat_score);
                const isCritical = t.severity === "critical";

                return (
                  <tr
                    key={t.id}
                    id={`log-row-${t.id}`}
                    onClick={() => onRowClick?.(t)}
                    className="cursor-pointer transition-colors duration-150 group"
                    style={{
                      borderBottom: "1px solid rgba(30,41,59,0.5)",
                      borderLeft: isCritical ? "3px solid #ef4444" : "3px solid transparent",
                      background: isCritical
                        ? "rgba(239,68,68,0.03)"
                        : "transparent",
                    }}
                    onMouseEnter={(e) => {
                      e.currentTarget.style.background = isCritical
                        ? "rgba(239,68,68,0.06)"
                        : "rgba(30,41,59,0.35)";
                    }}
                    onMouseLeave={(e) => {
                      e.currentTarget.style.background = isCritical
                        ? "rgba(239,68,68,0.03)"
                        : "transparent";
                    }}
                  >
                    {/* Timestamp */}
                    <td className="px-4 py-3.5">
                      <span className="mono text-[11px] text-slate-400 whitespace-nowrap">
                        {fmtTs(t.timestamp)}
                      </span>
                    </td>

                    {/* Threat Event */}
                    <td className="px-4 py-3.5">
                      <div className="flex items-center gap-2">
                        <div
                          className="w-6 h-6 rounded flex items-center justify-center flex-shrink-0"
                          style={{ background: `${sev.color}18` }}
                        >
                          <sev.Icon size={11} style={{ color: sev.color }} />
                        </div>
                        <div>
                          <p className="text-white text-xs font-semibold leading-tight">
                            {t.threat_type}
                          </p>
                          <div className="flex items-center gap-1.5 mt-0.5 flex-wrap">
                            <span
                              className="badge text-[10px] inline-block"
                              style={{
                                background: `${sev.color}15`,
                                color: sev.color,
                                border: `1px solid ${sev.color}30`,
                                padding: "1px 7px",
                              }}
                            >
                              {t.severity}
                            </span>
                            {(t.deception_status === "TRAPPED" || t.action_taken === "trapped_in_honeypot") && (
                              <span
                                className="badge text-[9px] font-bold text-cyan-400 bg-cyan-950/60 border border-cyan-500/40 shadow-[0_0_8px_rgba(6,182,212,0.25)] flex items-center gap-1"
                                style={{ padding: "1px 6px" }}
                              >
                                <span className="w-1 h-1 rounded-full bg-cyan-400 animate-ping flex-shrink-0" />
                                TRAPPED IN HONEYPOT
                              </span>
                            )}
                          </div>
                        </div>
                      </div>
                    </td>

                    {/* Source → Target */}
                    <td className="px-4 py-3.5">
                      <div className="mono text-[11px]">
                        <span className="text-slate-300">{t.source_ip}</span>
                        <span className="text-slate-600"> → </span>
                        <span className="text-slate-400">
                          {t.destination_ip ?? "local"}
                          <span className="text-slate-600">:{t.port}</span>
                        </span>
                      </div>
                    </td>

                    {/* Risk Score */}
                    <td className="px-4 py-3.5">
                      <div className="flex items-center gap-2">
                        {/* Mini arc */}
                        <div
                          className="relative w-8 h-8 rounded-full flex items-center justify-center flex-shrink-0"
                          style={{
                            background: `conic-gradient(${sev.color} ${pct * 3.6}deg, #1f2937 0deg)`,
                          }}
                        >
                          <div className="absolute inset-1 rounded-full" style={{ background: "#0d1117" }} />
                          <span
                            className="mono text-[9px] font-bold relative z-10"
                            style={{ color: sev.color }}
                          >
                            {pct}
                          </span>
                        </div>
                        <div>
                          <p className="mono text-xs font-bold" style={{ color: sev.color }}>
                            {pct}%
                          </p>
                          <div className="score-bar w-12 mt-1">
                            <div
                              className="score-bar-fill"
                              style={{ width: `${pct}%`, background: sev.color }}
                            />
                          </div>
                        </div>
                      </div>
                    </td>

                    {/* Action Taken */}
                    <td className="px-4 py-3.5">
                      <span
                        className="inline-flex items-center gap-1 px-2 py-1 rounded-full text-[11px] font-semibold border"
                        style={{
                          background: act.bg,
                          color: act.color,
                          borderColor: `${act.color}30`,
                        }}
                      >
                        <span
                          className="w-1.5 h-1.5 rounded-full flex-shrink-0"
                          style={{ background: act.color }}
                        />
                        {act.label}
                      </span>
                    </td>

                    {/* Quick Remediation Actions */}
                    <td className="px-4 py-3.5">
                      <QuickActionMenu threat={t} onOpenModal={onRowClick} />
                    </td>

                    {/* Details button */}
                    <td className="px-4 py-3.5">
                      <button
                        id={`details-btn-${t.id}`}
                        className="p-1.5 rounded-lg text-slate-600 group-hover:text-cyan-400 group-hover:bg-cyan-500/10 border border-transparent group-hover:border-cyan-500/20 transition-all"
                        onClick={(e) => { e.stopPropagation(); onRowClick?.(t); }}
                        title="View XAI details & telemetry"
                      >
                        <ExternalLink size={13} />
                      </button>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {/* ── Pagination footer ──────────────────────────────────────────── */}
      <div
        className="flex items-center justify-between px-4 py-3 border-t flex-shrink-0"
        style={{ borderColor: "#1e293b", background: "#0d1117" }}
      >
        {/* Count info */}
        <div className="flex items-center gap-4">
          <span className="text-slate-500 text-xs">
            {sorted.length === 0 ? (
              "No events"
            ) : (
              <>
                Showing <span className="text-slate-300 font-semibold">{showFrom}–{showTo}</span>
                {" "}of{" "}
                <span className="text-slate-300 font-semibold">{sorted.length}</span> events
              </>
            )}
          </span>

          {/* Rows per page */}
          <div className="flex items-center gap-1.5 text-xs text-slate-500">
            <span>Rows:</span>
            {PAGE_SIZE_OPTS.map((n) => (
              <button
                key={n}
                id={`page-size-${n}-btn`}
                onClick={() => setPageSize(n)}
                className="px-2 py-0.5 rounded transition text-xs font-semibold"
                style={{
                  background: pageSize === n ? "rgba(6,182,212,0.15)" : "transparent",
                  color: pageSize === n ? "#06b6d4" : "#64748b",
                  border: pageSize === n ? "1px solid rgba(6,182,212,0.3)" : "1px solid transparent",
                }}
              >
                {n}
              </button>
            ))}
          </div>
        </div>

        {/* Page navigation */}
        <div className="flex items-center gap-1">
          <button
            id="page-first-btn"
            onClick={() => setPage(1)}
            disabled={safePage === 1}
            className="p-1.5 rounded text-slate-500 hover:text-slate-300 disabled:opacity-30 transition"
          >
            <ChevronsLeft size={14} />
          </button>
          <button
            id="page-prev-btn"
            onClick={() => setPage((p) => Math.max(1, p - 1))}
            disabled={safePage === 1}
            className="p-1.5 rounded text-slate-500 hover:text-slate-300 disabled:opacity-30 transition"
          >
            <ChevronLeft size={14} />
          </button>

          {/* Page number pills */}
          {Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
            let p;
            if (totalPages <= 5) {
              p = i + 1;
            } else if (safePage <= 3) {
              p = i + 1;
            } else if (safePage >= totalPages - 2) {
              p = totalPages - 4 + i;
            } else {
              p = safePage - 2 + i;
            }
            return (
              <button
                key={p}
                id={`page-${p}-btn`}
                onClick={() => setPage(p)}
                className="w-7 h-7 rounded text-xs font-semibold transition"
                style={{
                  background: safePage === p ? "rgba(6,182,212,0.15)" : "transparent",
                  color: safePage === p ? "#06b6d4" : "#64748b",
                  border: safePage === p ? "1px solid rgba(6,182,212,0.3)" : "1px solid transparent",
                }}
              >
                {p}
              </button>
            );
          })}

          <button
            id="page-next-btn"
            onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
            disabled={safePage === totalPages}
            className="p-1.5 rounded text-slate-500 hover:text-slate-300 disabled:opacity-30 transition"
          >
            <ChevronRight size={14} />
          </button>
          <button
            id="page-last-btn"
            onClick={() => setPage(totalPages)}
            disabled={safePage === totalPages}
            className="p-1.5 rounded text-slate-500 hover:text-slate-300 disabled:opacity-30 transition"
          >
            <ChevronsRight size={14} />
          </button>
        </div>
      </div>
    </div>
  );
}
