import React from "react";
import { AlertTriangle, Shield, Clock, Globe } from "lucide-react";

const SEVERITY_CONFIG = {
  critical: { cls: "badge-critical", icon: AlertTriangle, color: "#ef4444", bar: "bg-red-500" },
  high:     { cls: "badge-high",     icon: AlertTriangle, color: "#f59e0b", bar: "bg-amber-500" },
  medium:   { cls: "badge-medium",   icon: Shield,        color: "#3b82f6", bar: "bg-blue-500" },
  low:      { cls: "badge-low",      icon: Shield,        color: "#10b981", bar: "bg-emerald-500" },
};

function formatTime(iso) {
  try {
    return new Date(iso).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  } catch { return iso; }
}

export default function ThreatCard({ threat, onClick }) {
  const cfg = SEVERITY_CONFIG[threat.severity] || SEVERITY_CONFIG.low;
  const Icon = cfg.icon;
  const scorePercent = Math.round(threat.threat_score * 100);

  return (
    <div
      id={`threat-card-${threat.id}`}
      onClick={() => onClick?.(threat)}
      className="card p-4 cursor-pointer hover:border-slate-600 transition-all duration-200 animate-slide-in group"
    >
      <div className="flex items-start justify-between gap-3">
        {/* Icon + Type */}
        <div className="flex items-center gap-3 min-w-0">
          <div
            className="flex-shrink-0 w-9 h-9 rounded-lg flex items-center justify-center"
            style={{ background: `${cfg.color}18`, border: `1px solid ${cfg.color}30` }}
          >
            <Icon size={16} style={{ color: cfg.color }} />
          </div>
          <div className="min-w-0">
            <p className="text-white text-sm font-semibold truncate">{threat.threat_type}</p>
            <p className="mono text-slate-400 text-[11px] truncate">{threat.source_ip} → :{threat.port}</p>
          </div>
        </div>

        {/* Severity badge */}
        <span className={`badge flex-shrink-0 ${cfg.cls}`}>{threat.severity}</span>
      </div>

      {/* Score Bar */}
      <div className="mt-3">
        <div className="flex justify-between text-[11px] mb-1">
          <span className="text-slate-500">Threat Score</span>
          <span className="font-semibold mono" style={{ color: cfg.color }}>{scorePercent}%</span>
        </div>
        <div className="score-bar">
          <div className={`score-bar-fill ${cfg.bar}`} style={{ width: `${scorePercent}%` }} />
        </div>
      </div>

      {/* Meta */}
      <div className="flex items-center gap-4 mt-3 text-[11px] text-slate-500">
        <span className="flex items-center gap-1">
          <Clock size={10} />
          {formatTime(threat.timestamp)}
        </span>
        <span className="flex items-center gap-1">
          <Globe size={10} />
          {threat.destination_ip}
        </span>
        {threat.action_taken === "process_isolated" && (
          <span className="text-amber-400 font-semibold">● Isolated</span>
        )}
        {(threat.action_taken === "trapped_in_honeypot" || threat.deception_status === "TRAPPED") && (
          <span className="text-cyan-400 font-semibold flex items-center gap-1 bg-cyan-950/50 px-1.5 py-0.5 rounded border border-cyan-500/30">
            <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />
            Trapped in Honeypot
          </span>
        )}
      </div>

      {/* XAI hint */}
      <p className="text-slate-600 text-[10px] mt-2 group-hover:text-slate-500 transition">
        Click for XAI explanation →
      </p>
    </div>
  );
}
