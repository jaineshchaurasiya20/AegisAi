import React, { useState } from "react";
import { Link } from "react-router-dom";
import {
  ArrowRight,
  Copy,
  Check,
  Clock,
  Sparkles,
  ShieldAlert,
  Brain,
} from "lucide-react";
import GlassCard from "./ui/GlassCard";
import StatusBadge from "./ui/StatusBadge";
import Button from "./ui/Button";

function formatTimestamp(ts) {
  if (!ts) return new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  try {
    const d = new Date(ts);
    if (!isNaN(d.getTime())) {
      return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
    }
  } catch {}
  return ts;
}

export default function IncidentHero({ incident, onInvestigate }) {
  const [copied, setCopied] = useState(false);

  const handleCopyIp = () => {
    if (!incident?.source_ip) return;
    navigator.clipboard?.writeText(incident.source_ip);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  if (!incident) return null;

  const displayTime = formatTimestamp(incident.timestamp);
  const scorePct = typeof incident.threat_score === "number"
    ? (incident.threat_score * 100).toFixed(1) + "%"
    : "94.2%";

  return (
    <GlassCard
      elevation="critical"
      className="p-5 sm:p-6 relative overflow-hidden transition-all duration-300"
    >
      {/* Subtle top indicator line */}
      <div className="absolute top-0 left-0 right-0 h-[2px] bg-gradient-to-r from-red-500 via-amber-400 to-red-600 opacity-80" />

      <div className="flex flex-col xl:flex-row xl:items-center justify-between gap-6">
        {/* Main Section */}
        <div className="space-y-4 flex-1">
          {/* Header Bar */}
          <div className="flex items-center justify-between flex-wrap gap-2.5 pb-2 border-b border-white/[0.06]">
            <div className="flex items-center gap-2.5 flex-wrap">
              <StatusBadge variant={incident.severity === "critical" || incident.risk_level === "HIGH" ? "critical" : "high"} pulse size="md">
                {incident.risk_level || "HIGH RISK"}
              </StatusBadge>

              <h2 className="text-white font-semibold text-base sm:text-lg tracking-tight flex items-center gap-2">
                <span className="font-mono text-red-400 font-medium">{incident.incident_number || "INCIDENT #0241"}:</span>
                <span className="text-slate-100">{incident.title?.replace(/^INCIDENT #\w+:\s*/, "") || "Coordinated SSH Brute-Force Activity"}</span>
              </h2>
            </div>

            <div className="flex items-center gap-2 text-xs font-mono text-slate-400">
              <span className="px-2 py-0.5 rounded bg-slate-800/80 border border-slate-700/60 text-slate-300 font-normal">
                MITRE: {incident.mitre_technique?.split(" - ")[0] || "T1110.001"}
              </span>
              <span className="flex items-center gap-1 text-slate-400 font-normal">
                <Clock size={12} className="text-slate-500" />
                <span>{displayTime}</span>
              </span>
            </div>
          </div>

          {/* Key Attributes 4-Column Grid */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 sm:gap-3">
            {/* Source IP */}
            <div className="p-3 rounded-lg bg-navy-950/70 border border-red-500/20 flex flex-col justify-between">
              <div className="flex items-center justify-between text-[11px] text-slate-400 mb-1 font-normal">
                <span>Source IP</span>
                <button
                  onClick={handleCopyIp}
                  className="text-slate-500 hover:text-slate-200 transition p-0.5 rounded focus-visible:outline-none"
                  title="Copy IP Address"
                >
                  {copied ? <Check size={12} className="text-emerald-400" /> : <Copy size={12} />}
                </button>
              </div>
              <p className="font-mono font-medium text-red-400 text-sm sm:text-base truncate">
                {incident.source_ip || "185.233.42.17"}
              </p>
              <span className="text-[10px] text-slate-500 font-mono mt-0.5 truncate">
                NL • AS202425 (Active Host)
              </span>
            </div>

            {/* Target Service */}
            <div className="p-3 rounded-lg bg-navy-950/70 border border-white/[0.06] flex flex-col justify-between">
              <span className="text-[11px] text-slate-400 mb-1 font-normal">Target</span>
              <p className="font-mono font-medium text-slate-100 text-sm sm:text-base truncate">
                {incident.target_service || (incident.port ? `Port ${incident.port}` : "SSH (22)")}
              </p>
              <span className="text-[10px] text-slate-500 font-mono mt-0.5 truncate">
                {incident.destination_ip || "127.0.0.1"} • Local Socket
              </span>
            </div>

            {/* Affected Users / Entity */}
            <div className="p-3 rounded-lg bg-navy-950/70 border border-white/[0.06] flex flex-col justify-between">
              <span className="text-[11px] text-slate-400 mb-1 font-normal">Affected Entity</span>
              <p className="font-mono font-medium text-amber-300 text-sm sm:text-base truncate">
                {incident.affected_users || (incident.telemetry?.processName ? `${incident.telemetry.processName}` : "3 accounts")}
              </p>
              <span className="text-[10px] text-slate-500 font-mono mt-0.5 truncate">
                {incident.telemetry?.pid ? `PID ${incident.telemetry.pid}` : "root, admin, deploy"}
              </span>
            </div>

            {/* Confidence / Threat Score */}
            <div className="p-3 rounded-lg bg-navy-950/70 border border-white/[0.06] flex flex-col justify-between">
              <span className="text-[11px] text-slate-400 mb-1 font-normal">ML Confidence</span>
              <p className="font-mono font-medium text-red-400 text-sm sm:text-base truncate">
                {scorePct}
              </p>
              <span className="text-[10px] text-slate-500 font-mono mt-0.5 truncate">
                IsolationForest (Edge ONNX)
              </span>
            </div>
          </div>

          {/* AI Narrative Summary Box */}
          <div className="p-3.5 rounded-lg bg-navy-950/50 border-l-2 border-red-500 border-t border-r border-b border-white/[0.04] text-xs sm:text-sm text-slate-300 leading-relaxed flex items-start gap-3">
            <Sparkles size={16} className="text-purple-400 flex-shrink-0 mt-0.5" />
            <div className="space-y-1">
              <span className="font-semibold text-slate-200 uppercase tracking-wider text-[10px] block font-mono text-purple-300">
                AI Narrative Analysis
              </span>
              <p className="text-slate-300 leading-relaxed">
                {incident.summary || (
                  `Multiple high-frequency security anomalies detected from ${incident.source_ip}. Threat score ${scorePct} exceeded local policy threshold. Autonomous edge containment engaged.`
                )}
              </p>
            </div>
          </div>
        </div>

        {/* Right / Primary Action Buttons */}
        <div className="flex flex-col sm:flex-row xl:flex-col items-stretch justify-center gap-2 xl:w-52 flex-shrink-0 pt-2 xl:pt-0">
          <Button
            variant="cyan"
            size="md"
            className="w-full py-2.5 text-xs font-medium"
            icon={Brain}
            iconPosition="left"
            onClick={() => onInvestigate ? onInvestigate(incident) : null}
            title="Open Explainable AI feature attributions & model reasoning"
          >
            Explain Prediction
          </Button>

          {onInvestigate ? (
            <Button
              variant="critical"
              size="md"
              className="w-full py-2.5 text-xs font-medium"
              icon={ArrowRight}
              iconPosition="right"
              onClick={() => onInvestigate(incident)}
            >
              Investigate Incident
            </Button>
          ) : (
            <Link
              to="/logs"
              id="cta-investigate-incident"
              className="w-full"
            >
              <Button
                variant="critical"
                size="md"
                className="w-full py-2.5 text-xs font-medium"
                icon={ArrowRight}
                iconPosition="right"
              >
                Investigate Incident
              </Button>
            </Link>
          )}
        </div>
      </div>
    </GlassCard>
  );
}
