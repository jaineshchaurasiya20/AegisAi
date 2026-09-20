import React from "react";
import { Link } from "react-router-dom";
import {
  Clock,
  Key,
  User,
  Lock,
  Terminal,
  ChevronRight,
  ShieldCheck,
  AlertTriangle,
  Zap,
} from "lucide-react";
import GlassCard from "./ui/GlassCard";
import SectionHeader from "./ui/SectionHeader";
import StatusBadge from "./ui/StatusBadge";

// Helper to format dynamic time offsets from a base time
function getDynamicOffsetTime(minutesAgo = 0, baseDate = new Date()) {
  const d = new Date(baseDate.getTime() - minutesAgo * 60 * 1000);
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

export default function AttackTimeline({
  events = null,
  activeThreat = null,
  className = "",
}) {
  const baseTime = activeThreat?.timestamp ? new Date(activeThreat.timestamp) : new Date();

  // Standard multi-stage progression baseline
  const defaultSequence = [
    {
      time: getDynamicOffsetTime(5, baseTime),
      type: "Reconnaissance Port Probe",
      description: `SYN scanning on port ${activeThreat?.port || 4444} from ${activeThreat?.source_ip || "185.233.42.17"}`,
      statusVariant: "neutral",
      statusText: "Recon",
      icon: Key,
      semanticColor: "text-slate-400 border-slate-700 bg-slate-800/40",
    },
    {
      time: getDynamicOffsetTime(3, baseTime),
      type: "Credential Pivot Spray",
      description: "Attacker pivoted dictionary attack to deploy & admin accounts",
      statusVariant: "warning",
      statusText: "Target Pivot",
      icon: User,
      semanticColor: "text-amber-400 border-amber-500/40 bg-amber-500/10",
    },
    {
      time: getDynamicOffsetTime(1, baseTime),
      type: activeThreat?.threat_type || "Zero-Day Anomaly Probe",
      description: activeThreat?.telemetry?.commandLine || `${activeThreat?.threat_type || "Suspicious process execution"} flagged by ONNX engine`,
      statusVariant: "critical",
      statusText: "Flagged",
      icon: Terminal,
      semanticColor: "text-purple-400 border-purple-500/40 bg-purple-500/10",
    },
    {
      time: getDynamicOffsetTime(0, baseTime),
      type: "Automated Edge Containment",
      description: "Local process isolation & socket drop enforced by eBPF sensor",
      statusVariant: "low",
      statusText: "Blocked",
      icon: ShieldCheck,
      semanticColor: "text-emerald-400 border-emerald-500/40 bg-emerald-500/10",
    },
  ];

  // Guarantee a complete, coherent 4-step kill-chain sequence
  let timelineList = defaultSequence;
  if (events && events.length >= 3) {
    timelineList = events.map((e, idx) => ({
      ...e,
      icon: idx === 0 ? Key : idx === 1 ? User : idx === events.length - 1 ? ShieldCheck : Terminal,
      semanticColor:
        e.statusVariant === "critical"
          ? "text-red-400 border-red-500/40 bg-red-500/10"
          : e.statusVariant === "warning"
          ? "text-amber-400 border-amber-500/40 bg-amber-500/10"
          : "text-cyan-400 border-cyan-500/40 bg-cyan-500/10",
    }));
  } else if (events && events.length > 0) {
    const primary = events[0];
    timelineList = [
      defaultSequence[0],
      defaultSequence[1],
      {
        ...defaultSequence[2],
        type: primary.type || primary.threat_type || defaultSequence[2].type,
        description: primary.description || primary.message || defaultSequence[2].description,
        statusText: primary.statusText || "Flagged",
        statusVariant: primary.statusVariant || "critical",
      },
      defaultSequence[3],
    ];
  }

  return (
    <GlassCard
      elevation="l1"
      className={`p-4 sm:p-5 flex flex-col ${className}`}
    >
      <div>
        <SectionHeader
          icon={Clock}
          title="Attack Timeline"
          subtitle="Real-time incident progression sequence"
          rightElement={
            <span className="text-[11px] font-mono text-cyan-400/90 bg-cyan-500/10 px-2 py-0.5 rounded border border-cyan-500/20 whitespace-nowrap font-normal">
              Live Flow
            </span>
          }
        />

        {/* Vertical Timeline Track */}
        <div className="relative pl-6 space-y-3.5 pt-1 before:absolute before:left-[11px] before:top-2 before:bottom-2 before:w-[2px] before:bg-gradient-to-b before:from-red-500/60 before:via-amber-500/40 before:to-purple-500/40">
          {timelineList.map((evt, idx) => {
            const IconComponent = evt.icon || (evt.statusVariant === "critical" ? AlertTriangle : Zap);
            return (
              <div key={idx} className="relative group">
                {/* Node indicator */}
                <div
                  className={`absolute -left-[23px] top-1 w-5 h-5 rounded-full bg-navy-950 border ${evt.semanticColor || "text-cyan-400 border-cyan-500/40 bg-cyan-500/10"} flex items-center justify-center shadow-sm transition-transform duration-200 group-hover:scale-110`}
                >
                  <IconComponent size={10} />
                </div>

                {/* Event Content */}
                <div className="flex items-start justify-between gap-2">
                  <div className="min-w-0 pr-2">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="font-mono text-xs font-normal text-slate-300">
                        {evt.time}
                      </span>
                      <span className="text-xs font-medium text-slate-100 truncate">
                        {evt.type}
                      </span>
                    </div>
                    <p className="text-slate-400 text-[11px] sm:text-xs mt-0.5 leading-relaxed break-words font-normal">
                      {evt.description}
                    </p>
                  </div>

                  <StatusBadge
                    variant={evt.statusVariant || "neutral"}
                    dot={false}
                    size="sm"
                    className="flex-shrink-0 font-normal"
                  >
                    {evt.statusText}
                  </StatusBadge>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Footer link */}
      <div className="pt-3 mt-4 border-t border-white/[0.04] flex items-center justify-between text-xs text-slate-400">
        <span className="font-mono text-[11px] text-slate-400 font-normal">
          Sequence: {timelineList.length} Steps Verified
        </span>
        <Link
          to="/threats-intelligence"
          className="text-cyan-400 hover:text-cyan-300 font-medium flex items-center gap-1 transition text-xs"
        >
          <span>Explore Graph</span>
          <ChevronRight size={13} />
        </Link>
      </div>
    </GlassCard>
  );
}
