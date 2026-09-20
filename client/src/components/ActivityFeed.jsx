import React from "react";
import { Link } from "react-router-dom";
import { Radio, ChevronRight, Terminal, Shield } from "lucide-react";
import GlassCard from "./ui/GlassCard";
import SectionHeader from "./ui/SectionHeader";
import StatusBadge from "./ui/StatusBadge";

const DEFAULT_FEED = [
  {
    id: "act-1",
    time: "10:45:32",
    source: "ebpf_sensor",
    type: "CRITICAL",
    message: "deploy : TTY=pts/2 ; USER=root ; COMMAND=/bin/bash",
    summary: "Privilege escalation attempt intercepted",
    severityVariant: "critical",
  },
  {
    id: "act-2",
    time: "10:45:18",
    source: "ssh_sensor",
    type: "HIGH",
    message: "Accepted password for deploy from 185.233.42.17 port 51922",
    summary: "Successful authentication on compromised account",
    severityVariant: "high",
  },
  {
    id: "act-3",
    time: "10:44:02",
    source: "aegis_engine",
    type: "HIGH",
    message: "Anomaly confidence 94.2% (IsolationForest edge inference)",
    summary: "ML threat threshold exceeded",
    severityVariant: "high",
  },
  {
    id: "act-4",
    time: "10:43:55",
    source: "ssh_sensor",
    type: "MEDIUM",
    message: "Failed password for invalid user admin from 185.233.42.17",
    summary: "Target user spray detected",
    severityVariant: "medium",
  },
  {
    id: "act-5",
    time: "10:41:12",
    source: "ssh_sensor",
    type: "MEDIUM",
    message: "Failed password for root from 185.233.42.17 port 51630",
    summary: "Initial brute-force attempt",
    severityVariant: "medium",
  },
  {
    id: "act-6",
    time: "10:40:02",
    source: "waf_filter",
    type: "INFO",
    message: "Rate limiting rule enforced on subnet 185.233.42.0/24",
    summary: "Edge containment rule active",
    severityVariant: "low",
  },
];

export default function ActivityFeed({
  events = DEFAULT_FEED,
  className = "",
}) {
  return (
    <GlassCard
      elevation="l1"
      className={`p-4 sm:p-5 flex flex-col ${className}`}
    >
      <div>
        <SectionHeader
          icon={Radio}
          title="Live Activity Feed"
          subtitle="Real-time host & network telemetry stream"
          rightElement={
            <StatusBadge variant="low" pulse size="sm">
              LIVE
            </StatusBadge>
          }
        />

        {/* Real-time Stream List */}
        <div className="space-y-2 max-h-[300px] overflow-y-auto pr-1">
          {events.map((item) => (
            <div
              key={item.id}
              className="p-2.5 rounded-lg bg-navy-950/60 border border-white/[0.04] hover:border-white/[0.08] transition-colors duration-150 space-y-1"
            >
              <div className="flex items-center justify-between text-[11px] gap-2">
                <div className="flex items-center gap-2 min-w-0">
                  <span className="font-mono font-medium text-cyan-400">
                    {item.time}
                  </span>
                  <span className="font-mono text-slate-400 text-[10px] truncate">
                    [{item.source}]
                  </span>
                </div>
                <StatusBadge
                  variant={item.severityVariant || "neutral"}
                  dot={false}
                  size="sm"
                  className="flex-shrink-0"
                >
                  {item.type}
                </StatusBadge>
              </div>

              {/* Monospace message snippet */}
              <p className="font-mono text-[11px] text-slate-300 leading-tight truncate">
                {item.message}
              </p>

              {/* Contextual Highlight */}
              <p className="text-[10px] text-slate-400 flex items-center gap-1">
                <span className="text-cyan-400">⚡</span>
                <span className="truncate">{item.summary}</span>
              </p>
            </div>
          ))}
        </div>
      </div>

      {/* Footer link */}
      <div className="pt-3 mt-4 border-t border-white/[0.04] flex items-center justify-between text-xs text-slate-400">
        <span className="font-mono text-[11px] text-slate-400">
          Sensor: eBPF + Syslog
        </span>
        <Link
          to="/logs"
          className="text-cyan-400 hover:text-cyan-300 font-medium flex items-center gap-1 transition text-xs"
        >
          <span>Full Event Logs</span>
          <ChevronRight size={13} />
        </Link>
      </div>
    </GlassCard>
  );
}
