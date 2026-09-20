import React, { useState } from "react";
import { Link } from "react-router-dom";
import {
  Globe,
  ChevronRight,
  Copy,
  Check,
} from "lucide-react";
import GlassCard from "./ui/GlassCard";
import SectionHeader from "./ui/SectionHeader";
import StatusBadge from "./ui/StatusBadge";

export default function SuspiciousIpTable({
  ips = null,
  onSelectIp = null,
  className = "",
}) {
  const [copiedIp, setCopiedIp] = useState(null);

  const handleCopy = (e, ip) => {
    e.stopPropagation();
    navigator.clipboard?.writeText(ip);
    setCopiedIp(ip);
    setTimeout(() => setCopiedIp(null), 1800);
  };

  const ipList = ips && ips.length > 0 ? ips : [
    {
      ip: "185.233.42.17",
      geo: "Netherlands",
      flag: "🇳🇱",
      requests: 47,
      threatLevel: "critical",
      threatText: "CRITICAL",
      status: "Active Threat",
      statusVariant: "critical",
      highlight: true,
    },
    {
      ip: "45.142.214.88",
      geo: "Russia",
      flag: "🇷🇺",
      requests: 24,
      threatLevel: "high",
      threatText: "HIGH",
      status: "Blocked",
      statusVariant: "warning",
      highlight: false,
    },
    {
      ip: "194.26.29.112",
      geo: "Romania",
      flag: "🇷🇴",
      requests: 18,
      threatLevel: "medium",
      threatText: "MEDIUM",
      status: "Flagged",
      statusVariant: "medium",
      highlight: false,
    },
    {
      ip: "91.240.118.50",
      geo: "Bulgaria",
      flag: "🇧🇬",
      requests: 9,
      threatLevel: "medium",
      threatText: "MEDIUM",
      status: "Rate-Limited",
      statusVariant: "neutral",
      highlight: false,
    },
    {
      ip: "103.145.13.4",
      geo: "Vietnam",
      flag: "🇻🇳",
      requests: 5,
      threatLevel: "low",
      threatText: "LOW",
      status: "Monitored",
      statusVariant: "neutral",
      highlight: false,
    },
  ];

  return (
    <GlassCard
      elevation="l1"
      className={`p-4 sm:p-5 flex flex-col ${className}`}
    >
      <div>
        <SectionHeader
          icon={Globe}
          title="Suspicious Source IPs"
          subtitle="Correlated threat actors & IPs"
          rightElement={
            <span className="text-[11px] font-mono text-slate-400 bg-navy-950 px-2 py-0.5 rounded border border-white/[0.06] whitespace-nowrap font-normal">
              {ipList.length} Tracked
            </span>
          }
        />

        {/* Compact Enterprise Data Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-white/[0.04] text-[10px] uppercase font-mono text-slate-400 tracking-wider">
                <th className="pb-2 font-medium">IP Address</th>
                <th className="pb-2 font-medium hidden sm:table-cell">Location</th>
                <th className="pb-2 font-medium text-right pr-2">Requests</th>
                <th className="pb-2 font-medium text-center">Threat</th>
                <th className="pb-2 font-medium text-right">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/[0.03]">
              {ipList.slice(0, 5).map((row, idx) => (
                <tr
                  key={row.ip || idx}
                  onClick={() => onSelectIp && onSelectIp(row.ip)}
                  className={`group transition-colors duration-150 hover:bg-white/[0.03] ${
                    row.highlight ? "bg-red-500/[0.03]" : ""
                  } ${onSelectIp ? "cursor-pointer" : ""}`}
                >
                  {/* IP Address */}
                  <td className="py-2.5 pr-2">
                    <div className="flex items-center gap-1.5">
                      <span className="font-mono text-xs font-medium text-slate-200 group-hover:text-cyan-300 transition">
                        {row.ip}
                      </span>
                      <button
                        onClick={(e) => handleCopy(e, row.ip)}
                        className="opacity-0 group-hover:opacity-100 text-slate-500 hover:text-slate-300 transition p-0.5 rounded focus-visible:opacity-100"
                        title="Copy IP"
                      >
                        {copiedIp === row.ip ? (
                          <Check size={11} className="text-emerald-400" />
                        ) : (
                          <Copy size={11} />
                        )}
                      </button>
                    </div>
                  </td>

                  {/* Location */}
                  <td className="py-2.5 text-xs text-slate-400 hidden sm:table-cell font-normal">
                    <span className="mr-1.5">{row.flag || "🌐"}</span>
                    <span>{row.geo || "External"}</span>
                  </td>

                  {/* Requests / Events count */}
                  <td className="py-2.5 text-right font-mono text-xs font-normal text-slate-300 pr-2">
                    {row.requests || 1}
                  </td>

                  {/* Threat level badge */}
                  <td className="py-2.5 text-center">
                    <StatusBadge
                      variant={row.threatLevel || "medium"}
                      dot={row.highlight}
                      pulse={row.highlight}
                      size="sm"
                    >
                      {row.threatText || (row.threatLevel ? row.threatLevel.toUpperCase() : "MEDIUM")}
                    </StatusBadge>
                  </td>

                  {/* Action / Status */}
                  <td className="py-2.5 text-right">
                    <span className="text-[11px] font-mono text-slate-400">
                      {row.status || "Monitored"}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Footer */}
      <div className="pt-3 mt-4 border-t border-white/[0.04] flex items-center justify-between text-xs text-slate-400">
        <span className="font-mono text-[11px] text-slate-400">
          Intel Sync: Real-Time
        </span>
        <Link
          to="/logs"
          className="text-cyan-400 hover:text-cyan-300 font-medium flex items-center gap-1 transition text-xs"
        >
          <span>View IP Intelligence</span>
          <ChevronRight size={13} />
        </Link>
      </div>
    </GlassCard>
  );
}
