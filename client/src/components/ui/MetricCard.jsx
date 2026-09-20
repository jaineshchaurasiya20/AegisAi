import React from "react";
import CountUp from "../CountUp";
import GlassCard from "./GlassCard";

export default function MetricCard({
  icon: Icon,
  label,
  value,
  decimals = 0,
  suffix = "",
  prefix = "",
  trend,
  trendIcon: TrendIcon,
  trendPositive = true,
  statusText,
  accentColor = "cyan",
  elevation = "l1",
  className = "",
}) {
  const colorMap = {
    cyan: {
      iconBg: "bg-cyan-500/10 border-cyan-500/20 text-cyan-400",
      accentBar: "bg-cyan-500",
      metricColor: "text-white",
    },
    red: {
      iconBg: "bg-red-500/10 border-red-500/20 text-red-400",
      accentBar: "bg-red-500",
      metricColor: "text-red-400",
    },
    emerald: {
      iconBg: "bg-emerald-500/10 border-emerald-500/20 text-emerald-400",
      accentBar: "bg-emerald-500",
      metricColor: "text-emerald-400",
    },
    blue: {
      iconBg: "bg-blue-500/10 border-blue-500/20 text-blue-400",
      accentBar: "bg-blue-500",
      metricColor: "text-blue-300",
    },
    purple: {
      iconBg: "bg-purple-500/10 border-purple-500/20 text-purple-400",
      accentBar: "bg-purple-500",
      metricColor: "text-purple-300",
    },
  }[accentColor] || {
    iconBg: "bg-cyan-500/10 border-cyan-500/20 text-cyan-400",
    accentBar: "bg-cyan-500",
    metricColor: "text-white",
  };

  return (
    <GlassCard
      elevation={elevation}
      className={`p-4 sm:p-5 flex flex-col justify-between relative overflow-hidden h-full ${className}`}
    >
      {/* Subtle top accent edge */}
      <div
        className={`absolute top-0 left-0 right-0 h-[2px] opacity-60 ${colorMap.accentBar}`}
      />

      {/* Header Row: Label & Icon */}
      <div className="flex items-center justify-between gap-2">
        <span className="text-slate-400 text-[11px] sm:text-xs font-medium uppercase tracking-wider">
          {label}
        </span>
        {Icon && (
          <div
            className={`w-8 h-8 rounded-lg border flex items-center justify-center flex-shrink-0 ${colorMap.iconBg}`}
          >
            <Icon size={16} />
          </div>
        )}
      </div>

      {/* Main Metric Value */}
      <div className="my-2.5">
        <p className={`font-mono font-semibold text-2xl sm:text-3xl tracking-tight leading-none ${colorMap.metricColor}`}>
          {typeof value === "number" ? (
            <CountUp
              end={value}
              decimals={decimals}
              suffix={suffix}
              prefix={prefix}
              duration={1200}
            />
          ) : (
            <span>{value}</span>
          )}
        </p>
      </div>

      {/* Footer: Trend / Contextual Explanation */}
      <div className="flex items-center gap-1.5 text-[11px] sm:text-xs text-slate-400 pt-1 border-t border-white/[0.04]">
        {TrendIcon && (
          <TrendIcon
            size={13}
            className={
              accentColor === "red"
                ? "text-red-400"
                : trendPositive
                ? "text-emerald-400"
                : "text-amber-400"
            }
          />
        )}
        <span className="truncate">{trend || statusText}</span>
      </div>
    </GlassCard>
  );
}
