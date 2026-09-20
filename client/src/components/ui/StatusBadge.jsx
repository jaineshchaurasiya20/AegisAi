import React from "react";

/**
 * Enterprise Status and Severity Badge with semantic colors and subtle glowing dots.
 *
 * @param {'critical' | 'high' | 'medium' | 'low' | 'cyan' | 'neutral' | 'success' | 'warning'} variant
 * @param {boolean} dot - Render a small status dot
 * @param {boolean} pulse - Animate dot pulse
 * @param {'sm' | 'md'} size
 */
export default function StatusBadge({
  children,
  variant = "neutral",
  dot = true,
  pulse = false,
  size = "sm",
  className = "",
}) {
  const variantStyles = {
    critical: {
      wrap: "bg-red-500/10 text-red-400 border-red-500/30",
      dot: "bg-red-400",
    },
    high: {
      wrap: "bg-amber-500/10 text-amber-400 border-amber-500/30",
      dot: "bg-amber-400",
    },
    medium: {
      wrap: "bg-blue-500/10 text-blue-400 border-blue-500/30",
      dot: "bg-blue-400",
    },
    low: {
      wrap: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30",
      dot: "bg-emerald-400",
    },
    success: {
      wrap: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30",
      dot: "bg-emerald-400",
    },
    warning: {
      wrap: "bg-amber-500/10 text-amber-400 border-amber-500/30",
      dot: "bg-amber-400",
    },
    cyan: {
      wrap: "bg-cyan-500/10 text-cyan-300 border-cyan-500/30",
      dot: "bg-cyan-400",
    },
    neutral: {
      wrap: "bg-slate-800/80 text-slate-300 border-slate-700/70",
      dot: "bg-slate-400",
    },
  }[variant] || {
    wrap: "bg-slate-800/80 text-slate-300 border-slate-700/70",
    dot: "bg-slate-400",
  };

  const sizeClasses = {
    sm: "px-2 py-0.5 text-[11px]",
    md: "px-2.5 py-1 text-xs",
  }[size] || "px-2 py-0.5 text-[11px]";

  return (
    <span
      className={`inline-flex items-center gap-1.5 font-mono font-medium rounded-md border tracking-wide select-none ${variantStyles.wrap} ${sizeClasses} ${className}`}
    >
      {dot && (
        <span
          className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${variantStyles.dot} ${
            pulse ? "animate-subtle-pulse" : ""
          }`}
        />
      )}
      <span>{children}</span>
    </span>
  );
}
