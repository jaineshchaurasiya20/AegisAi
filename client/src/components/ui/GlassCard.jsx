import React from "react";

/**
 * Enterprise GlassCard component with 3 distinct elevation levels.
 *
 * @param {'l1' | 'l2' | 'critical' | 'base'} elevation - Glassmorphic elevation hierarchy level
 * @param {boolean} hover - Whether to apply subtle hover elevation & border brightening
 * @param {string} className - Additional CSS classes
 */
export default function GlassCard({
  children,
  elevation = "l1",
  hover = false,
  className = "",
  ...props
}) {
  const elevationClasses = {
    base: "bg-navy-900/90 border border-white/[0.06] rounded-xl shadow-subtle",
    l1: "glass-panel-l1",
    l2: "glass-panel-l2",
    critical: "glass-panel-critical animate-critical-glow",
  }[elevation] || "glass-panel-l1";

  const hoverClass = hover ? "cursor-pointer" : "";

  return (
    <div
      className={`${elevationClasses} ${hoverClass} ${className}`}
      {...props}
    >
      {children}
    </div>
  );
}
