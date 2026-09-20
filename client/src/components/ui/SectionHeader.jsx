import React from "react";

export default function SectionHeader({
  icon: Icon,
  title,
  subtitle,
  rightElement,
  className = "",
}) {
  return (
    <div
      className={`flex items-center justify-between pb-3 mb-3 border-b border-white/[0.06] ${className}`}
    >
      <div className="flex items-center gap-2.5 min-w-0">
        {Icon && (
          <div className="w-7 h-7 rounded-lg bg-navy-800/80 border border-white/[0.08] flex items-center justify-center flex-shrink-0 text-cyan-400">
            <Icon size={14} />
          </div>
        )}
        <div className="min-w-0">
          <h3 className="text-white font-semibold text-xs sm:text-sm tracking-wide flex items-center gap-2 truncate">
            {title}
          </h3>
          {subtitle && (
            <p className="text-slate-400 text-[11px] font-normal truncate mt-0.5">
              {subtitle}
            </p>
          )}
        </div>
      </div>
      {rightElement && (
        <div className="flex items-center gap-2 flex-shrink-0">
          {rightElement}
        </div>
      )}
    </div>
  );
}
