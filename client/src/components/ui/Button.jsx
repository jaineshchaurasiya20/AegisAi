import React from "react";

export default function Button({
  children,
  variant = "primary",
  size = "md",
  icon: Icon,
  iconPosition = "left",
  iconClassName = "",
  loading = false,
  disabled = false,
  className = "",
  type = "button",
  ...props
}) {
  const baseClasses =
    "inline-flex items-center justify-center font-medium rounded-lg transition-all duration-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400/50 disabled:opacity-50 disabled:cursor-not-allowed select-none active:scale-[0.98]";

  const variantClasses = {
    primary:
      "bg-cyan-500 hover:bg-cyan-400 text-navy-950 font-semibold shadow-sm shadow-cyan-500/20 hover:shadow-cyan-glow",
    critical:
      "bg-gradient-to-r from-red-600 to-red-500 hover:from-red-500 hover:to-rose-500 text-white font-semibold shadow-lg shadow-red-950/40 border border-red-400/30",
    secondary:
      "bg-navy-800/80 hover:bg-navy-700/80 text-slate-200 hover:text-white border border-white/[0.08] hover:border-white/[0.16] shadow-sm",
    glass:
      "bg-white/[0.04] hover:bg-white/[0.08] text-slate-300 hover:text-white border border-white/[0.08] hover:border-cyan-400/30",
    ghost:
      "text-slate-400 hover:text-white hover:bg-white/[0.06]",
    outline:
      "border border-slate-700 hover:border-cyan-500/50 text-slate-300 hover:text-cyan-300 bg-transparent",
  }[variant] || "bg-cyan-500 text-navy-950";

  const sizeClasses = {
    xs: "px-2 py-1 text-xs gap-1",
    sm: "px-2.5 py-1.5 text-xs gap-1.5",
    md: "px-3.5 py-2 text-xs sm:text-sm gap-2",
    lg: "px-5 py-2.5 text-sm gap-2.5",
  }[size] || "px-3.5 py-2 text-sm gap-2";

  return (
    <button
      type={type}
      disabled={disabled || loading}
      className={`${baseClasses} ${variantClasses} ${sizeClasses} ${className}`}
      {...props}
    >
      {loading ? (
        <span className="w-4 h-4 border-2 border-current border-t-transparent rounded-full animate-spin mr-1" />
      ) : (
        Icon && iconPosition === "left" && (
          <Icon
            size={size === "xs" ? 13 : size === "sm" ? 14 : 16}
            className={`flex-shrink-0 ${iconClassName}`}
          />
        )
      )}
      <span>{children}</span>
      {!loading && Icon && iconPosition === "right" && (
        <Icon
          size={size === "xs" ? 13 : size === "sm" ? 14 : 16}
          className={`flex-shrink-0 ${iconClassName}`}
        />
      )}
    </button>
  );
}
