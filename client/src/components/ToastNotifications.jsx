/**
 * ToastNotifications — Fixed-position toast stack anchored to bottom-right.
 * Consumes the toast queue from EngineContext.
 * Types: "success" | "error" | "warning" | "info"
 */
import React from "react";
import { CheckCircle2, XCircle, AlertTriangle, Info, X } from "lucide-react";
import { useEngine } from "../context/EngineContext";

const TYPE_CFG = {
  success: { Icon: CheckCircle2, color: "#10b981", bg: "rgba(16,185,129,0.12)", border: "rgba(16,185,129,0.3)" },
  error:   { Icon: XCircle,      color: "#ef4444", bg: "rgba(239,68,68,0.12)",  border: "rgba(239,68,68,0.3)"  },
  warning: { Icon: AlertTriangle, color: "#f59e0b", bg: "rgba(245,158,11,0.12)", border: "rgba(245,158,11,0.3)" },
  info:    { Icon: Info,          color: "#06b6d4", bg: "rgba(6,182,212,0.12)",  border: "rgba(6,182,212,0.3)"  },
};

export default function ToastNotifications() {
  const { toasts, dismissToast } = useEngine();

  if (!toasts.length) return null;

  return (
    <div
      className="fixed bottom-5 right-5 z-[200] flex flex-col gap-2.5 pointer-events-none"
      style={{ maxWidth: 400 }}
    >
      {toasts.map((t) => {
        const cfg = TYPE_CFG[t.type] || TYPE_CFG.info;
        const Icon = cfg.Icon;
        return (
          <div
            key={t.id}
            className="pointer-events-auto flex items-start gap-3 rounded-xl px-4 py-3 border shadow-2xl"
            style={{
              background: "#0d1117",
              borderColor: cfg.border,
              boxShadow: `0 4px 32px rgba(0,0,0,0.5), 0 0 0 1px ${cfg.border}`,
              animation: t.exiting
                ? "toast-exit 0.3s ease forwards"
                : "toast-enter 0.3s cubic-bezier(0.22,1,0.36,1) forwards",
            }}
          >
            <Icon size={15} style={{ color: cfg.color, flexShrink: 0, marginTop: 1 }} />
            <p className="text-slate-200 text-sm leading-snug flex-1">{t.msg}</p>
            <button
              onClick={() => dismissToast(t.id)}
              className="text-slate-600 hover:text-slate-300 transition flex-shrink-0 mt-0.5"
            >
              <X size={13} />
            </button>
          </div>
        );
      })}
    </div>
  );
}
