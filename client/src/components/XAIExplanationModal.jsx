import React from "react";
import { createPortal } from "react-dom";
import { X, AlertTriangle, TrendingUp, TrendingDown, Info } from "lucide-react";
import XAIBarChart from "./XAIBarChart";

function SeverityColor(sev) {
  return { critical: "#ef4444", high: "#f59e0b", medium: "#3b82f6", low: "#10b981" }[sev] || "#9ca3af";
}

export default function XAIExplanationModal({ threat, onClose }) {
  if (!threat) return null;
  const color = SeverityColor(threat.severity);
  const features = threat.top_features || [];
  const chartData = features.map((f) => ({
    name: f.feature.replace(/_/g, " "),
    value: Math.abs(f.shap_value || f.abs_value || 0),
    direction: f.direction || (f.shap_value > 0 ? "increases_risk" : "decreases_risk"),
  }));

  return createPortal(
    <div
      id="xai-modal-overlay"
      className="fixed inset-0 z-[100] flex items-center justify-center p-4"
      style={{ background: "rgba(0,0,0,0.7)", backdropFilter: "blur(6px)" }}
      onClick={(e) => e.target.id === "xai-modal-overlay" && onClose()}
    >
      <div
        id="xai-modal"
        className="card w-full max-w-xl max-h-[90vh] overflow-y-auto animate-slide-in"
        style={{ borderColor: `${color}30` }}
      >
        {/* Header */}
        <div className="flex items-center justify-between p-5 border-b border-slate-800">
          <div className="flex items-center gap-3">
            <div
              className="w-9 h-9 rounded-lg flex items-center justify-center"
              style={{ background: `${color}18`, border: `1px solid ${color}30` }}
            >
              <AlertTriangle size={16} style={{ color }} />
            </div>
            <div>
              <h2 className="text-white font-semibold text-base">{threat.threat_type}</h2>
              <p className="text-slate-400 text-xs">Decision Risk Attribution (TreeSHAP)</p>
            </div>
          </div>
          <button
            id="xai-close-btn"
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-700 transition"
          >
            <X size={16} />
          </button>
        </div>

        {/* Score summary */}
        <div className="p-5 grid grid-cols-3 gap-3 border-b border-slate-800">
          {[
            { label: "Threat Score", value: `${(threat.threat_score * 100).toFixed(1)}%`, color },
            { label: "Source IP", value: threat.source_ip, mono: true },
            { label: "Port", value: `:${threat.port}`, mono: true },
          ].map(({ label, value, mono }) => (
            <div key={label} className="bg-slate-900/60 rounded-lg p-3">
              <p className="text-slate-500 text-[10px] mb-1">{label}</p>
              <p className={`text-white font-semibold text-sm ${mono ? "font-mono" : ""}`}>{value}</p>
            </div>
          ))}
        </div>

        {/* XAI Attribution Chart */}
        <div className="p-5">
          <XAIBarChart features={threat.top_features || features} />
        </div>

        {/* Action taken */}
        <div className="px-5 pb-5">
          <div className="bg-slate-900/60 rounded-lg p-3 border border-slate-800 flex items-center justify-between">
            <div>
              <p className="text-slate-500 text-[10px] mb-0.5">CONTAINMENT STATE</p>
              <p className="text-white text-sm font-medium capitalize">{threat.action_taken?.replace(/_/g, " ")}</p>
            </div>
            <span className="text-[10px] mono px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
              ID: {threat.id?.slice(0, 8)}
            </span>
          </div>
        </div>
      </div>
    </div>,
    document.body
  );
}
