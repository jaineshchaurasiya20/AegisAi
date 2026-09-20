import React, { useState } from "react";
import {
  TrendingUp,
  TrendingDown,
  ShieldCheck,
  AlertTriangle,
  Info,
  Code,
  Sparkles,
} from "lucide-react";

/* Friendly Zero-Jargon translation dictionary */
const HUMAN_FEATURE_MAP = {
  destination_port_entropy: {
    title: "Destination Port Randomness",
    impactLabel: "Risk Weight",
    desc: "Adversary is cycling through randomized destination ports characteristic of active reconnaissance.",
  },
  high_port_entropy: {
    title: "Destination Port Randomness",
    impactLabel: "Risk Weight",
    desc: "Adversary is cycling through randomized destination ports characteristic of active reconnaissance.",
  },
  process_cpu_anomaly: {
    title: "Unusual CPU Compute Burst",
    impactLabel: "Risk Weight",
    desc: "Process compute consumption exhibits an anomalous spike far exceeding normal baseline.",
  },
  cpu_usage_pct: {
    title: "Unusual CPU Compute Burst",
    impactLabel: "Risk Weight",
    desc: "Process compute consumption exhibits an anomalous spike far exceeding normal baseline.",
  },
  payload_shannon_entropy: {
    title: "Encrypted / Packed Payload Detected",
    impactLabel: "Risk Weight",
    desc: "Payload byte distribution indicates obfuscated shellcode or an encrypted C2 beacon.",
  },
  payload_entropy: {
    title: "Encrypted / Packed Payload Detected",
    impactLabel: "Risk Weight",
    desc: "Payload byte distribution indicates obfuscated shellcode or an encrypted C2 beacon.",
  },
  outbound_bytes_ratio: {
    title: "Abnormal Outbound Data Spike",
    impactLabel: "Risk Weight",
    desc: "Unusual burst of outbound traffic indicating potential exfiltration activity.",
  },
  connection_duration_ms: {
    title: "Rapid Connection Lifetimes",
    impactLabel: "Risk Weight",
    desc: "Short-lived connection bursts consistent with automated brute-force attempts.",
  },
  is_known_system_process: {
    title: "Verified OS System Binary",
    impactLabel: "Safety Factor",
    desc: "Binary matches cryptographically signed OS executables from trusted roots.",
  },
  process_signed: {
    title: "Cryptographically Verified Signature",
    impactLabel: "Safety Factor",
    desc: "Authenticode signature verified against local OS trust anchors.",
  },
  known_good_subnet: {
    title: "Approved Internal Subnet",
    impactLabel: "Safety Factor",
    desc: "Originates from a pre-whitelisted internal network range.",
  },
  parent_process_anomaly: {
    title: "Valid Parent-Child Process Tree",
    impactLabel: "Safety Factor",
    desc: "Process hierarchy matches expected operational initialization tree.",
  },
};

function humanize(key) {
  if (!key) return { title: "Heuristic Anomaly", desc: "Edge ML feature correlation factor." };
  const normalized = String(key).toLowerCase().trim().replace(/[\s-]+/g, "_");
  if (HUMAN_FEATURE_MAP[normalized]) return HUMAN_FEATURE_MAP[normalized];

  // Clean fallback title
  const cleanTitle = normalized
    .split("_")
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(" ");

  return {
    title: cleanTitle,
    desc: `Feature attribution calculated by local edge ONNX inference model.`,
  };
}

export default function XAIBarChart({ features = [] }) {
  const [showTechnicalKeys, setShowTechnicalKeys] = useState(false);

  // Normalize and sort items by absolute impact
  const items = features
    .slice()
    .sort((a, b) => Math.abs(b.impact ?? 0) - Math.abs(a.impact ?? 0))
    .map((f) => {
      const raw = f.feature || "feature";
      const info = humanize(raw);
      const rawVal = f.impact ?? 0;
      // Convert raw floating point into human readable percentage (e.g. +0.3953 -> +40%)
      const pctValue = Math.round(Math.abs(rawVal) * 100);
      const isRisk = rawVal >= 0;

      return {
        rawKey: raw,
        title: info.title,
        desc: f.description || info.desc,
        isRisk,
        pctDisplay: `${isRisk ? "+" : "-"}${Math.max(pctValue, 5)}%`,
        barWidth: Math.min(Math.max(pctValue * 1.5, 12), 100),
      };
    });

  const riskFactors = items.filter((d) => d.isRisk);
  const safetyFactors = items.filter((d) => !d.isRisk);

  return (
    <div className="space-y-4 font-sans select-none">
      {/* Zero-Jargon Header */}
      <div className="flex items-center justify-between pb-2 border-b border-white/[0.06]">
        <div className="flex items-center gap-2">
          <Sparkles size={16} className="text-purple-400" />
          <div>
            <h4 className="text-white text-xs sm:text-sm font-bold">
              AI Decision Attribution & Explainability
            </h4>
            <p className="text-slate-400 text-[11px]">
              Why the local ML engine flagged this event (Zero-Jargon Analysis)
            </p>
          </div>
        </div>

        {/* Toggle for Raw Technical Keys */}
        <button
          onClick={() => setShowTechnicalKeys(!showTechnicalKeys)}
          className="flex items-center gap-1.5 px-2 py-1 rounded bg-navy-950/70 border border-white/[0.08] text-[10px] font-mono text-slate-400 hover:text-slate-200 transition"
          title="Toggle raw SHAP feature variable names"
        >
          <Code size={11} />
          <span>{showTechnicalKeys ? "Hide Raw Keys" : "Show Raw Keys"}</span>
        </button>
      </div>

      {/* Primary Risk Drivers */}
      {riskFactors.length > 0 && (
        <div className="space-y-2">
          <div className="flex items-center justify-between text-xs font-semibold text-red-400 uppercase tracking-wider">
            <span className="flex items-center gap-1.5">
              <AlertTriangle size={13} />
              <span>Key Risk Multipliers (+Impact)</span>
            </span>
            <span className="text-[10px] font-mono text-slate-500">Relative Weight</span>
          </div>

          <div className="space-y-2">
            {riskFactors.map((item, idx) => (
              <div
                key={idx}
                className="p-3 rounded-xl bg-navy-950/70 border border-red-500/20 hover:border-red-500/40 transition"
              >
                <div className="flex items-center justify-between gap-2 mb-1.5">
                  <div className="min-w-0">
                    <span className="text-xs font-semibold text-white truncate block">
                      {item.title}
                    </span>
                    {showTechnicalKeys && (
                      <span className="text-[10px] font-mono text-slate-500 block">
                        {item.rawKey}
                      </span>
                    )}
                  </div>
                  <span className="font-mono text-xs font-bold text-red-400 flex-shrink-0">
                    {item.pctDisplay} Risk Weight
                  </span>
                </div>

                {/* Progress Bar */}
                <div className="h-1.5 w-full bg-navy-900 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-gradient-to-r from-amber-500 to-red-500 rounded-full transition-all duration-500"
                    style={{ width: `${item.barWidth}%` }}
                  />
                </div>

                <p className="text-slate-400 text-[11px] mt-1.5 leading-snug">
                  {item.desc}
                </p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Safety / Mitigating Indicators */}
      {safetyFactors.length > 0 && (
        <div className="space-y-2 pt-1">
          <div className="flex items-center justify-between text-xs font-semibold text-emerald-400 uppercase tracking-wider">
            <span className="flex items-center gap-1.5">
              <ShieldCheck size={13} />
              <span>Mitigating Factors (-Impact)</span>
            </span>
            <span className="text-[10px] font-mono text-slate-500">Risk Reduction</span>
          </div>

          <div className="space-y-2">
            {safetyFactors.map((item, idx) => (
              <div
                key={idx}
                className="p-3 rounded-xl bg-navy-950/70 border border-emerald-500/20 hover:border-emerald-500/40 transition"
              >
                <div className="flex items-center justify-between gap-2 mb-1.5">
                  <div className="min-w-0">
                    <span className="text-xs font-semibold text-white truncate block">
                      {item.title}
                    </span>
                    {showTechnicalKeys && (
                      <span className="text-[10px] font-mono text-slate-500 block">
                        {item.rawKey}
                      </span>
                    )}
                  </div>
                  <span className="font-mono text-xs font-bold text-emerald-400 flex-shrink-0">
                    {item.pctDisplay} Risk Reduction
                  </span>
                </div>

                {/* Progress Bar */}
                <div className="h-1.5 w-full bg-navy-900 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-gradient-to-r from-teal-500 to-emerald-500 rounded-full transition-all duration-500"
                    style={{ width: `${item.barWidth}%` }}
                  />
                </div>

                <p className="text-slate-400 text-[11px] mt-1.5 leading-snug">
                  {item.desc}
                </p>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
