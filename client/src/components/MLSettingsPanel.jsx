/**
 * MLSettingsPanel — Interactive Threshold & Hyperparameter Control Panel.
 *
 * Configurable parameters:
 *  - Threat Score Alert Threshold (50% – 95%)
 *  - Isolation Forest Contamination Rate (0.01 – 0.20)
 *  - Entropy Threshold for obfuscation detection (4.0 – 8.0)
 *  - Inference Sampling Rate (100ms, 250ms, 500ms, 1000ms)
 *
 * Actions:
 *  - Apply & Hot-Reload (POST /api/model/config)
 *  - Reset to Defaults
 *  - SOC Tooltips explaining ML terms to analysts
 */
import React, { useState, useEffect, useCallback } from "react";
import {
  Sliders, Zap, RotateCcw, Save, HelpCircle,
  AlertTriangle, CheckCircle2, Shield, Activity,
  Layers, Lock, Sparkles,
} from "lucide-react";
import { api } from "../services/api";
import { useEngine } from "../context/EngineContext";

const FACTORY_DEFAULTS = {
  alertThreshold: 0.75,       // 75%
  contaminationRate: 0.05,    // 5%
  entropyThreshold: 6.8,      // 6.8 bits
  samplingRateMs: 250,        // 250ms
};

const SAMPLING_OPTIONS = [
  { val: 100, label: "100 ms", sub: "Ultra-Low Latency", icon: "⚡" },
  { val: 250, label: "250 ms", sub: "Balanced (Recommended)", icon: "⚖️" },
  { val: 500, label: "500 ms", sub: "Conservative", icon: "🛡️" },
  { val: 1000, label: "1.0 s", sub: "Power-Saving", icon: "🔋" },
];

function ParamTooltip({ title, description, formula }) {
  const [show, setShow] = useState(false);

  return (
    <div className="relative inline-block ml-1.5">
      <button
        type="button"
        onMouseEnter={() => setShow(true)}
        onMouseLeave={() => setShow(false)}
        onClick={(e) => { e.preventDefault(); setShow((s) => !s); }}
        className="text-slate-500 hover:text-cyan-400 transition"
      >
        <HelpCircle size={13} />
      </button>

      {show && (
        <div
          className="absolute left-0 top-full mt-2 w-64 p-3 rounded-xl bg-slate-900 border border-cyan-500/40 shadow-2xl z-50 animate-fade-in text-xs"
          style={{ backdropFilter: "blur(12px)" }}
        >
          <p className="text-cyan-300 font-bold mb-1">{title}</p>
          <p className="text-slate-300 text-[11px] leading-relaxed mb-1.5">{description}</p>
          {formula && (
            <p className="mono text-[10px] text-slate-400 bg-slate-950/80 px-2 py-1 rounded border border-slate-800">
              {formula}
            </p>
          )}
        </div>
      )}
    </div>
  );
}

export default function MLSettingsPanel({ onConfigUpdated }) {
  const { addToast } = useEngine();
  const [config, setConfig] = useState(FACTORY_DEFAULTS);
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [savedSuccess, setSavedSuccess] = useState(false);

  // Load existing config on mount
  const loadConfig = useCallback(async () => {
    setLoading(true);
    try {
      const data = await api.getModelConfig();
      if (data && typeof data === "object") {
        setConfig({
          alertThreshold: data.alertThreshold ?? FACTORY_DEFAULTS.alertThreshold,
          contaminationRate: data.contaminationRate ?? FACTORY_DEFAULTS.contaminationRate,
          entropyThreshold: data.entropyThreshold ?? FACTORY_DEFAULTS.entropyThreshold,
          samplingRateMs: data.samplingRateMs ?? FACTORY_DEFAULTS.samplingRateMs,
        });
      }
    } catch (e) {
      console.warn("Failed to load ML model config:", e);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadConfig();
  }, [loadConfig]);

  const handleApply = async () => {
    setSaving(true);
    try {
      const res = await api.saveModelConfig(config);
      setSavedSuccess(true);
      addToast(
        `⚡ ONNX Engine re-configured with Contamination Rate: ${config.contaminationRate}`,
        "success",
        6000
      );
      onConfigUpdated?.(config);
      setTimeout(() => setSavedSuccess(false), 2500);
    } catch (err) {
      addToast(`Failed to hot-reload ML configuration: ${err.message}`, "error");
    } finally {
      setSaving(false);
    }
  };

  const handleReset = () => {
    setConfig(FACTORY_DEFAULTS);
    addToast("Restored factory default ML thresholds.", "info", 4000);
  };

  const alertThresholdPct = Math.round(config.alertThreshold * 100);

  return (
    <div className="space-y-6 animate-fade-in">
      {/* ── Section Header ──────────────────────────────────────────── */}
      <div className="card p-5">
        <div className="flex items-start justify-between gap-4 flex-wrap">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-cyan-500/15 border border-cyan-500/30 flex items-center justify-center flex-shrink-0">
              <Sliders size={20} className="text-cyan-400" />
            </div>
            <div>
              <h2 className="text-white text-base font-bold">ML Model & Threshold Tuning</h2>
              <p className="text-slate-400 text-xs">
                Fine-tune hybrid XGBoost classification and Isolation Forest anomaly baselines
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <span className="text-[11px] text-cyan-400 bg-cyan-500/10 border border-cyan-500/25 px-2.5 py-1 rounded-full font-semibold">
              ⚡ Zero-Downtime Hot Reloading
            </span>
          </div>
        </div>
      </div>

      {/* ── Sliders Matrix ──────────────────────────────────────────── */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Parameter 1: Alert Threshold */}
        <div className="card p-5 space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center">
              <h3 className="text-white text-sm font-bold">Threat Score Alert Threshold</h3>
              <ParamTooltip
                title="Threat Score Alert Threshold"
                description="Minimum fused model confidence score (0.50 to 0.95) required to generate high-severity alerts and notify SOC analysts."
                formula="FusedScore = 0.60·XGBoost + 0.40·IsoForest"
              />
            </div>
            <span
              className="mono text-sm font-extrabold px-2.5 py-0.5 rounded-lg border"
              style={{
                color: alertThresholdPct >= 85 ? "#ef4444" : alertThresholdPct >= 70 ? "#f59e0b" : "#06b6d4",
                background: alertThresholdPct >= 85 ? "rgba(239,68,68,0.12)" : "rgba(245,158,11,0.12)",
                borderColor: alertThresholdPct >= 85 ? "rgba(239,68,68,0.3)" : "rgba(245,158,11,0.3)",
              }}
            >
              {alertThresholdPct}%
            </span>
          </div>

          <input
            id="slider-ml-alert-threshold"
            type="range"
            min={50}
            max={95}
            step={1}
            value={alertThresholdPct}
            onChange={(e) =>
              setConfig((prev) => ({ ...prev, alertThreshold: Number(e.target.value) / 100 }))
            }
            className="w-full accent-cyan-500 cursor-pointer h-2 bg-slate-800 rounded-lg"
          />

          <div className="flex justify-between text-[11px] text-slate-500 font-mono">
            <span>50% (High Sensitivity)</span>
            <span className="text-cyan-400/90 font-semibold">75% (Standard)</span>
            <span>95% (Strict Critical)</span>
          </div>
        </div>

        {/* Parameter 2: Isolation Forest Contamination Rate */}
        <div className="card p-5 space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center">
              <h3 className="text-white text-sm font-bold">Isolation Forest Contamination</h3>
              <ParamTooltip
                title="Anomaly Contamination Rate (ν)"
                description="Expected proportion of zero-day anomalies in network traffic. Lower values restrict detections to extreme statistical anomalies; higher values detect subtle outliers."
                formula="Contamination: 0.01 ≤ ν ≤ 0.20"
              />
            </div>
            <span className="mono text-sm font-extrabold text-amber-400 bg-amber-500/10 border border-amber-500/30 px-2.5 py-0.5 rounded-lg">
              {config.contaminationRate.toFixed(2)} ({Math.round(config.contaminationRate * 100)}%)
            </span>
          </div>

          <input
            id="slider-ml-contamination-rate"
            type="range"
            min={0.01}
            max={0.20}
            step={0.01}
            value={config.contaminationRate}
            onChange={(e) =>
              setConfig((prev) => ({ ...prev, contaminationRate: parseFloat(Number(e.target.value).toFixed(2)) }))
            }
            className="w-full accent-amber-500 cursor-pointer h-2 bg-slate-800 rounded-lg"
          />

          <div className="flex justify-between text-[11px] text-slate-500 font-mono">
            <span>0.01 (1% Low Outliers)</span>
            <span className="text-amber-400/90 font-semibold">0.05 (Default 5%)</span>
            <span>0.20 (20% Aggressive)</span>
          </div>
        </div>

        {/* Parameter 3: Shannon Entropy Threshold */}
        <div className="card p-5 space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center">
              <h3 className="text-white text-sm font-bold">Payload Shannon Entropy Threshold</h3>
              <ParamTooltip
                title="Shannon Entropy Threshold (H)"
                description="Threshold for detecting encrypted C2 communications, shellcode packing, and encrypted payloads. Maximum byte entropy is 8.0 bits."
                formula="H(X) = -Σ P(xi)·log2(P(xi))"
              />
            </div>
            <span className="mono text-sm font-extrabold text-purple-400 bg-purple-500/10 border border-purple-500/30 px-2.5 py-0.5 rounded-lg">
              {config.entropyThreshold.toFixed(1)} bits
            </span>
          </div>

          <input
            id="slider-ml-entropy-threshold"
            type="range"
            min={4.0}
            max={8.0}
            step={0.1}
            value={config.entropyThreshold}
            onChange={(e) =>
              setConfig((prev) => ({ ...prev, entropyThreshold: parseFloat(Number(e.target.value).toFixed(1)) }))
            }
            className="w-full accent-purple-500 cursor-pointer h-2 bg-slate-800 rounded-lg"
          />

          <div className="flex justify-between text-[11px] text-slate-500 font-mono">
            <span>4.0 (Plaintext)</span>
            <span className="text-purple-400/90 font-semibold">6.8 (Encrypted / Obfuscated)</span>
            <span>8.0 (Maximum)</span>
          </div>
        </div>

        {/* Parameter 4: Inference Sampling Frequency */}
        <div className="card p-5 space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center">
              <h3 className="text-white text-sm font-bold">Inference Sampling Rate</h3>
              <ParamTooltip
                title="Inference Engine Sampling Frequency"
                description="Controls how frequently the ONNX Runtime extracts host snapshot features and scores incoming network telemetry."
                formula="Interval: 100ms - 1000ms"
              />
            </div>
            <span className="mono text-sm font-extrabold text-cyan-400 bg-cyan-500/10 border border-cyan-500/30 px-2.5 py-0.5 rounded-lg">
              {config.samplingRateMs} ms
            </span>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-1">
            {SAMPLING_OPTIONS.map((opt) => {
              const active = config.samplingRateMs === opt.val;
              return (
                <button
                  key={opt.val}
                  type="button"
                  id={`sampling-rate-${opt.val}-btn`}
                  onClick={() => setConfig((p) => ({ ...p, samplingRateMs: opt.val }))}
                  className={`p-2 rounded-xl border text-center transition flex flex-col items-center justify-center ${
                    active
                      ? "bg-cyan-500/15 border-cyan-500/60 text-cyan-300 shadow-[0_0_12px_rgba(6,182,212,0.25)]"
                      : "bg-slate-900/60 border-slate-800 text-slate-400 hover:text-white hover:bg-slate-800/80"
                  }`}
                >
                  <span className="text-base">{opt.icon}</span>
                  <span className="font-bold text-xs mt-0.5">{opt.label}</span>
                  <span className="text-[9px] text-slate-500 mt-0.5 leading-tight">{opt.sub}</span>
                </button>
              );
            })}
          </div>
        </div>
      </div>

      {/* ── Control Actions Row ─────────────────────────────────────── */}
      <div className="flex items-center justify-between gap-4 pt-2">
        <button
          type="button"
          id="reset-ml-config-btn"
          onClick={handleReset}
          className="flex items-center gap-2 px-4 py-2.5 rounded-xl border border-slate-700 text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition text-xs font-semibold"
        >
          <RotateCcw size={13} />
          Reset Factory Defaults
        </button>

        <button
          type="button"
          id="apply-ml-config-btn"
          onClick={handleApply}
          disabled={saving}
          className={`flex items-center gap-2 px-6 py-2.5 rounded-xl font-bold text-sm transition-all duration-200 shadow-lg ${
            savedSuccess
              ? "bg-emerald-500 text-white shadow-emerald-500/25"
              : "bg-cyan-500 hover:bg-cyan-400 text-slate-950 shadow-cyan-500/25 active:scale-98"
          }`}
        >
          {savedSuccess ? (
            <>
              <CheckCircle2 size={16} />
              Hot-Reloaded!
            </>
          ) : saving ? (
            <>
              <span className="w-4 h-4 border-2 border-slate-950 border-t-transparent rounded-full animate-spin" />
              Hot-Reloading Parameters...
            </>
          ) : (
            <>
              <Zap size={16} />
              Apply & Hot-Reload
            </>
          )}
        </button>
      </div>
    </div>
  );
}
