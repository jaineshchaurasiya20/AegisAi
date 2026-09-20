/**
 * PolicySettingsPanel — AegisAI Self-Healing Automation & Containment Policy Panel.
 *
 * Provides:
 *  - Engine Mode Switcher: MANUAL vs AUTONOMOUS (with glowing state)
 *  - Risk Score Threshold Slider (50% – 99%)
 *  - Self-Healing Action Matrix toggles (Process Kill, Host Isolation, Quarantine)
 *  - Active mode warning banner
 *  - Save & Reset controls wired to EngineContext
 */
import React, { useState, useEffect } from "react";
import {
  Shield, Zap, AlertTriangle, CheckCircle2, Save,
  RotateCcw, Sliders, Skull, WifiOff, Package, ShieldAlert,
} from "lucide-react";
import { useEngine } from "../context/EngineContext";

const DEFAULT_POLICY = {
  containmentMode: "MANUAL",
  autoContainThreshold: 0.85,
  enableAutoProcessKill: false,
  enableAutoHostIsolation: false,
  enableAutoQuarantine: false,
};

export default function PolicySettingsPanel({ onSaved }) {
  const { policy, savePolicy } = useEngine();
  const [draft, setDraft] = useState(policy || DEFAULT_POLICY);
  const [saving, setSaving] = useState(false);
  const [savedSuccess, setSavedSuccess] = useState(false);

  // Sync draft whenever upstream policy changes
  useEffect(() => {
    if (policy) {
      setDraft(policy);
    }
  }, [policy]);

  const isAutonomous = draft.containmentMode === "AUTONOMOUS";
  const thresholdPct = Math.round((draft.autoContainThreshold ?? 0.85) * 100);

  const handleModeChange = (mode) => {
    setDraft((prev) => ({
      ...prev,
      containmentMode: mode,
    }));
  };

  const handleToggle = (key) => {
    setDraft((prev) => ({
      ...prev,
      [key]: !prev[key],
    }));
  };

  const handleThresholdChange = (val) => {
    setDraft((prev) => ({
      ...prev,
      autoContainThreshold: val / 100,
    }));
  };

  const handleSave = async () => {
    setSaving(true);
    try {
      await savePolicy(draft);
      setSavedSuccess(true);
      onSaved?.(draft);
      setTimeout(() => setSavedSuccess(false), 2500);
    } finally {
      setSaving(false);
    }
  };

  const handleReset = () => {
    setDraft(DEFAULT_POLICY);
  };

  return (
    <div className="space-y-6">
      {/* ── Section 1: Engine Operating Mode ────────────────────────── */}
      <div className="card p-5">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-cyan-500/15 border border-cyan-500/30 flex items-center justify-center">
              <Zap size={16} className="text-cyan-400" />
            </div>
            <div>
              <h3 className="text-white text-base font-bold">Containment Engine Mode</h3>
              <p className="text-slate-400 text-xs">
                Select between human-in-the-loop analyst approval or automated self-healing
              </p>
            </div>
          </div>
        </div>

        {/* Mode selector segmented cards */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 mt-4">
          {/* Manual Mode Card */}
          <button
            type="button"
            id="mode-manual-btn"
            onClick={() => handleModeChange("MANUAL")}
            className="flex flex-col text-left p-4 rounded-xl border transition-all relative overflow-hidden"
            style={{
              background: !isAutonomous ? "rgba(6, 182, 212, 0.08)" : "rgba(17, 24, 39, 0.6)",
              borderColor: !isAutonomous ? "rgba(6, 182, 212, 0.5)" : "rgba(55, 65, 81, 0.5)",
              boxShadow: !isAutonomous ? "0 0 20px rgba(6, 182, 212, 0.15)" : "none",
            }}
          >
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center gap-2">
                <Shield size={16} className={!isAutonomous ? "text-cyan-400" : "text-slate-500"} />
                <span className={`text-sm font-bold ${!isAutonomous ? "text-cyan-300" : "text-slate-300"}`}>
                  Manual Approval Mode
                </span>
              </div>
              {!isAutonomous && (
                <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
              )}
            </div>
            <p className="text-slate-400 text-xs leading-relaxed">
              Analyst-first posture. Threat events are highlighted and recommended actions require explicit SOC confirmation.
            </p>
            <div className="mt-3 pt-2 border-t border-slate-800 flex items-center gap-1.5 text-[11px] text-cyan-400/90 font-medium">
              <span>● Safe for production & staging</span>
            </div>
          </button>

          {/* Autonomous Mode Card */}
          <button
            type="button"
            id="mode-autonomous-btn"
            onClick={() => handleModeChange("AUTONOMOUS")}
            className={`flex flex-col text-left p-4 rounded-xl border transition-all relative overflow-hidden ${
              isAutonomous ? "engine-autonomous-glow" : ""
            }`}
            style={{
              background: isAutonomous ? "rgba(239, 68, 68, 0.08)" : "rgba(17, 24, 39, 0.6)",
              borderColor: isAutonomous ? "rgba(239, 68, 68, 0.6)" : "rgba(55, 65, 81, 0.5)",
            }}
          >
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center gap-2">
                <ShieldAlert size={16} className={isAutonomous ? "text-red-400" : "text-slate-500"} />
                <span className={`text-sm font-bold ${isAutonomous ? "text-red-300" : "text-slate-300"}`}>
                  Autonomous Containment
                </span>
              </div>
              {isAutonomous && (
                <span className="w-2 h-2 rounded-full bg-red-500 animate-threat-pulse" />
              )}
            </div>
            <p className="text-slate-400 text-xs leading-relaxed">
              Self-healing edge response. When risk scores breach the threshold, active isolation rules execute autonomously.
            </p>
            <div className="mt-3 pt-2 border-t border-slate-800 flex items-center gap-1.5 text-[11px] text-red-400 font-medium">
              <span>⚡ Zero-latency active response</span>
            </div>
          </button>
        </div>

        {/* Dynamic Mode Warning Banner */}
        {isAutonomous ? (
          <div className="mt-4 bg-red-500/10 border border-red-500/30 rounded-xl p-3.5 flex items-start gap-3 animate-fade-in">
            <AlertTriangle size={17} className="text-red-400 flex-shrink-0 mt-0.5" />
            <div className="text-xs">
              <p className="text-red-200 font-semibold mb-0.5">Autonomous Containment is ACTIVE</p>
              <p className="text-red-300/80 leading-relaxed">
                The engine will execute containment actions (killing processes, isolating IPs) automatically without user approval whenever detected threats equal or exceed <span className="font-bold text-white">{thresholdPct}%</span> risk score. Ensure host monitoring agents have necessary privileges.
              </p>
            </div>
          </div>
        ) : (
          <div className="mt-4 bg-cyan-500/5 border border-cyan-500/20 rounded-xl p-3.5 flex items-start gap-3">
            <CheckCircle2 size={16} className="text-cyan-400 flex-shrink-0 mt-0.5" />
            <p className="text-xs text-slate-300">
              Manual mode active: Actions will only be executed when triggered by an analyst via the Threat Detail panel or quick-action row menus.
            </p>
          </div>
        )}
      </div>

      {/* ── Section 2: Autonomous Trigger Threshold ──────────────────── */}
      <div className="card p-5">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-amber-500/15 border border-amber-500/30 flex items-center justify-center">
              <Sliders size={16} className="text-amber-400" />
            </div>
            <div>
              <h3 className="text-white text-base font-bold">Autonomous Trigger Threshold</h3>
              <p className="text-slate-400 text-xs">
                Minimum ML threat score required before auto-containment triggers
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-xs text-slate-400">Trigger:</span>
            <span
              className="mono text-base font-extrabold px-3 py-1 rounded-lg border"
              style={{
                color: thresholdPct >= 85 ? "#ef4444" : thresholdPct >= 70 ? "#f59e0b" : "#06b6d4",
                background:
                  thresholdPct >= 85
                    ? "rgba(239,68,68,0.12)"
                    : thresholdPct >= 70
                    ? "rgba(245,158,11,0.12)"
                    : "rgba(6,182,212,0.12)",
                borderColor:
                  thresholdPct >= 85
                    ? "rgba(239,68,68,0.3)"
                    : thresholdPct >= 70
                    ? "rgba(245,158,11,0.3)"
                    : "rgba(6,182,212,0.3)",
              }}
            >
              {thresholdPct}%
            </span>
          </div>
        </div>

        <div className="space-y-3">
          <input
            id="slider-policy-threshold"
            type="range"
            min={50}
            max={99}
            step={1}
            value={thresholdPct}
            onChange={(e) => handleThresholdChange(Number(e.target.value))}
            className="w-full accent-cyan-500 cursor-pointer h-2 bg-slate-800 rounded-lg"
          />
          <div className="flex justify-between text-slate-500 text-[11px] font-medium">
            <span>50% (Aggressive)</span>
            <span className="text-amber-400/90">85% (Recommended Default)</span>
            <span>99% (Strict Critical Only)</span>
          </div>
        </div>
      </div>

      {/* ── Section 3: Self-Healing Action Matrix ───────────────────── */}
      <div className="card p-5">
        <div className="flex items-center gap-2.5 mb-1">
          <div className="w-8 h-8 rounded-lg bg-red-500/15 border border-red-500/30 flex items-center justify-center">
            <ShieldAlert size={16} className="text-red-400" />
          </div>
          <div>
            <h3 className="text-white text-base font-bold">Self-Healing Action Matrix</h3>
            <p className="text-slate-400 text-xs">
              Select specific actions permitted for autonomous execution upon threshold breach
            </p>
          </div>
        </div>

        <div className="divide-y divide-slate-800/80 mt-4">
          {/* Toggle 1: Auto Process Kill */}
          <div className="flex items-start justify-between gap-4 py-3.5">
            <div className="flex items-start gap-3">
              <div className="w-7 h-7 rounded-lg bg-red-500/10 border border-red-500/20 flex items-center justify-center flex-shrink-0 mt-0.5">
                <Skull size={14} className="text-red-400" />
              </div>
              <div>
                <p className="text-sm font-semibold text-white">Auto-Kill Malicious Process</p>
                <p className="text-slate-400 text-xs mt-0.5">
                  Execute force-termination (<code className="text-slate-300">taskkill /F /PID</code> / <code className="text-slate-300">kill -9</code>) against flagged PID
                </p>
              </div>
            </div>
            <button
              id="toggle-auto-process-kill"
              role="switch"
              aria-checked={draft.enableAutoProcessKill}
              onClick={() => handleToggle("enableAutoProcessKill")}
              className={`flex-shrink-0 relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                draft.enableAutoProcessKill ? "bg-red-500 shadow-[0_0_12px_rgba(239,68,68,0.5)]" : "bg-slate-700"
              }`}
            >
              <span
                className={`inline-block h-4 w-4 rounded-full bg-white transition-transform ${
                  draft.enableAutoProcessKill ? "translate-x-6" : "translate-x-1"
                }`}
              />
            </button>
          </div>

          {/* Toggle 2: Auto Host Isolation */}
          <div className="flex items-start justify-between gap-4 py-3.5">
            <div className="flex items-start gap-3">
              <div className="w-7 h-7 rounded-lg bg-red-500/10 border border-red-500/20 flex items-center justify-center flex-shrink-0 mt-0.5">
                <WifiOff size={14} className="text-red-400" />
              </div>
              <div>
                <p className="text-sm font-semibold text-white">Auto-Isolate Host & Block Remote IP</p>
                <p className="text-slate-400 text-xs mt-0.5">
                  Inject firewall drop rules for flagged target IP to sever lateral network traffic
                </p>
              </div>
            </div>
            <button
              id="toggle-auto-host-isolation"
              role="switch"
              aria-checked={draft.enableAutoHostIsolation}
              onClick={() => handleToggle("enableAutoHostIsolation")}
              className={`flex-shrink-0 relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                draft.enableAutoHostIsolation ? "bg-red-500 shadow-[0_0_12px_rgba(239,68,68,0.5)]" : "bg-slate-700"
              }`}
            >
              <span
                className={`inline-block h-4 w-4 rounded-full bg-white transition-transform ${
                  draft.enableAutoHostIsolation ? "translate-x-6" : "translate-x-1"
                }`}
              />
            </button>
          </div>

          {/* Toggle 3: Auto Quarantine File */}
          <div className="flex items-start justify-between gap-4 py-3.5">
            <div className="flex items-start gap-3">
              <div className="w-7 h-7 rounded-lg bg-amber-500/10 border border-amber-500/20 flex items-center justify-center flex-shrink-0 mt-0.5">
                <Package size={14} className="text-amber-400" />
              </div>
              <div>
                <p className="text-sm font-semibold text-white">Auto-Quarantine Binary / Script</p>
                <p className="text-slate-400 text-xs mt-0.5">
                  Relocate executable artifacts to the isolated AegisAI quarantine vault
                </p>
              </div>
            </div>
            <button
              id="toggle-auto-quarantine"
              role="switch"
              aria-checked={draft.enableAutoQuarantine}
              onClick={() => handleToggle("enableAutoQuarantine")}
              className={`flex-shrink-0 relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                draft.enableAutoQuarantine ? "bg-amber-500 shadow-[0_0_12px_rgba(245,158,11,0.5)]" : "bg-slate-700"
              }`}
            >
              <span
                className={`inline-block h-4 w-4 rounded-full bg-white transition-transform ${
                  draft.enableAutoQuarantine ? "translate-x-6" : "translate-x-1"
                }`}
              />
            </button>
          </div>
        </div>
      </div>

      {/* ── Section 4: Controls & Persistence ───────────────────────── */}
      <div className="flex items-center justify-between gap-4 pt-2">
        <button
          type="button"
          id="reset-policy-btn"
          onClick={handleReset}
          className="flex items-center gap-2 px-4 py-2.5 rounded-xl border border-slate-700 text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition text-xs font-semibold"
        >
          <RotateCcw size={13} />
          Reset Defaults
        </button>

        <button
          type="button"
          id="save-policy-btn"
          onClick={handleSave}
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
              Policy Persisted!
            </>
          ) : saving ? (
            <>
              <span className="w-4 h-4 border-2 border-slate-950 border-t-transparent rounded-full animate-spin" />
              Saving Policy...
            </>
          ) : (
            <>
              <Save size={16} />
              Save Engine Policy
            </>
          )}
        </button>
      </div>
    </div>
  );
}
