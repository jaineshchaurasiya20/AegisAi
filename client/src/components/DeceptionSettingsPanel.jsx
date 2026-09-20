/**
 * DeceptionSettingsPanel — AegisAI Active Defense & Honeypot Configuration Panel.
 *
 * Provides:
 *  - Active Decoy Infrastructure Status (Port listeners, fake services, canary files)
 *  - Real-time honeypot capture metrics
 *  - Interactive Zero-Day Honeypot Trap Simulator (triggers POST /api/deception/simulate)
 *  - Captured payload inspection viewer
 */
import React, { useState, useEffect, useCallback } from "react";
import {
  Shield, Flame, Zap, RefreshCw, Terminal, Eye,
  CheckCircle2, AlertTriangle, Play, Sparkles, Hash, Globe, Lock,
} from "lucide-react";
import { api } from "../services/api";

const TRAP_OPTIONS = [
  { id: "FAKE_FTP", label: "Fake FTP Daemon (Port 2121)", icon: Globe, decoy: "vsftpd-2.3.4 (synthetic backdoor)" },
  { id: "FAKE_SSH", label: "Fake SSH Banner (Port 2222)", icon: Lock, decoy: "OpenSSH_8.2p1 (canary honeypot)" },
  { id: "DECOY_FILE", label: "Canary Honeydoc / Credential File", icon: Eye, decoy: "C:\\Users\\Admin\\Documents\\aws_credentials.json" },
  { id: "FAKE_REGISTRY", label: "Fake Registry Key Persistence Trap", icon: Terminal, decoy: "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\svchost_canary" },
];

export default function DeceptionSettingsPanel() {
  const [stats, setStats] = useState(null);
  const [config, setConfig] = useState(null);
  const [traps, setTraps] = useState([]);
  const [loading, setLoading] = useState(true);

  // Simulation Form State
  const [trapType, setTrapType] = useState("FAKE_FTP");
  const [sourceIp, setSourceIp] = useState("185.220.101.42");
  const [rawPayload, setRawPayload] = useState("USER admin\\nPASS hunter2\\nSITE EXEC whoami");
  const [simulating, setSimulating] = useState(false);
  const [simResult, setSimResult] = useState(null);

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const [statsRes, configRes, trapsRes] = await Promise.allSettled([
        api.getDeceptionStats(),
        api.getDeceptionConfig(),
        api.getDeceptionTraps({ limit: 10 }),
      ]);
      if (statsRes.status === "fulfilled") setStats(statsRes.value);
      if (configRes.status === "fulfilled") setConfig(configRes.value);
      if (trapsRes.status === "fulfilled") setTraps(trapsRes.value || []);
    } catch (e) {
      console.warn("Failed to load deception data:", e);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  const handleGenerateIp = () => {
    const r1 = Math.floor(Math.random() * 150 + 45);
    const r2 = Math.floor(Math.random() * 250 + 1);
    const r3 = Math.floor(Math.random() * 250 + 1);
    const r4 = Math.floor(Math.random() * 250 + 2);
    setSourceIp(`${r1}.${r2}.${r3}.${r4}`);
  };

  const handleSimulate = async (e) => {
    e?.preventDefault();
    setSimulating(true);
    setSimResult(null);
    try {
      const res = await api.simulateHoneypotTrap({
        trapType,
        sourceIp,
        rawPayload,
      });
      setSimResult(res);
      fetchData(); // refresh traps and stats
    } catch (err) {
      console.error("Simulation error:", err);
    } finally {
      setSimulating(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* ── Section 1: Active Decoy Infrastructure ────────────────────────── */}
      <div className="card p-5">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-cyan-500/15 border border-cyan-500/30 flex items-center justify-center">
              <Shield size={16} className="text-cyan-400" />
            </div>
            <div>
              <h3 className="text-white text-base font-bold">Active Honeypot & Deception Fabric</h3>
              <p className="text-slate-400 text-xs">
                Zero-day tripwires diverting attackers into isolated sandbox emulators
              </p>
            </div>
          </div>
          <button
            onClick={fetchData}
            disabled={loading}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-700 bg-slate-800/60 hover:bg-slate-800 text-slate-300 text-xs font-semibold transition"
          >
            <RefreshCw size={12} className={loading ? "animate-spin text-cyan-400" : ""} />
            Refresh
          </button>
        </div>

        {/* Stats KPIs */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-4">
          <div className="bg-slate-900/80 p-3 rounded-lg border border-slate-800">
            <p className="text-slate-500 text-[11px]">Active Decoy Assets</p>
            <p className="text-cyan-400 font-bold text-lg">{stats?.activeDecoyCount ?? 4}</p>
          </div>
          <div className="bg-slate-900/80 p-3 rounded-lg border border-slate-800">
            <p className="text-slate-500 text-[11px]">Trapped Probes</p>
            <p className="text-emerald-400 font-bold text-lg">{stats?.totalCaptures ?? traps.length}</p>
          </div>
          <div className="bg-slate-900/80 p-3 rounded-lg border border-slate-800">
            <p className="text-slate-500 text-[11px]">Synthetic Listeners</p>
            <p className="text-purple-400 font-bold text-lg">2 (FTP/SSH)</p>
          </div>
          <div className="bg-slate-900/80 p-3 rounded-lg border border-slate-800">
            <p className="text-slate-500 text-[11px]">Containment State</p>
            <p className="text-amber-400 font-bold text-lg">ISOLATED</p>
          </div>
        </div>

        {/* Decoy List */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
          {TRAP_OPTIONS.map((t) => {
            const Icon = t.icon;
            return (
              <div key={t.id} className="bg-slate-900/50 p-3 rounded-lg border border-slate-800 flex items-start gap-3">
                <div className="w-7 h-7 rounded bg-slate-800/80 border border-slate-700 flex items-center justify-center flex-shrink-0 mt-0.5">
                  <Icon size={14} className="text-cyan-400" />
                </div>
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <p className="text-white text-xs font-semibold truncate">{t.label}</p>
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                  </div>
                  <p className="mono text-slate-500 text-[10px] truncate mt-0.5">{t.decoy}</p>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* ── Section 2: Interactive Honeypot Trap Simulator ──────────────── */}
      <div className="card p-5 border-amber-500/30 bg-gradient-to-b from-slate-900/90 to-amber-950/10">
        <div className="flex items-center gap-2.5 mb-3">
          <div className="w-8 h-8 rounded-lg bg-amber-500/15 border border-amber-500/30 flex items-center justify-center">
            <Flame size={16} className="text-amber-400" />
          </div>
          <div>
            <h3 className="text-white text-base font-bold">Simulate Zero-Day Honeypot Redirection</h3>
            <p className="text-slate-400 text-xs">
              Inject synthetic adversary traffic to verify deception containment and payload extraction
            </p>
          </div>
        </div>

        <form onSubmit={handleSimulate} className="space-y-4 mt-4">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            {/* Trap Type Selector */}
            <div>
              <label className="block text-slate-300 text-xs font-medium mb-1.5">
                Select Decoy Trap Target
              </label>
              <select
                id="select-trap-type"
                value={trapType}
                onChange={(e) => setTrapType(e.target.value)}
                className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-white text-xs focus:border-cyan-500 focus:outline-none"
              >
                {TRAP_OPTIONS.map((opt) => (
                  <option key={opt.id} value={opt.id}>
                    {opt.label}
                  </option>
                ))}
              </select>
            </div>

            {/* Source IP Input with Random generator */}
            <div>
              <div className="flex items-center justify-between mb-1.5">
                <label className="block text-slate-300 text-xs font-medium">
                  Attacker Source IP
                </label>
                <button
                  type="button"
                  onClick={handleGenerateIp}
                  className="text-cyan-400 hover:text-cyan-300 text-[10px] font-semibold flex items-center gap-1"
                >
                  <Sparkles size={10} /> Randomize
                </button>
              </div>
              <input
                id="input-sim-source-ip"
                type="text"
                value={sourceIp}
                onChange={(e) => setSourceIp(e.target.value)}
                className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-white text-xs mono focus:border-cyan-500 focus:outline-none"
                placeholder="e.g. 198.51.100.23"
                required
              />
            </div>
          </div>

          {/* Raw Payload input */}
          <div>
            <label className="block text-slate-300 text-xs font-medium mb-1.5">
              Simulated Malicious Payload / Command
            </label>
            <input
              id="input-sim-payload"
              type="text"
              value={rawPayload}
              onChange={(e) => setRawPayload(e.target.value)}
              className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-white text-xs mono focus:border-cyan-500 focus:outline-none"
              placeholder="e.g. USER anonymous / GET /wp-admin.php / cat /etc/passwd"
              required
            />
          </div>

          {/* Trigger Button */}
          <div className="flex items-center justify-between pt-2">
            <button
              id="btn-simulate-honeypot-trap"
              type="submit"
              disabled={simulating}
              className="flex items-center gap-2 px-5 py-2.5 rounded-lg bg-amber-500/20 text-amber-300 border border-amber-500/40 hover:bg-amber-500/30 font-semibold text-xs transition shadow-[0_0_15px_rgba(245,158,11,0.15)] disabled:opacity-50"
            >
              {simulating ? <RefreshCw size={13} className="animate-spin" /> : <Play size={13} className="fill-amber-400" />}
              {simulating ? "Executing Trap Redirection..." : "🔥 Trigger Honeypot Trap Simulation"}
            </button>
          </div>
        </form>

        {/* Simulation Result Box */}
        {simResult && (
          <div className="mt-4 p-4 rounded-xl border border-emerald-500/30 bg-emerald-950/20 space-y-2 animate-fade-in">
            <div className="flex items-center gap-2 text-emerald-400 text-xs font-bold">
              <CheckCircle2 size={15} />
              <span>Simulated Attack Trapped & Neutralized!</span>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-[11px] pt-1">
              <div>
                <span className="text-slate-500">Capture ID: </span>
                <span className="mono text-slate-300 font-semibold">{simResult.captureId?.slice(0, 12)}...</span>
              </div>
              <div>
                <span className="text-slate-500">Decoy Target: </span>
                <span className="mono text-cyan-300">{simResult.decoyTarget}</span>
              </div>
              <div>
                <span className="text-slate-500">Isolation Status: </span>
                <span className="text-emerald-400 font-bold">{simResult.isolationStatus}</span>
              </div>
            </div>
            {simResult.payloadHash && (
              <div className="text-[10px] mono text-slate-400 flex items-center gap-1.5 pt-1">
                <Hash size={11} className="text-slate-500" />
                <span>SHA-256: {simResult.payloadHash}</span>
              </div>
            )}
          </div>
        )}
      </div>

      {/* ── Section 3: Recent Honeypot Trap Captures Table ─────────────────── */}
      <div className="card overflow-hidden">
        <div className="p-4 border-b border-slate-800 flex items-center justify-between">
          <h4 className="text-white text-xs font-bold uppercase tracking-wider flex items-center gap-2">
            <Terminal size={14} className="text-cyan-400" />
            Recent Honeypot Captures & Payloads
          </h4>
          <span className="text-slate-500 text-xs">{traps.length} events logged</span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-xs text-left">
            <thead>
              <tr className="bg-slate-900/90 border-b border-slate-800 text-slate-400 uppercase tracking-wider text-[10px]">
                <th className="px-4 py-3">Timestamp</th>
                <th className="px-4 py-3">Attacker IP</th>
                <th className="px-4 py-3">Trap Type</th>
                <th className="px-4 py-3">Decoy Target</th>
                <th className="px-4 py-3">Captured Payload</th>
                <th className="px-4 py-3">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {traps.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-slate-500">
                    No honeypot captures recorded yet. Run a simulation above to generate data.
                  </td>
                </tr>
              ) : (
                traps.map((t) => (
                  <tr key={t.captureId} className="hover:bg-slate-800/30 transition">
                    <td className="px-4 py-2.5 mono text-slate-400 whitespace-nowrap">
                      {new Date(t.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="px-4 py-2.5 mono text-slate-300 font-semibold">
                      {t.sourceIp}:{t.sourcePort}
                    </td>
                    <td className="px-4 py-2.5">
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                        {t.trapType}
                      </span>
                    </td>
                    <td className="px-4 py-2.5 text-slate-400 mono text-[11px]">
                      {t.decoyTarget}
                    </td>
                    <td className="px-4 py-2.5 mono text-amber-300 text-[11px] truncate max-w-[200px]" title={t.rawPayload}>
                      {t.rawPayload}
                    </td>
                    <td className="px-4 py-2.5">
                      <span className="inline-flex items-center gap-1 text-emerald-400 text-[10px] font-bold">
                        <CheckCircle2 size={11} /> {t.isolationStatus}
                      </span>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
