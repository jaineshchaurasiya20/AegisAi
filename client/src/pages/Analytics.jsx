import React, { useState, useEffect } from "react";
import {
  Shield,
  Zap,
  Activity,
  Layers,
  Crosshair,
  ArrowRight,
  Terminal,
  Server,
  Lock,
  Radio,
  CheckCircle2,
  AlertTriangle,
  Flame,
  Globe,
  GitFork,
  Cpu,
  Eye,
} from "lucide-react";
import GlassCard from "../components/ui/GlassCard";
import SectionHeader from "../components/ui/SectionHeader";
import StatusBadge from "../components/ui/StatusBadge";
import MetricCard from "../components/ui/MetricCard";
import { api } from "../services/api";

/* ─── Attack Path Kill Chain Stages ──────────────────────────────────────── */
const KILL_CHAIN_STAGES = [
  {
    id: "recon",
    phase: "1. RECONNAISSANCE",
    technique: "T1046 • Network Service Scanning",
    title: "Port Probe & OS Fingerprint",
    source: "185.233.42.17",
    target: "Port 22 (SSH)",
    sensor: "eBPF Socket Filter",
    risk: "MEDIUM",
    riskVariant: "warning",
    detail: "Rapid TCP SYN/ACK handshake bursts on port 22. Adversary probed SSH version string (OpenSSH 8.9p1).",
  },
  {
    id: "spray",
    phase: "2. CREDENTIAL ACCESS",
    technique: "T1110.001 • Password Spraying",
    title: "Automated Dictionary Spray",
    source: "185.233.42.17",
    target: "Accounts: root, admin",
    sensor: "Auth Log Ingestion",
    risk: "HIGH",
    riskVariant: "critical",
    detail: "47 consecutive authentication failures across high-privilege usernames within a 4-minute window.",
  },
  {
    id: "access",
    phase: "3. INITIAL ACCESS",
    technique: "T1078 • Valid Accounts",
    title: "Compromised Account Login",
    source: "185.233.42.17",
    target: "Account: deploy (UID 1000)",
    sensor: "PAM Auth Monitor",
    risk: "CRITICAL",
    riskVariant: "critical",
    detail: "Valid credential accepted for user 'deploy'. Interactive PTY allocated on session pts/2.",
  },
  {
    id: "privesc",
    phase: "4. PRIVILEGE ESCALATION",
    technique: "T1548.003 • Sudo Caching",
    title: "Root Sudo Shell Execution",
    source: "PID 15024",
    target: "/bin/bash (UID 0)",
    sensor: "eBPF Execve Hook",
    risk: "CRITICAL",
    riskVariant: "critical",
    detail: "Unauthorized elevation attempt: 'sudo /bin/bash' without valid MFA quorum confirmation.",
  },
  {
    id: "contain",
    phase: "5. AUTONOMOUS DEFENSE",
    technique: "eBPF Mitigation",
    title: "Edge Kernel Quarantine",
    source: "AegisAI Engine",
    target: "Subnet 185.233.42.0/24",
    sensor: "Local IPTables + XDP",
    risk: "CONTAINED",
    riskVariant: "success",
    detail: "Session terminated, host socket quarantined, IP subnet rate-limited to 0 bps at kernel level.",
  },
];

/* ─── Attack Vector Matrix Dataset ───────────────────────────────────────── */
const ATTACK_VECTORS = [
  {
    name: "Coordinated SSH Brute-Force",
    mitre: "T1110.001",
    engine: "ONNX ML + Heuristics",
    events: 47,
    frequencyPct: 78,
    severity: "CRITICAL",
    severityVariant: "critical",
    status: "Containment Active",
    statusVariant: "critical",
  },
  {
    name: "Sudo Privilege Escalation",
    mitre: "T1548.003",
    engine: "eBPF Execve Sensor",
    events: 12,
    frequencyPct: 45,
    severity: "CRITICAL",
    severityVariant: "critical",
    status: "Auto-Terminated",
    statusVariant: "critical",
  },
  {
    name: "Deception Trap Interaction",
    mitre: "T1082",
    engine: "Honeypot Decoy Service",
    events: 11,
    frequencyPct: 38,
    severity: "HIGH",
    severityVariant: "high",
    status: "Captured in Decoy",
    statusVariant: "high",
  },
  {
    name: "Outbound C2 Beacon Probe",
    mitre: "T1071.001",
    engine: "IsolationForest Edge",
    events: 8,
    frequencyPct: 24,
    severity: "MEDIUM",
    severityVariant: "medium",
    status: "DNS Sinkholed",
    statusVariant: "medium",
  },
  {
    name: "Port & Service Fingerprinting",
    mitre: "T1046",
    engine: "TCP Syn Anomaly Engine",
    events: 6,
    frequencyPct: 18,
    severity: "LOW",
    severityVariant: "low",
    status: "Rate-Limited",
    statusVariant: "low",
  },
];

/* ─── Deception & Decoy Traps Intel ──────────────────────────────────────── */
const DECEPTION_TRAPS = [
  {
    name: "Decoy MySQL Port (3306)",
    type: "Database Honeypot",
    interactionCount: 6,
    lastAttacker: "45.142.214.88 (RU)",
    status: "Active & Trapping",
  },
  {
    name: "Fake AWS Credentials File (~/.aws/credentials)",
    type: "HoneyToken Canary",
    interactionCount: 3,
    lastAttacker: "194.26.29.112 (RO)",
    status: "Triggered & Alerted",
  },
  {
    name: "Internal Decoy Redis Node (6379)",
    type: "Cache Honeypot",
    interactionCount: 2,
    lastAttacker: "91.240.118.50 (BG)",
    status: "Active & Trapping",
  },
];

export default function Analytics() {
  const [stats, setStats] = useState(null);
  const [selectedStage, setSelectedStage] = useState(KILL_CHAIN_STAGES[2]); // Default on Initial Access

  useEffect(() => {
    api.getThreatStats().then(setStats).catch(() => {});
  }, []);

  return (
    <div className="p-4 sm:p-6 lg:p-7 space-y-6 max-w-[1600px] mx-auto animate-fade-in font-sans">
      {/* ── Page Header with inline technical metrics (No duplicate cards) ── */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-2 border-b border-white/[0.05]">
        <div>
          <div className="flex items-center gap-2.5">
            <h1 className="text-white text-xl sm:text-2xl font-bold tracking-tight">
              Threats Intelligence
            </h1>
            <StatusBadge variant="cyan" dot size="sm">
              AI VECTOR ENGINE
            </StatusBadge>
          </div>
          <p className="text-slate-400 text-xs sm:text-sm mt-0.5">
            MITRE ATT&CK Kill-Chain Mapping · Edge Vector Attribution & Deception Correlations
          </p>
        </div>

        {/* Inline technical summary */}
        <div className="flex items-center gap-2.5 flex-wrap text-xs font-mono">
          <div className="px-3 py-1.5 rounded-lg bg-navy-950/70 border border-white/[0.06] text-slate-300">
            <span className="text-slate-500">Kill-Chain: </span>
            <span className="text-cyan-400 font-bold">{KILL_CHAIN_STAGES.length} Stages</span>
          </div>

          <div className="px-3 py-1.5 rounded-lg bg-navy-950/70 border border-white/[0.06] text-slate-300">
            <span className="text-slate-500">Active Vectors: </span>
            <span className="text-white font-bold">{ATTACK_VECTORS.length}</span>
          </div>

          <div className="px-3 py-1.5 rounded-lg bg-navy-950/70 border border-emerald-500/25 text-emerald-300">
            <span className="text-emerald-400 font-bold">11</span>
            <span className="text-slate-400"> Decoy Captures</span>
          </div>
        </div>
      </div>

      {/* ── 2. Attack Path Vector Flow (Interactive Kill Chain Graph) ─── */}
      <GlassCard elevation="l2" className="p-5 sm:p-6 space-y-4">
        <SectionHeader
          icon={GitFork}
          title="Interactive Attack Path Vector Flow (Kill Chain Attribution)"
          subtitle="Real-time chronological progression through MITRE ATT&CK stages"
          rightElement={
            <span className="text-[11px] font-mono text-cyan-400 bg-cyan-500/10 px-2 py-0.5 rounded border border-cyan-500/20">
              Live Attack Session #0241
            </span>
          }
        />

        {/* Sequential Kill-Chain Vector Nodes Flow */}
        <div className="grid grid-cols-1 md:grid-cols-5 gap-3 pt-2">
          {KILL_CHAIN_STAGES.map((stage, idx) => {
            const isSelected = selectedStage.id === stage.id;
            return (
              <div
                key={stage.id}
                onClick={() => setSelectedStage(stage)}
                className={`cursor-pointer p-3.5 rounded-xl border transition-all duration-200 relative flex flex-col justify-between ${
                  isSelected
                    ? "bg-navy-800/90 border-cyan-400 shadow-glass-elevated ring-1 ring-cyan-400/40 transform -translate-y-1"
                    : "bg-navy-950/60 border-white/[0.06] hover:border-white/[0.14] hover:bg-navy-900/60"
                }`}
              >
                {/* Connecting Arrow for Desktop */}
                {idx < KILL_CHAIN_STAGES.length - 1 && (
                  <div className="hidden md:block absolute -right-2.5 top-1/2 -translate-y-1/2 z-20 text-slate-600">
                    <ArrowRight size={14} className={isSelected ? "text-cyan-400" : ""} />
                  </div>
                )}

                <div>
                  <div className="flex items-center justify-between gap-1 mb-1.5">
                    <span className="text-[10px] font-mono font-bold text-slate-400 uppercase tracking-wider">
                      {stage.phase}
                    </span>
                    <StatusBadge variant={stage.riskVariant} dot={false} size="sm">
                      {stage.risk}
                    </StatusBadge>
                  </div>

                  <p className="text-xs font-bold text-white mb-1">
                    {stage.title}
                  </p>
                  <p className="text-[11px] font-mono text-cyan-300/90 truncate">
                    {stage.technique}
                  </p>
                </div>

                <div className="mt-3 pt-2 border-t border-white/[0.04] text-[10px] font-mono text-slate-400 flex items-center justify-between">
                  <span className="truncate">{stage.sensor}</span>
                  <Eye size={11} className={isSelected ? "text-cyan-400" : "text-slate-600"} />
                </div>
              </div>
            );
          })}
        </div>

        {/* Selected Stage Detail Inspector Banner */}
        {selectedStage && (
          <div className="p-4 rounded-xl bg-navy-950/80 border border-cyan-500/20 text-xs text-slate-200 flex flex-col sm:flex-row sm:items-center justify-between gap-3 animate-fade-in">
            <div className="space-y-1">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="font-bold text-white text-sm">
                  {selectedStage.title}
                </span>
                <span className="font-mono text-cyan-400 text-xs">
                  [{selectedStage.technique}]
                </span>
                <span className="font-mono text-slate-400 text-[11px]">
                  Sensor: {selectedStage.sensor}
                </span>
              </div>
              <p className="text-slate-300 leading-relaxed text-xs">
                {selectedStage.detail}
              </p>
            </div>

            <div className="flex items-center gap-2 flex-shrink-0 font-mono text-[11px]">
              <span className="px-2.5 py-1 rounded bg-slate-900 border border-slate-700 text-slate-300">
                Source: {selectedStage.source}
              </span>
              <span className="px-2.5 py-1 rounded bg-slate-900 border border-slate-700 text-slate-300">
                Target: {selectedStage.target}
              </span>
            </div>
          </div>
        )}
      </GlassCard>

      {/* ── 3. Bottom Grid: Attack Vector Matrix & Deception Traps ────── */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-stretch">
        {/* Vector Classification Matrix (8 cols on lg) */}
        <div className="lg:col-span-8 flex flex-col">
          <GlassCard elevation="l1" className="p-5 flex flex-col justify-between h-full">
            <div>
              <SectionHeader
                icon={Crosshair}
                title="Attack Vector Classification Matrix"
                subtitle="Identified intrusion vectors, MITRE ATT&CK mapping, and mitigation telemetry"
                rightElement={
                  <span className="text-[11px] font-mono text-slate-400 bg-navy-950 px-2 py-0.5 rounded border border-white/[0.06]">
                    5 Active Vectors
                  </span>
                }
              />

              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse">
                  <thead>
                    <tr className="border-b border-white/[0.04] text-[10px] uppercase font-mono text-slate-400 tracking-wider">
                      <th className="pb-2.5 font-medium">Vector Name</th>
                      <th className="pb-2.5 font-medium">MITRE ID</th>
                      <th className="pb-2.5 font-medium hidden sm:table-cell">Detection Engine</th>
                      <th className="pb-2.5 font-medium text-center">Frequency</th>
                      <th className="pb-2.5 font-medium text-center">Severity</th>
                      <th className="pb-2.5 font-medium text-right">Policy Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-white/[0.03]">
                    {ATTACK_VECTORS.map((v, idx) => (
                      <tr
                        key={idx}
                        className="group hover:bg-white/[0.03] transition-colors duration-150 text-xs"
                      >
                        <td className="py-3 font-semibold text-white group-hover:text-cyan-300 transition">
                          {v.name}
                        </td>
                        <td className="py-3 font-mono text-cyan-400 text-[11px]">
                          {v.mitre}
                        </td>
                        <td className="py-3 text-slate-400 font-mono text-[11px] hidden sm:table-cell">
                          {v.engine}
                        </td>
                        <td className="py-3 text-center">
                          <div className="inline-flex flex-col items-center">
                            <span className="font-mono text-slate-200 text-[11px] font-bold">
                              {v.events} events
                            </span>
                            <div className="w-14 h-1 bg-navy-950 rounded-full overflow-hidden mt-0.5">
                              <div
                                className="h-full bg-cyan-400 rounded-full"
                                style={{ width: `${v.frequencyPct}%` }}
                              />
                            </div>
                          </div>
                        </td>
                        <td className="py-3 text-center">
                          <StatusBadge variant={v.severityVariant} dot={false} size="sm">
                            {v.severity}
                          </StatusBadge>
                        </td>
                        <td className="py-3 text-right">
                          <span className="font-mono text-[11px] text-slate-300">
                            {v.status}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            <div className="pt-3 mt-4 border-t border-white/[0.04] flex items-center justify-between text-xs text-slate-400 font-mono text-[11px]">
              <span>Matrix Sync: Real-Time Stream</span>
              <span className="text-cyan-400">Zero Cloud Egress Active</span>
            </div>
          </GlassCard>
        </div>

        {/* Deception & Honeypot Trap Intelligence (4 cols on lg) */}
        <div className="lg:col-span-4 flex flex-col">
          <GlassCard elevation="l1" className="p-5 flex flex-col justify-between h-full">
            <div>
              <SectionHeader
                icon={Shield}
                title="Active Deception Traps"
                subtitle="High-interaction decoy nodes & canary tokens"
                rightElement={
                  <StatusBadge variant="low" pulse size="sm">
                    DEFENSE ON
                  </StatusBadge>
                }
              />

              <div className="space-y-3">
                {DECEPTION_TRAPS.map((trap, idx) => (
                  <div
                    key={idx}
                    className="p-3 rounded-xl bg-navy-950/70 border border-white/[0.06] hover:border-emerald-500/30 transition space-y-1.5"
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-xs font-bold text-white">
                        {trap.name}
                      </span>
                      <span className="font-mono text-[10px] text-emerald-400 font-semibold px-1.5 py-0.2 rounded bg-emerald-500/10 border border-emerald-500/20">
                        {trap.interactionCount} Trapped
                      </span>
                    </div>

                    <p className="text-[11px] text-slate-400 font-mono">
                      Type: {trap.type}
                    </p>

                    <div className="flex items-center justify-between text-[10px] font-mono text-slate-500 pt-1 border-t border-white/[0.04]">
                      <span>Last: {trap.lastAttacker}</span>
                      <span className="text-emerald-400">{trap.status}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div className="pt-3 mt-4 border-t border-white/[0.04] text-xs text-slate-400 flex items-center justify-between font-mono text-[11px]">
              <span>Honeypot Decoy Fleet: 3 Nodes</span>
              <span className="text-emerald-400">100% Isolated</span>
            </div>
          </GlassCard>
        </div>
      </div>
    </div>
  );
}
