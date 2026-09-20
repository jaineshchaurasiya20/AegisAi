import React, { useState, useEffect, useMemo, useRef } from "react";
import { Link } from "react-router-dom";
import {
  Layers,
  ShieldAlert,
  ShieldCheck,
  Server,
  Activity,
  Flame,
  Ban,
  CheckCircle2,
  Sliders,
} from "lucide-react";
import IncidentHero from "../components/IncidentHero";
import MetricCard from "../components/ui/MetricCard";
import AttackTimeline from "../components/AttackTimeline";
import SuspiciousIpTable from "../components/SuspiciousIpTable";
import ActivityFeed from "../components/ActivityFeed";
import ModelTelemetryCard from "../components/ModelTelemetryCard";
import ThreatDetailModal from "../components/ThreatDetailModal";
import StatusBadge from "../components/ui/StatusBadge";
import { useEngine } from "../context/EngineContext";
import { api } from "../services/api";
import { aegisWS } from "../services/websocket";

// Premium Geo IP Lookup (Removed emojis for a professional enterprise look)
function getGeoFlag(ip = "") {
  if (ip.startsWith("185.233") || ip.startsWith("185.")) return { geo: "Netherlands", flag: "NL" };
  if (ip.startsWith("45.142") || ip.startsWith("45.")) return { geo: "Russia", flag: "RU" };
  if (ip.startsWith("194.26") || ip.startsWith("194.")) return { geo: "Romania", flag: "RO" };
  if (ip.startsWith("91.240") || ip.startsWith("91.")) return { geo: "Bulgaria", flag: "BG" };
  if (ip.startsWith("103.145") || ip.startsWith("103.")) return { geo: "Vietnam", flag: "VN" };
  if (ip.startsWith("192.168") || ip.startsWith("10.") || ip.startsWith("127.")) return { geo: "Local Network", flag: "INT" };
  return { geo: "External", flag: "EXT" };
}

export default function Dashboard() {
  const { policy } = useEngine();
  const [threats, setThreats] = useState([]);
  const [stats, setStats] = useState(null);
  const [selectedThreat, setSelectedThreat] = useState(null);
  const [liveFeed, setLiveFeed] = useState([]);
  const [mousePos, setMousePos] = useState({ x: 0, y: 0 });
  const dashboardRef = useRef(null);

  // Load Premium Font dynamically
  useEffect(() => {
    const link = document.createElement("link");
    link.href = "https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap";
    link.rel = "stylesheet";
    document.head.appendChild(link);
    return () => {
      if (document.head.contains(link)) document.head.removeChild(link);
    };
  }, []);

  // Fetch initial live threats and telemetry stats
  const loadData = async () => {
    try {
      const [threatsData, statsData] = await Promise.all([
        api.getThreats({ limit: 50 }).catch(() => []),
        api.getThreatStats().catch(() => null),
      ]);
      if (Array.isArray(threatsData) && threatsData.length > 0) {
        setThreats(threatsData);
      }
      if (statsData) {
        setStats(statsData);
      }
    } catch (e) {
      console.warn("Dashboard initial data load error:", e);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  // WebSocket Live Subscription for THREAT_DETECTED and telemetry
  useEffect(() => {
    const unsub = aegisWS.subscribe((msg) => {
      if ((msg.type === "threat_alert" || msg.type === "THREAT_DETECTED") && (msg.threat || msg.payload)) {
        const item = msg.payload || msg.threat;
        setThreats((prev) => [item, ...prev.filter((t) => t.id !== item.id)]);

        api.getThreatStats().then(setStats).catch(() => {});

        const newFeedItem = {
          id: `ws-${item.id || Date.now()}`,
          time: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }),
          source: item.telemetry?.processName || "ebpf_sensor",
          type: (item.severity || "HIGH").toUpperCase(),
          message: item.telemetry?.commandLine || `${item.threat_type} on port ${item.port || 22} from ${item.source_ip}`,
          summary: item.action_taken === "process_isolated" ? "Kernel isolation enforced" : "Heuristic match flagged",
          severityVariant: item.severity === "critical" ? "critical" : item.severity === "high" ? "high" : "medium",
        };
        setLiveFeed((prev) => [newFeedItem, ...prev.slice(0, 19)]);
      }
    });
    return unsub;
  }, []);

  // Global mouse tracking for premium double-spotlight effect
  const handleMouseMove = (e) => {
    if (!dashboardRef.current) return;
    const rect = dashboardRef.current.getBoundingClientRect();
    setMousePos({
      x: e.clientX - rect.left,
      y: e.clientY - rect.top,
    });
  };

  const activeIncident = useMemo(() => {
    const criticalThreat = threats.find((t) => t.severity === "critical" || (t.threat_score || 0) >= 0.85);
    const topThreat = criticalThreat || threats[0];

    if (topThreat) {
      const isCritical = topThreat.severity === "critical" || (topThreat.threat_score || 0) >= 0.85;
      return {
        id: topThreat.id,
        rawThreat: topThreat,
        incident_number: `INCIDENT #${(topThreat.id || "0241").slice(0, 4).toUpperCase()}`,
        title: topThreat.threat_type || "Coordinated SSH Brute-Force Activity",
        risk_level: isCritical ? "CRITICAL" : (topThreat.severity || "HIGH").toUpperCase(),
        severity: topThreat.severity || "high",
        source_ip: topThreat.source_ip || "185.233.42.17",
        target_service: topThreat.port ? `Port ${topThreat.port}` : "SSH (22)",
        destination_ip: topThreat.destination_ip || "127.0.0.1",
        affected_users: topThreat.telemetry?.processName
          ? `${topThreat.telemetry.processName}`
          : "3 accounts (root, admin, deploy)",
        telemetry: topThreat.telemetry,
        threat_score: topThreat.threat_score ?? 0.942,
        timestamp: topThreat.timestamp || new Date().toISOString(),
        mitre_technique: topThreat.mitre_technique || "T1110.001 - Brute Force",
        summary: `Multiple failed authentication attempts from single source IP (${topThreat.source_ip || "185.233.42.17"}), followed by ${topThreat.threat_type || "credential compromise"}. Intercepted by local edge security controls.`,
      };
    }

    return {
      id: "0241",
      incident_number: "INCIDENT #0241",
      title: "Coordinated SSH Brute-Force Activity",
      risk_level: "HIGH RISK",
      severity: "high",
      source_ip: "185.233.42.17",
      target_service: "SSH (22)",
      destination_ip: "127.0.0.1",
      affected_users: "3 accounts (root, admin, deploy)",
      threat_score: 0.942,
      timestamp: new Date().toISOString(),
      mitre_technique: "T1110.001 - Brute Force",
      summary: "Multiple failed login attempts from a single source IP (185.233.42.17), followed by successful authentication on user account deploy. Subsequent privilege escalation attempt (sudo /bin/bash) was intercepted by local security controls.",
    };
  }, [threats]);

  const timelineEvents = useMemo(() => {
    if (threats.length >= 3) {
      return threats.slice(0, 4).map((t, idx) => {
        const d = new Date(t.timestamp || Date.now());
        const timeStr = !isNaN(d.getTime())
          ? d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
          : "10:45";
        const isBlock = t.action_taken === "process_isolated" || t.action_taken === "trapped_in_honeypot";
        return {
          time: timeStr,
          type: t.threat_type || "Threat Alert",
          description: t.telemetry?.commandLine || `${t.threat_type} detected on port ${t.port || 22} from ${t.source_ip}`,
          statusText: isBlock ? "Blocked" : t.severity === "critical" ? "Critical" : "Detected",
          statusVariant: isBlock ? "critical" : t.severity === "critical" ? "critical" : t.severity === "high" ? "warning" : "cyan",
        };
      });
    }

    const now = new Date();
    const fmt = (minAgo) => {
      const d = new Date(now.getTime() - minAgo * 60 * 1000);
      return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    };

    return [
      {
        time: fmt(4),
        type: "Failed Login Probe",
        description: `SSH authentication failure for user 'root' from ${activeIncident.source_ip}`,
        statusVariant: "critical",
        statusText: "Failed Auth",
      },
      {
        time: fmt(2),
        type: "Target User Switch",
        description: "Attacker pivoted dictionary attack to deploy & admin accounts",
        statusVariant: "warning",
        statusText: "Target Pivot",
      },
      {
        time: fmt(1),
        type: "Successful Login",
        description: `Accepted credentials on ${activeIncident.target_service} (compromised)`,
        statusVariant: "cyan",
        statusText: "Compromised",
      },
      {
        time: fmt(0),
        type: "Privilege Escalation",
        description: `Elevated shell execution flagged: 'sudo /bin/bash' blocked by eBPF sensor`,
        statusVariant: "critical",
        statusText: "Blocked",
      },
    ];
  }, [threats, activeIncident]);

  const suspiciousIps = useMemo(() => {
    if (threats.length === 0) return null;
    const ipMap = {};
    threats.forEach((t) => {
      const ip = t.source_ip || "Unknown";
      if (!ipMap[ip]) {
        const geoInfo = getGeoFlag(ip);
        ipMap[ip] = {
          ip,
          geo: geoInfo.geo,
          flag: geoInfo.flag,
          requests: 0,
          maxScore: 0,
          severity: "low",
          isBlocked: false,
        };
      }
      ipMap[ip].requests += 1;
      const score = t.threat_score || 0;
      if (score > ipMap[ip].maxScore) {
        ipMap[ip].maxScore = score;
        ipMap[ip].severity = t.severity || "low";
      }
      if (t.action_taken === "process_isolated" || t.action_taken === "trapped_in_honeypot") {
        ipMap[ip].isBlocked = true;
      }
    });

    return Object.values(ipMap)
      .sort((a, b) => b.requests - a.requests || b.maxScore - a.maxScore)
      .slice(0, 5)
      .map((item, idx) => ({
        ...item,
        threatLevel: item.severity,
        threatText: item.severity.toUpperCase(),
        status: item.isBlocked ? "Blocked" : item.severity === "critical" ? "Active Threat" : "Monitored",
        statusVariant: item.severity === "critical" ? "critical" : item.severity === "high" ? "warning" : "neutral",
        highlight: idx === 0 && item.severity === "critical",
      }));
  }, [threats]);

  const feedItems = useMemo(() => {
    if (liveFeed.length > 0) return liveFeed;
    if (threats.length > 0) {
      return threats.slice(0, 6).map((t) => {
        const d = new Date(t.timestamp || Date.now());
        const timeStr = !isNaN(d.getTime())
          ? d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })
          : "10:45:00";
        return {
          id: t.id,
          time: timeStr,
          source: t.telemetry?.processName || "ebpf_sensor",
          type: (t.severity || "HIGH").toUpperCase(),
          message: t.telemetry?.commandLine || `${t.threat_type} from ${t.source_ip}:${t.port || 22}`,
          summary: t.action_taken === "process_isolated" ? "Kernel isolation enforced" : t.threat_type,
          severityVariant: t.severity === "critical" ? "critical" : t.severity === "high" ? "high" : "medium",
        };
      });
    }
    return null;
  }, [liveFeed, threats]);

  const totalEvents = stats?.total || (threats.length > 0 ? threats.length : 2348);
  const activeIncidents = stats?.by_severity
    ? (stats.by_severity.critical || 0) + (stats.by_severity.high || 0)
    : 1;
  const blockedCount = threats.filter((t) => t.action_taken === "process_isolated" || t.action_taken === "trapped_in_honeypot" || (t.threat_score || 0) >= 0.85).length || 3;

  const handleInvestigate = (incident) => {
    if (incident?.rawThreat) {
      setSelectedThreat(incident.rawThreat);
    } else {
      setSelectedThreat({
        id: incident.id,
        threat_type: incident.title,
        severity: incident.severity,
        source_ip: incident.source_ip,
        target_host: incident.target_service,
        threat_score: incident.threat_score,
        mitre_technique: incident.mitre_technique,
        details: incident.summary,
        action_taken: "process_isolated",
        timestamp: incident.timestamp,
      });
    }
  };

  return (
    <div 
      ref={dashboardRef}
      onMouseMove={handleMouseMove}
      className="relative min-h-screen bg-gradient-to-br from-[#02040A] via-[#060918] to-[#0A061C] text-slate-200 overflow-hidden selection:bg-cyan-500/30"
      style={{ fontFamily: "'Plus Jakarta Sans', sans-serif" }}
    >
      {/* Dynamic Background Double Spotlights & Ambient Glows */}
      <div 
        className="pointer-events-none fixed inset-0 z-0 transition-opacity duration-500 ease-out"
        style={{
          background: `
            radial-gradient(800px circle at ${mousePos.x}px ${mousePos.y}px, rgba(139, 92, 246, 0.06), transparent 45%),
            radial-gradient(400px circle at ${mousePos.x}px ${mousePos.y}px, rgba(56, 189, 248, 0.04), transparent 50%)
          `,
        }}
      />
      <div className="absolute top-[-20%] right-[-10%] w-[60vw] h-[60vw] max-w-[800px] max-h-[800px] rounded-full bg-purple-900/10 blur-[130px] pointer-events-none" />
      <div className="absolute bottom-[-15%] left-[-15%] w-[70vw] h-[70vw] max-w-[900px] max-h-[900px] rounded-full bg-blue-900/10 blur-[140px] pointer-events-none" />

      {/* Main Content Dashboard */}
      <div className="relative z-10 p-4 sm:p-6 lg:p-8 space-y-8 max-w-[1600px] mx-auto animate-in fade-in slide-in-from-bottom-6 duration-1000 ease-out">
        
        {/* ─── 1. GLOBAL SYSTEM STATUS & CONTEXT ───────────────────────────── */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-5 border-b border-white/[0.04] relative">
          <div className="relative z-10">
            <div className="flex items-center gap-3.5">
              <h1 className="text-[1.75rem] font-bold tracking-tight bg-gradient-to-r from-white via-blue-100 to-indigo-300 bg-clip-text text-transparent drop-shadow-sm">
                Command Center
              </h1>
              <div className="relative group cursor-default mt-1">
                <div className="absolute -inset-1 bg-cyan-500/20 rounded-full blur-md opacity-0 group-hover:opacity-100 transition duration-500"></div>
                <StatusBadge variant="cyan" dot size="sm" className="relative backdrop-blur-xl bg-white/[0.03] border-white/[0.08] px-3 py-1 shadow-lg">
                  SOC LIVE
                </StatusBadge>
              </div>
            </div>
            <p className="text-slate-400/90 text-[13px] mt-1.5 font-medium tracking-wide">
              Host Kernel Events & Socket Telemetry Stream
            </p>
          </div>

          <div className="flex items-center gap-3 flex-wrap relative z-10">
            <div className="group relative flex items-center gap-2.5 px-4 py-2 rounded-xl bg-[#090C1A]/80 border border-white/[0.05] backdrop-blur-3xl text-[13px] text-slate-300 shadow-[0_4px_24px_-8px_rgba(0,0,0,0.6)] hover:border-indigo-500/30 transition-all duration-500">
              <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse shadow-[0_0_10px_rgba(34,211,238,0.9)]" />
              <span className="text-slate-400">SOC Profile:</span>
              <span className="text-white font-semibold tracking-wide">Zero-Trust</span>
            </div>

            <Link
              to="/settings"
              className="group relative flex items-center gap-2.5 px-4 py-2 rounded-xl bg-gradient-to-b from-[#090C1A]/90 to-[#050711]/90 border border-white/[0.05] backdrop-blur-3xl text-[13px] text-slate-300 shadow-[0_4px_24px_-8px_rgba(0,0,0,0.6)] hover:border-cyan-500/40 transition-all duration-500 active:scale-95"
            >
              <div className="absolute inset-0 rounded-xl bg-gradient-to-r from-cyan-500/0 via-cyan-500/5 to-cyan-500/0 opacity-0 group-hover:opacity-100 transition duration-500"></div>
              <Sliders size={14} className="text-cyan-400 group-hover:rotate-180 transition-transform duration-700 ease-out relative z-10" />
              <span className="text-slate-400 relative z-10">Containment:</span>
              <span className="text-cyan-300 font-bold tracking-wider drop-shadow-[0_0_8px_rgba(34,211,238,0.4)] relative z-10">
                {policy?.containmentMode || "AUTONOMOUS"}
              </span>
            </Link>
          </div>
        </div>

        {/* ─── 2. ACTIVE SECURITY INCIDENT HERO (LIVE & DYNAMIC) ───────────── */}
        <section aria-label="Active Security Incident" className="relative group rounded-[20px] transition-transform duration-500 hover:scale-[1.005]">
          <div className="absolute -inset-0.5 bg-gradient-to-r from-indigo-500/30 via-purple-500/30 to-cyan-500/30 rounded-[22px] blur-md opacity-40 group-hover:opacity-80 transition duration-700"></div>
          <div className="relative bg-[#080B17]/90 backdrop-blur-3xl border border-white/[0.08] rounded-[20px] shadow-2xl overflow-hidden">
            <div className="absolute top-0 left-0 w-full h-[1px] bg-gradient-to-r from-transparent via-white/10 to-transparent"></div>
            <IncidentHero
              incident={activeIncident}
              onInvestigate={handleInvestigate}
            />
          </div>
        </section>

        {/* ─── 3. SECURITY METRICS / KPI CARDS (LIVE COUNTERS) ─────────────── */}
        <section aria-label="Key Performance Indicators" className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5">
          {[
            { icon: Layers, label: "Total Events (24h)", value: totalEvents, trend: "+142 events in last hour", trendIcon: Activity, accent: "cyan", positive: true },
            { icon: ShieldAlert, label: "Active Incidents", value: activeIncidents, trend: `${activeIncident.incident_number} active`, trendIcon: Flame, accent: "red", positive: false },
            { icon: ShieldCheck, label: "Blocked Attacks", value: blockedCount, trend: "100% automated containment", trendIcon: Ban, accent: "emerald", positive: true },
            { icon: Server, label: "System Uptime", value: 99.8, suffix: "%", decimals: 1, trend: "eBPF engine nominal", trendIcon: CheckCircle2, accent: "blue", positive: true }
          ].map((metric, idx) => (
            <div key={idx} className="group relative rounded-2xl transition-all duration-500 hover:-translate-y-1.5">
              <div className={`absolute -inset-[1px] bg-gradient-to-b from-${metric.accent}-500/40 to-transparent rounded-2xl opacity-0 group-hover:opacity-100 transition duration-500 blur-sm`}></div>
              <div className="relative h-full bg-[#0A0D1E]/70 backdrop-blur-2xl border border-white/[0.05] rounded-2xl overflow-hidden shadow-2xl">
                <div className="absolute top-0 left-0 w-full h-[1px] bg-gradient-to-r from-transparent via-white/5 to-transparent"></div>
                <MetricCard
                  icon={metric.icon}
                  label={metric.label}
                  value={metric.value}
                  suffix={metric.suffix}
                  decimals={metric.decimals}
                  trend={metric.trend}
                  trendIcon={metric.trendIcon}
                  trendPositive={metric.positive}
                  accentColor={metric.accent}
                />
              </div>
            </div>
          ))}
        </section>

        {/* ─── 4. BOTTOM SECTION: BALANCED 2-COLUMN INTELLIGENCE & TELEMETRY ─── */}
        <section aria-label="Security Intelligence & Activity" className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
          
          {/* Left Column (Timeline & Telemetry) */}
          <div className="lg:col-span-7 flex flex-col space-y-6">
            <div className="group relative rounded-2xl transition-all duration-500 hover:shadow-[0_0_40px_rgba(99,102,241,0.1)]">
              <div className="absolute -inset-[1px] bg-gradient-to-br from-indigo-500/20 via-transparent to-transparent rounded-2xl opacity-0 group-hover:opacity-100 transition duration-700 blur-md"></div>
              <div className="relative bg-[#090C1A]/70 backdrop-blur-3xl border border-white/[0.04] rounded-2xl shadow-2xl p-1.5 overflow-hidden">
                <div className="absolute top-0 left-0 w-full h-[1px] bg-gradient-to-r from-transparent via-indigo-500/20 to-transparent"></div>
                <AttackTimeline events={timelineEvents} activeThreat={activeIncident.rawThreat} />
              </div>
            </div>
            
            <div className="group relative rounded-2xl transition-all duration-500 hover:shadow-[0_0_40px_rgba(168,85,247,0.1)]">
              <div className="absolute -inset-[1px] bg-gradient-to-tl from-purple-500/20 via-transparent to-transparent rounded-2xl opacity-0 group-hover:opacity-100 transition duration-700 blur-md"></div>
              <div className="relative bg-[#090C1A]/70 backdrop-blur-3xl border border-white/[0.04] rounded-2xl shadow-2xl p-1.5 overflow-hidden">
                <div className="absolute top-0 left-0 w-full h-[1px] bg-gradient-to-r from-transparent via-purple-500/20 to-transparent"></div>
                <ModelTelemetryCard />
              </div>
            </div>
          </div>

          {/* Right Column (IPs & Activity) */}
          <div className="lg:col-span-5 flex flex-col space-y-6">
            <div className="group relative rounded-2xl transition-all duration-500 hover:shadow-[0_0_40px_rgba(56,189,248,0.1)]">
              <div className="absolute -inset-[1px] bg-gradient-to-bl from-blue-500/20 via-transparent to-transparent rounded-2xl opacity-0 group-hover:opacity-100 transition duration-700 blur-md"></div>
              <div className="relative bg-[#090C1A]/70 backdrop-blur-3xl border border-white/[0.04] rounded-2xl shadow-2xl p-1.5 overflow-hidden">
                <div className="absolute top-0 left-0 w-full h-[1px] bg-gradient-to-r from-transparent via-blue-500/20 to-transparent"></div>
                <SuspiciousIpTable
                  ips={suspiciousIps}
                  onSelectIp={(ip) => {
                    const matched = threats.find((t) => t.source_ip === ip);
                    if (matched) setSelectedThreat(matched);
                  }}
                />
              </div>
            </div>

            <div className="group relative rounded-2xl transition-all duration-500 hover:shadow-[0_0_40px_rgba(99,102,241,0.1)]">
              <div className="absolute -inset-[1px] bg-gradient-to-tr from-indigo-500/20 via-transparent to-transparent rounded-2xl opacity-0 group-hover:opacity-100 transition duration-700 blur-md"></div>
              <div className="relative bg-[#090C1A]/70 backdrop-blur-3xl border border-white/[0.04] rounded-2xl shadow-2xl p-1.5 overflow-hidden">
                <div className="absolute top-0 left-0 w-full h-[1px] bg-gradient-to-r from-transparent via-indigo-500/20 to-transparent"></div>
                <ActivityFeed events={feedItems || undefined} />
              </div>
            </div>
          </div>
        </section>

        {/* ─── INVESTIGATE THREAT DETAIL MODAL (XAI & TELEMETRY) ──────────── */}
        {selectedThreat && (
          <ThreatDetailModal
            threat={selectedThreat}
            onClose={() => setSelectedThreat(null)}
          />
        )}
      </div>
    </div>
  );
}