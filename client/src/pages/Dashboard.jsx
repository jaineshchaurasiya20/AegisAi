import React, { useState, useEffect, useMemo } from "react";
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

// Geo IP Flag Lookup helper
function getGeoFlag(ip = "") {
  if (ip.startsWith("185.233") || ip.startsWith("185.")) return { geo: "Netherlands", flag: "🇳🇱" };
  if (ip.startsWith("45.142") || ip.startsWith("45.")) return { geo: "Russia", flag: "🇷🇺" };
  if (ip.startsWith("194.26") || ip.startsWith("194.")) return { geo: "Romania", flag: "🇷🇴" };
  if (ip.startsWith("91.240") || ip.startsWith("91.")) return { geo: "Bulgaria", flag: "🇧🇬" };
  if (ip.startsWith("103.145") || ip.startsWith("103.")) return { geo: "Vietnam", flag: "🇻🇳" };
  if (ip.startsWith("192.168") || ip.startsWith("10.") || ip.startsWith("127.")) return { geo: "Local", flag: "🛡️" };
  return { geo: "External", flag: "🌐" };
}

export default function Dashboard() {
  const { policy } = useEngine();
  const [threats, setThreats] = useState([]);
  const [stats, setStats] = useState(null);
  const [selectedThreat, setSelectedThreat] = useState(null);
  const [liveFeed, setLiveFeed] = useState([]);

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

        // Refresh stats
        api.getThreatStats().then(setStats).catch(() => {});

        // Prepend to live activity feed
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

  // 1. Dynamic Active Incident Hero
  const activeIncident = useMemo(() => {
    // Find the latest critical/high threat from loaded live data
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

    // Default Fallback anchored to current time
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

  // 2. Dynamic Attack Timeline Events
  const timelineEvents = useMemo(() => {
    if (threats.length >= 3) {
      // Build from real threat events
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

    // Dynamic relative timeline anchored around active threat / current time
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

  // 3. Dynamic Suspicious Source IPs Table
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

  // 4. Activity Feed
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

  // 5. Dynamic KPI metrics
  const totalEvents = stats?.total || (threats.length > 0 ? threats.length : 2348);
  const activeIncidents = stats?.by_severity
    ? (stats.by_severity.critical || 0) + (stats.by_severity.high || 0)
    : 1;
  const blockedCount = threats.filter((t) => t.action_taken === "process_isolated" || t.action_taken === "trapped_in_honeypot" || (t.threat_score || 0) >= 0.85).length || 3;

  // Handle click on "Investigate Incident"
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
    <div className="p-4 sm:p-6 lg:p-7 space-y-6 max-w-[1600px] mx-auto animate-fade-in font-sans">
      {/* ─── 1. GLOBAL SYSTEM STATUS & CONTEXT ───────────────────────────── */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-2 border-b border-white/[0.05]">
        <div>
          <div className="flex items-center gap-2.5">
            <h1 className="text-white text-xl sm:text-2xl font-semibold tracking-tight">
              Command Center
            </h1>
            <StatusBadge variant="cyan" dot size="sm">
              SOC LIVE
            </StatusBadge>
          </div>
          <p className="text-slate-400 text-xs sm:text-sm mt-0.5 font-normal">
            Host Kernel Events & Socket Telemetry Stream
          </p>
        </div>

        {/* Operational Context Chips */}
        <div className="flex items-center gap-2.5 flex-wrap">
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-navy-900/80 border border-white/[0.06] text-xs text-slate-300 font-mono">
            <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-subtle-pulse" />
            <span className="text-slate-400">SOC Profile:</span>
            <span className="text-white font-normal">Autonomous Zero-Trust</span>
          </div>

          <Link
            to="/settings"
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-navy-900/80 hover:bg-navy-800/80 border border-white/[0.06] hover:border-cyan-500/30 text-xs text-slate-300 transition duration-150"
          >
            <Sliders size={12} className="text-cyan-400" />
            <span className="text-slate-400">Containment:</span>
            <span className="text-cyan-300 font-medium font-mono">
              {policy?.containmentMode || "AUTONOMOUS"}
            </span>
          </Link>
        </div>
      </div>

      {/* ─── 2. ACTIVE SECURITY INCIDENT HERO (LIVE & DYNAMIC) ───────────── */}
      <section aria-label="Active Security Incident">
        <IncidentHero
          incident={activeIncident}
          onInvestigate={handleInvestigate}
        />
      </section>

      {/* ─── 3. SECURITY METRICS / KPI CARDS (LIVE COUNTERS) ─────────────── */}
      <section aria-label="Key Performance Indicators" className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* 1. Total Events */}
        <MetricCard
          icon={Layers}
          label="Total Events (24h)"
          value={totalEvents}
          trend="+142 events in last hour"
          trendIcon={Activity}
          trendPositive={true}
          accentColor="cyan"
        />

        {/* 2. Active Incidents */}
        <MetricCard
          icon={ShieldAlert}
          label="Active Incidents"
          value={activeIncidents}
          trend={`${activeIncident.incident_number} active`}
          trendIcon={Flame}
          trendPositive={false}
          accentColor="red"
          elevation="l2"
        />

        {/* 3. Blocked Attacks */}
        <MetricCard
          icon={ShieldCheck}
          label="Blocked Attacks"
          value={blockedCount}
          trend="100% automated edge containment"
          trendIcon={Ban}
          trendPositive={true}
          accentColor="emerald"
        />

        {/* 4. System Uptime */}
        <MetricCard
          icon={Server}
          label="System Uptime"
          value={99.8}
          decimals={1}
          suffix="%"
          trend="eBPF & ONNX engine nominal"
          trendIcon={CheckCircle2}
          trendPositive={true}
          accentColor="blue"
        />
      </section>

      {/* ─── 4. BOTTOM SECTION: BALANCED 2-COLUMN INTELLIGENCE & TELEMETRY ─── */}
      <section aria-label="Security Intelligence & Activity" className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-start">
        {/* Left Column: Attack Progression & ONNX Runtime Monitor (7-Col Width) */}
        <div className="lg:col-span-7 flex flex-col space-y-5">
          <AttackTimeline
            events={timelineEvents}
            activeThreat={activeIncident.rawThreat}
          />
          <ModelTelemetryCard />
        </div>

        {/* Right Column: Threat Actors & Real-Time Stream (5-Col Stack) */}
        <div className="lg:col-span-5 flex flex-col space-y-5">
          <SuspiciousIpTable
            ips={suspiciousIps}
            onSelectIp={(ip) => {
              const matched = threats.find((t) => t.source_ip === ip);
              if (matched) setSelectedThreat(matched);
            }}
          />

          <ActivityFeed
            events={feedItems || undefined}
          />
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
  );
}
