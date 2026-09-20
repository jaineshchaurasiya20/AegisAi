import React, { useState } from "react";
import { Link } from "react-router-dom";
import {
  Menu,
  Bell,
  Wifi,
  WifiOff,
  User,
  LogOut,
  RefreshCw,
  Terminal,
  ShieldAlert,
  Check,
} from "lucide-react";
import Button from "./ui/Button";

export default function Header({
  onToggleSidebar,
  wsConnected,
  onScan,
  scanning,
}) {
  const [showUser, setShowUser] = useState(false);
  const [showNotifications, setShowNotifications] = useState(false);
  const [localSpinning, setLocalSpinning] = useState(false);
  const [unreadCount, setUnreadCount] = useState(2);
  const [notifications, setNotifications] = useState([
    {
      id: "notif-1",
      title: "Zero-Day Memory Injection Intercepted",
      desc: "Reflective DLL execution detected on port 4444. Auto-isolation rule executed.",
      time: "2m ago",
      severity: "critical",
      read: false,
    },
    {
      id: "notif-2",
      title: "Coordinated SSH Spray Flagged",
      desc: "14 failed authentication attempts from 185.233.42.17 exceeded threshold.",
      time: "8m ago",
      severity: "high",
      read: false,
    },
    {
      id: "notif-3",
      title: "S3 WORM Vault State Sealed",
      desc: "SHA-256 telemetry ledger committed to AWS S3 Object-Locked bucket.",
      time: "25m ago",
      severity: "info",
      read: true,
    },
  ]);

  const handleMarkAllRead = () => {
    setNotifications((prev) => prev.map((n) => ({ ...n, read: true })));
    setUnreadCount(0);
  };

  const handleScanClick = (e) => {
    setLocalSpinning(true);
    setTimeout(() => setLocalSpinning(false), 2200);
    if (onScan) onScan(e);
  };

  const isScanning = scanning || localSpinning;

  return (
    <header className="flex items-center justify-between h-14 px-4 sm:px-6 bg-navy-900/80 backdrop-blur-md border-b border-white/[0.06] z-30 sticky top-0 select-none font-sans">
      {/* Left: Sidebar Toggle + Streamlined View Context (Unified font) */}
      <div className="flex items-center gap-3">
        <button
          id="sidebar-toggle"
          onClick={onToggleSidebar}
          className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-white/[0.06] border border-transparent hover:border-white/[0.08] transition focus-visible:outline-none"
          aria-label="Toggle navigation sidebar"
        >
          <Menu size={17} />
        </button>

        <div className="flex items-center gap-2 text-xs text-slate-400 font-normal">
          <Terminal size={13} className="text-cyan-400" />
          <span className="text-slate-500 hidden sm:inline font-normal">CONSOLE /</span>
          <span className="text-cyan-300 font-medium tracking-wide">LIVE MONITOR</span>
        </div>
      </div>

      {/* Center / Operational Status Streamlined Badges (Unified font & accurate technical tooltips) */}
      <div className="hidden md:flex items-center gap-2.5 text-xs">
        {/* System Operational Indicator */}
        <div
          className="flex items-center gap-2 px-2.5 py-1 rounded-md bg-navy-950/60 border border-white/[0.04] text-slate-300 text-xs font-normal cursor-help"
          title="eBPF host sensors & ONNX inference runtime active"
        >
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-subtle-pulse" />
          <span className="text-slate-400 font-normal">SYSTEM:</span>
          <span className="text-emerald-300 font-medium">OPERATIONAL</span>
        </div>

        {/* AWS EventBridge Fleet Sync */}
        <div
          className="flex items-center gap-2 px-2.5 py-1 rounded-md bg-navy-950/60 border border-white/[0.04] text-slate-300 text-xs font-normal cursor-help"
          title="Connected to aegisai.deception event bus"
        >
          <span className="w-1.5 h-1.5 rounded-full bg-amber-400" />
          <span className="text-slate-400 font-normal">EVENTBRIDGE:</span>
          <span className="text-slate-200 font-medium">SYNCED</span>
        </div>

        {/* S3 WORM Vault Active */}
        <div
          className="flex items-center gap-2 px-2.5 py-1 rounded-md bg-navy-950/60 border border-white/[0.04] text-slate-300 text-xs font-normal cursor-help"
          title="AWS S3 Object Lock COMPLIANCE mode enabled (7-day retention)"
        >
          <span className="w-1.5 h-1.5 rounded-full bg-cyan-400" />
          <span className="text-slate-400 font-normal">WORM VAULT:</span>
          <span className="text-cyan-300 font-medium">ACTIVE</span>
        </div>
      </div>

      {/* Right: Actions & User Profile */}
      <div className="flex items-center gap-2 sm:gap-2.5">
        {/* Run Scan Button with live rotation on click */}
        <Button
          id="manual-scan-btn"
          variant="secondary"
          size="xs"
          onClick={handleScanClick}
          disabled={isScanning}
          icon={RefreshCw}
          iconClassName={isScanning ? "animate-spin text-cyan-400" : "transition-transform duration-300 group-hover:rotate-90"}
        >
          {isScanning ? "Scanning..." : "Run Scan"}
        </Button>

        {/* WebSocket Status Indicator */}
        <div
          id="ws-status"
          className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-navy-950/70 border border-white/[0.06] text-xs font-medium"
        >
          {wsConnected ? (
            <>
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-subtle-pulse" />
              <span className="text-emerald-400 font-medium hidden sm:inline">Live</span>
            </>
          ) : (
            <>
              <span className="w-1.5 h-1.5 rounded-full bg-red-400" />
              <span className="text-red-400 font-medium hidden sm:inline">Offline</span>
            </>
          )}
        </div>

        {/* Notifications Popover */}
        <div className="relative">
          <button
            id="notifications-btn"
            onClick={() => {
              setShowNotifications(!showNotifications);
              setShowUser(false);
            }}
            className="relative p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-white/[0.06] transition focus-visible:outline-none"
            aria-label="Security Notifications"
          >
            <Bell size={16} />
            {unreadCount > 0 && (
              <span className="absolute top-1 right-1 w-2 h-2 bg-red-500 rounded-full animate-pulse border border-navy-950" />
            )}
          </button>

          {showNotifications && (
            <div className="absolute right-0 top-10 w-80 sm:w-96 bg-navy-850/95 backdrop-blur-xl border border-white/[0.1] rounded-xl py-2 z-50 shadow-2xl shadow-black/70 animate-fade-in font-sans">
              <div className="flex items-center justify-between px-3.5 py-2 border-b border-white/[0.06]">
                <div className="flex items-center gap-2">
                  <span className="font-bold text-xs text-white">Security Alerts</span>
                  {unreadCount > 0 && (
                    <span className="text-[10px] font-mono font-bold px-1.5 py-0.2 rounded bg-red-500/20 text-red-400 border border-red-500/30">
                      {unreadCount} new
                    </span>
                  )}
                </div>
                {unreadCount > 0 && (
                  <button
                    onClick={handleMarkAllRead}
                    className="text-[11px] text-cyan-400 hover:text-cyan-300 font-medium transition"
                  >
                    Mark all read
                  </button>
                )}
              </div>

              <div className="max-h-72 overflow-y-auto divide-y divide-white/[0.04]">
                {notifications.map((n) => (
                  <div
                    key={n.id}
                    className={`p-3 hover:bg-white/[0.03] transition flex items-start gap-2.5 ${
                      !n.read ? "bg-cyan-500/[0.04]" : ""
                    }`}
                  >
                    <span
                      className={`w-2 h-2 rounded-full mt-1.5 flex-shrink-0 ${
                        n.severity === "critical"
                          ? "bg-red-500 shadow-[0_0_8px_#ef4444]"
                          : n.severity === "high"
                          ? "bg-amber-400"
                          : "bg-cyan-400"
                      }`}
                    />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center justify-between gap-1 mb-0.5">
                        <p className="text-xs font-semibold text-white truncate">{n.title}</p>
                        <span className="text-[10px] text-slate-500 font-mono whitespace-nowrap">{n.time}</span>
                      </div>
                      <p className="text-[11px] text-slate-400 leading-snug">{n.desc}</p>
                    </div>
                  </div>
                ))}
              </div>

              <div className="px-3.5 pt-2 pb-1 border-t border-white/[0.06] text-center">
                <Link
                  to="/logs"
                  onClick={() => setShowNotifications(false)}
                  className="text-[11px] text-cyan-400 hover:text-cyan-300 font-semibold block transition"
                >
                  View full security log stream →
                </Link>
              </div>
            </div>
          )}
        </div>

        {/* User Menu */}
        <div className="relative">
          <button
            id="user-menu-btn"
            onClick={() => setShowUser(!showUser)}
            className="flex items-center gap-2 p-1 rounded-lg hover:bg-white/[0.06] transition focus-visible:outline-none"
          >
            <div className="w-6 h-6 rounded-full bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center text-white text-[11px] font-bold">
              <User size={12} />
            </div>
            <span className="text-xs font-medium text-slate-300 hidden md:block">sec_admin</span>
          </button>

          {showUser && (
            <div className="absolute right-0 top-10 w-48 bg-navy-850/95 backdrop-blur-xl border border-white/[0.1] rounded-xl py-1.5 z-50 shadow-xl shadow-black/50">
              <div className="px-3 py-2 border-b border-white/[0.06]">
                <p className="font-semibold text-xs text-white">Security Admin</p>
                <p className="text-slate-400 font-mono text-[10px] truncate">admin@aegis-edr.local</p>
              </div>
              <button
                id="logout-btn"
                onClick={() => {
                  localStorage.removeItem("aegis_token");
                  window.location.reload();
                }}
                className="flex items-center gap-2 w-full px-3 py-2 text-xs text-red-400 hover:bg-red-500/10 transition"
              >
                <LogOut size={13} />
                <span>Sign Out</span>
              </button>
            </div>
          )}
        </div>
      </div>
    </header>
  );
}
