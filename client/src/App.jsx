import React, { useState, useEffect } from "react";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import Sidebar from "./components/Sidebar";
import Header from "./components/Header";
import Dashboard from "./pages/Dashboard";
import ThreatLogs from "./pages/ThreatLogs";
import Analytics from "./pages/Analytics";
import Settings from "./pages/Settings";
import Login from "./pages/Login";
import ToastNotifications from "./components/ToastNotifications";
import QuorumAuthModal from "./components/QuorumAuthModal";
import { EngineProvider, useEngine } from "./context/EngineContext";
import { getToken, onUnauthorized } from "./services/api";
import { api } from "./services/api";
import { aegisWS } from "./services/websocket";

function AppShell() {
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [mobileSidebarOpen, setMobileSidebarOpen] = useState(false);
  const [wsConnected, setWsConnected] = useState(aegisWS.isConnected());
  const [scanning, setScanning] = useState(false);
  const [replaying, setReplaying] = useState(false);
  const { policy } = useEngine();

  useEffect(() => {
    const unsub = aegisWS.subscribe((msg) => {
      if (msg.type === "connected") setWsConnected(true);
      if (msg.type === "disconnected") setWsConnected(false);
    });
    aegisWS.connect(getToken() || "");
    return unsub;
  }, []);

  const handleScan = async () => {
    setScanning(true);
    try {
      await api.triggerScan();
    } catch (e) {
      console.warn(e);
    }
    setTimeout(() => setScanning(false), 2000);
  };

  const handleReplay = async () => {
    setReplaying(true);
    try {
      await api.triggerReplay(4, 1.0);
    } catch (e) {
      console.warn(e);
    }
    setTimeout(() => setReplaying(false), 5000);
  };

  return (
    <div className="flex h-screen overflow-hidden cyber-atmosphere text-slate-100">
      {/* Sidebar with 4 Core Features */}
      <Sidebar
        collapsed={sidebarCollapsed}
        mobileOpen={mobileSidebarOpen}
        onCloseMobile={() => setMobileSidebarOpen(false)}
      />

      {/* Main Content Area */}
      <div className="flex flex-col flex-1 min-w-0 overflow-hidden">
        <Header
          onToggleSidebar={() => {
            if (window.innerWidth < 768) {
              setMobileSidebarOpen((prev) => !prev);
            } else {
              setSidebarCollapsed((prev) => !prev);
            }
          }}
          wsConnected={wsConnected}
          onScan={handleScan}
          scanning={scanning}
          onReplay={handleReplay}
          replaying={replaying}
          containmentMode={policy?.containmentMode || "AUTONOMOUS"}
        />

        <main className="flex-1 overflow-y-auto overflow-x-hidden">
          <Routes>
            {/* 1. Dashboard */}
            <Route path="/" element={<Dashboard />} />
            <Route path="/dashboard" element={<Dashboard />} />

            {/* 2. Log Analysis */}
            <Route path="/logs" element={<ThreatLogs />} />
            <Route path="/log-analysis" element={<ThreatLogs />} />
            <Route path="/threats" element={<ThreatLogs />} />
            <Route path="/incidents" element={<ThreatLogs />} />
            <Route path="/events" element={<ThreatLogs />} />

            {/* 3. Threats Intelligence */}
            <Route path="/threats-intelligence" element={<Analytics />} />
            <Route path="/threat-intel" element={<Analytics />} />
            <Route path="/analytics" element={<Analytics />} />
            <Route path="/reports" element={<Analytics />} />
            <Route path="/attack-explorer" element={<Analytics />} />

            {/* 4. Setting */}
            <Route path="/settings" element={<Settings />} />
            <Route path="/setting" element={<Settings />} />
            <Route path="/system" element={<Settings />} />
            <Route path="/detection-rules" element={<Settings />} />

            {/* Default Catch-all */}
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </main>
      </div>

      {/* Global toast notification stack */}
      <ToastNotifications />

      {/* Cryptographic Action Quorum Modal */}
      <QuorumAuthModal />
    </div>
  );
}

export default function App() {
  const [authed, setAuthed] = useState(!!getToken());
  const [showLoginView, setShowLoginView] = useState(
    () => !getToken() || (typeof window !== "undefined" && window.location.pathname === "/login")
  );

  useEffect(() => {
    return onUnauthorized(() => {
      setAuthed(false);
      setShowLoginView(true);
    });
  }, []);

  if (!authed || showLoginView) {
    return (
      <Login
        onLogin={() => {
          setAuthed(true);
          setShowLoginView(false);
          if (typeof window !== "undefined" && window.location.pathname === "/login") {
            window.history.replaceState({}, "", "/");
          }
        }}
      />
    );
  }

  return (
    <BrowserRouter>
      <EngineProvider>
        <AppShell />
      </EngineProvider>
    </BrowserRouter>
  );
}