/**
 * EngineContext — Global state for:
 *  - Engine policy (MANUAL / AUTONOMOUS mode, threshold, auto-action toggles)
 *  - Toast notification queue
 *  - Containment action dispatcher
 *
 * Wrap <App> with <EngineProvider> and consume via useEngine() hook.
 */
import React, { createContext, useContext, useState, useCallback, useRef, useEffect } from "react";
import { api } from "../services/api";
import { aegisWS } from "../services/websocket";

const EngineContext = createContext(null);

const DEFAULT_POLICY = {
  containmentMode: "MANUAL",      // "MANUAL" | "AUTONOMOUS"
  autoContainThreshold: 0.85,
  enableAutoProcessKill: false,
  enableAutoHostIsolation: false,
  enableAutoQuarantine: false,
};

let _toastId = 0;

export function EngineProvider({ children }) {
  const [policy, setPolicy]   = useState(DEFAULT_POLICY);
  const [toasts, setToasts]   = useState([]);
  const timerRefs             = useRef({});
  const policyRef             = useRef(policy);
  const lastAutoExecRef       = useRef(0);

  useEffect(() => {
    policyRef.current = policy;
  }, [policy]);

  /* ── Load policy from backend on mount ─────────────────────────────── */
  const loadPolicy = useCallback(async () => {
    try {
      const data = await api.getPolicy();
      if (data && typeof data === "object") {
        setPolicy(data);
      }
    } catch {
      // Backend not yet reachable or policy endpoint fallback
    }
  }, []);

  useEffect(() => {
    loadPolicy();
  }, [loadPolicy]);

  /* ── Toast helpers ──────────────────────────────────────────────────── */
  const addToast = useCallback((msg, type = "info", duration = 5000) => {
    const id = ++_toastId;
    setToasts((prev) => [...prev, { id, msg, type, exiting: false }]);
    timerRefs.current[id] = setTimeout(() => dismissToast(id), duration);
    return id;
  }, []);

  const dismissToast = useCallback((id) => {
    clearTimeout(timerRefs.current[id]);
    // Mark as exiting for animation then remove
    setToasts((prev) => prev.map((t) => (t.id === id ? { ...t, exiting: true } : t)));
    setTimeout(() => setToasts((prev) => prev.filter((t) => t.id !== id)), 320);
  }, []);

  /* ── Policy save ─────────────────────────────────────────────────────── */
  const savePolicy = useCallback(
    async (next) => {
      setPolicy(next);
      try {
        await api.savePolicy(next);
        addToast("Engine policy saved successfully.", "success");
      } catch {
        addToast("Failed to persist policy to server — changes are session-only.", "warning");
      }
    },
    [addToast]
  );

  /* ── Containment action dispatcher ─────────────────────────────────── */
  const dispatchAction = useCallback(
    async (payload) => {
      try {
        const res = await api.containAction(payload);
        const type = res.success ? "success" : "error";
        const icon = {
          KILL_PROCESS: "⚡",
          ISOLATE_HOST: "🔒",
          QUARANTINE_FILE: "📦",
          WHITELIST: "✅",
        }[payload.actionType] ?? "⚡";

        addToast(`${icon} ${res.statusLabel}: ${res.detail}`, type, 7000);
        return res;
      } catch (err) {
        addToast(`❌ Action failed: ${err.message}`, "error", 6000);
        throw err;
      }
    },
    [addToast]
  );

  /* ── Self-Healing Autonomous Engine Listener ───────────────────────── */
  useEffect(() => {
    const unsub = aegisWS.subscribe(async (msg) => {
      if (msg.type !== "telemetry") return;

      const currentPolicy = policyRef.current;
      if (currentPolicy.containmentMode !== "AUTONOMOUS") return;

      const score = msg.threat?.score ?? 0;
      const threshold = currentPolicy.autoContainThreshold ?? 0.85;

      if (score >= threshold) {
        const now = Date.now();
        // Cooldown: 15 seconds between autonomous burst executions
        if (now - lastAutoExecRef.current < 15000) return;
        lastAutoExecRef.current = now;

        const threatId = `auto-evt-${now}`;
        
        // Extract real active processes from live system telemetry
        const realProcesses = (msg.host?.top_processes || []).filter(
          (p) => p && p.pid && p.pid > 4 && !["system", "system idle process", "registry", "smss.exe", "csrss.exe"].includes((p.name || "").toLowerCase())
        );
        
        // Pick a dynamic active userland process
        const targetProc = realProcesses.length > 0
          ? realProcesses[Math.floor(Math.random() * realProcesses.length)]
          : null;
        const pid = targetProc?.pid;
        const procName = targetProc?.name || "active_worker.exe";
        
        // Extract real active remote socket IP or local host IP
        const activeSockets = msg.host?.active_sockets || [];
        const targetIp = activeSockets[0]?.remote_ip || msg.host?.host_ip || "127.0.0.1";

        // Execute enabled autonomous actions with live system parameters
        if (currentPolicy.enableAutoProcessKill && pid) {
          try {
            await dispatchAction({
              threatId,
              pid,
              processName: procName,
              actionType: "KILL_PROCESS",
              mode: "AUTONOMOUS",
            });
          } catch (e) {
            console.warn("Autonomous process kill error:", e);
          }
        } else if (currentPolicy.enableAutoHostIsolation && targetIp) {
          try {
            await dispatchAction({
              threatId,
              targetIp,
              actionType: "ISOLATE_HOST",
              mode: "AUTONOMOUS",
            });
          } catch (e) {
            console.warn("Autonomous host isolation error:", e);
          }
        } else if (currentPolicy.enableAutoQuarantine && procName) {
          try {
            await dispatchAction({
              threatId,
              processName: procName,
              actionType: "QUARANTINE_FILE",
              mode: "AUTONOMOUS",
            });
          } catch (e) {
            console.warn("Autonomous quarantine error:", e);
          }
        }
      }
    });

    return unsub;
  }, [dispatchAction]);

  return (
    <EngineContext.Provider
      value={{
        policy,
        setPolicy,
        savePolicy,
        loadPolicy,
        toasts,
        addToast,
        dismissToast,
        dispatchAction,
      }}
    >
      {children}
    </EngineContext.Provider>
  );
}

export function useEngine() {
  const ctx = useContext(EngineContext);
  if (!ctx) throw new Error("useEngine must be used inside <EngineProvider>");
  return ctx;
}
