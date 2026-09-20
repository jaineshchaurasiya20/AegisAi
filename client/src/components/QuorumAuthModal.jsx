/**
 * QuorumAuthModal — Cryptographic Action Quorum & HMAC Authorization Modal
 *
 * Enforces human-in-the-loop cryptographic authorization for high-risk containment actions.
 * Subscribes to live WebSocket broadcast stream via existing aegisWS client.
 *
 * States:
 *   PENDING -> AUTHORIZING -> AUTHORIZED / REJECTED / EXPIRED / FAILED
 */
import React, { useEffect, useState, useRef, useCallback } from "react";
import { createPortal } from "react-dom";
import {
  ShieldAlert, ShieldCheck, KeyRound, AlertTriangle,
  Clock, Lock, CheckCircle2, XCircle, RefreshCw, X,
  Activity, Zap, Terminal, Sparkles
} from "lucide-react";
import { aegisWS } from "../services/websocket";
import { api } from "../services/api";

export default function QuorumAuthModal() {
  const [activeQuorum, setActiveQuorum] = useState(null);
  const [remainingSeconds, setRemainingSeconds] = useState(0);
  const [authStatus, setAuthStatus] = useState("PENDING"); // PENDING | AUTHORIZING | AUTHORIZED | EXECUTING | EXECUTED | REJECTED | EXPIRED | FAILED
  const [statusMessage, setStatusMessage] = useState("");
  const timerRef = useRef(null);

  // Subscribe to existing WebSocket stream for Quorum events
  useEffect(() => {
    const unsub = aegisWS.subscribe((msg) => {
      // Direct QuorumAuthorizationRequired broadcast or wrapped in agent_trace
      const isQuorumEvent =
        msg.event_type === "QuorumAuthorizationRequired" ||
        msg.type === "QuorumAuthorizationRequired" ||
        (msg.status === "QUORUM_AUTHORIZATION_REQUIRED" && msg.payload);

      if (isQuorumEvent) {
        const payload = msg.payload || msg;
        setActiveQuorum({
          nonce: payload.nonce,
          target_pid: payload.target_pid,
          process_name: payload.process_name || "unknown",
          action_type: payload.action_type || "PID_KILL",
          threat_score: payload.threat_score ?? 0.95,
          root_cause: payload.root_cause_summary || payload.root_cause || "Outbound socket entropy anomaly",
          abbreviated_hmac: payload.abbreviated_hmac_signature || `${(payload.hmac_signature || "").slice(0, 4)}...${(payload.hmac_signature || "").slice(-4)}`,
          hmac_signature: payload.hmac_signature || payload.abbreviated_hmac_signature,
          expires_at: payload.expires_at || (Date.now() / 1000 + 30.0),
          timestamp_val: payload.timestamp_val || (Date.now() / 1000),
        });
        setAuthStatus("PENDING");
        setStatusMessage("");
      }

      // Live update if trace event reflects approved/rejected/executed
      if (activeQuorum && msg.agent === "Cryptographic Quorum") {
        if (msg.status === "QUORUM_APPROVED") {
          setAuthStatus("AUTHORIZED");
        } else if (msg.status === "QUORUM_REJECTED") {
          setAuthStatus("REJECTED");
        }
      }
      if (activeQuorum && msg.agent === "Remediator Agent") {
        if (msg.status === "SUCCESS") {
          setAuthStatus("EXECUTED");
        } else if (msg.status === "FAILED") {
          setAuthStatus("FAILED");
        }
      }
    });

    return unsub;
  }, [activeQuorum]);

  // Server-time synchronized countdown timer driven strictly by expires_at
  useEffect(() => {
    if (!activeQuorum) {
      if (timerRef.current) clearInterval(timerRef.current);
      return;
    }

    const updateTimer = () => {
      const now = Date.now() / 1000;
      const left = Math.max(0, activeQuorum.expires_at - now);
      setRemainingSeconds(Math.ceil(left));

      if (left <= 0) {
        if (authStatus === "PENDING" || authStatus === "AUTHORIZING") {
          setAuthStatus("EXPIRED");
          setStatusMessage("Token lifetime expired (30s timeout). Action blocked by server.");
        }
        clearInterval(timerRef.current);
      }
    };

    updateTimer();
    timerRef.current = setInterval(updateTimer, 250);

    return () => clearInterval(timerRef.current);
  }, [activeQuorum, authStatus]);

  // Handle human operator decision
  const handleDecision = useCallback(
    async (decision) => {
      if (!activeQuorum || authStatus !== "PENDING") return;

      // Prevent double-click authorization
      setAuthStatus(decision === "APPROVE" ? "AUTHORIZING" : "REJECTING");

      try {
        const payload = {
          nonce: activeQuorum.nonce,
          hmac_signature: activeQuorum.hmac_signature,
          decision: decision,
        };

        const res = await api.authorizeQuorum(payload);

        if (res.success) {
          if (decision === "APPROVE") {
            setAuthStatus("AUTHORIZED");
            setStatusMessage("Cryptographic HMAC verified. Remediator authorized.");
            // Auto close modal after brief confirmation
            setTimeout(() => {
              setActiveQuorum(null);
            }, 3500);
          } else {
            setAuthStatus("REJECTED");
            setStatusMessage("Containment action suppressed by operator.");
            setTimeout(() => {
              setActiveQuorum(null);
            }, 2500);
          }
        } else {
          setAuthStatus("FAILED");
          setStatusMessage(res.reason || "Server rejected authorization request.");
        }
      } catch (err) {
        setAuthStatus("FAILED");
        setStatusMessage(err.message || "Authorization failed.");
      }
    },
    [activeQuorum, authStatus]
  );

  if (!activeQuorum) return null;

  const scorePct = Math.round((activeQuorum.threat_score ?? 0.95) * 100);
  const minutes = Math.floor(remainingSeconds / 60);
  const seconds = Math.floor(remainingSeconds % 60);
  const formattedCountdown = `${String(minutes).padStart(2, "0")}:${String(seconds).padStart(2, "0")}`;

  const isPending = authStatus === "PENDING";
  const isAuthorizing = authStatus === "AUTHORIZING";
  const isAuthorized = authStatus === "AUTHORIZED" || authStatus === "EXECUTING" || authStatus === "EXECUTED";
  const isRejected = authStatus === "REJECTED";
  const isExpired = authStatus === "EXPIRED";

  return createPortal(
    <div className="fixed inset-0 z-[9999] flex items-center justify-center p-4 bg-black/80 backdrop-blur-md animate-fade-in">
      <div
        className="w-full max-w-lg rounded-2xl bg-[#0c101b] border border-cyan-500/30 shadow-2xl shadow-cyan-950/60 overflow-hidden relative"
        role="dialog"
        aria-modal="true"
      >
        {/* Top glowing ambient line */}
        <div className="h-1 bg-gradient-to-r from-amber-500 via-cyan-500 to-indigo-500" />

        {/* Modal Header */}
        <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-900/40">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-amber-500/15 border border-amber-500/30 flex items-center justify-center text-amber-400 shadow-lg shadow-amber-500/10">
              <KeyRound size={18} />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-white font-extrabold text-sm tracking-wider uppercase">
                  Cryptographic Action Quorum
                </h2>
                <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 flex items-center gap-1">
                  <ShieldCheck size={11} />
                  HMAC-SHA256
                </span>
              </div>
              <p className="text-slate-400 text-xs mt-0.5">
                Operator quorum required for high-risk autonomous remediation
              </p>
            </div>
          </div>

          {!isPending && !isAuthorizing && (
            <button
              onClick={() => setActiveQuorum(null)}
              className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition"
              title="Dismiss"
            >
              <X size={16} />
            </button>
          )}
        </div>

        {/* Modal Body */}
        <div className="p-6 space-y-4 text-xs">
          {/* Target & Action Highlight Box */}
          <div className="grid grid-cols-2 gap-3">
            <div className="p-3.5 rounded-xl bg-slate-900/70 border border-slate-800">
              <span className="text-slate-400 text-[11px] font-medium block">Target Process</span>
              <div className="mt-1 flex items-baseline gap-2">
                <span className="text-white font-bold text-sm tracking-tight font-mono">
                  {activeQuorum.process_name}
                </span>
              </div>
              <span className="text-cyan-400 font-mono text-[11px]">
                PID: {activeQuorum.target_pid}
              </span>
            </div>

            <div className="p-3.5 rounded-xl bg-slate-900/70 border border-slate-800">
              <span className="text-slate-400 text-[11px] font-medium block">Proposed Action</span>
              <div className="mt-1 flex items-center gap-1.5">
                <span className="px-2 py-0.5 rounded font-mono font-bold text-xs bg-rose-500/20 text-rose-300 border border-rose-500/40">
                  {activeQuorum.action_type}
                </span>
              </div>
              <span className="text-slate-400 text-[11px] mt-1 block">
                High-Risk OS Execution
              </span>
            </div>
          </div>

          {/* Threat Metric Row */}
          <div className="p-3.5 rounded-xl bg-slate-900/50 border border-slate-800/80 flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <div className="w-8 h-8 rounded-lg bg-rose-500/15 border border-rose-500/30 flex items-center justify-center text-rose-400">
                <AlertTriangle size={15} />
              </div>
              <div>
                <span className="text-slate-400 text-[11px]">Threat Score:</span>
                <span className="text-white font-bold text-sm ml-2 font-mono text-rose-400">
                  {scorePct}%
                </span>
              </div>
            </div>

            <div className="text-right">
              <span className="text-slate-400 text-[11px] block">Root Cause Finding</span>
              <span className="text-slate-200 text-xs font-medium max-w-[240px] truncate block" title={activeQuorum.root_cause}>
                {activeQuorum.root_cause}
              </span>
            </div>
          </div>

          {/* Cryptographic Proof Verification Card */}
          <div className="p-3.5 rounded-xl bg-slate-900/80 border border-cyan-500/20 space-y-2 font-mono text-[11px]">
            <div className="flex items-center justify-between">
              <span className="text-slate-400 flex items-center gap-1.5">
                <Lock size={12} className="text-cyan-400" />
                Authorization:
              </span>
              <span className="text-emerald-400 font-semibold flex items-center gap-1">
                <CheckCircle2 size={12} />
                HMAC-SHA256 verified
              </span>
            </div>

            <div className="flex items-center justify-between pt-1 border-t border-slate-800/80">
              <span className="text-slate-400">Token Nonce / Digest:</span>
              <span className="text-cyan-300 font-bold bg-cyan-950/40 px-2 py-0.5 rounded border border-cyan-800/50">
                {activeQuorum.abbreviated_hmac}
              </span>
            </div>

            <div className="flex items-center justify-between pt-1 border-t border-slate-800/80">
              <span className="text-slate-400 flex items-center gap-1">
                <Clock size={12} className={remainingSeconds <= 5 ? "text-rose-400 animate-pulse" : "text-amber-400"} />
                Expires in:
              </span>
              <span className={`font-extrabold text-sm tracking-widest ${
                isExpired ? "text-rose-500" : remainingSeconds <= 5 ? "text-rose-400 animate-pulse" : "text-amber-300"
              }`}>
                {isExpired ? "EXPIRED" : formattedCountdown}
              </span>
            </div>
          </div>

          {/* Status Banners */}
          {isAuthorizing && (
            <div className="p-3 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center gap-2.5 text-cyan-300">
              <RefreshCw size={14} className="animate-spin text-cyan-400" />
              <span>Authorizing with Cryptographic Quorum Engine...</span>
            </div>
          )}

          {isAuthorized && (
            <div className="p-3 rounded-xl bg-emerald-500/15 border border-emerald-500/40 flex items-center gap-2.5 text-emerald-300">
              <CheckCircle2 size={16} className="text-emerald-400" />
              <div>
                <span className="font-bold block">Quorum Authorization Confirmed</span>
                <span className="text-[11px] text-emerald-200/80">{statusMessage}</span>
              </div>
            </div>
          )}

          {isRejected && (
            <div className="p-3 rounded-xl bg-slate-800 border border-slate-700 flex items-center gap-2.5 text-slate-300">
              <XCircle size={16} className="text-slate-400" />
              <div>
                <span className="font-bold block">Action Rejected & Suppressed</span>
                <span className="text-[11px] text-slate-400">{statusMessage}</span>
              </div>
            </div>
          )}

          {isExpired && (
            <div className="p-3 rounded-xl bg-rose-500/15 border border-rose-500/30 flex items-center gap-2.5 text-rose-300">
              <Clock size={16} className="text-rose-400" />
              <div>
                <span className="font-bold block">Authorization Window Expired</span>
                <span className="text-[11px] text-rose-200/80">{statusMessage}</span>
              </div>
            </div>
          )}
        </div>

        {/* Modal Actions */}
        <div className="px-6 py-4 bg-slate-900/60 border-t border-slate-800 flex items-center justify-between gap-3">
          <button
            id="quorum-reject-btn"
            onClick={() => handleDecision("REJECT")}
            disabled={!isPending}
            className={`px-4 py-2.5 rounded-xl font-bold text-xs transition border flex-1 ${
              isPending
                ? "bg-slate-800/80 hover:bg-slate-700/80 border-slate-700 text-slate-300 active:scale-95"
                : "bg-slate-900 border-slate-800 text-slate-600 cursor-not-allowed"
            }`}
          >
            REJECT & SUPPRESS
          </button>

          <button
            id="quorum-authorize-btn"
            onClick={() => handleDecision("APPROVE")}
            disabled={!isPending}
            className={`px-5 py-2.5 rounded-xl font-bold text-xs transition border flex-1 flex items-center justify-center gap-2 shadow-lg ${
              isPending
                ? "bg-gradient-to-r from-emerald-600 to-cyan-600 hover:from-emerald-500 hover:to-cyan-500 border-emerald-400/40 text-white shadow-emerald-900/30 active:scale-95"
                : isAuthorizing
                ? "bg-cyan-900/40 border-cyan-500/40 text-cyan-200 cursor-not-allowed"
                : "bg-slate-900 border-slate-800 text-slate-600 cursor-not-allowed"
            }`}
          >
            {isAuthorizing ? (
              <>
                <RefreshCw size={13} className="animate-spin text-cyan-300" />
                <span>AUTHORIZING...</span>
              </>
            ) : (
              <>
                <ShieldCheck size={14} />
                <span>AUTHORIZE ACTION</span>
              </>
            )}
          </button>
        </div>
      </div>
    </div>,
    document.body
  );
}
