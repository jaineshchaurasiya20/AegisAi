import React, { useEffect, useState, useRef } from 'react';
import { createPortal } from 'react-dom';
import { X, Zap, CheckCircle, AlertCircle, Loader2, Download, RefreshCw } from 'lucide-react';
import { getToken } from '../services/api';

const API_BASE = import.meta.env.VITE_API_URL || '';

/**
 * AgentReasoningDrawer – Slide-over panel that streams the agentic remediation
 * SSE log for a given threat.
 *
 * Props:
 *   open     – boolean to control visibility
 *   onClose  – callback to hide drawer
 *   threatId – ID of the threat to remediate
 *   mode     – "AUTONOMOUS" | "MANUAL" (default AUTONOMOUS)
 */
export default function AgentReasoningDrawer({ open, onClose, threatId, threat, mode = 'AUTONOMOUS' }) {
  const [logs, setLogs] = useState([]);
  const [status, setStatus] = useState('connecting'); // connecting | streaming | done | error
  const [patchPath, setPatchPath] = useState(null);
  const [retryKey, setRetryKey] = useState(0);
  const scrollRef = useRef(null);

  // Auto-scroll to bottom when new logs arrive
  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [logs]);

  useEffect(() => {
    if (!open) return;

    // Reset state on open
    setLogs([]);
    setStatus('connecting');
    setPatchPath(null);

    const controller = new AbortController();
    const url = `${API_BASE}/api/agent/remediate`;
    const payload = {
      threat_id: threatId,
      mode,
      ...(threat?.source_ip ? { source_ip: threat.source_ip } : {}),
      ...(threat?.port ? { destination_port: threat.port } : {}),
    };
    const token = getToken();

    fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'text/event-stream',
        ...(token ? { 'Authorization': `Bearer ${token}` } : {}),
      },
      body: JSON.stringify(payload),
      signal: controller.signal,
    })
      .then((resp) => {
        if (!resp.ok) {
          setStatus('error');
          setLogs([{ step: 'ERROR', message: `HTTP ${resp.status}: ${resp.statusText}`, status: 'ERROR' }]);
          return;
        }
        if (!resp.body) {
          setStatus('error');
          return;
        }
        setStatus('streaming');
        const reader = resp.body.getReader();
        const decoder = new TextDecoder();
        let buf = '';
        const readChunk = () => {
          reader.read().then(({ done, value }) => {
            if (done) {
              setStatus('done');
              return;
            }
            buf += decoder.decode(value, { stream: true });
            const lines = buf.split('\n');
            buf = lines.pop(); // keep incomplete line in buffer
            lines.forEach((line) => {
              if (line.startsWith('data:')) {
                try {
                  const data = JSON.parse(line.slice(5).trim());
                  setLogs((prev) => [...prev, data]);
                  // Capture patch path if present
                  if (data.generated_patch) {
                    setPatchPath(data.generated_patch);
                  }
                  // Mark done on final events
                  if (data.step === 'Summary' || data.step === 'END') {
                    setStatus('done');
                  }
                } catch (e) {
                  // ignore malformed JSON
                }
              }
            });
            readChunk();
          }).catch(() => {
            setStatus('done');
          });
        };
        readChunk();
      })
      .catch((err) => {
        if (err.name !== 'AbortError') {
          console.error('Agent SSE error:', err);
          setStatus('error');
          setLogs((prev) => [...prev, { step: 'ERROR', message: String(err), status: 'ERROR' }]);
        }
      });

    return () => controller.abort();
  }, [open, threatId, threat, mode, retryKey]);

  if (!open) return null;

  const stepIcon = (entry) => {
    const s = entry.status || 'INFO';
    if (s === 'COMPLETED' || s === 'DONE') return <CheckCircle size={14} className="text-emerald-400 flex-shrink-0" />;
    if (s === 'ERROR' || s === 'FAILED') return <AlertCircle size={14} className="text-red-400 flex-shrink-0" />;
    return <Zap size={14} className="text-cyan-400 flex-shrink-0" />;
  };

  const stepColor = (entry) => {
    const s = entry.status || 'INFO';
    if (s === 'COMPLETED' || s === 'DONE') return '#10b981';
    if (s === 'ERROR' || s === 'FAILED') return '#ef4444';
    return '#06b6d4';
  };

  return createPortal(
    <div
      className="fixed inset-0 z-[110] flex items-center justify-end"
      style={{ background: 'rgba(0,0,0,0.65)', backdropFilter: 'blur(4px)' }}
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        className="relative h-full flex flex-col w-[480px] bg-[#0b0f19] shadow-xl border-l border-slate-800"
        style={{ animation: 'slide-in-right 0.28s cubic-bezier(0.22,1,0.36,1) forwards' }}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b" style={{ borderColor: '#1e293b' }}>
          <div className="flex items-center gap-2">
            <Zap size={16} className="text-amber-400" />
            <h3 className="text-white font-semibold text-sm">Agentic Remediation Engine</h3>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded-full" style={{
              background: status === 'done' ? 'rgba(16,185,129,0.15)' :
                          status === 'error' ? 'rgba(239,68,68,0.15)' :
                          status === 'streaming' ? 'rgba(6,182,212,0.15)' : 'rgba(100,116,139,0.15)',
              color: status === 'done' ? '#10b981' :
                     status === 'error' ? '#ef4444' :
                     status === 'streaming' ? '#06b6d4' : '#64748b',
              border: `1px solid ${status === 'done' ? 'rgba(16,185,129,0.3)' :
                                   status === 'error' ? 'rgba(239,68,68,0.3)' :
                                   status === 'streaming' ? 'rgba(6,182,212,0.3)' : 'rgba(100,116,139,0.3)'}`,
            }}>
              {status}
            </span>
            <button
              onClick={onClose}
              className="p-1 rounded text-slate-400 hover:text-white hover:bg-slate-800 transition"
            >
              <X size={15} />
            </button>
          </div>
        </div>

        {/* Threat context bar */}
        {threat && (
          <div className="px-5 py-2.5 bg-slate-900/80 border-b border-slate-800/80 flex items-center justify-between text-xs">
            <span className="font-semibold text-white">{threat.threat_type || threat.title || 'Threat'}</span>
            <span className="mono text-slate-400">{threat.source_ip}:{threat.port}</span>
          </div>
        )}

        {/* Streaming log body */}
        <div className="flex-1 overflow-y-auto p-4 space-y-3 font-mono text-xs">
          {logs.length === 0 && status === 'connecting' && (
            <div className="flex items-center gap-2 text-slate-500 text-xs py-8 justify-center">
              <Loader2 size={14} className="animate-spin" />
              Connecting to remediation engine...
            </div>
          )}
          {logs.length === 0 && status === 'streaming' && (
            <div className="flex items-center gap-2 text-cyan-400 text-xs py-8 justify-center">
              <Loader2 size={14} className="animate-spin" />
              Awaiting first node output...
            </div>
          )}
          {logs.map((entry, idx) => (
            <div
              key={idx}
              className="flex items-start gap-2 px-3 py-2 rounded-lg text-xs"
              style={{
                background: `${stepColor(entry)}08`,
                border: `1px solid ${stepColor(entry)}20`,
              }}
            >
              {stepIcon(entry)}
              <div className="min-w-0">
                <span className="font-bold text-white" style={{ color: stepColor(entry) }}>
                  [{entry.step}]
                </span>{' '}
                <span className="text-slate-300">{entry.message}</span>
              </div>
            </div>
          ))}
          {status === 'error' && (
            <div className="pt-2">
              <button
                onClick={() => setRetryKey((k) => k + 1)}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-red-500/20 hover:bg-red-500/30 text-red-300 border border-red-500/30 text-xs font-semibold transition"
              >
                <RefreshCw size={12} />
                Retry Remediation
              </button>
            </div>
          )}
          {status === 'done' && logs.length > 0 && (
            <div className="flex items-center gap-2 px-3 py-2 mt-2 rounded-lg text-xs bg-emerald-950/30 border border-emerald-500/20 text-emerald-400 font-semibold">
              <CheckCircle size={14} />
              Remediation workflow complete
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-5 py-3 border-t flex items-center justify-between" style={{ borderColor: '#1e293b', background: '#0d1117' }}>
          {patchPath ? (
            <a
              href={`${API_BASE}/static/patches/${patchPath.split(/[/\\]/).pop()}`}
              target="_blank"
              rel="noreferrer"
              className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1 transition"
            >
              <Download size={12} /> Download Patch
            </a>
          ) : (
            <span className="text-[11px] text-slate-600 mono">
              {status === 'done' ? 'No patch generated' : ''}
            </span>
          )}
          <button
            onClick={onClose}
            className="text-xs text-slate-500 hover:text-slate-300 transition flex items-center gap-1"
          >
            <X size={10} /> Dismiss
          </button>
        </div>
      </div>
    </div>,
    document.body
  );
}
