import React, { useState } from "react";
import { Shield, Eye, EyeOff, Loader2 } from "lucide-react";
import { api, setToken } from "../services/api";

export default function Login({ onLogin }) {
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [showPass, setShowPass] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError("");
    try {
      const data = await api.login(username, password);
      if (data.access_token) {
        setToken(data.access_token);
        onLogin(data);
      } else {
        setError(data.detail || "Login failed");
      }
    } catch (err) {
      setError(err.message || "Server unreachable");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#0b0f19] flex items-center justify-center p-4">
      {/* Background grid effect */}
      <div
        className="fixed inset-0 opacity-[0.03]"
        style={{
          backgroundImage: "linear-gradient(#06b6d4 1px, transparent 1px), linear-gradient(90deg, #06b6d4 1px, transparent 1px)",
          backgroundSize: "40px 40px",
        }}
      />

      <div className="w-full max-w-sm relative z-10 animate-slide-in">
        {/* Logo */}
        <div className="text-center mb-8">
          <div className="inline-flex w-16 h-16 rounded-2xl bg-gradient-to-br from-cyan-500 to-blue-600 items-center justify-center mb-4 shadow-2xl shadow-cyan-500/20">
            <Shield size={30} className="text-white" />
          </div>
          <h1 className="text-white text-2xl font-bold">AegisAI</h1>
          <p className="text-slate-500 text-sm mt-1">Edge Threat Detection Engine</p>
        </div>

        {/* Card */}
        <div className="glass-card p-7">
          <h2 className="text-white font-semibold text-base mb-5">Sign In to Dashboard</h2>
          <form id="login-form" onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-xs text-slate-400 mb-1.5" htmlFor="login-username">Username</label>
              <input
                id="login-username"
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
                className="w-full bg-slate-900/80 border border-slate-700 rounded-lg px-3 py-2.5 text-white text-sm placeholder-slate-600 focus:outline-none focus:border-cyan-500 transition"
              />
            </div>
            <div>
              <label className="block text-xs text-slate-400 mb-1.5" htmlFor="login-password">Password</label>
              <div className="relative">
                <input
                  id="login-password"
                  type={showPass ? "text" : "password"}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                  placeholder="••••••••"
                  className="w-full bg-slate-900/80 border border-slate-700 rounded-lg px-3 py-2.5 pr-10 text-white text-sm placeholder-slate-600 focus:outline-none focus:border-cyan-500 transition"
                />
                <button
                  type="button"
                  id="toggle-password-btn"
                  onClick={() => setShowPass(!showPass)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300"
                >
                  {showPass ? <EyeOff size={14} /> : <Eye size={14} />}
                </button>
              </div>
            </div>

            {error && (
              <div className="bg-red-500/10 border border-red-500/20 text-red-400 text-xs rounded-lg px-3 py-2">
                {error}
              </div>
            )}

            <button
              id="login-submit-btn"
              type="submit"
              disabled={loading}
              className="w-full py-2.5 rounded-lg bg-gradient-to-r from-cyan-500 to-blue-600 text-white font-semibold text-sm hover:opacity-90 transition flex items-center justify-center gap-2 disabled:opacity-60"
            >
              {loading ? <Loader2 size={15} className="animate-spin" /> : null}
              {loading ? "Authenticating..." : "Sign In"}
            </button>
          </form>

          <p className="text-slate-600 text-[11px] text-center mt-4">
            Demo credentials: <span className="mono text-slate-500">admin / aegis2024</span>
          </p>
        </div>
      </div>
    </div>
  );
}
