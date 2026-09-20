import React, { useState } from "react";
import {
  Shield,
  Brain,
  Crosshair,
} from "lucide-react";
import PolicySettingsPanel from "../components/PolicySettingsPanel";
import ModelTelemetryCard from "../components/ModelTelemetryCard";
import MLSettingsPanel from "../components/MLSettingsPanel";
import DeceptionSettingsPanel from "../components/DeceptionSettingsPanel";
import StatusBadge from "../components/ui/StatusBadge";

export default function Settings() {
  const [activeTab, setActiveTab] = useState("containment");

  const tabs = [
    { id: "containment", label: "Containment Policies", icon: Shield },
    { id: "ml-engine", label: "ML & ONNX Engine", icon: Brain },
    { id: "deception", label: "Deception & Honeypots", icon: Crosshair },
  ];

  return (
    <div className="p-4 sm:p-6 lg:p-7 space-y-5 max-w-[1600px] mx-auto animate-fade-in font-sans">
      {/* ── Page Header ──────────────────────────────────────────────── */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-2 border-b border-white/[0.05]">
        <div>
          <div className="flex items-center gap-2.5">
            <h1 className="text-white text-xl sm:text-2xl font-bold tracking-tight">
              Setting
            </h1>
            <StatusBadge variant="cyan" dot size="sm">
              EDR CONTROL PANEL
            </StatusBadge>
          </div>
          <p className="text-slate-400 text-xs sm:text-sm mt-0.5">
            Manage autonomous self-healing containment policies, detection thresholds, and active deception rules
          </p>
        </div>
      </div>

      {/* ── Navigation Tabs ──────────────────────────────────────────── */}
      <div className="flex border-b border-white/[0.06] gap-1.5 flex-wrap">
        {tabs.map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              id={`tab-${tab.id}-btn`}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-2 px-4 py-2.5 text-xs sm:text-sm font-semibold border-b-2 transition-all duration-150 ${
                isActive
                  ? "border-cyan-400 text-white bg-white/[0.04] rounded-t-lg shadow-sm"
                  : "border-transparent text-slate-400 hover:text-slate-200 hover:bg-white/[0.02]"
              }`}
            >
              <Icon
                size={15}
                className={isActive ? "text-cyan-400" : "text-slate-400"}
              />
              <span>{tab.label}</span>
            </button>
          );
        })}
      </div>

      {/* ── Tab Content Panels ───────────────────────────────────────── */}
      <div className="pt-2">
        {activeTab === "containment" && <PolicySettingsPanel />}

        {activeTab === "ml-engine" && (
          <div className="space-y-5">
            <ModelTelemetryCard />
            <MLSettingsPanel />
          </div>
        )}

        {activeTab === "deception" && <DeceptionSettingsPanel />}
      </div>
    </div>
  );
}
