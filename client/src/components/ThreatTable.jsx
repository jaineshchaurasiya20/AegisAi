/**
 * ThreatTable — Real-time live threat table component.
 * Connects to ws://localhost:8000/api/ws/telemetry and auto-prepends incoming events.
 */
import React, { useState, useEffect } from "react";
import LogTable from "./LogTable";
import { api } from "../services/api";
import { WS_URL } from "../services/websocket";

export default function ThreatTable({ onRowClick, initialThreats = [] }) {
  const [threats, setThreats] = useState(initialThreats);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (initialThreats.length === 0) {
      setLoading(true);
      api.getThreats({ limit: 50 })
        .then((res) => {
          if (Array.isArray(res)) setThreats(res);
        })
        .catch(() => {})
        .finally(() => setLoading(false));
    } else {
      setThreats(initialThreats);
    }
  }, [initialThreats]);

  // Real-time WebSocket connection to /api/ws/telemetry
  useEffect(() => {
    let ws;
    try {
      ws = new WebSocket(`${WS_URL}/api/ws/telemetry`);
      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          if (data.type === "THREAT_DETECTED" && (data.payload || data.threat)) {
            const newThreat = data.payload || data.threat;
            setThreats((prev) => [newThreat, ...prev.filter((t) => t.id !== newThreat.id)]);
          } else if (data.type === "threat_alert" && data.threat) {
            setThreats((prev) => [data.threat, ...prev.filter((t) => t.id !== data.threat.id)]);
          } else if (data.type === "telemetry" && data.threat?.new_alert) {
            setThreats((prev) => [data.threat.new_alert, ...prev.filter((t) => t.id !== data.threat.new_alert.id)]);
          }
        } catch (e) {
          console.warn("[ThreatTable] Error parsing message", e);
        }
      };
    } catch (err) {
      console.warn("[ThreatTable] Failed to open WebSocket", err);
    }

    return () => {
      if (ws) ws.close();
    };
  }, []);

  return (
    <LogTable
      threats={threats}
      loading={loading}
      onRowClick={onRowClick}
    />
  );
}
