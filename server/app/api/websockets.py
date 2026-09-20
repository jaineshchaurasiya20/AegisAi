"""
AegisAI WebSocket broadcaster — streams live telemetry and agent trace events to SOC clients.
Integrates with the 4-Agent Architecture Event Bus and Orchestrator.
"""
import asyncio
import json
from datetime import datetime, timezone
from fastapi import WebSocket, WebSocketDisconnect
from loguru import logger
from app.collector.host_monitor import get_host_snapshot


class ConnectionManager:
    """Manages all active WebSocket client connections across telemetry and agent channels."""

    def __init__(self):
        self.active_connections: list[WebSocket] = []
        self.agent_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket, channel: str = "telemetry"):
        await websocket.accept()
        if channel == "agents":
            self.agent_connections.append(websocket)
        else:
            self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        if websocket in self.agent_connections:
            self.agent_connections.remove(websocket)

    async def broadcast(self, message: dict, channel: str = "all"):
        """Broadcast to connected clients on telemetry, agents, or all channels."""
        if channel == "telemetry":
            targets = list(self.active_connections)
        elif channel == "agents":
            targets = list(self.agent_connections)
        else:
            targets = list(set(self.active_connections + self.agent_connections))

        dead = []
        for connection in targets:
            try:
                await connection.send_json(message)
            except Exception as e:
                logger.debug(f"[WebSocket] Exception sending {message.get('type')}: {e}")
                dead.append(connection)
        for d in dead:
            self.disconnect(d)

    async def broadcast_agent_trace(self, trace_payload: dict):
        """Broadcast structured agent trace event to both agents channel and dashboard clients."""
        await self.broadcast(trace_payload, channel="all")


manager = ConnectionManager()


async def telemetry_broadcaster():
    """Background coroutine — broadcasts genuine live host telemetry and threat metrics."""
    try:
        while True:
            try:
                if manager.active_connections:
                    from app.agents.orchestrator import orchestrator
                    from app.ml.inference import run_inference

                    snapshot = await get_host_snapshot()
                    inf = await run_inference(snapshot)
                    threat_score = float(inf.get("threat_score", 0.05))
                    severity = inf.get("severity", "low")

                    payload = {
                        "type": "telemetry",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "host": snapshot,
                        "threat": {
                            "score": threat_score,
                            "severity": severity,
                            "dynamic_threshold": orchestrator.detector.dynamic_threshold,
                        },
                    }
                    await manager.broadcast(payload, channel="telemetry")
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.debug(f"[WebSocket Broadcaster] Error in loop: {e}")
            await asyncio.sleep(1.0)
    except asyncio.CancelledError:
        pass
