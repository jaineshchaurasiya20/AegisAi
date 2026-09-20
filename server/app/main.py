"""
AegisAI — FastAPI Application Entry Point
Wires together: REST API routes, WebSocket broadcaster, CORS, lifespan events,
embedded React production SPA serving, and standalone desktop launcher.
"""
import sys
import os

# PyInstaller with console=False / windowed mode sets standard streams to None on Windows.
# Assign dummy / devnull streams to prevent 'NoneType' object has no attribute 'isatty'
if sys.stdout is None:
    sys.stdout = open(os.devnull, "w", encoding="utf-8")
if sys.stderr is None:
    sys.stderr = open(os.devnull, "w", encoding="utf-8")
if sys.stdin is None:
    sys.stdin = open(os.devnull, "r", encoding="utf-8")

import time
import asyncio
import threading
import webbrowser
from pathlib import Path

# Ensure server root and bundle root are in sys.path
_CURRENT_DIR = Path(__file__).resolve().parent
_SERVER_DIR = _CURRENT_DIR.parent
for _p in [str(_SERVER_DIR), str(_CURRENT_DIR)]:
    if _p not in sys.path:
        sys.path.insert(0, _p)
if hasattr(sys, "_MEIPASS"):
    for _p in [sys._MEIPASS, os.path.join(sys._MEIPASS, "server")]:
        if _p not in sys.path:
            sys.path.insert(0, _p)

from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from loguru import logger

from app.core.path_utils import get_resource_path
from app.api.routes import auth, telemetry, threats, actions, model, deception, agent, quorum, audit
from app.api.websockets import manager, telemetry_broadcaster
from app.core.config import get_settings
from app.core.sandbox import ephemeral_sandbox
from app.deception.honeypot_emulator import honeypot_emulator
from app.services.deception import dynamic_honeypot_engine
from app.agents.orchestrator import orchestrator

settings = get_settings()

# Register orchestrator traces to broadcast over WebSocket and buffer in Ephemeral Sandbox
orchestrator.register_trace_callback(manager.broadcast_agent_trace)
orchestrator.register_trace_callback(ephemeral_sandbox.buffer_trace)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Start 4-Agent Architecture orchestrator, telemetry broadcaster, honeypot listeners, and ephemeral sandbox."""
    logger.info("AegisAI 4-Agent Security Architecture starting...")
    await orchestrator.start()
    broadcaster_task = asyncio.create_task(telemetry_broadcaster())
    sandbox_wipe_task = asyncio.create_task(ephemeral_sandbox.start_wipe_loop())
    # Start synthetic & dynamic honeypot socket listeners
    try:
        await dynamic_honeypot_engine.start()
        await honeypot_emulator.start_synthetic_listeners()
    except Exception as e:
        logger.warning(f"Could not start honeypot listeners: {e}")
    yield
    logger.info("AegisAI shutting down...")
    ephemeral_sandbox.stop_wipe_loop()
    sandbox_wipe_task.cancel()
    broadcaster_task.cancel()
    try:
        await broadcaster_task
    except asyncio.CancelledError:
        pass
    try:
        await sandbox_wipe_task
    except asyncio.CancelledError:
        pass
    await orchestrator.stop()
    await dynamic_honeypot_engine.stop()
    await honeypot_emulator.stop_synthetic_listeners()


app = FastAPI(
    title="AegisAI",
    description="Edge-Native Cyber Threat Detection & Autonomous Response Engine",
    version="2.0.0",
    lifespan=lifespan,
)

# CORS — allow React dev server & local origin
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:8000", "http://127.0.0.1:8000", "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# REST API Routers
app.include_router(auth.router)
app.include_router(telemetry.router)
app.include_router(threats.router)
app.include_router(actions.router)
app.include_router(model.router)
app.include_router(deception.router)
app.include_router(agent.router)
app.include_router(quorum.router)
app.include_router(audit.router)

# Health & Status API Endpoints
@app.get("/api/health")
@app.get("/health")
async def health_check():
    return {
        "service": "AegisAI",
        "version": "2.0.0",
        "status": "operational",
        "docs": "/docs",
        "agents": {
            "status": "active",
            "detector_threshold": orchestrator.detector.dynamic_threshold,
        },
    }


# Serve generated patch files for download
try:
    _patches_dir = os.path.join(os.path.dirname(__file__), "agents", "patches")
    os.makedirs(_patches_dir, exist_ok=True)
    app.mount("/static/patches", StaticFiles(directory=_patches_dir), name="patches")
except Exception as _e:
    logger.warning(f"Could not mount /static/patches: {_e}")


@app.websocket("/ws/telemetry")
@app.websocket("/api/ws/telemetry")
async def websocket_endpoint(websocket: WebSocket):
    """Live WebSocket endpoint — streams telemetry and agent traces to React dashboard clients."""
    await manager.connect(websocket, channel="telemetry")
    logger.info(f"WebSocket client connected. Active connections: {len(manager.active_connections)}")
    try:
        while True:
            # Keep connection alive; broadcaster pushes messages
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
        logger.info(f"WebSocket client disconnected. Active connections: {len(manager.active_connections)}")


@app.websocket("/ws/agents")
@app.websocket("/api/ws/agents")
async def agent_websocket_endpoint(websocket: WebSocket):
    """Dedicated WebSocket endpoint for real-time inter-agent trace streaming."""
    await manager.connect(websocket, channel="agents")
    logger.info(f"Agent WebSocket client connected. Active connections: {len(manager.agent_connections)}")
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
        logger.info(f"Agent WebSocket client disconnected. Active connections: {len(manager.agent_connections)}")


# ---------------------------------------------------------------------------
# Embed React Production Build & SPA Catch-All Routing
# ---------------------------------------------------------------------------
CLIENT_DIST = Path(get_resource_path("client/dist"))
if not CLIENT_DIST.exists():
    CLIENT_DIST = Path(__file__).resolve().parents[2] / "client" / "dist"

if CLIENT_DIST.exists():
    _assets_dir = CLIENT_DIST / "assets"
    if _assets_dir.exists():
        app.mount("/assets", StaticFiles(directory=str(_assets_dir)), name="assets")

    @app.get("/{full_path:path}")
    async def serve_spa(full_path: str):
        # Exclude API, WebSocket, Docs, and Static endpoints from SPA fallback
        if full_path.startswith(("api", "ws", "docs", "openapi.json", "static", "health")):
            raise HTTPException(status_code=404, detail="Not Found")
        
        file_path = CLIENT_DIST / full_path
        if full_path and file_path.is_file():
            return FileResponse(file_path)
        
        index_path = CLIENT_DIST / "index.html"
        if index_path.exists():
            return FileResponse(index_path)
        raise HTTPException(status_code=404, detail="Frontend build index.html not found")
else:
    @app.get("/")
    async def root():
        return {
            "service": "AegisAI",
            "version": "2.0.0",
            "status": "operational",
            "docs": "/docs",
            "notice": "Frontend client/dist not built yet. Run 'npm run build' in client/ folder."
        }


# ---------------------------------------------------------------------------
# Standalone Desktop Execution Entry Point
# ---------------------------------------------------------------------------
def start_standalone():
    """Starts Uvicorn in a background thread, launches browser, and runs Tray icon."""
    import uvicorn
    import uvicorn.config

    config = uvicorn.Config(
        app=app,
        host="0.0.0.0",
        port=8000,
        log_level="info",
        log_config=None,
        access_log=False,
    )
    server = uvicorn.Server(config)

    server_thread = threading.Thread(target=server.run, daemon=True)
    server_thread.start()
    time.sleep(1.0)

    # Launch browser to dashboard
    try:
        webbrowser.open("http://localhost:8000")
    except Exception as e:
        logger.warning(f"Could not automatically open browser: {e}")

    # Launch system tray in main GUI thread
    try:
        from app.collector.tray_agent import AegisTrayController
        controller = AegisTrayController()
        controller.is_running = True
        controller.run(auto_start_engine=False)
    except Exception as e:
        logger.info(f"Tray event loop finished or not supported: {e}. Keeping server alive.")
        while server_thread.is_alive():
            time.sleep(1.0)


if __name__ == "__main__":
    import multiprocessing
    multiprocessing.freeze_support()
    
    if "--server-only" in sys.argv or "--headless" in sys.argv:
        import uvicorn
        uvicorn.run(app, host="0.0.0.0", port=8000, log_config=None)
    else:
        start_standalone()

