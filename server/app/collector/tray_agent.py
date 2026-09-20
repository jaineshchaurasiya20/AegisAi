"""
AegisAI 2.0 — Taskbar System Tray Agent & Background Daemon Controller
======================================================================
Provides a persistent Windows / macOS / Linux system tray icon (pystray),
context menu controls for launching the SOC dashboard, triggering live attack
replay demos, stopping/starting the background ML engine, and displaying status.
"""
from __future__ import annotations

import os
import sys
import time
import socket
import threading
import subprocess
import webbrowser
from pathlib import Path
from typing import Optional

from PIL import Image, ImageDraw
# pyrefly: ignore [missing-import]
import pystray
# pyrefly: ignore [missing-import]
from pystray import MenuItem as item, Menu

# Ensure project root & server dir are in sys.path
SERVER_ROOT = Path(__file__).resolve().parents[2]
if str(SERVER_ROOT) not in sys.path:
    sys.path.insert(0, str(SERVER_ROOT))

from app.core.notifications import send_system_alert

DASHBOARD_URL = "http://localhost:5173"
BACKEND_HOST = "127.0.0.1"
BACKEND_PORT = 8000
BACKEND_HEALTH_URL = f"http://{BACKEND_HOST}:{BACKEND_PORT}/"

# Resolve python / pythonw executables in venv
if os.name == "nt":
    VENV_PYTHON = SERVER_ROOT / "venv" / "Scripts" / "python.exe"
    VENV_PYTHONW = SERVER_ROOT / "venv" / "Scripts" / "pythonw.exe"
else:
    VENV_PYTHON = SERVER_ROOT / "venv" / "bin" / "python"
    VENV_PYTHONW = SERVER_ROOT / "venv" / "bin" / "python"

if not VENV_PYTHON.exists():
    VENV_PYTHON = Path(sys.executable)
if not VENV_PYTHONW.exists():
    VENV_PYTHONW = Path(sys.executable)


class AegisTrayController:
    def __init__(self):
        self.is_running: bool = False
        self.backend_proc: Optional[subprocess.Popen] = None
        self.replay_proc: Optional[subprocess.Popen] = None
        self.icon: Optional[pystray.Icon] = None
        self._monitor_thread: Optional[threading.Thread] = None
        self._stop_monitor = threading.Event()
        
        # Cache icons
        self.icon_active = self._create_shield_image(active=True)
        self.icon_stopped = self._create_shield_image(active=False)

    def _create_shield_image(self, active: bool = True) -> Image.Image:
        """Dynamically render a sharp 64x64 shield icon with state indicators."""
        size = 64
        image = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        draw = ImageDraw.Draw(image)

        # Base Shield outline / fill
        primary_color = (16, 185, 129, 255) if active else (239, 68, 68, 255)   # Emerald vs Rose
        secondary_color = (6, 95, 70, 255) if active else (153, 27, 27, 255)
        glow_color = (52, 211, 153, 180) if active else (248, 113, 113, 180)

        # Outer rounded shield polygon
        shield_points = [
            (32, 6),   # Top center peak
            (56, 14),  # Top right shoulder
            (52, 40),  # Mid right curve
            (32, 58),  # Bottom center tip
            (12, 40),  # Mid left curve
            (8, 14),   # Top left shoulder
        ]
        
        # Draw soft glow
        draw.polygon(shield_points, fill=secondary_color, outline=glow_color, width=2)
        
        # Inner shield
        inner_points = [
            (32, 10),
            (50, 17),
            (47, 38),
            (32, 53),
            (17, 38),
            (14, 17),
        ]
        draw.polygon(inner_points, fill=primary_color)

        # Center Emblem (Checkmark for active, X for stopped)
        if active:
            # Clean checkmark
            draw.line([(22, 32), (29, 41), (43, 23)], fill=(255, 255, 255, 255), width=4)
        else:
            # Clean X mark
            draw.line([(23, 23), (41, 41)], fill=(255, 255, 255, 255), width=4)
            draw.line([(41, 23), (23, 41)], fill=(255, 255, 255, 255), width=4)

        return image

    def is_port_open(self, host: str = BACKEND_HOST, port: int = BACKEND_PORT) -> bool:
        """Check if FastAPI Uvicorn port is actively listening."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.6)
            return sock.connect_ex((host, port)) == 0

    def start_backend(self):
        """Spawn the AegisAI FastAPI backend server silently in the background."""
        if self.is_port_open():
            self.is_running = True
            send_system_alert("🛡️ AegisAI Security Guard", "AegisAI background engine is already running on port 8000.")
            self._update_tray_state()
            return

        creation_flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        cmd = [
            str(VENV_PYTHONW),
            "-m",
            "uvicorn",
            "app.main:app",
            "--host",
            "0.0.0.0",
            "--port",
            str(BACKEND_PORT),
        ]
        
        try:
            self.backend_proc = subprocess.Popen(
                cmd,
                cwd=str(SERVER_ROOT),
                creationflags=creation_flags,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            # Wait briefly for port to open
            for _ in range(15):
                time.sleep(0.4)
                if self.is_port_open():
                    self.is_running = True
                    break

            send_system_alert(
                "🛡️ AegisAI Security Guard",
                "AegisAI 2.0 Edge ML Defense Engine is active & guarding host telemetry.",
            )
        except Exception as e:
            send_system_alert("⚠️ AegisAI Error", f"Failed to start AegisAI backend service: {e}")
        
        self._update_tray_state()

    def stop_backend(self):
        """Terminate the Uvicorn backend process cleanly."""
        stopped = False
        if self.backend_proc and self.backend_proc.poll() is None:
            try:
                self.backend_proc.terminate()
                self.backend_proc.wait(timeout=3)
                stopped = True
            except Exception:
                self.backend_proc.kill()
                stopped = True
            self.backend_proc = None

        # Also kill any orphan uvicorn processes listening on port 8000 (Windows)
        if os.name == "nt" and self.is_port_open():
            try:
                subprocess.run(
                    ["powershell", "-NoProfile", "-Command",
                     "Get-NetTCPConnection -LocalPort 8000 -ErrorAction SilentlyContinue | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }"],
                    creationflags=subprocess.CREATE_NO_WINDOW,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                time.sleep(0.5)
                stopped = True
            except Exception:
                pass

        self.is_running = self.is_port_open()
        send_system_alert(
            "🛑 AegisAI Guard Stopped",
            "AegisAI background defense engine has been stopped for this session.",
        )
        self._update_tray_state()

    def launch_dashboard(self):
        """Open the AegisAI React SOC dashboard in the default browser."""
        try:
            # 1. If Vite dev server is running on port 5173, prioritize dev URL
            if self.is_port_open(BACKEND_HOST, 5173):
                webbrowser.open_new_tab("http://localhost:5173")
                return

            # 2. If FastAPI backend (port 8000) is running, open the hosted SPA dashboard
            if self.is_port_open(BACKEND_HOST, BACKEND_PORT):
                webbrowser.open_new_tab(f"http://localhost:{BACKEND_PORT}")
                return

            # 3. If neither is running, start the backend engine first
            self.start_backend()
            time.sleep(1.0)
            target_url = f"http://localhost:{BACKEND_PORT}" if self.is_port_open(BACKEND_HOST, BACKEND_PORT) else "http://localhost:5173"
            webbrowser.open_new_tab(target_url)
        except Exception as e:
            send_system_alert("AegisAI Launch Error", f"Could not open browser: {e}")

    def trigger_replay_demo(self):
        """Execute the live attack replay streamer in a non-blocking background process."""
        if not self.is_port_open():
            send_system_alert("⚠️ AegisAI Demo", "Please start AegisAI Engine before triggering attack replay.")
            return

        replay_script = SERVER_ROOT / "scripts" / "replay_attacks.py"
        creation_flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        
        try:
            # Run replay in background with continuous demonstration rate
            cmd = [
                str(VENV_PYTHON),
                str(replay_script),
                "--delay",
                "1.5",
                "--count",
                "15",
                "--agent",
            ]
            self.replay_proc = subprocess.Popen(
                cmd,
                cwd=str(SERVER_ROOT),
                creationflags=creation_flags,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            send_system_alert(
                "📊 AegisAI Attack Replay",
                "Replaying 15 live cyber attack vectors (DDoS, Zero-Day & Scans) into SOC dashboard.",
            )
        except Exception as e:
            send_system_alert("AegisAI Replay Error", f"Failed to launch attack replay: {e}")

    def _get_status_text(self) -> str:
        return "🟢 AegisAI Guard Active (Port 8000)" if self.is_running else "🔴 AegisAI Engine Stopped"

    def _update_tray_state(self):
        """Refresh icon image and menu title."""
        if not self.icon:
            return
        self.is_running = self.is_port_open()
        self.icon.icon = self.icon_active if self.is_running else self.icon_stopped
        self.icon.title = f"AegisAI 2.0 ({'Active' if self.is_running else 'Stopped'})"
        self.icon.menu = self._build_menu()

    def _build_menu(self) -> Menu:
        """Construct the dynamic context menu."""
        status_text = self._get_status_text()
        
        return Menu(
            item(status_text, lambda: None, enabled=False),
            Menu.SEPARATOR,
            item("⚡ Launch Dashboard", lambda: self.launch_dashboard()),
            item("📊 Trigger Replay Demo", lambda: self.trigger_replay_demo()),
            Menu.SEPARATOR,
            item("▶️ Start Engine", lambda: self.start_backend(), enabled=not self.is_running),
            item("⏹️ Stop Engine (This Session)", lambda: self.stop_backend(), enabled=self.is_running),
            Menu.SEPARATOR,
            item("❌ Exit AegisAI Tray", lambda: self.exit_app()),
        )

    def _monitor_loop(self):
        """Background thread to detect engine state changes and sync tray UI."""
        while not self._stop_monitor.is_set():
            time.sleep(3.0)
            current_state = self.is_port_open()
            if current_state != self.is_running:
                self.is_running = current_state
                if self.icon:
                    self.icon.icon = self.icon_active if self.is_running else self.icon_stopped
                    self.icon.title = f"AegisAI 2.0 ({'Active' if self.is_running else 'Stopped'})"
                    self.icon.menu = self._build_menu()

    def exit_app(self):
        """Stop background monitors and terminate tray icon loop."""
        self._stop_monitor.set()
        if self.icon:
            self.icon.stop()

    def run(self, auto_start_engine: bool = True):
        """Initialize and run the pystray mainloop (blocking in calling thread)."""
        self.is_running = self.is_port_open()
        
        if auto_start_engine and not self.is_running:
            self.start_backend()

        self.icon = pystray.Icon(
            name="AegisAI",
            icon=self.icon_active if self.is_running else self.icon_stopped,
            title=f"AegisAI 2.0 ({'Active' if self.is_running else 'Stopped'})",
            menu=self._build_menu(),
        )

        # Start health monitor
        self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._monitor_thread.start()

        # Run system tray event loop
        self.icon.run()


def main():
    import argparse
    parser = argparse.ArgumentParser(description="AegisAI System Tray Controller")
    parser.add_argument("--no-autostart", action="store_true", help="Do not automatically start the FastAPI engine")
    args = parser.parse_args()

    controller = AegisTrayController()
    controller.run(auto_start_engine=not args.no_autostart)


if __name__ == "__main__":
    main()
