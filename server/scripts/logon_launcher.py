"""
AegisAI 2.0 — Windows Logon Permission Launcher Dialog
======================================================
Prompts the user at Windows login to allow AegisAI Edge Defense Engine
to run silently in the background with taskbar system tray monitoring.

Triggered via Registry Run key:
  HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run -> AegisAILauncher
"""
from __future__ import annotations

import os
import sys
import subprocess
import tkinter as tk
from pathlib import Path

# Resolve project paths
SERVER_ROOT = Path(__file__).resolve().parents[1]
if str(SERVER_ROOT) not in sys.path:
    sys.path.insert(0, str(SERVER_ROOT))

# Executables
if os.name == "nt":
    VENV_PYTHONW = SERVER_ROOT / "venv" / "Scripts" / "pythonw.exe"
    VENV_PYTHON = SERVER_ROOT / "venv" / "Scripts" / "python.exe"
else:
    VENV_PYTHONW = SERVER_ROOT / "venv" / "bin" / "python"
    VENV_PYTHON = SERVER_ROOT / "venv" / "bin" / "python"

if not VENV_PYTHONW.exists():
    VENV_PYTHONW = Path(sys.executable)
if not VENV_PYTHON.exists():
    VENV_PYTHON = Path(sys.executable)

TRAY_AGENT_SCRIPT = SERVER_ROOT / "app" / "collector" / "tray_agent.py"


def launch_aegis_background():
    """Spawn the AegisAI Tray Controller which manages the backend and tray icon silently."""
    creation_flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    
    cmd = [
        str(VENV_PYTHONW),
        str(TRAY_AGENT_SCRIPT),
    ]
    
    try:
        subprocess.Popen(
            cmd,
            cwd=str(SERVER_ROOT),
            creationflags=creation_flags,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception as e:
        # Fallback to standard python if pythonw has any issue
        subprocess.Popen(
            [str(VENV_PYTHON), str(TRAY_AGENT_SCRIPT)],
            cwd=str(SERVER_ROOT),
            creationflags=creation_flags,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )


class AegisLogonDialog:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("AegisAI Security Engine")
        self.root.geometry("490x320")
        self.root.resizable(False, False)
        self.root.configure(bg="#0B1120")  # Dark slate navy

        # Attempt to make window stay on top during logon
        try:
            self.root.attributes("-topmost", True)
        except Exception:
            pass

        # Center on screen
        self._center_window()

        # UI Components
        self._build_ui()

    def _center_window(self):
        self.root.update_idletasks()
        width = 490
        height = 320
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f"{width}x{height}+{x}+{y}")

    def _build_ui(self):
        # Header banner container
        header_frame = tk.Frame(self.root, bg="#0F172A", height=70)
        header_frame.pack(fill="x", side="top")

        # Shield Icon & Title in Header
        title_label = tk.Label(
            header_frame,
            text="🛡️  AegisAI 2.0 Security Engine",
            font=("Segoe UI", 14, "bold"),
            fg="#38BDF8",  # Cyan accent
            bg="#0F172A",
            padx=20,
            pady=16,
        )
        title_label.pack(anchor="w")

        # Main Body Container
        body_frame = tk.Frame(self.root, bg="#0B1120", padx=24, pady=20)
        body_frame.pack(fill="both", expand=True)

        # Prompt question
        prompt_label = tk.Label(
            body_frame,
            text="Start AegisAI Defense Engine for this session?",
            font=("Segoe UI", 12, "bold"),
            fg="#F8FAFC",
            bg="#0B1120",
            anchor="w",
            justify="left",
        )
        prompt_label.pack(fill="x", pady=(0, 8))

        # Description
        desc_text = (
            "AegisAI runs silently in the taskbar with real-time ML anomaly detection, "
            "zero-day honeypot containment, and instant desktop alerts for high-severity threats."
        )
        desc_label = tk.Label(
            body_frame,
            text=desc_text,
            font=("Segoe UI", 9),
            fg="#94A3B8",
            bg="#0B1120",
            wraplength=440,
            justify="left",
            anchor="w",
        )
        desc_label.pack(fill="x", pady=(0, 16))

        # Divider
        divider = tk.Frame(body_frame, height=1, bg="#1E293B")
        divider.pack(fill="x", pady=(0, 20))

        # Action Buttons Container
        button_frame = tk.Frame(body_frame, bg="#0B1120")
        button_frame.pack(fill="x", side="bottom")

        # Allow & Start Button
        btn_allow = tk.Button(
            button_frame,
            text="🛡️ Allow & Start",
            font=("Segoe UI", 10, "bold"),
            bg="#0284C7",       # Sky Blue 600
            fg="#FFFFFF",
            activebackground="#0369A1",
            activeforeground="#FFFFFF",
            relief="flat",
            padx=18,
            pady=8,
            cursor="hand2",
            command=self.on_allow,
        )
        btn_allow.pack(side="right", padx=(8, 0))

        # Skip for Now Button
        btn_skip = tk.Button(
            button_frame,
            text="Skip for Now",
            font=("Segoe UI", 10),
            bg="#1E293B",       # Slate 800
            fg="#CBD5E1",
            activebackground="#334155",
            activeforeground="#FFFFFF",
            relief="flat",
            padx=16,
            pady=8,
            cursor="hand2",
            command=self.on_skip,
        )
        btn_skip.pack(side="right")

    def on_allow(self):
        launch_aegis_background()
        self.root.destroy()

    def on_skip(self):
        self.root.destroy()


def main():
    root = tk.Tk()
    app = AegisLogonDialog(root)
    root.mainloop()


if __name__ == "__main__":
    main()
