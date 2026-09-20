"""
AegisAI Dynamic Path Resolution Utility
=======================================
Resolves filesystem paths whether running in standard Python development mode
or packaged inside a PyInstaller frozen one-file/one-dir bundle (sys._MEIPASS).
"""
import sys
import os
from pathlib import Path


def get_resource_path(relative_path: str) -> str:
    """
    Get absolute path to a bundled resource.
    Works for development environment and for PyInstaller frozen bundles.
    """
    if hasattr(sys, "_MEIPASS"):
        # PyInstaller extracts bundled data files to sys._MEIPASS
        base_path = sys._MEIPASS
    else:
        # Development mode: base is the repository root
        base_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
        
    resolved = os.path.normpath(os.path.join(base_path, relative_path))
    return resolved


def get_data_dir() -> Path:
    """
    Returns a persistent, writable directory for runtime databases, logs, and quarantine.
    In frozen mode, defaults to the executable directory or local app data.
    """
    if hasattr(sys, "_MEIPASS"):
        exe_dir = Path(sys.executable).parent
        return exe_dir
    return Path(__file__).resolve().parents[3]
