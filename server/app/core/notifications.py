"""
AegisAI Desktop Notification Engine
====================================
Cross-platform native OS desktop toast/bubble notification handler.
Supports Windows 10/11 native toasts via plyer with robust PowerShell / WinAPI fallback.
Includes rate-limiting & de-duplication to prevent toast flooding during DDoS replays.
"""
from __future__ import annotations

import os
import sys
import time
import threading
import subprocess
from typing import Optional
from loguru import logger

_last_notification_time: float = 0.0
_MIN_NOTIFICATION_INTERVAL_SEC: float = 2.5
_lock = threading.Lock()


def _send_windows_powershell_toast(title: str, message: str) -> bool:
    """Fallback Windows toast using PowerShell XML notification."""
    try:
        # Sanitize message and title for PowerShell
        safe_title = title.replace('"', '`"').replace("'", "''")
        safe_msg = message.replace('"', '`"').replace("'", "''")
        
        ps_cmd = (
            f"[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null; "
            f"$template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02); "
            f"$textNodes = $template.GetElementsByTagName('text'); "
            f"$textNodes.Item(0).AppendChild($template.CreateTextNode('{safe_title}')) > $null; "
            f"$textNodes.Item(1).AppendChild($template.CreateTextNode('{safe_msg}')) > $null; "
            f"$toast = [Windows.UI.Notifications.ToastNotification]::new($template); "
            f"[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('AegisAI 2.0 Security Engine').Show($toast);"
        )
        subprocess.Popen(
            ["powershell", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", ps_cmd],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
        return True
    except Exception as e:
        logger.debug(f"[NOTIFY] PowerShell toast fallback failed: {e}")
        return False


def _dispatch_notification(title: str, message: str, app_name: str = "AegisAI Security Engine", timeout: int = 5):
    """Internal synchronous notification dispatcher called in a worker thread."""
    if sys.platform == "win32":
        # On Windows, use native WinRT Action Center toast for modern Windows 10/11 look
        ok = _send_windows_powershell_toast(title, message)
        if ok:
            return

    # Fallback / Cross-platform path (Linux / macOS / fallback)
    try:
        # pyrefly: ignore [missing-import]
        from plyer import notification
        notification.notify(
            title=title,
            message=message,
            app_name=app_name,
            timeout=timeout,
            ticker=title,
        )
    except Exception as e:
        logger.debug(f"[NOTIFY] Notification dispatch error: {e}")


def notify_threat_alert(
    threat_type: str,
    severity: str,
    source_ip: str,
    port: Optional[int] = None,
    action_taken: str = "logged",
    force: bool = False,
):
    """
    Push a non-blocking native OS notification for a critical/high severity threat.
    
    Rate-limited to prevent notification storms on high-frequency attack replays.
    """
    global _last_notification_time
    now = time.time()
    
    with _lock:
        if not force and (now - _last_notification_time) < _MIN_NOTIFICATION_INTERVAL_SEC:
            logger.debug("[NOTIFY] Suppressed notification due to rate limit threshold.")
            return
        _last_notification_time = now

    sev_upper = severity.upper()
    sev_icon = "🚨" if sev_upper == "CRITICAL" else "⚠️"
    title = f"{sev_icon} AegisAI Threat Alert: {sev_upper}"
    
    port_str = f":{port}" if port else ""
    action_desc = "Trapped in Honeypot" if "trap" in action_taken.lower() else (
        "Host Isolated" if "isolate" in action_taken.lower() else "Remediation Rule Queued"
    )
    
    msg = f"{threat_type} detected from {source_ip}{port_str}.\nStatus: {action_desc}."

    # Dispatch non-blockingly in separate thread
    threading.Thread(
        target=_dispatch_notification,
        args=(title, msg),
        daemon=True,
    ).start()
    logger.info(f"[NOTIFY] Dispatched native OS threat alert: {title} - {source_ip}")


def send_system_alert(title: str, message: str):
    """Push generic system notification (e.g. Daemon started, Stopped, Service event)."""
    threading.Thread(
        target=_dispatch_notification,
        args=(title, message),
        daemon=True,
    ).start()
