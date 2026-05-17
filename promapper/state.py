"""
State management — persistent state, diff detection, desktop notifications.
"""
from __future__ import annotations

import json
import logging
import os
import subprocess
import tempfile
import threading
from typing import Any, Dict, List

from promapper.config import IS_WINDOWS, IS_MACOS, cfg
from promapper.datatypes import HostResult

logger = logging.getLogger(__name__)

_STATE_FILE: str = os.path.join(tempfile.gettempdir(), "promapper_state.json")
_STATE_LOCK: threading.Lock = threading.Lock()


def save_state(results: List[HostResult]) -> None:
    try:
        data = [{
            "host": r.host, "ip": r.ip, "up": r.up,
            "open_ports": sorted(r.open_tcp + r.open_udp),
            "os": r.os_guess, "latency_ms": r.latency_ms,
        } for r in results]
        with _STATE_LOCK:
            with open(_STATE_FILE, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
    except Exception as e:
        logger.debug("Save state error: %s", e)


def load_state() -> List[Dict[str, Any]]:
    try:
        with _STATE_LOCK:
            with open(_STATE_FILE, encoding="utf-8") as f:
                return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def diff_results(old: List[Dict[str, Any]], new: List[HostResult]) -> List[str]:
    changes: List[str] = []
    old_map = {o["ip"]: o for o in old}
    for n in new:
        o = old_map.get(n.ip)
        if not o:
            changes.append(f"[+] New host: {n.host} ({n.ip})")
            continue
        if o["up"] != n.up:
            changes.append(f"[!] {n.ip} status change: {'up' if n.up else 'down'} "
                           f"(was {'up' if o['up'] else 'down'})")
            continue
        old_ports = set(o.get("open_ports", []))
        new_ports = set(n.open_tcp + n.open_udp)
        for p in new_ports - old_ports:
            changes.append(f"[+] {n.ip}:{p} new open port")
        for p in old_ports - new_ports:
            changes.append(f"[-] {n.ip}:{p} port closed")
    return changes


def send_notification(title: str, message: str) -> None:
    if IS_WINDOWS:
        try:
            import ctypes
            ctypes.windll.user32.MessageBoxW(0, message, title, 0)
        except Exception:
            pass
    elif IS_MACOS:
        try:
            esc_msg = message.replace('"', '\\"')
            esc_title = title.replace('"', '\\"')
            subprocess.run(
                ["osascript", "-e", f'display notification "{esc_msg}" with title "{esc_title}"'],
                capture_output=True, timeout=2,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
    else:
        for cmd in [
            ["notify-send", title, message],
            ["kdialog", "--title", title, "--passivepopup", message, "3"],
        ]:
            try:
                subprocess.run(cmd, timeout=2)
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass
