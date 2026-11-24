"""Collector for systemd-journald via `journalctl -f -o json`."""
from __future__ import annotations

import json
import os
import signal
import subprocess
import time
from datetime import datetime
from typing import Optional

from ..events import Event, Severity, make_event
from ..utils import which, eprint
from .base import Collector, EventQueue
from .parsers import kernel_device, parse_auth_line, parse_kernel_line, parse_firewall_line


# syslog PRIORITY → Severity
_PRIORITY_MAP = {
    0: Severity.CRITICAL,  # emerg
    1: Severity.CRITICAL,  # alert
    2: Severity.CRITICAL,  # crit
    3: Severity.ERROR,     # err
    4: Severity.WARN,      # warning
    5: Severity.INFO,      # notice
    6: Severity.INFO,      # info
    7: Severity.DEBUG,     # debug
}


class JournalCollector(Collector):
    name = "journal"
    source = "system"

    def __init__(self, queue: EventQueue, config, stop_event=None):
        super().__init__(queue, config, stop_event)
        self._proc: Optional[subprocess.Popen] = None

    # ── lifecycle ──────────────────────────────────────────────
    def _on_stop(self) -> None:
        if self._proc and self._proc.poll() is None:
            try:
                os.killpg(os.getpgid(self._proc.pid), signal.SIGTERM)
            except (ProcessLookupError, PermissionError):
                try:
                    self._proc.terminate()
                except Exception:
                    pass
            try:
                self._proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(os.getpgid(self._proc.pid), signal.SIGKILL)
                except Exception:
                    try:
                        self._proc.kill()
                    except Exception:
                        pass

    # ── main loop ──────────────────────────────────────────────
    def _run(self) -> None:
        if not which("journalctl"):
            raise RuntimeError("journalctl unavailable")

        cmd = [
            "journalctl", "-f", "-n", "50",
            "-o", "json", "--no-pager", "-q",
        ]
        try:
            self._proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
                start_new_session=True,
            )
        except FileNotFoundError as exc:
            raise RuntimeError("could not start journalctl") from exc

        try:
            assert self._proc.stdout is not None
            for line in self._proc.stdout:
                if self.should_stop():
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                ev = self._to_event(rec)
                if ev:
                    self.emit(ev)
                if self._proc.poll() is not None:
                    break
        finally:
            self._on_stop()

    # ── parsing ────────────────────────────────────────────────
    def _to_event(self, rec: dict) -> Optional[Event]:
        # Timestamp: realtime is a JSON field as string microseconds
        ts = self._parse_ts(rec)

        message = rec.get("MESSAGE", "")
        if isinstance(message, list):  # some fields are binary
            message = "<binary>"
        if not message:
            return None

        priority = self._int(rec.get("PRIORITY"))
        severity = _PRIORITY_MAP.get(priority, Severity.INFO)

        ident = rec.get("SYSLOG_IDENTIFIER") or rec.get("_COMM") or "unknown"
        hostname = rec.get("_HOSTNAME") or ""
        pid = self._int(rec.get("_PID"))
        unit_field = {"systemd-coredump": "COREDUMP_UNIT", "systemd": "UNIT"}.get(
            ident, "_SYSTEMD_UNIT",
        )
        unit = rec.get(unit_field, "")
        if not isinstance(unit, str):
            unit = ""
        transport = rec.get("_TRANSPORT", "")

        # Detect category & possibly upgrade severity via shared parsers
        category = ident
        extra: dict = {"ident": ident, "unit": unit, "transport": transport}
        source = "kernel" if transport == "kernel" else "system"
        user = None
        src_ip = None
        dst_ip = None
        dst_port = None
        protocol = None

        # Try auth patterns
        auth = parse_auth_line(message, ident)
        if auth:
            source = "auth"
            category = auth["category"]
            severity = max(severity, Severity.parse(auth["severity"]))
            user = auth.get("user")
            src_ip = auth.get("src_ip")
            extra.update(auth.get("extra", {}))

        # Try kernel patterns
        kern = parse_kernel_line(message)
        if kern:
            source = "kernel"
            category = kern["category"]
            severity = max(severity, Severity.parse(kern["severity"]))
            pid = kern.get("pid") or pid
            extra.update(kern.get("extra", {}))

        # Try firewall patterns
        fw = parse_firewall_line(message)
        if fw:
            source = "firewall"
            category = fw["category"]
            severity = max(severity, Severity.parse(fw["severity"]))
            src_ip = fw.get("src_ip") or src_ip
            dst_ip = fw.get("dst_ip")
            dst_port = fw.get("dst_port")
            protocol = fw.get("protocol")
            extra.update(fw.get("extra", {}))

        if source == "kernel":
            extra["device"] = kernel_device(message)
        return Event(
            ts=ts,
            source=source,
            category=category,
            severity=severity,
            message=message[:2000],
            raw=json.dumps(rec, ensure_ascii=False),
            host=hostname,
            pid=pid,
            user=user,
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=dst_port,
            protocol=protocol,
            extra=extra,
        )

    @staticmethod
    def _parse_ts(rec: dict) -> float:
        rt = rec.get("__REALTIME_TIMESTAMP")
        if rt:
            try:
                return int(rt) / 1_000_000.0
            except (TypeError, ValueError):
                pass
        # Fallback: try to parse from message dict (rare)
        return time.time()

    @staticmethod
    def _int(v) -> Optional[int]:
        if v is None:
            return None
        try:
            return int(v)
        except (TypeError, ValueError):
            return None


# ── standalone test ───────────────────────────────────────────────
if __name__ == "__main__":
    import argparse

    from ..config import Config

    p = argparse.ArgumentParser(description="Test JournalCollector in isolation")
    p.add_argument("--verbose", action="store_true", help="Show raw JSON")
    args = p.parse_args()

    q = EventQueue(maxsize=1000)
    c = JournalCollector(q, Config.load())
    c.start()
    print(f"[journal] running, Ctrl+C to stop\n")
    try:
        while True:
            ev = q.get(timeout=0.5)
            if ev:
                print(
                    f"{ev.ts:.3f} [{ev.severity.name:8}] "
                    f"{ev.source:8} {ev.category:20} {ev.message[:110]}"
                )
                if args.verbose:
                    print(f"           raw: {ev.raw[:200]}")
    except KeyboardInterrupt:
        print("\n[journal] stopping…")
    finally:
        c.stop()