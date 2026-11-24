"""Collectors for traditional /var/log/* files (syslog, auth, kern, firewall)."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Callable, Optional

from ..events import Event, Severity, make_event
from ..utils import follow_file, eprint
from .base import Collector, EventQueue
from .parsers import (
    parse_syslog_line, parse_syslog_ts,
    parse_auth_line, parse_kernel_line, parse_firewall_line,
)


# ── path discovery ─────────────────────────────────────────────────
SYSLOG_CANDIDATES = ["/var/log/syslog", "/var/log/messages"]
AUTH_CANDIDATES = ["/var/log/auth.log", "/var/log/secure"]
KERNEL_CANDIDATES = ["/var/log/kern.log", "/var/log/kernel.log"]
FIREWALL_CANDIDATES = ["/var/log/ufw.log", "/var/log/firewall.log"]


def find_log(candidates: list[str]) -> Optional[Path]:
    for p in candidates:
        path = Path(p)
        if path.exists() and path.is_file():
            return path
    return None


def _firewall_event(line, parsed, ts):
    message = parsed["message"]
    fw = parse_firewall_line(message)
    if not fw:
        return None

    return Event(
        ts=ts,
        source="firewall",
        category=fw["category"],
        severity=Severity.parse(fw["severity"]),
        message=message[:2000],
        raw=line,
        host=parsed["host"],
        pid=parsed["pid"],
        src_ip=fw.get("src_ip"),
        dst_ip=fw.get("dst_ip"),
        dst_port=fw.get("dst_port"),
        protocol=fw.get("protocol"),
        extra=fw.get("extra", {}),
    )


# ── base tail collector ────────────────────────────────────────────
class BaseFileCollector(Collector):
    """Generic file follower. Subclasses supply `_handle_line`."""

    def __init__(self, queue: EventQueue, config, path: Path, stop_event=None):
        super().__init__(queue, config, stop_event)
        self.path = Path(path)

    def _run(self) -> None:
        if not self.path.exists():
            eprint(f"[{self.name}] {self.path} not found — skipping")
            return
        try:
            for line in follow_file(self.path, poll=0.3, from_start=False, stop_event=self.stop_event):
                if self.should_stop():
                    break
                if not line:
                    continue
                try:
                    ev = self._handle_line(line)
                except Exception as e:
                    eprint(f"[{self.name}] parse error: {e}")
                    continue
                if ev:
                    self.emit(ev)
        except OSError as exc:
            raise RuntimeError(f"{self.path}: {exc.strerror}") from exc

    def _handle_line(self, line: str) -> Optional[Event]:
        raise NotImplementedError


# ── syslog / messages ──────────────────────────────────────────────
class SyslogCollector(BaseFileCollector):
    name = "syslog"
    source = "system"

    def __init__(self, queue: EventQueue, config, path: Optional[Path] = None, stop_event=None):
        path = path or find_log(SYSLOG_CANDIDATES)
        if not path:
            raise FileNotFoundError("no syslog or messages file found")
        super().__init__(queue, config, path, stop_event)

    def _handle_line(self, line: str) -> Optional[Event]:
        parsed = parse_syslog_line(line)
        if not parsed:
            return self._raw_event(line)

        message = parsed["message"]
        ident = parsed["ident"]
        ts = parse_syslog_ts(parsed["ts_raw"])

        # Defaults
        source = "system"
        category = ident
        severity = Severity.INFO
        user = None
        src_ip = None
        dst_ip = None
        dst_port = None
        protocol = None
        extra = {"ident": ident, "host": parsed["host"]}

        # Kernel message in syslog?
        if ident == "kernel":
            source = "kernel"
            k = parse_kernel_line(message)
            if k:
                source = "kernel"
                category = k["category"]
                severity = Severity.parse(k["severity"])
                extra.update(k.get("extra", {}))

            fw = parse_firewall_line(message)
            if fw:
                source = "firewall"
                category = fw["category"]
                severity = Severity.parse(fw["severity"])
                src_ip = fw.get("src_ip")
                dst_ip = fw.get("dst_ip")
                dst_port = fw.get("dst_port")
                protocol = fw.get("protocol")
                extra.update(fw.get("extra", {}))
        else:
            # Auth-looking messages sometimes land in syslog
            a = parse_auth_line(message, ident)
            if a:
                source = "auth"
                category = a["category"]
                severity = Severity.parse(a["severity"])
                user = a.get("user")
                src_ip = a.get("src_ip")
                extra.update(a.get("extra", {}))

        # Raise severity heuristically if nothing matched
        if severity == Severity.INFO:
            low = message.lower()
            if any(term in low for term in ("critical", "panic", "fatal")):
                severity = Severity.CRITICAL
            elif any(term in low for term in ("error", "fail", "denied", "exception")):
                severity = Severity.ERROR
            elif "warn" in low:
                severity = Severity.WARN

        return Event(
            ts=ts,
            source=source,
            category=category,
            severity=severity,
            message=message[:2000],
            raw=line,
            host=parsed["host"],
            pid=parsed["pid"],
            user=user,
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=dst_port,
            protocol=protocol,
            extra=extra,
        )

    def _raw_event(self, line: str) -> Event:
        return make_event(
            source="system", category="raw", severity="INFO",
            message=line[:500], raw=line, extra={"file": str(self.path)},
        )


# ── auth.log / secure ──────────────────────────────────────────────
class AuthLogCollector(BaseFileCollector):
    name = "auth"
    source = "auth"

    def __init__(self, queue: EventQueue, config, path: Optional[Path] = None, stop_event=None):
        path = path or find_log(AUTH_CANDIDATES)
        if not path:
            raise FileNotFoundError("no auth.log or secure file found")
        super().__init__(queue, config, path, stop_event)

    def _handle_line(self, line: str) -> Optional[Event]:
        parsed = parse_syslog_line(line)
        if not parsed:
            return None
        message = parsed["message"]
        ident = parsed["ident"]
        ts = parse_syslog_ts(parsed["ts_raw"])

        a = parse_auth_line(message, ident)
        if a:
            return Event(
                ts=ts,
                source="auth",
                category=a["category"],
                severity=Severity.parse(a["severity"]),
                message=message[:2000],
                raw=line,
                host=parsed["host"],
                pid=parsed["pid"],
                user=a.get("user"),
                src_ip=a.get("src_ip"),
                extra={"ident": ident, **a.get("extra", {})},
            )

        # Unmatched auth line — keep as INFO for visibility
        return Event(
            ts=ts,
            source="auth",
            category=ident,
            severity=Severity.INFO,
            message=message[:2000],
            raw=line,
            host=parsed["host"],
            pid=parsed["pid"],
            extra={"ident": ident},
        )


# ── kern.log ───────────────────────────────────────────────────────
class KernelLogCollector(BaseFileCollector):
    name = "kernel"
    source = "kernel"

    def __init__(self, queue: EventQueue, config, path: Optional[Path] = None, stop_event=None):
        path = path or find_log(KERNEL_CANDIDATES)
        if not path:
            raise FileNotFoundError("no kern.log file found")
        super().__init__(queue, config, path, stop_event)

    def _handle_line(self, line: str) -> Optional[Event]:
        parsed = parse_syslog_line(line)
        if not parsed:
            return None
        message = parsed["message"]
        ts = parse_syslog_ts(parsed["ts_raw"])

        if self.config.firewall_enabled:
            firewall = _firewall_event(line, parsed, ts)
            if firewall:
                return firewall

        k = parse_kernel_line(message)
        if k:
            return Event(
                ts=ts,
                source="kernel",
                category=k["category"],
                severity=Severity.parse(k["severity"]),
                message=message[:2000],
                raw=line,
                host=parsed["host"],
                pid=k.get("pid") or parsed["pid"],
                extra=k.get("extra", {}),
            )

        return Event(
            ts=ts,
            source="kernel",
            category="kernel",
            severity=Severity.INFO,
            message=message[:2000],
            raw=line,
            host=parsed["host"],
            pid=parsed["pid"],
            extra={},
        )


# ── ufw.log / firewall.log ─────────────────────────────────────────
class FirewallLogCollector(BaseFileCollector):
    name = "firewall"
    source = "firewall"

    def __init__(self, queue: EventQueue, config, path: Optional[Path] = None, stop_event=None):
        path = path or find_log(FIREWALL_CANDIDATES)
        if not path:
            raise FileNotFoundError("no ufw.log or firewall.log file found")
        super().__init__(queue, config, path, stop_event)

    def _handle_line(self, line: str) -> Optional[Event]:
        parsed = parse_syslog_line(line)
        if not parsed:
            return None
        message = parsed["message"]
        ts = parse_syslog_ts(parsed["ts_raw"])

        return _firewall_event(line, parsed, ts)


# ── standalone test ───────────────────────────────────────────────
if __name__ == "__main__":
    import argparse

    from ..config import Config

    p = argparse.ArgumentParser(description="Test a file-based collector")
    p.add_argument("--type", required=True,
                   choices=["syslog", "auth", "kernel", "firewall"])
    p.add_argument("--path", default=None, help="Override auto-detected path")
    args = p.parse_args()

    classes = {
        "syslog": SyslogCollector,
        "auth": AuthLogCollector,
        "kernel": KernelLogCollector,
        "firewall": FirewallLogCollector,
    }
    cls = classes[args.type]

    q = EventQueue(maxsize=1000)
    try:
        c = cls(q, Config.load(), path=Path(args.path) if args.path else None)
    except FileNotFoundError as e:
        print(f"[{args.type}] {e}")
        raise SystemExit(1)

    print(f"[{args.type}] following {c.path}, Ctrl+C to stop\n")
    c.start()
    try:
        while True:
            ev = q.get(timeout=0.5)
            if ev:
                print(
                    f"{ev.ts:.3f} [{ev.severity.name:8}] "
                    f"{ev.source:8} {ev.category:20} {ev.message[:110]}"
                )
    except KeyboardInterrupt:
        print(f"\n[{args.type}] stopping…")
    finally:
        c.stop()