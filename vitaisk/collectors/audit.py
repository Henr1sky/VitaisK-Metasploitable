"""Collector for /var/log/audit/audit.log (auditd). Auto-skips if absent."""
from __future__ import annotations

import re
from pathlib import Path
from socket import gethostname
from typing import Optional

from ..events import Event, Severity
from ..utils import follow_file, eprint
from .base import Collector, EventQueue


_RE_TYPE = re.compile(r"^type=(?P<type>\w+)\s+msg=audit\((?P<audit_id>\d+\.\d+:\d+)\):\s*(?P<rest>.*)$")
_RE_KV = re.compile(r'(\w+)=((?:"[^"]*")|(?:\S+))')

# Audit record types of interest → severity
_TYPE_SEVERITY = {
    "USER_AUTH": Severity.INFO,
    "USER_ACCT": Severity.INFO,
    "USER_LOGIN": Severity.INFO,
    "USER_CMD": Severity.INFO,
    "CRED_ACQ": Severity.INFO,
    "CRED_DISP": Severity.INFO,
    "USER_START": Severity.INFO,
    "USER_END": Severity.INFO,
    "SERVICE_START": Severity.INFO,
    "SERVICE_STOP": Severity.INFO,
    "EXECVE": Severity.DEBUG,
    "SYSCALL": Severity.DEBUG,
    "CWD": Severity.DEBUG,
    "PATH": Severity.DEBUG,
    "CONFIG_CHANGE": Severity.WARN,
    "ANOM_ABEND": Severity.ERROR,       # abnormal termination
    "ANOM_EXEC": Severity.WARN,          # unusual exec
    "ANOM_LOGIN_FAILURES": Severity.WARN,
    "ANOM_LOGIN_LOCATION": Severity.WARN,
    "ANOM_LOGIN_TIME": Severity.WARN,
    "AVC": Severity.WARN,                # SELinux denial
    "SECCOMP": Severity.WARN,
    "KERN_MODULE": Severity.WARN,
    "NETFILTER_CFG": Severity.INFO,
    "DAEMON_START": Severity.INFO,
    "DAEMON_END": Severity.WARN,
}

DEFAULT_AUDIT_LOG = Path("/var/log/audit/audit.log")


class AuditCollector(Collector):
    name = "audit"
    source = "audit"

    def __init__(self, queue: EventQueue, config, path: Optional[Path] = None, stop_event=None):
        super().__init__(queue, config, stop_event)
        self.path = Path(path or getattr(config, "audit_log_path", DEFAULT_AUDIT_LOG))
        self.host = gethostname()
        self._pending: dict[str, dict] = {}  # audit_id → accumulated record
        self._pending_max = 1000

    def _run(self) -> None:
        if not self.path.exists():
            eprint(f"[{self.name}] {self.path} not found — auditd not installed?")
            return
        try:
            for line in follow_file(self.path, poll=0.3, from_start=False, stop_event=self.stop_event):
                if self.should_stop():
                    break
                if not line:
                    continue
                ev = self._handle_line(line)
                if ev:
                    self.emit(ev)
        except Exception as e:
            eprint(f"[{self.name}] read error: {e}")

    def _handle_line(self, line: str) -> Optional[Event]:
        m = _RE_TYPE.match(line)
        if not m:
            return None
        rtype = m.group("type")
        audit_id = m.group("audit_id")
        rest = m.group("rest")

        kv = self._parse_kv(rest)
        severity = _TYPE_SEVERITY.get(rtype, Severity.DEBUG)

        # Ignore the very chatty SYSCALL/EXECVE/CWD/PATH unless they have a key
        if rtype in ("SYSCALL", "EXECVE", "CWD", "PATH"):
            key = kv.get("key", "")
            if not key or key in ('"(null)"', "(null)"):
                # Accumulate for potential later use; emit nothing to avoid noise
                self._accumulate(audit_id, rtype, kv)
                return None

        ts = self._audit_ts(audit_id)
        user = kv.get("acct") or kv.get("auid") or kv.get("uid")
        # strip quotes from values
        user = self._unquote(user)

        message_parts = [f"{rtype}"]
        if "exe" in kv:
            message_parts.append(f"exe={self._unquote(kv['exe'])}")
        if "comm" in kv:
            message_parts.append(f"comm={self._unquote(kv['comm'])}")
        if "acct" in kv:
            message_parts.append(f"acct={self._unquote(kv['acct'])}")
        if "res" in kv:
            message_parts.append(f"res={self._unquote(kv['res'])}")
        if "key" in kv:
            message_parts.append(f"key={self._unquote(kv['key'])}")

        # Upgrade severity if auth result is failure
        if kv.get("res") and "fail" in self._unquote(kv["res"]).lower():
            severity = max(severity, Severity.WARN)

        return Event(
            ts=ts,
            source="audit",
            category=rtype.lower(),
            severity=severity,
            message=" ".join(message_parts)[:2000],
            raw=line,
            host=self.host,
            user=user,
            extra={"audit_id": audit_id, "type": rtype,
                   **{name: self._unquote(value) for name, value in kv.items()}},
        )

    # ── helpers ────────────────────────────────────────────────
    @staticmethod
    def _parse_kv(text: str) -> dict[str, str]:
        return {m.group(1): m.group(2) for m in _RE_KV.finditer(text)}

    @staticmethod
    def _unquote(v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
            return v[1:-1]
        return v

    @staticmethod
    def _audit_ts(audit_id: str) -> float:
        try:
            return float(audit_id.split(":")[0])
        except (ValueError, IndexError):
            import time
            return time.time()

    def _accumulate(self, audit_id: str, rtype: str, kv: dict) -> None:
        if len(self._pending) >= self._pending_max:
            # drop oldest
            oldest = next(iter(self._pending))
            del self._pending[oldest]
        rec = self._pending.setdefault(audit_id, {})
        rec[rtype] = kv


# ── standalone test ───────────────────────────────────────────────
if __name__ == "__main__":
    import argparse

    from ..config import Config

    p = argparse.ArgumentParser(description="Test AuditCollector in isolation")
    p.add_argument("--path", default=str(DEFAULT_AUDIT_LOG))
    args = p.parse_args()

    q = EventQueue(maxsize=1000)
    c = AuditCollector(q, Config.load(), path=Path(args.path))
    if not c.path.exists():
        print(f"[audit] {c.path} does not exist — auditd is probably not installed")
        raise SystemExit(1)

    print(f"[audit] following {c.path}, Ctrl+C to stop\n")
    c.start()
    try:
        while True:
            ev = q.get(timeout=0.5)
            if ev:
                print(
                    f"{ev.ts:.3f} [{ev.severity.name:8}] "
                    f"{ev.category:20} user={ev.user or '-':15} {ev.message[:90]}"
                )
    except KeyboardInterrupt:
        print("\n[audit] stopping…")
    finally:
        c.stop()