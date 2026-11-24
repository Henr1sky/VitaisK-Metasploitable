"""Collectors for network activity: active connections (ss) and packet sniffing (tcpdump)."""
from __future__ import annotations

import os
import re
import signal
import subprocess
from socket import gethostname
import time
from typing import Optional

from ..events import Event, Severity, make_event
from ..utils import which, eprint
from .base import Collector, EventQueue


# ── active connections via `ss -tunap` ─────────────────────────────
_RE_SS_ROW = re.compile(
    r"^(?P<proto>tcp|udp|raw)\s+"
    r"(?P<state>\S+)\s+"
    r"\d+\s+\d+\s+"
    r"(?P<local>\S+)\s+"
    r"(?P<peer>\S+)"
    r"(?:\s+users:\(\((?P<users>.+)\)\))?\s*$"
)
_RE_USER = re.compile(r'\("(?P<name>[^"]+)",pid=(?P<pid>\d+),fd=\d+\)')


def _split_addr(addr: str) -> tuple[Optional[str], Optional[int]]:
    """'1.2.3.4:5678' → ('1.2.3.4', 5678). '[::1]:22' → ('::1', 22)."""
    if not addr:
        return None, None
    if addr.startswith("["):
        # IPv6 with brackets
        end = addr.find("]")
        if end == -1:
            return addr, None
        host = addr[1:end]
        port_part = addr[end + 1:]
        port = int(port_part[1:]) if port_part.startswith(":") and port_part[1:].isdigit() else None
        return host, port
    if ":" in addr:
        host, _, port = addr.rpartition(":")
        return host or None, int(port) if port.isdigit() else None
    return addr, None


class ConnectionsCollector(Collector):
    """Poll `ss -tunap` and diff to detect new connections."""

    name = "connections"
    source = "network"

    def __init__(self, queue: EventQueue, config, stop_event=None):
        super().__init__(queue, config, stop_event)
        self.interval = 5.0
        self.host = gethostname()
        self._known: set[tuple] = set()

    def _run(self) -> None:
        if not which("ss"):
            eprint(f"[{self.name}] ss not found — skipping")
            return
        # Prime known set
        try:
            self._known = self._snapshot()
        except Exception:
            pass

        while not self.should_stop():
            try:
                self._poll()
            except Exception as e:
                eprint(f"[{self.name}] poll error: {e}")
            deadline = time.time() + self.interval
            while time.time() < deadline and not self.should_stop():
                time.sleep(min(0.2, max(0.0, deadline - time.time())))

    def _poll(self) -> None:
        current = self._snapshot()
        new = current - self._known
        closed = self._known - current
        known_endpoints = {(proto, local, peer) for proto, _, local, peer, _, _ in self._known}
        seen = set()
        for row in sorted(new):
            proto, _, local, peer, _, _ = row
            endpoint = (proto, local, peer)
            first_seen = endpoint not in known_endpoints and endpoint not in seen
            self._emit(row, "new_connection", first_seen=first_seen)
            seen.add(endpoint)
        for row in closed:
            self._emit(row, "closed_connection", severity="DEBUG")
        self._known = current

    def _snapshot(self) -> set[tuple]:
        try:
            out = subprocess.check_output(
                ["ss", "-tunap"], text=True, timeout=3, stderr=subprocess.DEVNULL,
            )
        except (subprocess.SubprocessError, FileNotFoundError):
            return set()
        rows: set[tuple] = set()

        # Skip connections in teardown — they are noise, not new activity
        _TEARDOWN_STATES = {
            "TIME-WAIT", "CLOSE-WAIT", "FIN-WAIT-1", "FIN-WAIT-2",
            "LAST-ACK", "CLOSING", "CLOSED",
        }
        for line in out.splitlines()[1:]:
            m = _RE_SS_ROW.match(line)
            if not m:
                continue
            proto = m.group("proto")
            state = m.group("state")
            if state in _TEARDOWN_STATES:
                continue
            local = m.group("local")
            peer = m.group("peer")
            users = m.group("users") or ""
            user_m = _RE_USER.search(users)
            proc_name = user_m.group("name") if user_m else ""
            proc_pid = int(user_m.group("pid")) if user_m else 0
            rows.add((proto, state, local, peer, proc_name, proc_pid))
        return rows

    def _emit(self, row: tuple, category: str, severity: str = "INFO", *, first_seen=False) -> None:
        proto, state, local, peer, proc_name, proc_pid = row
        l_ip, l_port = _split_addr(local)
        p_ip, p_port = _split_addr(peer)
        is_external = p_ip and not (
            p_ip.startswith(("10.", "192.168.", "127.", "169.254.", "::1", "fe80:", "fc", "fd"))
            or (p_ip.startswith("172.") and 16 <= int(p_ip.split(".")[1] or 0) <= 31)
        )
        # Suspicious port heuristic (common reverse-shell / backdoor ports)
        suspicious_ports = {4444, 4445, 5555, 6666, 12345, 31337, 1337}
        sev = Severity.parse(severity)
        if p_port in suspicious_ports and category == "new_connection":
            sev = Severity.ERROR

        self.emit(make_event(
            source="network",
            category=category,
            severity=sev,
            message=(
                f"{proto.upper()} {state} {local} → {peer}"
                + (f" ({proc_name}/{proc_pid})" if proc_name else "")
            ),
            host=self.host,
            src_ip=p_ip,
            dst_ip=l_ip,
            dst_port=l_port,
            protocol=proto,
            extra={
                "peer_ip": p_ip, "peer_port": p_port,
                "local_ip": l_ip, "local_port": l_port,
                "state": state, "process": proc_name, "pid": proc_pid,
                "external": bool(is_external),
                "first_seen": first_seen,
            },
        ))


# ── packet sniffing via tcpdump ────────────────────────────────────
_RE_TCPDUMP_SYN = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)\s+IP6?\s+"
    r"(?P<src>.+?)\.(?P<sport>\d+)\s+>\s+(?P<dst>.+?)\.(?P<dport>\d+):\s+"
    r"Flags\s+\[(?P<flags>[^\]]+)\]"
)


class SniffCollector(Collector):
    """Optional sniffing collector. Requires root + tcpdump. Off by default."""

    name = "sniff"
    source = "network"

    def __init__(self, queue: EventQueue, config, stop_event=None):
        super().__init__(queue, config, stop_event)
        self.interface = getattr(config, "network_sniff_interface", "any")
        self.bpf = getattr(config, "network_sniff_filter", "tcp or udp or icmp")
        self.host = gethostname()
        self.sample_rate = max(1, int(getattr(config, "network_sniff_sample_rate", 10)))
        self._proc: Optional[subprocess.Popen] = None
        self._counter = 0

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

    def _run(self) -> None:
        if not which("tcpdump"):
            eprint(f"[{self.name}] tcpdump not found — skipping")
            return
        if os.geteuid() != 0:
            eprint(f"[{self.name}] sniffing requires root — skipping")
            return

        cmd = [
            "tcpdump", "-l", "-n", "-tttt",
            "-i", self.interface,
            "(tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0)",
        ]
        if self.bpf:
            cmd += ["and", f"({self.bpf})"]

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
        except FileNotFoundError:
            eprint(f"[{self.name}] could not start tcpdump")
            return

        try:
            assert self._proc.stdout is not None
            for line in self._proc.stdout:
                if self.should_stop():
                    break
                self._counter += 1
                if self._counter % self.sample_rate != 0:
                    continue
                ev = self._parse(line)
                if ev:
                    self.emit(ev)
                if self._proc.poll() is not None:
                    break
        finally:
            self._on_stop()

    def _parse(self, line: str) -> Optional[Event]:
        m = _RE_TCPDUMP_SYN.match(line.strip())
        if not m or "S" not in m["flags"] or "." in m["flags"]:
            return None
        try:
            ts = time.mktime(time.strptime(m.group("ts")[:19], "%Y-%m-%d %H:%M:%S"))
            frac = float("0." + m.group("ts")[20:])
            ts += frac
        except ValueError:
            ts = time.time()

        src_ip = m.group("src")
        dst_ip = m.group("dst")
        sport = int(m.group("sport"))
        dport = int(m.group("dport"))

        suspicious_ports = {4444, 4445, 5555, 6666, 12345, 31337, 1337, 23, 3389}
        sev = Severity.INFO
        if dport in suspicious_ports:
            sev = Severity.WARN

        return make_event(
            source="network",
            category="syn",
            severity=sev,
            message=f"SYN {src_ip}:{sport} → {dst_ip}:{dport}",
            ts=ts,
            host=self.host,
            raw=line.rstrip("\n"),
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=dport,
            protocol="tcp",
            extra={"src_port": sport, "flags": m.group("flags")},
        )


# ── standalone test ───────────────────────────────────────────────
if __name__ == "__main__":
    import argparse

    from ..config import Config

    p = argparse.ArgumentParser(description="Test network collectors in isolation")
    p.add_argument("--mode", choices=["conn", "sniff"], default="conn")
    p.add_argument("--interface", default="any")
    p.add_argument("--sample-rate", type=int, default=1)
    args = p.parse_args()

    q = EventQueue(maxsize=1000)
    cfg = Config.load()
    if args.mode == "sniff":
        cfg.network_sniff_interface = args.interface
        cfg.network_sniff_sample_rate = args.sample_rate
        c = SniffCollector(q, cfg)
    else:
        c = ConnectionsCollector(q, cfg)

    print(f"[{args.mode}] running, Ctrl+C to stop\n")
    c.start()
    try:
        while True:
            ev = q.get(timeout=0.5)
            if ev:
                print(
                    f"{ev.ts:.1f} [{ev.severity.name:8}] {ev.category:18} "
                    f"src={ev.src_ip or '-':18} {ev.message[:90]}"
                )
    except KeyboardInterrupt:
        print(f"\n[{args.mode}] stopping…")
    finally:
        c.stop()