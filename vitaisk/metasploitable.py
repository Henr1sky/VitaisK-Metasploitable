"""Monitor an isolated Metasploitable 2 VM with the modern VitaisK engine."""

from __future__ import annotations

import base64
import ipaddress
import json
import re
import shlex
import subprocess
import tempfile
import time
from contextlib import contextmanager, suppress
from getpass import getpass
from importlib.resources import files
from pathlib import Path

from .collectors.audit import AuditCollector
from .collectors.base import Collector
from .collectors.filetail import (
    AuthLogCollector, FirewallLogCollector, KernelLogCollector, SyslogCollector,
)
from .collectors.manager import CollectorManager
from .collectors.metrics import MetricsCollector
from .events import Severity, make_event

_PRIVATE_NETWORKS = tuple(map(ipaddress.IPv4Network, (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
)))
_LOGS = {
    "system": ("syslog_enabled", SyslogCollector, "/var/log/syslog"),
    "auth": ("auth_enabled", AuthLogCollector, "/var/log/auth.log"),
    "kernel": ("kern_enabled", KernelLogCollector, "/var/log/kern.log"),
    "firewall": ("firewall_enabled", FirewallLogCollector, "/var/log/ufw.log"),
    "audit": ("audit_enabled", AuditCollector, "/var/log/audit/audit.log"),
}
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_MAX_RECORD = 16_384


def lab_interface(host: str, bind: str) -> str:
    """Reject destinations reached through a gateway or outside a private subnet."""
    target, source = map(ipaddress.IPv4Address, (host, bind))
    if target == source or not any(target in net and source in net for net in _PRIVATE_NETWORKS):
        raise ValueError("Use distinct private IPv4 addresses for the VM and Kali")
    try:
        route = json.loads(subprocess.check_output(
            ["ip", "-j", "-4", "route", "get", host, "from", bind],
            timeout=5, stderr=subprocess.DEVNULL,
        ))[0]
        if "gateway" in route or "via" in route or route.get("type") == "local":
            raise ValueError("The VM must be directly reachable on the isolated interface")
        interface = route["dev"]
        addresses = json.loads(subprocess.check_output(
            ["ip", "-j", "-4", "addr", "show", "dev", interface, "up"],
            timeout=5, stderr=subprocess.DEVNULL,
        ))[0]["addr_info"]
    except (subprocess.SubprocessError, KeyError, IndexError, json.JSONDecodeError) as exc:
        raise ValueError("Could not verify the isolated network route") from exc
    if not any(addr["local"] == bind and target in ipaddress.IPv4Interface(
        f"{bind}/{addr['prefixlen']}",
    ).network for addr in addresses):
        raise ValueError("The VM and the Kali address must share the isolated subnet")
    return interface


@contextmanager
def lab_ssh(host: str, bind: str, user: str):
    """Authenticate before entering the dashboard, using OpenSSH's own prompt."""
    lab_interface(host, bind)
    if not re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_-]{0,31}", user):
        raise ValueError("Invalid SSH username")
    with tempfile.TemporaryDirectory(prefix="vitaisk-ssh-", dir="/tmp") as directory:
        socket = str(Path(directory) / "control")
        target = f"{user}@{host}"
        base = [
            "ssh", "-F", "/dev/null", "-S", socket, "-b", bind,
            "-o", "StrictHostKeyChecking=yes", "-o", "HostKeyAlgorithms=+ssh-rsa",
            "-o", "ForwardAgent=no", "-o", "ForwardX11=no",
            "-o", "ClearAllForwardings=yes", "-o", "ConnectTimeout=8",
            "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=2",
        ]
        try:
            subprocess.run([*base, "-MNf", target], check=True, timeout=90)
            yield [*base, "-T", "-o", "BatchMode=yes", target]
        except subprocess.CalledProcessError as exc:
            raise ValueError("SSH authentication failed. Verify the known host key and VM login.") from exc
        except subprocess.TimeoutExpired as exc:
            raise ValueError("SSH authentication timed out") from exc
        finally:
            if Path(socket).exists():
                try:
                    subprocess.run([*base, "-O", "exit", target], timeout=5, check=False,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                except subprocess.SubprocessError:
                    pass

def lab_doctor(host: str, bind: str, user: str):
    interface = lab_interface(host, bind)
    print(f"Kali lab interface: {interface} ({bind})", flush=True)
    with lab_ssh(host, bind, user) as command:
        try:
            subprocess.run([*command, "python - doctor"], input=agent_script(),
                           check=True, timeout=12)
        except subprocess.SubprocessError as exc:
            raise ValueError("Could not run the VM diagnostics over SSH") from exc


def agent_script() -> bytes:
    return files("legacy").joinpath("vitaisk.py").read_bytes()


def _endpoint(value: str) -> tuple[str, int]:
    address, port = value.split(":", 1)
    return str(ipaddress.IPv4Address(bytes.fromhex(address)[::-1])), int(port, 16)


class MetasploitableCollector(MetricsCollector):
    """Read framed output and pass remote data through the original event engine."""

    name = "metasploitable-ssh"
    source = "system"

    def __init__(self, queue, config, stop_event, command, host):
        super().__init__(queue, config, stop_event)
        self.command = command
        self.host = host
        self.process = None
        self.ready = False
        self.status = None
        self.cpu_ticks = None
        self.parsers = {
            source: parser(queue, config, path=Path(path), stop_event=stop_event)
            for source, (setting, parser, path) in _LOGS.items() if getattr(config, setting)
        }

    def _run(self) -> None:
        try:
            with subprocess.Popen(
                [*self.command, "python -u - bridge"],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            ) as proc:
                self.process = proc
                try:
                    if self.should_stop():
                        return
                    proc.stdin.write(agent_script())
                    proc.stdin.close()
                    while not self.should_stop():
                        record = proc.stdout.readline(_MAX_RECORD + 1)
                        if not record:
                            break
                        if len(record) > _MAX_RECORD or not record.endswith(b"\n"):
                            raise ValueError("Invalid record size from VM")
                        self._record(record.decode("ascii").rstrip("\n").split("\t"))
                    if not self.should_stop():
                        raise RuntimeError("The VM collector disconnected")
                finally:
                    self._on_stop()
        finally:
            # End the UI if the only remote data source is lost.
            self.stop_event.set()

    def _on_stop(self) -> None:
        process = self.process
        if process and process.poll() is None:
            try:
                process.terminate()
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)
            except ProcessLookupError:
                pass

    def emit(self, event) -> None:
        event.extra["lab_host"] = self.host
        event.host = event.host or self.host
        super().emit(event)

    def _record(self, fields: list[str]) -> None:
        kind, *data = fields
        if not self.ready:
            if fields != ["hello", "1"]:
                raise ValueError("Unexpected VM collector protocol")
            self.ready = True
            return
        if kind == "status":
            if len(data) != 2 or data[0] not in ("0", "1"):
                raise ValueError("Invalid VM status")
            self._status(data[0] == "1", data[1].split(",") if data[1] else [])
        elif kind == "metrics":
            self._metrics(tuple(map(int, data)))
        elif kind == "log":
            source, timestamp, payload = data
            parser = self.parsers.get(source)
            if parser is None:
                return
            raw = base64.b64decode(payload, validate=True).decode("utf-8", "replace")
            event = parser._handle_line(_CONTROL.sub("?", raw))
            if event:
                event.ts = int(timestamp)
                event.extra.setdefault("collector", parser.name)
                self.emit(event)
        elif kind == "connection":
            self._connection(*data)
        else:
            raise ValueError("Unknown record from VM collector")

    def _status(self, read_only: bool, sources: list[str]) -> None:
        current = read_only, tuple(sources)
        if current == self.status:
            return
        self.status = current
        available = ", ".join(source for source in _LOGS if source in sources) or "none"
        message = f"VM {self.host} | logs: {available} | root: "
        message += "read-only (log files may stop updating)" if read_only else "read-write"
        self.emit(make_event(
            source="system", category="lab_status", message=message,
            severity=Severity.ERROR if read_only or not sources else Severity.INFO,
        ))

    def _metrics(self, sample: tuple[int, ...]) -> None:
        total, idle, ram_total, ram_used, disk_used, disk_total, load, cpus, processes = sample
        if not self.config.metrics_enabled:
            return
        previous, self.cpu_ticks = self.cpu_ticks, (total, idle)
        if not previous or total <= previous[0] or ram_total <= 0 or disk_total <= 0:
            return
        cpu = (total - previous[0] - idle + previous[1]) * 100 / (total - previous[0])
        ram = ram_used * 100 / ram_total
        disk = disk_used * 100 / disk_total
        if not all(0 <= value <= 100 for value in (cpu, ram, disk)):
            return
        self.vitals = (cpu, ram, disk)
        now = time.time()
        self._check_sustained("cpu", cpu, now, warn=self.CPU_WARN, crit=self.CPU_CRIT,
                              warn_dur=self.CPU_WARN_DUR, crit_dur=self.CPU_CRIT_DUR,
                              extra={"cpu_percent": cpu})
        self._check_sustained("memory", ram, now, warn=self.MEM_WARN, crit=self.MEM_CRIT,
                              warn_dur=self.MEM_WARN_DUR, crit_dur=self.MEM_CRIT_DUR,
                              extra={"mem_percent": ram})
        severity = Severity.INFO
        if disk >= self.DISK_CRIT:
            severity = Severity.CRITICAL
        elif disk >= self.DISK_WARN:
            severity = Severity.WARN
        self._transition("disk", severity, extra={"disk_percent": disk})
        if cpus > 0:
            load /= 100
            severity = Severity.INFO
            if load > cpus * 2:
                severity = Severity.ERROR
            elif load > cpus:
                severity = Severity.WARN
            self._transition("load", severity, extra={"load_1m": load, "ncpu": cpus},
                             message=f"load average {load:.2f} ({cpus} CPUs)")
        self._transition(
            "procs", Severity.WARN if processes > 2000 else Severity.INFO,
            extra={"process_count": processes}, message=f"process count {processes}",
        )

    def _connection(self, change: str, protocol: str, local: str, peer: str) -> None:
        if not self.config.connections_enabled:
            return
        if change not in ("new", "closed") or protocol not in ("tcp", "udp"):
            raise ValueError("Invalid VM connection record")
        local_ip, local_port = _endpoint(local)
        peer_ip, peer_port = _endpoint(peer)
        peer_address = ipaddress.IPv4Address(peer_ip)
        self.emit(make_event(
            source="network", category=f"{change}_connection",
            severity=Severity.INFO if change == "new" else Severity.DEBUG,
            message=f"{protocol.upper()} {local_ip}:{local_port} → {peer_ip}:{peer_port}",
            protocol=protocol, src_ip=peer_ip, dst_ip=local_ip, dst_port=local_port,
            extra={"peer_ip": peer_ip, "peer_port": peer_port, "local_ip": local_ip,
                   "local_port": local_port, "external": peer_address.is_global},
        ))


_SYN_LINE = re.compile(
    r"^(?P<time>[0-9]+\.[0-9]+) (?:IP )?"
    r"(?P<src>[0-9.]+)\.(?P<sport>[0-9]+) > "
    r"(?P<dst>[0-9.]+)\.(?P<dport>[0-9]+):"
)


class LabPacketCollector(Collector):
    """Observe TCP connection attempts from Kali at the VM interface."""

    name = "metasploitable-packets"
    source = "network"

    def __init__(self, queue, config, stop_event, command, host, bind, password):
        super().__init__(queue, config, stop_event)
        self.command = command
        self.host = host
        self.bind = bind
        self.password = password
        self.process = None

    def _run(self):
        agent = shlex.quote(agent_script().decode("utf-8"))
        with subprocess.Popen(
            [*self.command, f"python -u -c {agent} packet-bridge"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        ) as process:
            self.process = process
            try:
                if self.should_stop():
                    return
                process.stdin.write(self.password)
                process.stdin.flush()
                self.password.clear()
                while not self.should_stop():
                    line = process.stdout.readline(4096)
                    if not line:
                        break
                    if line == b"packet-ready\n":
                        event = make_event(
                            source="network", category="lab_packet_monitor", severity=Severity.INFO,
                            message=f"TCP SYN monitor active for {self.bind} → {self.host}",
                            host=self.host, extra={"lab_host": self.host},
                        )
                    else:
                        event = self._parse(line.decode("ascii", "replace"))
                    if event:
                        self.emit(event)
                if not self.should_stop():
                    raise RuntimeError("VM packet capture stopped; check sudo access and tcpdump")
            finally:
                self.password.clear()
                self._on_stop()

    def _on_stop(self):
        process = self.process
        if process is None:
            return
        with suppress(OSError, ValueError):
            process.stdin.close()
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            with suppress(ProcessLookupError):
                process.terminate()
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                with suppress(ProcessLookupError):
                    process.kill()

    def _parse(self, line):
        match = _SYN_LINE.match(line)
        if not match or match["src"] != self.bind or match["dst"] != self.host:
            return None
        return make_event(
            source="network", category="syn", severity=Severity.INFO,
            message=f"TCP SYN {self.bind}:{match['sport']} → {self.host}:{match['dport']}",
            ts=float(match["time"]), host=self.host, src_ip=self.bind, dst_ip=self.host,
            dst_port=int(match["dport"]), protocol="tcp",
            extra={"src_port": int(match["sport"]), "lab_host": self.host, "flags": "S"},
        )


@contextmanager
def lab_manager(config, host: str, bind: str, user: str, *, packets: bool = False):
    with lab_ssh(host, bind, user) as command:
        password = bytearray()
        if packets:
            password.extend(getpass("VM sudo password for packet monitoring: ").encode("utf-8"))
            password.append(10)

        def collectors(settings, queue, stop):
            sources = [MetasploitableCollector(queue, settings, stop, command, host)]
            if packets:
                sources.append(LabPacketCollector(queue, settings, stop, command, host, bind, password))
            return sources

        manager = CollectorManager(config, build=collectors)
        try:
            yield manager
            errors = [str(collector.error) for collector in manager.collectors if collector.error]
            if errors:
                raise ValueError("; ".join(errors))
        finally:
            password.clear()
