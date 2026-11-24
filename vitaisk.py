#!/usr/bin/env python
"""Local log monitor for Metasploitable 2 (Python 2.5)."""

import base64
import os
import re
import select
import signal
import subprocess
import sys
import time
from optparse import OptionParser


LOG_PATHS = {
    "system": ("/var/log/syslog", "/var/log/messages"),
    "auth": ("/var/log/auth.log",),
    "kernel": ("/var/log/kern.log",),
}
SOURCES = ("system", "auth", "kernel")
BRIDGE_PATHS = (
    ("system", LOG_PATHS["system"]),
    ("auth", LOG_PATHS["auth"]),
    ("kernel", LOG_PATHS["kernel"]),
    ("firewall", ("/var/log/ufw.log", "/var/log/firewall.log")),
    ("audit", ("/var/log/audit/audit.log",)),
)
SYSLOG = re.compile(r"^(\w{3}\s+\d+\s+\d\d:\d\d:\d\d)\s+(\S+)\s+(\S+?):\s+(.*)$")
SSH_LOGIN = re.compile(r"^Accepted (password|publickey|keyboard-interactive/pam) for ")
SSH_FAILURE = re.compile(r"^(Failed password for |Invalid user )")
CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def format_event(source, line):
    line = CONTROL.sub("?", line.rstrip("\r\n"))
    event = SYSLOG.match(line)
    category = "log"
    if event:
        timestamp, host, ident, message = event.groups()
        if ident == "sshd" or ident.startswith("sshd["):
            if SSH_LOGIN.match(message):
                category = "ssh_login"
            elif SSH_FAILURE.match(message):
                category = "ssh_failed"
    return "[%s/%s] %s" % (source, category, line)


def show_event(source, line):
    sys.stdout.write(format_event(source, line) + "\n")
    sys.stdout.flush()


def open_log(paths):
    for path in paths:
        try:
            return path, open(path, "r")
        except IOError:
            continue
    return None, None


def read_lines(handle, source, follow, emit):
    # Bound each ready file's batch so a busy log cannot starve the others.
    count = 0
    while not follow or count < 256:
        position = handle.tell()
        line = handle.readline()
        if not line:
            return False
        if follow and not line.endswith("\n"):
            handle.seek(position)
            return False
        emit(source, line)
        count += 1
    return True


def read_history(handle, source, emit):
    handle.seek(0, 2)
    start = max(0, handle.tell() - 32768)
    handle.seek(start)
    if start:
        handle.readline()
    lines = handle.read().splitlines(True)
    if lines and not lines[-1].endswith("\n"):
        handle.seek(handle.tell() - len(lines.pop()))
    for line in lines[-12:]:
        emit(source, line)


def root_read_only():
    try:
        mounts = open("/proc/mounts")
        try:
            for line in mounts:
                fields = line.split()
                if fields[1] == "/" and fields[2] != "rootfs":
                    return "ro" in fields[3].split(",")
        finally:
            mounts.close()
    except IOError:
        pass
    return False


def dashboard(screen, paths_by_source, curses):
    events = []
    screen.timeout(250)
    health = [0, False, None, ""]
    selected = [None]
    paused = [None]

    def emit(source, line):
        events.append((source, format_event(source, line)))
        if len(events) > 200:
            del events[0]

    def draw(logs):
        height, width = screen.getmaxyx()
        screen.erase()
        now = time.time()
        if now >= health[0]:
            health[0] = now + 2
            health[1] = root_read_only()
            try:
                total, idle, ram_total, ram_used, disk_used, disk_total = sample_vitals()[:6]
                previous = health[2]
                health[2] = (total, idle)
                cpu = "--"
                if previous and total > previous[0]:
                    used = total - previous[0] - idle + previous[1]
                    cpu = "%.0f%%" % (100.0 * used / (total - previous[0]))
                health[3] = "CPU %s | RAM %.0f%% | Disk %.0f%%" % (
                    cpu, 100.0 * ram_used / ram_total, 100.0 * disk_used / disk_total,
                )
            except (IOError, OSError, ValueError, ZeroDivisionError):
                health[3] = "Metrics unavailable"
        status = "Sources: " + ", ".join(sorted(logs))
        if health[1]:
            status += " | Root is read-only"
        activity = "Paused" if paused[0] is not None else "Live"
        view = selected[0] or "all"
        rows = ["VitaisK | %s logs | q to quit" % activity, status, health[3],
                "View: %s | a all, 1 system, 2 auth, 3 kernel, p pause" % view]
        available = max(0, height - len(rows))
        if available:
            visible = paused[0] if paused[0] is not None else events
            matching = [line for source, line in visible
                        if selected[0] is None or source == selected[0]]
            rows.extend(matching[-available:])
        for row, text in enumerate(rows[:height]):
            if width > 1:
                screen.addnstr(row, 0, text, width - 1)
        screen.refresh()
        key = screen.getch()
        if key == ord("p"):
            paused[0] = list(events) if paused[0] is None else None
        if key == ord("a"):
            selected[0] = None
        elif key in (ord("1"), ord("2"), ord("3")):
            selected[0] = SOURCES[key - ord("1")]
        return key not in (ord("q"), ord("Q"))

    return watch(paths_by_source, False, emit, draw, history=True)


def watch(paths_by_source, once, emit=show_event, refresh=None,
          history=False, allow_empty=False):
    logs = {}
    try:
        while True:
            for source, paths in paths_by_source:
                if source not in logs:
                    path, handle = open_log(paths)
                    if handle is None:
                        continue
                    if history:
                        read_history(handle, source, emit)
                    elif not once:
                        handle.seek(0, 2)
                    logs[source] = (path, handle)

                path, handle = logs[source]
                batch_full = read_lines(handle, source, not once, emit)
                if once:
                    continue
                try:
                    current = os.stat(path)
                except OSError:
                    continue
                opened = os.fstat(handle.fileno())
                if (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino):
                    # Keep the old file until its remaining batch has been read.
                    if batch_full:
                        continue
                    try:
                        replacement = open(path, "r")
                    except IOError:
                        continue
                    handle.close()
                    logs[source] = (path, replacement)
                elif current.st_size < handle.tell():
                    handle.seek(0)

            if not logs and not allow_empty:
                sys.stderr.write("No readable log files found.\n")
                return 1
            if once:
                return 0
            if refresh:
                if not refresh(logs):
                    return 0
            else:
                time.sleep(0.25)
    finally:
        for path, handle in logs.values():
            handle.close()


def proc_lines(path):
    handle = open(path)
    try:
        # The bridge only reads fixed kernel files.
        return handle.readlines()
    finally:
        handle.close()


def check_vm_route():
    for line in proc_lines("/proc/net/route")[1:]:
        fields = line.split()
        if fields[1] == "00000000" and fields[7] == "00000000" and int(fields[3], 16) & 1:
            raise ValueError("VM has an IPv4 default route")
    if os.path.exists("/proc/net/ipv6_route"):
        for line in proc_lines("/proc/net/ipv6_route"):
            fields = line.split()
            if fields[0] == "0" * 32 and fields[1] == "00" and int(fields[8], 16) & 1:
                raise ValueError("VM has an IPv6 default route")


def send_record(*fields):
    sys.stdout.write("\t".join(str(field) for field in fields) + "\n")
    sys.stdout.flush()


def log_timestamp(line):
    match = SYSLOG.match(line)
    now = time.time()
    if match:
        try:
            date = "%d %s" % (time.localtime(now)[0], match.group(1))
            timestamp = time.mktime(time.strptime(date, "%Y %b %d %H:%M:%S"))
            if timestamp > now + 86400:
                date = "%d %s" % (time.localtime(now)[0] - 1, match.group(1))
                timestamp = time.mktime(time.strptime(date, "%Y %b %d %H:%M:%S"))
            return int(timestamp)
        except (ValueError, OverflowError):
            pass
    return int(now)


def send_log(source, line):
    timestamp = log_timestamp(line)
    line = line.rstrip("\r\n")[:8192]
    if not isinstance(line, bytes_type):
        line = line.encode("utf-8", "replace")
    encoded = base64.b64encode(line)
    if not isinstance(encoded, str):
        encoded = encoded.decode("ascii")
    send_record("log", source, timestamp, encoded)


try:
    bytes_type = bytes
except NameError:
    bytes_type = str


def sample_vitals():
    stats = proc_lines("/proc/stat")
    cpu_count = len([line for line in stats if re.match(r"^cpu[0-9]", line)])
    stat = stats[0].split()[1:9]
    ticks = [int(value) for value in stat]
    idle = sum(ticks[3:5])
    memory = {}
    for line in proc_lines("/proc/meminfo"):
        fields = line.split()
        if len(fields) >= 2:
            memory[fields[0].rstrip(":")] = int(fields[1])
    total = memory["MemTotal"]
    available = memory.get("MemAvailable", memory["MemFree"] + memory.get("Buffers", 0)
                           + memory.get("Cached", 0) + memory.get("SReclaimable", 0))
    disk = os.statvfs("/")
    used = disk.f_blocks - disk.f_bfree
    processes = len([entry for entry in os.listdir("/proc") if entry.isdigit()])
    return (sum(ticks), idle, total, max(0, total - available), used, used + disk.f_bavail,
            int(os.getloadavg()[0] * 100), cpu_count, processes)


def ipv4_connections():
    rows = {}
    tcp_states = {"01": "ESTAB", "02": "SYN-SENT", "03": "SYN-RECV", "0A": "LISTEN"}
    tables = (("tcp", "/proc/net/tcp"), ("udp", "/proc/net/udp"),
              ("tcp", "/proc/net/tcp6"), ("udp", "/proc/net/udp6"))
    mapped = "0000000000000000FFFF0000"
    for protocol, path in tables:
        try:
            lines = proc_lines(path)
        except IOError:
            continue
        for line in lines[1:]:
            fields = line.split()
            if len(fields) < 4:
                continue
            state = tcp_states.get(fields[3]) if protocol == "tcp" else "UNCONN"
            if not state or (state != "LISTEN" and fields[2] == "00000000:0000"):
                continue
            local, peer = fields[1:3]
            if path.endswith("6"):
                # A dual-stack listener can accept IPv4 through a mapped IPv6 socket.
                if not (local.startswith(mapped) and peer.startswith(mapped)):
                    continue
                local, peer = local[len(mapped):], peer[len(mapped):]
            rows[(protocol, local, peer)] = state
    return rows


def bridge(paths=BRIDGE_PATHS):
    try:
        check_vm_route()
        send_record("hello", 1)
        next_sample = [0.0]
        known = [None]

        def publish(logs):
            now = time.time()
            if now < next_sample[0]:
                time.sleep(0.25)
                return True
            check_vm_route()
            availability = ",".join(sorted(logs))
            send_record("status", int(root_read_only()), availability)
            send_record("metrics", *sample_vitals())
            connections = ipv4_connections()
            if known[0] is not None:
                previous = known[0]
                for row in sorted(set(connections) - set(previous)):
                    send_record("connection", "new", *(row + (connections[row],)))
                for row in sorted(set(previous) - set(connections)):
                    send_record("connection", "closed", *(row + (previous[row],)))
            known[0] = connections
            next_sample[0] = now + 2.0
            return True

        return watch(paths, False, send_log, publish, allow_empty=True)
    except (IOError, OSError, ValueError):
        error = sys.exc_info()[1]
        if getattr(error, "errno", None) == 32:  # SSH closed its pipe.
            return 0
        sys.stderr.write("VM collector: %s\n" % error)
        return 1


def packet_bridge():
    """Stream only inbound IPv4 SYN metadata over the existing lab SSH link."""
    check_vm_route()
    peer, peer_port, host, ssh_port = os.environ["SSH_CONNECTION"].split()
    for address in (peer, host):
        fields = address.split(".")
        if len(fields) != 4 or not all_digits(fields):
            raise ValueError("Packet monitoring requires IPv4 SSH endpoints")
    import pwd
    user = pwd.getpwuid(os.getuid()).pw_name
    packet_filter = "ip and dst host %s and tcp[13] & 18 = 2" % host
    password = sys.stdin.readline(4096)
    if not password.endswith("\n"):
        raise ValueError("Missing password for packet monitoring")
    proc = subprocess.Popen(
        ["sudo", "-S", "-p", "", "/usr/sbin/tcpdump", "-Z", user, "-p",
         "-i", "any", "-l", "-nn", "-tt", "-s", "96", packet_filter],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        close_fds=True,
    )
    try:
        proc.stdin.write(password)
        del password
        proc.stdin.close()
        readable = [sys.stdin, proc.stdout, proc.stderr]
        next_check = time.time() + 2
        diagnostics = ""
        while proc.poll() is None:
            descriptors = select.select(readable, [], [], 0.5)[0]
            for stream in descriptors:
                data = os.read(stream.fileno(), 4096)
                if stream is sys.stdin or not data:
                    if stream is proc.stderr and not data:
                        readable.remove(stream)
                        continue
                    return 0 if stream is sys.stdin else 1
                if stream is proc.stdout:
                    sys.stdout.write(data)
                    sys.stdout.flush()
                else:
                    lines = (diagnostics + data).split("\n")
                    diagnostics = lines.pop()
                    for line in lines:
                        if line.startswith("listening on "):
                            send_record("packet-ready")
                        elif not line.startswith("tcpdump: verbose output suppressed"):
                            sys.stderr.write(line + "\n")
                            sys.stderr.flush()
            if time.time() >= next_check:
                check_vm_route()
                next_check = time.time() + 2
        return proc.returncode
    finally:
        if proc.poll() is None:
            try:
                os.kill(proc.pid, signal.SIGTERM)
            except OSError:
                pass
        proc.stdout.close()
        proc.stderr.close()


def all_digits(fields):
    for field in fields:
        if not field.isdigit() or int(field) > 255:
            return False
    return True


def doctor():
    sys.stdout.write("Python %s | %s %s\n" % (
        sys.version.split()[0], os.uname()[2], os.uname()[4],
    ))
    sys.stdout.write("Root filesystem: %s\n" % ("read-only" if root_read_only() else "read-write"))
    try:
        check_vm_route()
        sys.stdout.write("Network: no default route\n")
    except (IOError, OSError, ValueError):
        sys.stdout.write("Network: %s\n" % sys.exc_info()[1])
    for source, paths in BRIDGE_PATHS:
        path, handle = open_log(paths)
        if handle:
            handle.close()
        sys.stdout.write("%s: %s\n" % (source, path or "not readable"))
    return 0


def main():
    if sys.argv[1:] == ["packet-bridge"]:
        try:
            return packet_bridge()
        except (IOError, OSError, ValueError, KeyError):
            error = sys.exc_info()[1]
            if getattr(error, "errno", None) != 32:
                sys.stderr.write("VM packet monitor: %s\n" % error)
                return 1
            return 0
    if sys.argv[1:] == ["doctor"]:
        return doctor()
    if sys.argv[1:] == ["bridge"]:
        return bridge()
    parser = OptionParser(usage="%prog watch [options] | doctor")
    parser.add_option("--source", action="append", type="choice",
                      choices=SOURCES, help="Log source: system, auth or kernel (repeatable)")
    parser.add_option("--file", help="Read a specific log file instead of the default path")
    parser.add_option("--mode", type="choice", choices=("stream", "dashboard"),
                      default="stream", help="Display mode: stream or dashboard")
    parser.add_option("--once", action="store_true", default=False,
                      help="Read existing lines and exit")
    options, args = parser.parse_args()
    if args != ["watch"]:
        parser.error("expected the watch command")
    sources = options.source or SOURCES
    if options.file and len(sources) != 1:
        parser.error("--file requires exactly one --source")
    paths_by_source = []
    for source in SOURCES:
        if source not in sources:
            continue
        paths = LOG_PATHS[source]
        if options.file:
            paths = (options.file,)
        paths_by_source.append((source, paths))
    if options.mode == "dashboard":
        if options.once:
            parser.error("--once is only available in stream mode")
        if not (sys.stdin.isatty() and sys.stdout.isatty()):
            parser.error("dashboard requires an interactive terminal")
        try:
            import curses
        except ImportError:
            parser.error("dashboard requires Python curses")
        try:
            terminal = os.environ.get("TERM")
            if terminal == "xterm-256color":
                os.environ["TERM"] = "xterm"
            return curses.wrapper(dashboard, paths_by_source, curses)
        except KeyboardInterrupt:
            return 0
        except curses.error:
            sys.stderr.write("Could not initialize or draw the dashboard.\n")
            return 1
        except IOError:
            sys.stderr.write("Could not read or display the log.\n")
            return 1
    if not options.once and sys.stderr.isatty():
        status = "Waiting for new log entries."
        if root_read_only():
            status += " Root is read-only; system logs may stop updating."
        sys.stderr.write(status + "\n")
    try:
        return watch(paths_by_source, options.once)
    except KeyboardInterrupt:
        return 0
    except IOError:
        sys.stderr.write("Could not read or display the log.\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
