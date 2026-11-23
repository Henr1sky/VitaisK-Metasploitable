#!/usr/bin/env python
"""Local log monitor for Metasploitable 2 (Python 2.5)."""

import os
import re
import sys
import time
from optparse import OptionParser


LOG_PATHS = {
    "system": ("/var/log/syslog", "/var/log/messages"),
    "auth": ("/var/log/auth.log",),
    "kernel": ("/var/log/kern.log",),
}
SOURCES = ("system", "auth", "kernel")
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
    read_only = root_read_only()

    def emit(source, line):
        events.append(format_event(source, line))
        if len(events) > 200:
            del events[0]

    def draw(logs):
        height, width = screen.getmaxyx()
        screen.erase()
        status = "Sources: " + ", ".join(sorted(logs))
        if read_only:
            status += " | Root is read-only"
        rows = ["VitaisK | Live logs | q to quit", status]
        available = max(0, height - len(rows))
        if available:
            rows.extend(events[-available:])
        for row, text in enumerate(rows[:height]):
            if width > 1:
                screen.addnstr(row, 0, text, width - 1)
        screen.refresh()
        return screen.getch() not in (ord("q"), ord("Q"))

    return watch(paths_by_source, False, emit, draw)


def watch(paths_by_source, once, emit=show_event, refresh=None):
    logs = {}
    try:
        while True:
            for source, paths in paths_by_source:
                if source not in logs:
                    path, handle = open_log(paths)
                    if handle is None:
                        continue
                    if refresh:
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

            if not logs:
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


def main():
    parser = OptionParser(usage="%prog watch [options]")
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
            return curses.wrapper(dashboard, paths_by_source, curses)
        except KeyboardInterrupt:
            return 0
        except curses.error:
            sys.stderr.write("Could not initialize or draw the dashboard.\n")
            return 1
        except IOError:
            sys.stderr.write("Could not read or display the log.\n")
            return 1
    try:
        return watch(paths_by_source, options.once)
    except KeyboardInterrupt:
        return 0
    except IOError:
        sys.stderr.write("Could not read or display the log.\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
