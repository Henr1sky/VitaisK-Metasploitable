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


def show_event(source, line):
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
    sys.stdout.write("[%s/%s] %s\n" % (source, category, line))
    sys.stdout.flush()


def open_log(paths):
    for path in paths:
        try:
            return path, open(path, "r")
        except IOError:
            continue
    return None, None


def read_lines(handle, source, follow):
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
        show_event(source, line)
        count += 1
    return True


def watch(paths_by_source, once):
    logs = {}
    try:
        while True:
            for source, paths in paths_by_source:
                if source not in logs:
                    path, handle = open_log(paths)
                    if handle is None:
                        continue
                    if not once:
                        handle.seek(0, 2)
                    logs[source] = (path, handle)

                path, handle = logs[source]
                batch_full = read_lines(handle, source, not once)
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
            time.sleep(0.25)
    finally:
        for path, handle in logs.values():
            handle.close()


def main():
    parser = OptionParser(usage="%prog watch [options]")
    parser.add_option("--source", action="append", type="choice",
                      choices=SOURCES, help="Log source: system, auth or kernel (repeatable)")
    parser.add_option("--file", help="Read a specific log file instead of the default path")
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
    try:
        return watch(paths_by_source, options.once)
    except KeyboardInterrupt:
        return 0
    except IOError:
        sys.stderr.write("Could not read or display the log.\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
