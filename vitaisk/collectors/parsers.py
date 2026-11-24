"""Shared text parsers. Pure functions, no I/O — easy to unit-test."""
from __future__ import annotations

import re
from ipaddress import ip_address
from datetime import datetime
from typing import Any, Optional


# ── generic syslog line ────────────────────────────────────────────
# Handles both "Oct 22 14:30:12" and "Oct 22 2026 14:30:12"
_SYSLOG_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s+(?:\d{4}\s+)?\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<ident>\S+?)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<msg>.*)$"
)


def parse_syslog_line(line: str) -> Optional[dict[str, Any]]:
    """Parse a classic syslog line. Returns None if it doesn't match."""
    m = _SYSLOG_RE.match(line)
    if not m:
        return None
    return {
        "ts_raw": m.group("ts"),
        "host": m.group("host"),
        "ident": m.group("ident"),
        "pid": int(m.group("pid")) if m.group("pid") else None,
        "message": m.group("msg"),
    }


def parse_syslog_ts(ts_raw: str, now: Optional[datetime] = None) -> float:
    """Parse syslog timestamp. Handles both with and without year."""
    now = now or datetime.now()
    for fmt in ("%b %d %H:%M:%S", "%b %d %Y %H:%M:%S"):
        try:
            dt = datetime.strptime(ts_raw, fmt)
            if "%Y" not in fmt:
                # Patch year; if result is in the future by more than 1 day,
                # assume previous year (handles Dec 31 → Jan 1 rollover)
                dt = dt.replace(year=now.year)
                if (dt - now).days > 1:
                    dt = dt.replace(year=now.year - 1)
            return dt.timestamp()
        except ValueError:
            continue
    return now.timestamp()


# ── auth / sshd / sudo ─────────────────────────────────────────────
_RE_SSH_FAIL = re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\da-fA-F:.]+)(?=\s|$)")
_RE_SSH_KEY_FAIL = re.compile(
    r"Failed publickey for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\da-fA-F:.]+)(?=\s|$)"
)
_RE_SSH_INVALID = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>[\da-fA-F:.]+)(?=\s|$)")
_RE_SSH_OK = re.compile(r"Accepted (?:password|publickey|keyboard-interactive/pam) for (?P<user>\S+) from (?P<ip>[\da-fA-F:.]+)(?=\s|$)")
_RE_SSH_CLOSED = re.compile(r"Connection closed by (?:invalid user \S+ )?(?P<ip>[\da-fA-F:.]+)(?=\s|$)")
_RE_SSH_DISCONNECT = re.compile(r"Disconnected from (?:invalid user \S+ )?(?:authenticating user \S+ )?(?P<ip>[\da-fA-F:.]+)(?=\s|$)")
_RE_SUDO_CMD = re.compile(r"sudo:\s+(?P<user>\S+)\s+:\s+.*COMMAND=(?P<cmd>.+)$")
_RE_SUDO_AUTHFAIL = re.compile(r"authentication failure")
_RE_SUDO_INCORRECT = re.compile(r"incorrect password attempts?")
_RE_SUDO_USER = re.compile(r"(?:^sudo:\s*(?P<actor>[^\s:]+)\s+:|\buser=(?P<pam>[^\s;]+))")
_RE_PAM_FAIL = re.compile(r"pam_unix\([^)]+\):.*authentication failure.*?user=(?P<user>\S+)")
_RE_USERADD = re.compile(r"^(?:useradd(?:\[\d+\])?:\s*)?new user: name=(?P<user>[^\s,]+)")
_RE_USERDEL = re.compile(r"^(?:userdel(?:\[\d+\])?:\s*)?delete user '(?P<user>[^']+)'")
_RE_PASSWD = re.compile(r"^(?:passwd(?:\[\d+\])?:\s*)?(?:pam_unix\([^)]+\):\s*)?password changed for (?P<user>\S+)")


def canonical_ip(value):
    try:
        return str(ip_address(value))
    except ValueError:
        return None


def kernel_device(message):
    match = re.search(
        r"(?:\(device\s+|\bI/O error, dev\s+|\bXFS\s*\()(?:/dev/)?([\w.-]+)",
        message, re.I,
    )
    return match[1] if match else None


def parse_auth_line(message: str, ident: str) -> Optional[dict[str, Any]]:
    """Detect auth-related patterns. Returns {category, severity, user, src_ip, ...} or None."""
    low = message.lower()

    if m := _RE_SSH_FAIL.search(message):
        return {"category": "ssh_failed", "severity": "WARN",
                "user": m.group("user"), "src_ip": canonical_ip(m.group("ip"))}

    if m := _RE_SSH_KEY_FAIL.search(message):
        return {"category": "ssh_key_failed", "severity": "WARN",
                "user": m.group("user"), "src_ip": canonical_ip(m.group("ip"))}

    if m := _RE_SSH_INVALID.search(message):
        return {"category": "ssh_invalid_user", "severity": "WARN",
                "user": m.group("user"), "src_ip": canonical_ip(m.group("ip"))}

    if m := _RE_SSH_OK.search(message):
        return {"category": "ssh_login", "severity": "INFO",
                "user": m.group("user"), "src_ip": canonical_ip(m.group("ip"))}

    if m := _RE_SSH_CLOSED.search(message):
        return {"category": "ssh_closed", "severity": "INFO", "src_ip": canonical_ip(m.group("ip"))}

    if m := _RE_SSH_DISCONNECT.search(message):
        return {"category": "ssh_disconnect", "severity": "INFO", "src_ip": canonical_ip(m.group("ip"))}

    if ident.lower() == "sudo" or low.startswith("sudo:"):
        sudo_line = message if low.startswith("sudo:") else f"sudo: {message}"
        match = _RE_SUDO_USER.search(sudo_line)
        actor = (match.group("actor") or match.group("pam")) if match else None
        if _RE_SUDO_AUTHFAIL.search(sudo_line):
            return {"category": "sudo_auth_fail", "severity": "WARN", "user": actor}
        if _RE_SUDO_INCORRECT.search(sudo_line):
            return {"category": "sudo_wrong_password", "severity": "WARN", "user": actor}
        if m := _RE_SUDO_CMD.search(sudo_line):
            return {"category": "sudo", "severity": "INFO",
                    "user": m.group("user"), "extra": {"command": m.group("cmd").strip()}}

    if "pam_faillock(" in low and "temporarily locked" in low:
        return {"category": "pam_lockout", "severity": "WARN"}

    if m := _RE_PAM_FAIL.search(message):
        return {"category": "pam_fail", "severity": "WARN", "user": m.group("user")}

    if (ident == "useradd" or low.startswith(("useradd:", "useradd["))) and (m := _RE_USERADD.search(message)):
        return {"category": "user_added", "severity": "WARN",
                "user": m.group("user"), "extra": {"event": "useradd"}}

    if (ident == "userdel" or low.startswith(("userdel:", "userdel["))) and (m := _RE_USERDEL.search(message)):
        return {"category": "user_removed", "severity": "WARN",
                "user": m.group("user"), "extra": {"event": "userdel"}}

    if (ident == "passwd" or low.startswith(("passwd:", "passwd["))) and (m := _RE_PASSWD.search(message)):
        return {"category": "password_changed", "severity": "INFO", "user": m.group("user")}

    if "session opened for user" in low or "session closed for user" in low:
        return {"category": "session", "severity": "INFO"}

    if ident == "CRON" or "cron[" in low:
        return {"category": "cron", "severity": "INFO"}

    return None


# ── kernel ─────────────────────────────────────────────────────────
_RE_OOM = re.compile(r"Out of memory: Kill(?:ed)? process (?P<pid>\d+) \((?P<comm>[^)]+)\)")
_RE_OOM_ALT = re.compile(r"Killed process (?P<pid>\d+) \((?P<comm>[^)]+)\)")
_RE_SEGFAULT = re.compile(r"(?P<comm>\S+)\[(?P<pid>\d+)\]: segfault at")
_RE_USB = re.compile(r"usb [\d-]+: new .* device")
_RE_PANIC = re.compile(r"\bKernel panic")
_RE_OOPS = re.compile(r"\b(?:BUG:|Oops:)")


def parse_kernel_line(message: str) -> Optional[dict[str, Any]]:
    if m := _RE_OOM.search(message) or _RE_OOM_ALT.search(message):
        return {"category": "oom", "severity": "CRITICAL",
                "pid": int(m.group("pid")),
                "extra": {"process": m.group("comm")}}

    if m := _RE_SEGFAULT.search(message):
        return {"category": "segfault", "severity": "ERROR",
                "pid": int(m.group("pid")),
                "extra": {"process": m.group("comm")}}

    if _RE_PANIC.search(message):
        return {"category": "kernel_panic", "severity": "CRITICAL"}

    if _RE_OOPS.search(message):
        return {"category": "kernel_oops", "severity": "ERROR"}

    if _RE_USB.search(message):
        return {"category": "usb", "severity": "INFO"}

    return None


# ── firewall (ufw / iptables in kernel log) ────────────────────────
_RE_UFW = re.compile(
    r"\[UFW (?P<action>\w+)\]"
    r".*?SRC=(?P<src>\S+)"
    r".*?DST=(?P<dst>\S+)"
    r".*?PROTO=(?P<proto>\S+)"
    r"(?:.*?SPT=(?P<spt>\d+))?"
    r"(?:.*?DPT=(?P<dpt>\d+))?"
)
_RE_IPTABLES = re.compile(
    r"IN=(?P<in>\S*)\s+OUT=(?P<out>\S*).*?"
    r"SRC=(?P<src>\S+)\s+DST=(?P<dst>\S+).*?"
    r"PROTO=(?P<proto>\S+)"
    r"(?:.*?SPT=(?P<spt>\d+))?"
    r"(?:.*?DPT=(?P<dpt>\d+))?"
)


def parse_firewall_line(message: str) -> Optional[dict[str, Any]]:
    m = _RE_UFW.search(message) or _RE_IPTABLES.search(message)
    if not m:
        return None
    action = m.groupdict().get("action") or "BLOCK"
    ports = dict(re.findall(r"\b(SPT|DPT)=(\d+)\b", message))
    return {
        "category": "firewall_" + action.lower(),
        "severity": "WARN" if action.upper() == "BLOCK" else "INFO",
        "src_ip": m.group("src"),
        "dst_ip": m.group("dst"),
        "protocol": m.group("proto"),
        "dst_port": int(ports["DPT"]) if "DPT" in ports else None,
        "extra": {"action": action, "src_port": ports.get("SPT")},
    }