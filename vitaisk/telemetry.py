"""Validate opt-in JSONL observations and classifications from local integrations."""
from dataclasses import dataclass
from ipaddress import ip_address
import json
import re

from .events import Event, SOURCES, Severity

MAX_RECORD_BYTES = 65536
_IDENTIFIER = re.compile(r"[A-Za-z0-9_.:@/-]{1,160}")
_FIELDS = {
    "record_type", "rule_id", "producer", "observation_id", "scope",
    "ts", "source", "host", "severity", "message", "confidence", "unit",
    "src_ip", "dst_ip", "dst_port", "protocol", "user", "pid", "valid_until", "device",
}


_EVENT_FIELDS = _FIELDS - {"rule_id", "confidence", "valid_until"} | {"kind", "facts"}
_EVENT_SCHEMAS = {
    "dns": ("network", {
        "direction": {"inbound", "outbound"}, "operation": {"query", "response"},
        "qtype": str, "rcode": str, "query_length": int, "payload_bytes": int,
        "size_bytes": int, "edns": bool, "authorized": bool,
    }),
    "http": ("network", {
        "method": str, "uri_length": int, "body_bytes": int,
        "external_destination": bool, "approved_destination": bool, "status": int,
        "authentication": str, "login_endpoint": bool, "sensitive_endpoint": bool,
        "user_agent_present": bool, "http_version": str, "host_header_present": bool,
        "content_length_mismatch": bool, "framing_conflict": bool, "chunk_size_invalid": bool,
    }),
    "authentication": ("auth", {
        "result": {"success", "failure"}, "anonymous": bool, "remote": bool,
    }),
    "service": ("system", {
        "state": {"active", "inactive", "failed", "activating", "deactivating"},
        "health_reachable": bool, "functional_probe_ok": bool, "latency_over_p95": bool,
        "throughput_drop_percent": int, "error_rate_above_baseline": bool,
        "external_dependency_reachable": bool, "fd_usage_percent": int, "tasks_usage_percent": int,
        "available_pool_connections": int, "utilized_pool_connections": int,
        "burn_rate_above_limit": bool, "unit_file_changed": bool, "needs_reload": bool,
        "masked": bool, "expected_unmasked": bool, "critical_unit": bool,
        "running_as_root": bool, "dedicated_user_required": bool,
        "no_new_privileges": bool, "private_tmp": bool, "protect_system": bool,
        "exposure_tenths": int, "timer_delay_ratio_percent": int,
    }),
    "monitoring": ("metrics", {
        "exporter_reachable": bool, "systemd_collector_enabled": bool,
        "systemd_metric_expected": bool, "systemd_metric_present": bool,
        "scrape_duration_ms": int, "failed_units": int,
        "critical_unit": bool, "alert_rule_present": bool,
        "alert_open": bool, "runbook_present": bool, "acknowledged": bool,
        "critical_alert": bool, "open_seconds": int,
        "remediation_failed": bool, "remediation_failures_last_hour": int,
        "maintenance": bool, "baseline_drift": bool,
    }),
    "flow": ("network", {
        "direction": {"inbound", "outbound"}, "duration_seconds": int,
        "outbound_bytes": int, "response_bytes": int, "external_destination": bool,
        "new_destination": bool, "outside_business_hours": bool, "continuous": bool,
        "process": str, "upload": bool,
    }),
}


@dataclass
class TelemetryEvent(Event):
    """A validated observation supplied by an explicit integration."""


@dataclass
class SignalEvent(TelemetryEvent):
    signal_id: str = ""
    confidence: float = 1.0

    def to_dict(self):
        values = super().to_dict()
        values.pop("signal_id")
        values.pop("confidence")
        return values


def decode_telemetry(line, allowed):
    if len(line.encode("utf-8")) > MAX_RECORD_BYTES:
        raise ValueError("signal exceeds the size limit")
    data = json.loads(line)
    return telemetry_from_record(data, allowed, line)


def telemetry_from_record(data, allowed, raw):
    if not isinstance(data, dict):
        raise ValueError("invalid telemetry envelope")
    if data.get("record_type") == "event":
        return structured_from_record(data, raw)
    return signal_from_record(data, allowed, raw)


def _identity(data):
    for name in ("producer", "observation_id", "scope", "host"):
        value = data.get(name)
        if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
            raise ValueError(f"telemetry requires a valid {name}")
    ts = data.get("ts")
    if type(ts) not in (int, float) or not 0 <= ts <= 253402300799:
        raise ValueError("invalid telemetry timestamp")
    return ts


def signal_from_record(data, allowed, raw):
    if (data.get("record_type") != "signal" or data.keys() - _FIELDS
            or len(raw.encode("utf-8")) > MAX_RECORD_BYTES):
        raise ValueError("invalid signal envelope")
    ts = _identity(data)
    if not isinstance(data.get("rule_id"), str) or not _IDENTIFIER.fullmatch(data["rule_id"]):
        raise ValueError("signal requires a valid rule_id")
    if data["rule_id"] not in allowed:
        raise ValueError("unknown signal rule_id")
    if data.get("source") not in SOURCES:
        raise ValueError("unknown signal source")
    deadline = data.get("valid_until")
    if deadline is not None and (
        type(deadline) not in (int, float) or not ts <= deadline <= ts + 86400
    ):
        raise ValueError("signal valid_until must be within the following 24 hours")
    confidence = data.get("confidence", 0.90)
    if type(confidence) not in (int, float) or not 0 <= confidence <= 1:
        raise ValueError("invalid signal confidence")
    message = data.get("message")
    if not isinstance(message, str) or not message.strip() or len(message) > 2000:
        raise ValueError("signal requires a message of at most 2000 characters")
    for name in ("unit", "user", "protocol", "device"):
        value = data.get(name)
        if value is not None and (not isinstance(value, str) or not _IDENTIFIER.fullmatch(value)):
            raise ValueError(f"invalid signal {name}")
    for name, low, high in (("dst_port", 0, 65535), ("pid", 1, 2**31 - 1)):
        value = data.get(name)
        if value is not None and (type(value) is not int or not low <= value <= high):
            raise ValueError(f"invalid signal {name}")
    addresses = {}
    for name in ("src_ip", "dst_ip"):
        value = data.get(name)
        if value is not None:
            if not isinstance(value, str):
                raise ValueError(f"invalid signal {name}")
            addresses[name] = str(ip_address(value))
    try:
        severity = Severity.parse(data.get("severity", allowed[data["rule_id"]]["severity"]))
    except (ValueError, KeyError, AttributeError) as exc:
        raise ValueError("invalid signal severity") from exc
    return SignalEvent(
        ts=float(ts), host=data["host"], source=data["source"], category="external_signal",
        severity=severity, message=message, raw=raw, signal_id=data["rule_id"], confidence=confidence,
        user=data.get("user"), pid=data.get("pid"), protocol=data.get("protocol"),
        dst_port=data.get("dst_port"), **addresses,
        extra={"producer": data["producer"], "observation_id": data["observation_id"],
               "correlation_id": data["scope"], "unit": data.get("unit"), "device": data.get("device"),
               "signal_rule_id": data["rule_id"], "confidence": confidence, "valid_until": deadline,
               "suggested_actions": allowed[data["rule_id"]].get("suggested_actions", [])},
    )


def structured_from_record(data, raw):
    if (data.get("record_type") != "event" or data.keys() - _EVENT_FIELDS
            or len(raw.encode("utf-8")) > MAX_RECORD_BYTES):
        raise ValueError("invalid structured telemetry envelope")
    kind = data.get("kind")
    if not isinstance(kind, str) or kind not in _EVENT_SCHEMAS:
        raise ValueError("unknown structured telemetry kind")
    source, schema = _EVENT_SCHEMAS[kind]
    facts = data.get("facts")
    if not isinstance(facts, dict) or not facts or facts.keys() - schema.keys():
        raise ValueError("invalid structured telemetry fields")
    for field, value in facts.items():
        constraint = schema[field]
        if isinstance(constraint, set):
            valid = isinstance(value, str) and value in constraint
        elif constraint is str:
            valid = isinstance(value, str) and bool(_IDENTIFIER.fullmatch(value))
        elif constraint is int:
            valid = type(value) is int and 0 <= value <= 2**63 - 1
        else:
            valid = type(value) is bool
        if not valid:
            raise ValueError(f"invalid structured telemetry field: {field}")
    if data.get("source", source) != source:
        raise ValueError("structured telemetry source does not match its kind")
    common = {key: value for key, value in data.items() if key not in ("kind", "facts")}
    common.update(record_type="signal", source=source, rule_id="observation")
    normalized = signal_from_record(common, {"observation": {"severity": "INFO"}}, raw)
    extra = {**facts, **{key: normalized.extra[key] for key in
                         ("producer", "observation_id", "correlation_id", "unit", "device")}}
    return TelemetryEvent(
        ts=normalized.ts, source=source, category=f"telemetry_{kind}",
        severity=normalized.severity, message=normalized.message, raw=raw,
        host=normalized.host, pid=normalized.pid, user=normalized.user,
        src_ip=normalized.src_ip, dst_ip=normalized.dst_ip, dst_port=normalized.dst_port,
        protocol=normalized.protocol, extra=extra,
    )
