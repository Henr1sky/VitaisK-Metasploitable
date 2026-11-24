"""Bounded event-time joins over detected signals."""
from collections import OrderedDict, defaultdict, deque
from dataclasses import dataclass
from hashlib import sha256
from itertools import product
import json

from ..events import Severity
from ..telemetry import TelemetryEvent


def event_field(event, name):
    return event.extra.get(name[6:]) if name.startswith("extra.") else getattr(event, name)


def group_values(event, fields):
    group = tuple(event_field(event, field) for field in fields)
    return group if all(type(value) in (str, int) and value != "" for value in group) else None


@dataclass
class Evidence:
    identity: tuple
    rule_id: str
    ts: float
    window_start: float
    source: str
    sources: tuple
    category: str
    message: str
    confidence: float
    severity: Severity
    producer: str | None

    @classmethod
    def from_signal(cls, signal):
        event = signal.event
        if isinstance(event, TelemetryEvent):
            producer = event.extra["producer"]
            identity = ("external", producer, event.extra["observation_id"])
        else:
            producer = None
            identity = ("native", event.ts, event.fingerprint(), event.dst_port, event.pid)
        return cls(identity, signal.rule_id, event.ts, signal.window_start, event.source,
                   tuple(signal.sources_matched), event.category, event.message[:512],
                   signal.confidence, signal.severity, producer)

    def to_dict(self):
        result = {"rule_id": self.rule_id, "ts": self.ts, "source": self.source,
                  "category": self.category, "message": self.message, "severity": self.severity.name}
        if self.producer is not None:
            result["producer"] = self.producer
            result["observation_id"] = self.identity[2]
        return result


class Correlator:
    def __init__(self, rules, max_groups):
        self.by_signal = defaultdict(list)
        self.groups = OrderedDict()
        self.max_groups = max_groups
        for rule in rules:
            for signal in rule["requires"]:
                self.by_signal[signal].append(rule)

    def observe(self, signals):
        from .pipeline import Anomaly

        for signal in signals:
            rules = self.by_signal.get(signal.rule_id)
            if not rules:
                continue
            current = Evidence.from_signal(signal)
            for rule in rules:
                group = group_values(signal.event, rule["group_by"])
                if group is None:
                    continue
                key = (rule["id"], group)
                state = self.groups.setdefault(key, {})
                self.groups.move_to_end(key)
                if len(self.groups) > self.max_groups:
                    self.groups.popitem(last=False)
                history = state.setdefault(signal.rule_id, deque(maxlen=4))
                if any(item.identity == current.identity for item in history):
                    continue
                history.append(current)
                evidence = self._match(rule, state, current)
                if evidence is None:
                    continue
                for item in evidence:
                    state[item.rule_id].remove(item)
                if not any(state.values()):
                    del self.groups[key]
                severity = Severity.parse(rule["severity"])
                if rule.get("requires_scope"):
                    severity = max(severity, *(item.severity for item in evidence))
                yield Anomaly(
                    event=signal.event, rule_id=rule["id"], reasons=[],
                    confidence=min(item.confidence for item in evidence),
                    sources_matched=sorted({source for item in evidence for source in item.sources}),
                    event_count=len({item.identity for item in evidence}),
                    window_start=min(item.window_start for item in evidence),
                    window_end=max(item.ts for item in evidence),
                    severity=severity,
                    anomaly_id=sha256(json.dumps(key).encode()).hexdigest()[:16],
                    group_key="/".join(map(str, group)),
                    evidence=[item.to_dict() for item in evidence],
                    supersedes=rule.get("supersedes", []),
                )

    @staticmethod
    def _match(rule, state, current):
        choices = [
            (current,) if wanted == current.rule_id else sorted(
                (item for item in state.get(wanted, ()) if abs(item.ts - current.ts) <= rule["window"]),
                key=lambda item: item.ts,
                reverse=True,
            )
            for wanted in rule["requires"]
        ]
        for evidence in product(*choices):
            times = [item.ts for item in evidence]
            if max(times) - min(times) > rule["window"]:
                continue
            if rule.get("ordered") and times != sorted(times):
                continue
            if not rule.get("same_event") and len({item.identity for item in evidence}) != len(evidence):
                continue
            return evidence
        return None
