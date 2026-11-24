"""In-memory rule evaluation over normalized events."""
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from hashlib import sha256
import json
from operator import gt, ge, lt, le
import re

from ..events import Event, SOURCES, Severity
from ..telemetry import SignalEvent, TelemetryEvent
from .correlation import Correlator, event_field
from .priorities import Priorities


@dataclass
class Anomaly:
    event: Event
    rule_id: str
    reasons: list[str]
    confidence: float
    sources_matched: list[str]
    event_count: int
    window_start: float
    window_end: float
    severity: Severity
    anomaly_id: str
    group_key: str
    suggested_actions: list[str] = field(default_factory=list)

    z_score: float | None = None
    evidence: list[dict] = field(default_factory=list)
    supersedes: list[str] = field(default_factory=list)
    triage: list[dict] = field(default_factory=list)

    def localized_reason(self, lang):
        if self.evidence:
            prefix = "Correlação" if lang == "pt" else "Correlation"
            signals = " + ".join(item["rule_id"] for item in self.evidence)
            return f"{prefix}: {self.rule_id} ({signals})"
        if self.z_score is not None:
            if lang == "pt":
                return f"{self.event_count} erros neste minuto (Z={self.z_score:.1f})"
            return f"{self.event_count} errors this minute (Z={self.z_score:.1f})"
        if self.event_count == 1:
            return self.rule_id
        elapsed = self.window_end - self.window_start
        unit = "eventos em" if lang == "pt" else "events in"
        return f"{self.rule_id}: {self.event_count} {unit} {elapsed:g} s"

    def to_dict(self):
        return {
            **{key: value for key, value in vars(self).items()
               if key not in ("z_score", "evidence", "supersedes", "triage")},
            **({"z_score": self.z_score} if self.z_score is not None else {}),
            **({"evidence": self.evidence} if self.evidence else {}),
            **({"supersedes": self.supersedes} if self.supersedes else {}),
            **({"triage": self.triage} if self.triage else {}),
            "event": self.event.to_dict(),
            "severity": self.severity.name,
        }


_COMPARISONS = {"gt": gt, "gte": ge, "lt": lt, "lte": le}


def _numeric_matches(value, bounds):
    return type(value) in (int, float) and all(
        _COMPARISONS[operator](value, limit) for operator, limit in bounds.items()
    )


def _matches(event, rule, message):
    source = rule.get("source")
    category = rule.get("category")
    categories = [category] if isinstance(category, str) else category
    return (
        (source is None or source == event.source)
        and (categories is None or event.category in categories)
        and ("contains" not in rule or any(token in message for token in rule["contains"]))
        and ("regex" not in rule or re.search(rule["regex"], event.message, re.IGNORECASE))
        and all(event_field(event, key) == value for key, value in rule.get("equals", {}).items())
        and all(event_field(event, key) in choices for key, choices in rule.get("one_of", {}).items())
        and all(_numeric_matches(event_field(event, key), bounds)
                for key, bounds in rule.get("number", {}).items())
    )


def _branches(rule):
    yield rule
    if rule.get("followed_by") is not None:
        yield rule["followed_by"]


def _categories(match):
    categories = match.get("category", ())
    return (categories,) if isinstance(categories, str) else categories


def _candidates(rules, source, category):
    return [
        rule for rule in rules
        if any(match.get("source") in (None, source)
               and (not _categories(match) or category in _categories(match))
               for match in _branches(rule))
    ]


class Pipeline:
    def __init__(self, rules, max_groups=5000, sensitivity="medium", dedup_window=1, baseline=None, correlations=(), priorities=()):
        definitions = tuple(rules.values())
        categories_by_source = {source: set() for source in SOURCES}
        for rule in definitions:
            for match in _branches(rule):
                sources = (match["source"],) if "source" in match else SOURCES
                for source in sources:
                    categories_by_source[source].update(_categories(match))
        self.uncategorized = {
            source: _candidates(definitions, source, None) for source in SOURCES
        }
        self.rules_by_category = {
            (source, category): _candidates(definitions, source, category)
            for source, categories in categories_by_source.items()
            for category in categories
        }
        self.max_groups = max(1, max_groups)
        self.minimum_confidence = {"low": 0.9, "medium": 0.75, "high": 0.5}[sensitivity]
        self.groups = OrderedDict()
        self.recent_events = OrderedDict()
        self.external_seen = OrderedDict()
        self.dedup_window = dedup_window
        self.baseline = baseline
        self.correlator = Correlator(correlations, self.max_groups)
        self.priorities = Priorities(priorities, self.max_groups)

    def _duplicate(self, event):
        collector = event.extra.get("collector")
        if not collector or self.dedup_window <= 0:
            return False
        key = (event.host, event.fingerprint(), event.pid, event.dst_ip, event.dst_port)
        history = self.recent_events.get(key)
        if history is None:
            history = deque(maxlen=16)
            self.recent_events[key] = history
        self.recent_events.move_to_end(key)
        if len(self.recent_events) > self.max_groups:
            self.recent_events.popitem(last=False)
        for index, (ts, other) in enumerate(history):
            if other != collector and abs(event.ts - ts) <= self.dedup_window:
                del history[index]
                return True
        history.append((event.ts, collector))
        return False

    def process(self, event, lang="en"):
        signals = list(self._detect(event, lang))
        combined = list(self.correlator.observe(signals))
        for alert in combined:
            alert.reasons.append(alert.localized_reason(lang))
        self.priorities.annotate([*signals, *combined])
        yield from signals
        yield from combined

    def _detect(self, event, lang):
        is_signal = isinstance(event, SignalEvent)
        if isinstance(event, TelemetryEvent):
            key = (event.host, event.extra["producer"], event.extra["observation_id"],
                   event.signal_id if is_signal else "")
            if key in self.external_seen:
                return
            self.external_seen[key] = None
            if len(self.external_seen) > self.max_groups:
                self.external_seen.popitem(last=False)
        if is_signal:
            if event.confidence < self.minimum_confidence:
                return
            alert = Anomaly(
                event, event.signal_id, [event.signal_id], event.confidence, [event.source], 1,
                event.ts, event.ts, event.severity, sha256(json.dumps(key).encode()).hexdigest()[:16],
                event.extra["correlation_id"], event.extra["suggested_actions"],
            )
            yield alert
            return
        if self._duplicate(event):
            return
        message = event.message.casefold()
        candidates = self.rules_by_category.get(
            (event.source, event.category), self.uncategorized.get(event.source, ()),
        )
        for rule in candidates:
            first = _matches(event, rule, message)
            terminal = rule.get("followed_by")
            last = terminal is not None and _matches(event, terminal, message)
            if not (first or last):
                continue
            group = tuple(event_field(event, field) for field in rule.get("group_by", []))
            if any(type(value) not in (str, int) or (value == "" and field != "host")
                   for field, value in zip(rule.get("group_by", []), group)):
                continue
            rule_id = rule["id"]
            key = (rule_id, group)
            threshold = rule.get("threshold", 1)
            window = rule.get("window", 0)
            distinct = rule.get("distinct")
            value = event_field(event, distinct) if distinct is not None else None
            if first and distinct is not None and value is None:
                first = False
            history = self.groups.get(key)
            if history is None:
                history = deque(maxlen=threshold)
            while history and history[0][0] < event.ts - window:
                history.popleft()
            matched = (
                last and len(history) >= threshold and history[-1][0] <= event.ts
                and history[-1][0] - history[0][0] <= rule.get("match_window", window)
            )
            if matched:
                matched_history = list(history)
                self.groups.pop(key, None)
            elif first and (not history or history[-1][0] <= event.ts):
                was_full = len(history) == threshold
                if distinct is not None:
                    for index, (_, _, old_value) in enumerate(history):
                        if old_value == value:
                            del history[index]
                            break
                history.append((event.ts, event.source, value))
                matched = terminal is None and not was_full and len(history) == threshold
                matched_history = list(history) if matched else []
                if window:
                    self.groups[key] = history
                    self.groups.move_to_end(key)
                    if len(self.groups) > self.max_groups:
                        self.groups.popitem(last=False)
            if not matched:
                continue
            count = len(matched_history) + int(last)
            start = matched_history[0][0]
            confidence = 0.95 if last or threshold > 1 or rule.get("category") else 0.85
            if confidence < self.minimum_confidence:
                continue
            group_key = "/".join(map(str, group)) or event.category
            identity = json.dumps((rule_id, group or (event.host, event.category)), default=str)
            alert = Anomaly(
                event, rule_id, [], confidence,
                sorted({event.source, *(source for _, source, _ in matched_history)}),
                count, start, event.ts, Severity.parse(rule.get("severity", "WARN")),
                sha256(identity.encode()).hexdigest()[:16], group_key,
                list(rule.get("suggested_actions", [])),
            )
            alert.reasons.append(alert.localized_reason(lang))
            yield alert

        if self.baseline is not None:
            burst = self.baseline.observe(event)
            if burst is not None and self.minimum_confidence <= 0.8:
                count, start, score = burst
                key = event.host + "/" + event.source
                identity = sha256(("error-rate-spike/" + key).encode()).hexdigest()[:16]
                alert = Anomaly(
                    event, "error-rate-spike", [], 0.8, [event.source], count,
                    start, event.ts, Severity.WARN, identity, key, z_score=score,
                )
                alert.reasons.append(alert.localized_reason(lang))
                yield alert
