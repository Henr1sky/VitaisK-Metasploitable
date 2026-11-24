"""Apply time-limited triage annotations without discarding audit evidence."""
from collections import OrderedDict, defaultdict
from hashlib import sha256
import json

from .correlation import group_values
from ..events import Severity


class Priorities:
    def __init__(self, rules, max_groups):
        self.triggers = defaultdict(list)
        self.targets = defaultdict(list)
        self.prefixes = []
        self.markers = OrderedDict()
        self.max_groups = max_groups
        for rule in rules:
            self.triggers[rule["when"]].append(rule)
            for target in rule["target"]:
                if target.endswith("*"):
                    self.prefixes.append((target[:-1], rule))
                else:
                    self.targets[target].append(rule)

    def annotate(self, alerts):
        for alert in alerts:
            for rule in self.triggers.get(alert.rule_id, ()):
                group = group_values(alert.event, rule["group_by"])
                if group is None:
                    continue
                key = (rule["id"], group)
                previous = self.markers.get(key)
                ts = alert.event.ts
                if previous is None or ts >= previous[0]:
                    deadline = alert.event.extra.get("valid_until")
                    if rule["action"] == "lower" and type(deadline) in (int, float) and ts <= deadline <= ts + 86400:
                        window_end = deadline
                    else:
                        window_end = ts + rule["window"]
                    started = previous[2] if previous and ts <= previous[1] else ts
                    self.markers[key] = (ts, window_end, started)
                    self.markers.move_to_end(key)
                    if len(self.markers) > self.max_groups:
                        self.markers.popitem(last=False)
        for alert in alerts:
            targets = [*self.targets.get(alert.rule_id, ())]
            targets.extend(rule for prefix, rule in self.prefixes if alert.rule_id.startswith(prefix))
            for rule in targets:
                self._apply(rule, alert)

    def _apply(self, rule, alert):
        group = group_values(alert.event, rule["group_by"])
        if group is None:
            return
        key = (rule["id"], group)
        marker = self.markers.get(key)
        if marker is None or not marker[2] <= alert.event.ts <= marker[1]:
            return
        action = rule["action"]
        note = {"policy_id": rule["id"], "action": action, "trigger": rule["when"]}
        if action == "group":
            note["incident_id"] = sha256(json.dumps((key, marker[2])).encode()).hexdigest()[:16]
        if action in ("raise", "lower"):
            note["severity"] = rule["severity"]
        if action == "human_review":
            note["severity"] = Severity.CRITICAL.name
            note["automation_allowed"] = False
        alert.triage.append(note)


def presentation_severity(alert):
    raised = [Severity.parse(item["severity"]) for item in alert.triage
              if item["action"] in ("raise", "human_review")]
    if raised:
        return max(alert.severity, *raised)
    lowered = [Severity.parse(item["severity"]) for item in alert.triage
               if item["action"] == "lower"]
    return min([alert.severity, *lowered])


def hidden_by_priority(alert):
    # Escalation has precedence over a suppression from another policy.
    if any(item["action"] in ("raise", "human_review") for item in alert.triage):
        return False
    return any(item["action"] == "suppress" for item in alert.triage)
