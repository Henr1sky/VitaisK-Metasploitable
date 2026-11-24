"""Load bundled rules and user overrides through the same validation path."""
from importlib.resources import files
from pathlib import Path

import re

import yaml

from ..events import Event, SOURCES, Severity
from ..utils import config_dir

_MATCH_KEYS = {"source", "category", "contains", "equals", "regex", "number", "one_of"}
_RULE_KEYS = _MATCH_KEYS | {"id", "group_by", "threshold", "window", "severity", "followed_by", "distinct", "suggested_actions", "match_window"}
_FIELDS = set(Event.__dataclass_fields__)
_GROUP_FIELDS = _FIELDS - {"extra"}


def _strings(value):
    return isinstance(value, list) and bool(value) and all(
        isinstance(item, str) and bool(item) for item in value
    )


def _group_field(name):
    return name in _GROUP_FIELDS or (name.startswith("extra.") and len(name) > 6)


def _match_valid(match):
    if "source" in match and match["source"] not in SOURCES:
        return False
    if "category" in match and not (
        isinstance(match["category"], str) and match["category"] or _strings(match["category"])
    ):
        return False
    if "contains" in match and not _strings(match["contains"]):
        return False
    if "regex" in match:
        if not isinstance(match["regex"], str) or not match["regex"]:
            return False
        re.compile(match["regex"], re.IGNORECASE)
    number = match.get("number", {})
    if not isinstance(number, dict) or any(
        not isinstance(key, str) or not _group_field(key) or not isinstance(bounds, dict)
        or not bounds or bounds.keys() - {"lt", "lte", "gt", "gte"}
        or any(type(value) is not int for value in bounds.values())
        for key, bounds in number.items()
    ):
        return False
    membership = match.get("one_of", {})
    if not isinstance(membership, dict) or any(
        not isinstance(key, str) or not _group_field(key) or not isinstance(choices, list)
        or not choices or any(type(choice) not in (str, int, bool) for choice in choices)
        for key, choices in membership.items()
    ):
        return False
    equals = match.get("equals", {})
    return isinstance(equals, dict) and all(k in _FIELDS or isinstance(k, str) and _group_field(k) for k in equals) and bool(set(match) & _MATCH_KEYS)


def _validate(rule):
    if not isinstance(rule, dict) or rule.keys() - _RULE_KEYS:
        raise ValueError("invalid rule fields")
    if not isinstance(rule.get("id"), str) or not rule["id"].strip() or not _match_valid(rule):
        raise ValueError("invalid rule id or match")
    threshold = rule.get("threshold", 1)
    window = rule.get("window", 0)
    groups = rule.get("group_by", [])
    if type(threshold) is not int or threshold < 1 or type(window) is not int or window < 0:
        raise ValueError(f"{rule['id']}: invalid threshold or window")
    if not isinstance(groups, list) or (groups and not _strings(groups)) or not all(map(_group_field, groups)):
        raise ValueError(f"{rule['id']}: invalid group_by")
    distinct = rule.get("distinct")
    if distinct is not None and (not isinstance(distinct, str) or not _group_field(distinct)):
        raise ValueError(f"{rule['id']}: invalid distinct field")
    if "suggested_actions" in rule and not _strings(rule["suggested_actions"]):
        raise ValueError(f"{rule['id']}: invalid suggested actions")
    terminal = rule.get("followed_by")
    if terminal is not None and (
        not isinstance(terminal, dict) or terminal.keys() - _MATCH_KEYS or not _match_valid(terminal)
    ):
        raise ValueError(f"{rule['id']}: invalid followed_by")
    match_window = rule.get("match_window")
    if match_window is not None and (
        terminal is None or type(match_window) is not int or not 0 < match_window <= window
    ):
        raise ValueError(f"{rule['id']}: invalid match_window")
    if (threshold > 1 or terminal is not None) and not window:
        raise ValueError(f"{rule['id']}: a positive window is required")
    try:
        Severity.parse(rule.get("severity", "WARN"))
    except (AttributeError, KeyError, ValueError) as exc:
        raise ValueError(f"{rule['id']}: invalid severity") from exc


def load_rules(directory: Path | None = None):
    directory = directory if directory is not None else config_dir() / "rules.d"
    paths = [files(__package__).joinpath(name) for name in ("builtin.yaml", "structured.yaml")]
    paths.extend(sorted([*directory.glob("*.yaml"), *directory.glob("*.yml")]))
    rules = {}
    for path in paths:
        try:
            entries = yaml.safe_load(path.read_text(encoding="utf-8"))
            if not isinstance(entries, list):
                raise ValueError("expected a list of rules")
            seen = set()
            for rule in entries:
                _validate(rule)
                if rule["id"] in seen:
                    raise ValueError(f"duplicate id {rule['id']}")
                for match in (rule, rule.get("followed_by") or {}):
                    if "contains" in match:
                        match["contains"] = [token.casefold() for token in match["contains"]]
                seen.add(rule["id"])
                rules[rule["id"]] = rule
        except (ValueError, re.error, yaml.YAMLError) as exc:
            raise ValueError(f"{path}: {exc}") from exc
    return rules


def load_correlations():
    """Validate and complete the shipped correlation definitions."""
    path = files(__package__).joinpath("correlations.yaml")
    entries = yaml.safe_load(path.read_text(encoding="utf-8"))
    ids = set()
    for rule in entries:
        rule_id = rule["id"]
        requires = rule["requires"]
        if (rule_id in ids or not _strings(requires) or not 2 <= len(requires) <= 4
                or len(set(requires)) != len(requires)):
            raise ValueError(f"invalid correlation: {rule_id}")
        ids.add(rule_id)
        rule["requires_scope"] = "group_by" not in rule
        if rule["requires_scope"]:
            rule.update(group_by=["host", "extra.correlation_id"], window=300, severity="WARN")
        fields = rule["group_by"]
        if not _strings(fields) or not all(map(_group_field, fields)):
            raise ValueError(f"invalid correlation grouping: {rule_id}")
        if type(rule.get("window")) is not int or rule["window"] < 1:
            raise ValueError(f"invalid correlation window: {rule_id}")
        Severity.parse(rule["severity"])
    return entries


def signal_levels(rules, correlations):
    path = files(__package__).joinpath("signals.yaml")
    entries = yaml.safe_load(path.read_text(encoding="utf-8"))
    for rule_id, rule in rules.items():
        entries[rule_id] = {"severity": rule.get("severity", "WARN"),
                            "suggested_actions": rule.get("suggested_actions", [])}
    for rule in correlations:
        for signal in rule["requires"]:
            entries.setdefault(signal, {"severity": "WARN"})
    return entries


def load_priorities():
    path = files(__package__).joinpath("priorities.yaml")
    rules = yaml.safe_load(path.read_text(encoding="utf-8"))
    ids = set()
    for rule in rules:
        rule_id = rule["id"]
        if (rule_id in ids or not _strings(rule["target"]) or not _strings(rule["group_by"])
                or not all(map(_group_field, rule["group_by"]))
                or type(rule["window"]) is not int or rule["window"] < 1):
            raise ValueError(f"invalid priority policy: {rule_id}")
        ids.add(rule_id)
        if rule["action"] not in {"suppress", "lower", "raise", "group", "human_review"}:
            raise ValueError(f"invalid priority action: {rule_id}")
        if rule["action"] in ("raise", "lower"):
            Severity.parse(rule["severity"])
    return rules


def rule_input(rule):
    if rule is None:
        return "external"
    category = rule.get("category", "")
    categories = [category] if isinstance(category, str) else category
    if categories and all(item.startswith("telemetry_") for item in categories):
        return "structured"
    return "native"
