"""Configuration loading, validation, and persistence (YAML)."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict, fields
from pathlib import Path
from typing import Any

import yaml

from .events import SOURCES
from .utils import config_dir, data_dir, ensure_private_dir, ensure_private_file

CONFIG_FILENAME = "config.yaml"

_VALID_SENSITIVITY = ("low", "medium", "high")
_VALID_MODE = ("dashboard", "stream")
_VALID_LEVELS = ("DEBUG", "INFO", "WARN", "ERROR", "CRITICAL")


@dataclass
class Config:
    # general
    lang: str = "auto"                      # auto | en | pt
    sensitivity: str = "medium"             # low | medium | high
    log_level: str = "WARNING"

    # storage
    save_sessions: bool = True
    session_format: str = "jsonl.gz"        # jsonl | jsonl.gz
    max_sessions: int = 20
    max_session_size_mb: int = 50
    max_history_size_mb: int = 500

    # watch / UI
    mode: str = "dashboard"                 # dashboard | stream
    only_anomalies: bool = False
    view: str = "important"                 # important | all | anomalies
    min_level: str = "DEBUG"
    refresh_hz: float = 4.0
    max_events_in_memory: int = 5000
    profiles: dict[str, dict[str, Any]] = field(default_factory=dict)
    ignore_patterns: list[str] = field(default_factory=list)

    # collectors — system
    journal_enabled: bool = True
    syslog_enabled: bool = True
    auth_enabled: bool = True
    kern_enabled: bool = True
    firewall_enabled: bool = True

    # collectors — audit
    audit_enabled: bool = True
    audit_log_path: str = "/var/log/audit/audit.log"

    # collectors — metrics
    metrics_enabled: bool = True
    metrics_interval: float = 2.0

    # collectors — network (passive sniffing is opt-in)
    network_sniff_enabled: bool = False
    network_sniff_interface: str = "any"
    network_sniff_filter: str = "tcp or udp or icmp"
    network_sniff_sample_rate: int = 10
    connections_enabled: bool = True

    # opt-in structured telemetry and classified signals
    signal_files: list[str] = field(default_factory=list)

    # detection
    baseline_enabled: bool = True
    baseline_window: int = 3600
    anomaly_z_threshold: float = 3.0
    correlation_window: int = 60
    dedup_window: int = 1

    # pcap
    pcap_max_size_mb: int = 100
    pcap_default_duration: int = 60

    # ── paths ───────────────────────────────────────────────────
    @staticmethod
    def path() -> Path:
        return config_dir() / CONFIG_FILENAME

    @staticmethod
    def data_path() -> Path:
        return data_dir()

    # ── load / save ─────────────────────────────────────────────
    @classmethod
    def load(cls, path: Path | None = None, create: bool = True) -> "Config":
        path = path or cls.path()
        if not path.exists():
            cfg = cls()
            if create:
                cfg.save(path)
            return cfg
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = yaml.safe_load(fh)
        except yaml.YAMLError as exc:
            raise ValueError(f"config: invalid YAML in {path}") from exc
        if data is None:
            data = {}
        if not isinstance(data, dict) or any(not isinstance(key, str) for key in data):
            raise ValueError("config: expected a mapping of option names")
        cfg = cls()
        names = {item.name for item in fields(cfg)}
        for key, value in data.items():
            if key in names:
                setattr(cfg, key, value)
        cfg.validate()
        return cfg

    def save(self, path: Path | None = None) -> Path:
        path = path or self.path()
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            yaml.safe_dump(asdict(self), fh, sort_keys=True, allow_unicode=True)
        ensure_private_file(path)
        return path

    # ── validation ──────────────────────────────────────────────
    def validate(self) -> None:
        if self.lang not in ("auto", "en", "pt"):
            raise ValueError("config: lang must be auto, en or pt")
        if self.sensitivity not in _VALID_SENSITIVITY:
            raise ValueError(f"config: sensitivity must be one of {_VALID_SENSITIVITY}")
        if self.mode not in _VALID_MODE:
            raise ValueError(f"config: mode must be one of {_VALID_MODE}")
        if self.view not in ("important", "all", "anomalies"):
            raise ValueError("config: view must be important, all or anomalies")
        for key in ("max_sessions", "max_session_size_mb", "max_history_size_mb", "max_events_in_memory"):
            value = getattr(self, key)
            if type(value) is not int or value < 1:
                raise ValueError(f"config: {key} must be a positive integer")
        if (not isinstance(self.signal_files, list) or len(self.signal_files) > 32
                or not all(isinstance(path, str) and path.strip() for path in self.signal_files)):
            raise ValueError("config: signal_files must contain up to 32 file paths")
        if not isinstance(self.profiles, dict):
            raise ValueError("config: profiles must be a mapping")
        allowed = {"view", "level", "sources", "grep", "ip", "ignore"}
        for name, profile in self.profiles.items():
            if not isinstance(name, str) or not name or not isinstance(profile, dict) or profile.keys() - allowed:
                raise ValueError("config: invalid filter profile")
            for key, value in profile.items():
                if key in ("sources", "ignore"):
                    valid = isinstance(value, list) and all(
                        isinstance(item, str) and (key == "ignore" or item in SOURCES) for item in value
                    )
                else:
                    valid = isinstance(value, str)
                    if key == "level":
                        valid = value in _VALID_LEVELS
                    elif key == "view":
                        valid = value in ("important", "all", "anomalies")
                if not valid:
                    raise ValueError(f"config: invalid profile {name}.{key}")
        if self.min_level not in _VALID_LEVELS:
            raise ValueError(f"config: min_level must be one of {_VALID_LEVELS}")
        if self.session_format not in ("jsonl", "jsonl.gz"):
            raise ValueError("config: session_format must be jsonl or jsonl.gz")
        if not 60 <= self.baseline_window or not 0 < self.anomaly_z_threshold:
            raise ValueError("config: invalid statistical baseline limits")
        if not 0 <= self.dedup_window:
            raise ValueError("config: dedup_window must be nonnegative")
        if not 0.5 <= self.refresh_hz <= 20:
            raise ValueError("config: refresh_hz must be between 0.5 and 20")
        if not 1 <= self.network_sniff_sample_rate <= 10000:
            raise ValueError("config: network_sniff_sample_rate must be in [1, 10000]")

    # ── dotted get/set for the CLI ──────────────────────────────
    def get(self, key: str) -> Any:
        cur: Any = self
        for part in key.split("."):
            if not hasattr(cur, part):
                raise KeyError(key)
            cur = getattr(cur, part)
        return cur

    def set(self, key: str, raw: str) -> None:
        """Set a value from a CLI string. Coerces to the field's type."""
        parts = key.split(".")
        target: Any = self
        for part in parts[:-1]:
            if not hasattr(target, part):
                raise KeyError(key)
            target = getattr(target, part)
        last = parts[-1]
        if not hasattr(target, last):
            raise KeyError(key)
        current = getattr(target, last)
        setattr(target, last, _coerce(raw, current))
        self.validate()

    def reset(self) -> None:
        fresh = Config()
        for f in fields(self):
            setattr(self, f.name, getattr(fresh, f.name))

    # ── directories ─────────────────────────────────────────────
    def ensure_dirs(self) -> None:
        ensure_private_dir(self.data_path())
        ensure_private_dir(self.data_path() / "sessions")
        ensure_private_dir(self.data_path() / "pcap")


def _coerce(raw: str, template: Any) -> Any:
    """Convert a string CLI value into the type of `template`."""
    if isinstance(template, bool):
        v = raw.strip().lower()
        if v in ("1", "true", "yes", "on", "y"):
            return True
        if v in ("0", "false", "no", "off", "n"):
            return False
        raise ValueError(f"expected bool, got {raw!r}")
    if isinstance(template, int):
        return int(raw)
    if isinstance(template, float):
        return float(raw)
    if isinstance(template, list):
        return [x for x in (s.strip() for s in raw.split(",")) if x]
    return raw