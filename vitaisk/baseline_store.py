"""Persist statistical state separately from user-visible log sessions."""
import json
import os
from pathlib import Path
from tempfile import NamedTemporaryFile

from .utils import ensure_private_dir


def load_baseline(config, filename="baseline.json"):
    path = config.data_path() / filename
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, ValueError):
        return None
    if isinstance(data, dict) and data.get("version") == 1:
        return data.get("rates")
    return None


def save_baseline(config, baseline, filename="baseline.json"):
    directory = ensure_private_dir(config.data_path())
    with NamedTemporaryFile(mode="w", encoding="utf-8", dir=directory, delete=False) as temp:
        try:
            json.dump({"version": 1, "rates": baseline.snapshot()}, temp)
            temp.close()
            os.replace(temp.name, directory / filename)
        finally:
            Path(temp.name).unlink(missing_ok=True)
