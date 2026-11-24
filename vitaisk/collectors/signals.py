"""Tail an explicit JSONL source of observations and classified detections."""
import os
from pathlib import Path
import stat

from ..telemetry import MAX_RECORD_BYTES, decode_telemetry
from .base import Collector


class SignalCollector(Collector):
    def __init__(self, queue, config, stop_event, path, allowed):
        super().__init__(queue, config, stop_event)
        self.path = Path(path)
        self.name = f"signals:{self.path.name}"
        self.allowed = allowed
        self.rejected = 0

    def _open(self):
        fd = os.open(self.path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise ValueError("signal input must be a regular file")
            return os.fdopen(fd, "rb")
        except BaseException:
            os.close(fd)
            raise

    def _run(self):
        first_open = True
        while not self.should_stop():
            try:
                with self._open() as handle:
                    if first_open:
                        handle.seek(0, os.SEEK_END)
                    first_open = False
                    self._read(handle)
            except FileNotFoundError:
                self.stop_event.wait(0.2)

    def _read(self, handle):
        identity = os.fstat(handle.fileno())
        partial = b""
        oversized = False
        while not self.should_stop():
            chunk = handle.readline(MAX_RECORD_BYTES + 1)
            if not chunk:
                try:
                    current = self.path.stat()
                except FileNotFoundError:
                    return
                if ((current.st_dev, current.st_ino) != (identity.st_dev, identity.st_ino)
                        or current.st_size < handle.tell()):
                    return
                self.stop_event.wait(0.2)
                continue
            if not oversized and len(partial) + len(chunk) > MAX_RECORD_BYTES:
                oversized = True
                partial = b""
            if not chunk.endswith(b"\n"):
                if not oversized:
                    partial += chunk
                continue
            if oversized:
                self.rejected += 1
            else:
                self._decode(partial + chunk)
            partial = b""
            oversized = False

    def _decode(self, line):
        if not line.strip():
            return
        try:
            event = decode_telemetry(line.decode("utf-8").rstrip("\r\n"), self.allowed)
        except (ValueError, RecursionError):
            self.rejected += 1
            return
        self.emit(event)
