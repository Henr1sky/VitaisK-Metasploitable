"""Live terminal views for local monitoring."""
from collections import Counter, deque
from contextlib import contextmanager, nullcontext
import codecs
import os
import re
import select
import signal
import sys
import termios
import threading
import time
import tty

from rich.live import Live

from .baseline_store import load_baseline, save_baseline
from .collectors import CollectorManager
from .dashboard import Dashboard, PulseSample, ViewFilter, effective_level, event_row, label
from .engine.pipeline import Pipeline
from .engine.statistical import ErrorRates
from .events import Severity
from .i18n import current_lang
from .rules.loader import load_rules
from .sessions import SessionWriter
from .utils import eprint

_SEQUENCES = {
    "A": "up", "B": "down", "C": "right", "D": "left", "H": "home",
    "1~": "home", "3~": "delete", "5~": "pageup", "6~": "pagedown",
}
_ESCAPE = re.compile(r"^\x1b(?:\[([0-9;]*[A-Za-z~])|O([A-Za-z]))")
_SINGLE = {"\r": "enter", "\n": "enter", "\x7f": "backspace", "\x08": "backspace",
           "\x15": "clear"}


class KeyReader:
    def __init__(self):
        self.decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        self.pending = ""

    def feed(self, data):
        self.pending += self.decoder.decode(data)
        while self.pending:
            first = self.pending[0]
            if first != "\x1b":
                self.pending = self.pending[1:]
                yield _SINGLE.get(first, first)
                continue
            match = _ESCAPE.match(self.pending)
            if match:
                self.pending = self.pending[match.end():]
                key = _SEQUENCES.get(match.group(1) or match.group(2))
                if key:
                    yield key
            elif data and (self.pending == "\x1b" or self.pending.startswith(("\x1b[", "\x1bO"))):
                break
            else:
                self.pending = self.pending[1:]
                yield "esc"


@contextmanager
def _keyboard():
    if not sys.stdin.isatty():
        yield lambda: ()
        return
    fd = sys.stdin.fileno()
    settings = termios.tcgetattr(fd)
    reader = KeyReader()

    def read():
        data = os.read(fd, 4096) if select.select([fd], [], [], 0)[0] else b""
        return tuple(reader.feed(data))

    try:
        tty.setcbreak(fd)
        yield read
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, settings)


def watch(config, console, *, mode, view, only_anomalies, min_level, sources, grep, ip,
          ignore, sensitivity, save, profile, manager=None, baseline_name="baseline.json"):
    if profile is not None and profile not in config.profiles:
        raise ValueError(label("Unknown profile", "Perfil desconhecido") + f": {profile}")
    filters = ViewFilter.for_profile(
        config, profile, view="anomalies" if only_anomalies else view, min_level=min_level,
        sources=sources, grep=grep, ip=ip, ignore=ignore,
    )
    if manager is None:
        manager = CollectorManager(config)
    baseline = None
    if config.baseline_enabled:
        try:
            baseline = ErrorRates(config.baseline_window, config.anomaly_z_threshold,
                                  config.max_events_in_memory, load_baseline(config, baseline_name))
        except (OSError, KeyError, TypeError, ValueError):
            baseline = ErrorRates(config.baseline_window, config.anomaly_z_threshold,
                                  config.max_events_in_memory)
    pipeline = Pipeline(
        load_rules(), config.max_events_in_memory, sensitivity or config.sensitivity,
        config.dedup_window, baseline,
    )
    recording = config.save_sessions if save is None else save
    writer = SessionWriter(config) if recording else None
    dashboard = (mode or config.mode) == "dashboard" and console.is_terminal
    recent = deque(maxlen=config.max_events_in_memory)
    screen = Dashboard(config, filters) if dashboard else None
    activity = deque([PulseSample()] * 48, maxlen=48)
    tick_level = Severity.INFO
    severity_counts = Counter()
    alert_total = tick_count = 0
    last_refresh = 0.0
    last_tick = time.monotonic()
    last_flush = last_tick

    def consume(event):
        nonlocal alert_total, tick_count, tick_level
        alerts = tuple(pipeline.process(event, current_lang()))
        if writer:
            writer.write(event, alerts)
        if dashboard:
            level = effective_level(event, alerts)
            severity_counts[level] += 1
            tick_count += 1
            tick_level = max(tick_level, level)
            alert_total += len(alerts)
            recent.append((event, alerts))
        elif filters.matches(event, alerts):
            console.print(*event_row(event, alerts))

    keyboard = _keyboard() if dashboard else nullcontext(lambda: ())
    live_view = Live(console=console, auto_refresh=False, screen=True) if dashboard else nullcontext()
    saved = None
    stop_requested = False

    def request_stop(signum, frame):
        nonlocal stop_requested
        stop_requested = True

    handle_sigterm = threading.current_thread() is threading.main_thread()
    if handle_sigterm:
        original_sigterm = signal.signal(signal.SIGTERM, request_stop)
    try:
        with keyboard as read_keys, live_view as live:
            manager.start()
            while not stop_requested and not manager.stop_event.is_set():
                event = manager.queue.get(timeout=0.1)
                now = time.monotonic()
                elapsed = int(now - last_tick)
                if elapsed:
                    activity.append(PulseSample(tick_count, tick_level))
                    activity.extend([PulseSample()] * min(elapsed - 1, activity.maxlen))
                    tick_count, tick_level = 0, Severity.INFO
                    last_tick += elapsed
                if event is not None:
                    consume(event)
                if writer and now - last_flush >= 1:
                    saved = writer.flush() or saved
                    last_flush = now
                if screen is not None:
                    keys = read_keys()
                    for key in keys:
                        if not screen.handle(key, recent):
                            stop_requested = True
                            break
                    if stop_requested:
                        break
                    if now - last_refresh >= 1 / config.refresh_hz or keys:
                        samples = [*activity, PulseSample(tick_count, tick_level)]
                        live.update(screen.render(
                            console, manager, recent, samples, severity_counts, alert_total, recording,
                        ), refresh=True)
                        last_refresh = now
    except KeyboardInterrupt:
        pass
    finally:
        try:
            manager.stop()
            while (event := manager.queue.get(timeout=0)) is not None:
                consume(event)
        finally:
            try:
                if writer:
                    saved = writer.close() or saved
                if baseline is not None and baseline.rates:
                    try:
                        save_baseline(config, baseline, baseline_name)
                    except OSError as exc:
                        eprint(label("Baseline could not be saved", "Falha ao gravar a referência estatística"), exc)
            finally:
                if handle_sigterm:
                    signal.signal(signal.SIGTERM, original_sigterm)
    return saved
