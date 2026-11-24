"""Rich views and keyboard navigation for the live monitor."""
from dataclasses import dataclass
from ipaddress import ip_address
from itertools import islice
import re

from rich import box
from rich.columns import Columns
from rich.console import Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .collectors import MetricsCollector
from .engine.priorities import hidden_by_priority, presentation_severity
from .events import SOURCES, Severity
from .telemetry import SignalEvent
from .i18n import _, current_lang, set_lang
from .utils import short_ts

CONTROLS = re.compile(r"[\x00-\x1f\x7f-\x9f]")
VIEWS = ("important", "all", "anomalies")
PALETTE = {
    Severity.DEBUG: "green",
    Severity.INFO: "bright_green",
    Severity.WARN: "bright_yellow",
    Severity.ERROR: "bright_red",
    Severity.CRITICAL: "bold bright_red",
}


def label(en, pt):
    return pt if current_lang() == "pt" else en


def severity_name(level):
    return level.name if level == Severity.DEBUG else _("sev." + level.name)


def effective_level(event, alerts):
    raw_level = Severity.INFO if isinstance(event, SignalEvent) else event.severity
    visible = (presentation_severity(alert) for alert in alerts if not hidden_by_priority(alert))
    return max(raw_level, max(visible, default=raw_level))


def view_name(view):
    return {
        "important": label("Important", "Importantes"),
        "all": label("All events", "Todos os eventos"),
        "anomalies": label("Anomalies", "Anomalias"),
    }[view]


def _cycle(options, value, direction):
    return options[(options.index(value) + direction) % len(options)]


def _clean(value):
    return CONTROLS.sub(" ", str(value))


class ViewFilter:
    def __init__(self, config, view=None, min_level=None, sources=(), grep=None, ip=None,
                 ignore=()):
        self.view = view or ("anomalies" if config.only_anomalies else config.view)
        self.min_level = Severity.parse(min_level or config.min_level)
        self.sources = frozenset(sources)
        self.grep = self.compile(grep) if grep else None
        self.ip = ip
        self.ignore = tuple(self.compile(pattern) for pattern in (*config.ignore_patterns, *ignore))

    @property
    def ip(self):
        return str(self._address) if self._address is not None else None

    @ip.setter
    def ip(self, value):
        try:
            self._address = ip_address(value) if value else None
        except ValueError as exc:
            raise ValueError(label("Invalid IP address", "Endereço IP inválido")) from exc

    def _matches_address(self, value):
        if value is None:
            return False
        try:
            return ip_address(value) == self._address
        except ValueError:
            return False

    @staticmethod
    def compile(pattern):
        return re.compile(pattern, re.I)

    def matches(self, event, alerts):
        if self.sources and event.source not in self.sources and not any(
            self.sources.intersection(alert.sources_matched) for alert in alerts
        ):
            return False
        if self._address is not None and not (
            self._matches_address(event.src_ip) or self._matches_address(event.dst_ip)
        ):
            return False
        if self.grep and not self.grep.search(event.message):
            return False
        if any(pattern.search(event.message) for pattern in self.ignore):
            return False
        level = effective_level(event, alerts)
        visible_alert = any(not hidden_by_priority(alert) for alert in alerts)
        if self.view == "anomalies" and not visible_alert:
            return False
        if self.view == "important" and not visible_alert and level < Severity.WARN:
            return False
        return level >= self.min_level

    @classmethod
    def for_profile(cls, config, name, **overrides):
        preset = config.profiles.get(name, {})
        return cls(
            config, overrides.get("view") or preset.get("view"),
            overrides.get("min_level") or preset.get("level"),
            overrides.get("sources") or preset.get("sources", ()),
            overrides.get("grep") or preset.get("grep"), overrides.get("ip") or preset.get("ip"),
            (*preset.get("ignore", ()), *overrides.get("ignore", ())),
        )


def _alert_text(alert):
    message = alert.localized_reason(current_lang())
    if alert.suggested_actions:
        actions = ", ".join(alert.suggested_actions)
        message += f" [{label('suggested', 'sugerido')}: {actions}]"
    for item in alert.triage:
        if item["action"] == "human_review":
            message += " · " + label("Human review required", "Revisão humana necessária")
        elif item["action"] == "group":
            message += f" · {label('Incident', 'Incidente')} {item['incident_id']}"
    return Text(_clean(message), style=PALETTE[presentation_severity(alert)])


def _display_alerts(alerts):
    visible = [alert for alert in alerts if not hidden_by_priority(alert)]
    superseded = {rule for alert in visible for rule in alert.supersedes}
    return sorted(
        (alert for alert in visible if alert.rule_id not in superseded),
        key=lambda alert: (bool(alert.evidence), presentation_severity(alert)),
        reverse=True,
    )


def event_row(event, alerts):
    level = effective_level(event, alerts)
    message = Text()
    for alert in _display_alerts(alerts):
        if message:
            message.append("  ·  ", "dim")
        message.append_text(_alert_text(alert))
    if message:
        message.append("  ·  ", "dim")
    message.append(_clean(event.message))
    return (
        Text(short_ts(event.ts), style="dim"),
        Text(severity_name(level), style=PALETTE[level]),
        Text(_("src." + event.source), style="cyan"),
        message,
    )


@dataclass(frozen=True)
class PulseSample:
    count: int = 0
    severity: Severity = Severity.INFO


def pulse_trace(activity, width):
    """Draw event volume vertically and color each sample by its highest severity."""
    samples = list(activity)[-width:]
    peak = max((sample.count for sample in samples), default=1) or 1
    top, bottom = Text(), Text()
    dots = ((1, 2, 4, 64), (8, 16, 32, 128))
    previous = 7
    for sample in samples:
        current = 7 - round(sample.count * 7 / peak)
        cells = [0, 0]
        for dot in range(min(previous, current), max(previous, current) + 1):
            cells[dot // 4] |= dots[0][dot % 4]
        cells[current // 4] |= dots[1][current % 4]
        style = PALETTE[sample.severity]
        top.append(chr(0x2800 + cells[0]), style)
        bottom.append(chr(0x2800 + cells[1]), style)
        previous = current
    return Text.assemble(top, "\n", bottom)


def severity_counters(counts):
    """Show all severities, including levels with zero events."""
    return Columns(
        [
            Text(f" {level.name} {counts.get(level, 0)} ", style=PALETTE[level] + " on grey15")
            for level in reversed(Severity)
        ],
        padding=(0, 1),
    )


class Dashboard:
    def __init__(self, config, filters):
        self.config = config
        self.filters = filters
        self.frozen = None
        self.selection = 0
        self.modal = None
        self.details = None
        self.capacity = 8
        self.filter_cursor = 0
        self.source_cursor = 0
        self.ignore_cursor = 0
        self.profile_cursor = 0
        self.editor = None
        self.draft = ""
        self.error = None

    def _entries(self, recent):
        history = self.frozen if self.frozen is not None else recent
        seen = set()
        for event, alerts in reversed(history):
            if not self.filters.matches(event, alerts):
                continue
            if self.filters.view == "anomalies":
                visible = _display_alerts(alerts)
                incidents = [next((item["incident_id"] for item in alert.triage
                                   if item["action"] == "group"), None) for alert in visible]
                if incidents and all(incident in seen for incident in incidents):
                    continue
                seen.update(incident for incident in incidents if incident is not None)
            yield event, alerts

    def handle(self, key, recent):
        if self.editor:
            self._edit(key)
            return True
        if key in ("i", "I"):
            set_lang("en" if current_lang() == "pt" else "pt")
            return True
        if key == "esc" and self.modal:
            self.modal = None
            return True
        if self.modal == "filters":
            self._filter_key(key)
            return True
        if self.modal:
            return True
        if key in ("q", "Q"):
            return False
        if key in ("left", "right"):
            self.frozen = None
            self.filters.view = _cycle(VIEWS, self.filters.view, 1 if key == "right" else -1)
            self.selection = 0
        if key in ("1", "2", "3"):
            self.frozen = None
            self.filters.view = VIEWS[int(key) - 1]
            self.selection = 0
        if key in ("f", "F", "/", "l", "s"):
            self.modal = "filters"
            if key in ("l", "s"):
                self.filter_cursor = self._fields().index({"l": "level", "s": "source"}[key])
            if key == "/":
                self.filter_cursor = self._fields().index("grep")
                self._filter_key("enter")
        if key == "?":
            self.modal = "help"
        if key in ("c", "C"):
            self.modal = "collectors"
        if key in ("esc", "home") or (key == " " and self.frozen is not None):
            self.frozen = None
            self.selection = 0
        elif key in ("up", "down", "pageup", "pagedown", " "):
            self._navigate(key, recent)
        if key == "enter":
            self.details = next(islice(self._entries(recent), self.selection, None), None)
            if self.details:
                self.modal = "details"
        return True

    def _navigate(self, key, recent):
        if self.frozen is None:
            self.frozen = tuple(recent)
            if key == " ":
                return
        step = {"up": -1, "down": 1, "pageup": -self.capacity,
                "pagedown": self.capacity, " ": 0}[key]
        last = sum(1 for _ in self._entries(recent)) - 1
        self.selection = max(0, min(last, self.selection + step))

    def _fields(self):
        return ("level", "source", "grep", "ip", "ignore") + (
            ("profile",) if self.config.profiles else ()
        )

    def _filter_key(self, key):
        self.error = None
        fields = self._fields()
        if key in ("up", "down"):
            self.filter_cursor = (self.filter_cursor + (1 if key == "down" else -1)) % len(fields)
        field = fields[self.filter_cursor]
        direction = {"left": -1, "right": 1}.get(key, 0)
        if field == "level" and (direction or key == "enter"):
            self.filters.min_level = _cycle(list(Severity), self.filters.min_level, direction or 1)
        elif field == "source":
            self.source_cursor = (self.source_cursor + direction) % len(SOURCES)
            if key == "enter":
                self.filters.sources ^= {SOURCES[self.source_cursor]}
            elif key == "delete":
                self.filters.sources = frozenset()
        elif field == "profile":
            names = sorted(self.config.profiles)
            self.profile_cursor = (self.profile_cursor + direction) % len(names)
            if key == "enter":
                try:
                    self.filters = ViewFilter.for_profile(self.config, names[self.profile_cursor])
                    self.frozen = None
                    self.selection = 0
                    self.ignore_cursor = 0
                except re.error:
                    self.error = label("Invalid regular expression in profile",
                                       "Expressão regular inválida no perfil")
                except ValueError as exc:
                    self.error = str(exc)
        elif field == "ignore":
            patterns = self.filters.ignore
            self.ignore_cursor = (self.ignore_cursor + direction) % max(1, len(patterns))
            if key == "delete" and patterns:
                index = self.ignore_cursor
                self.filters.ignore = patterns[:index] + patterns[index + 1:]
                self.ignore_cursor = min(index, max(0, len(self.filters.ignore) - 1))
            elif key == "enter":
                self.editor, self.draft = field, ""
        elif field in ("grep", "ip") and key == "delete":
            setattr(self.filters, field, None)
        elif key == "enter":
            self.editor = field
            value = getattr(self.filters, field)
            self.draft = value.pattern if field == "grep" and value else value or ""
        self.selection = 0

    def _edit(self, key):
        if key == "esc":
            self.editor = self.error = None
        elif key == "backspace":
            self.draft = self.draft[:-1]
        elif key == "clear":
            self.draft = ""
        elif key == "enter":
            value = self.draft.strip() if self.editor == "ip" else self.draft
            if self.editor == "ip":
                try:
                    self.filters.ip = value or None
                except ValueError as exc:
                    self.error = str(exc)
                    return
            else:
                try:
                    pattern = self.filters.compile(value) if value else None
                except re.error:
                    self.error = label("Invalid regular expression", "Expressão regular inválida")
                    return
                if self.editor == "grep":
                    self.filters.grep = pattern
                elif pattern:
                    self.filters.ignore += (pattern,)
                    self.ignore_cursor = len(self.filters.ignore) - 1
            self.editor = self.error = None
        elif len(key) == 1 and key.isprintable() and len(self.draft) < 2048:
            self.draft += key

    def render(self, console, manager, recent, activity, counts, alerts, recording):
        header = self._header(console, manager, activity, counts, alerts, recording)
        if self.modal == "filters":
            return Group(header, self._filter_panel())
        if self.modal == "details":
            return Group(header, self._detail_panel(console.height))
        if self.modal == "help":
            return Group(header, self._help_panel())
        if self.modal == "collectors":
            return Group(header, self._collectors_panel(manager))
        return Group(header, self._event_panel(console, recent), self._footer())

    def _header(self, console, manager, activity, counts, alerts, recording):
        stats = manager.stats()
        level = max((sample.severity for sample in activity[-5:]), default=Severity.INFO)
        style = PALETTE[level]
        status = {
            Severity.INFO: label("NORMAL", "NORMAL"),
            Severity.WARN: label("ATTENTION", "ATENÇÃO"),
            Severity.ERROR: label("HIGH", "ALTO"),
            Severity.CRITICAL: label("CRITICAL", "CRÍTICO"),
        }.get(level, "NORMAL")
        title = Text.assemble(("✚  VitaisK", "bold white"), ("    ● " + status, style))
        counters = Text.assemble(
            (label("EVENT PULSE", "PULSO DE EVENTOS"), "bold " + PALETTE[level].removeprefix("bold ")),
            (f"    {sum(counts.values())} " + label("events", "eventos"), "white"),
            (f"    {alerts} " + label("alerts", "alertas"), "white"),
        )
        dropped = stats["queue"]["dropped"]
        if dropped:
            counters.append(f"    {dropped} " + label("dropped", "perdidos"), "bright_red")
        if recording:
            counters.append("    ● REC", "bright_red")
        measurements = Text()
        vitals = next((c.vitals for c in manager.collectors if isinstance(c, MetricsCollector)), None)
        if vitals is not None:
            for name, value in zip(("CPU", "RAM", label("DISK", "DISCO")), vitals):
                if value is not None:
                    color = "bright_red" if value >= 95 else "bright_yellow" if value >= 85 else "bright_green"
                    measurements.append(f"{name} ", "bold white")
                    measurements.append(f"{value:3.0f}%   ", color)
        active = sum(collector["alive"] for collector in stats["collectors"])
        available = len(stats["collectors"])
        measurements.append(label("Collectors ", "Coletores ") + f"{active}/{available}",
                            "cyan" if active else "bright_yellow")
        trace = pulse_trace(activity, max(1, console.width - 6))
        return Panel(Group(counters, trace, severity_counters(counts), measurements),
                     title=title, title_align="left",
                     border_style=style, box=box.ROUNDED)

    def _event_panel(self, console, recent):
        tabs = Text()
        for number, view in enumerate(VIEWS, start=1):
            style = "bold black on bright_cyan" if self.filters.view == view else "dim"
            tabs.append(f" {number} {view_name(view)} ", style)
            tabs.append(" ")
        if self.frozen is not None:
            tabs.append(label("  HISTORY", "  HISTÓRICO"), "bold bright_yellow")

        table = Table(expand=True, box=box.SIMPLE_HEAD, header_style="bold cyan", pad_edge=False)
        table.add_column("", width=1, no_wrap=True)
        table.add_column(label("Time", "Hora"), no_wrap=True)
        table.add_column(label("Level", "Nível"), no_wrap=True)
        table.add_column(label("Source", "Fonte"), no_wrap=True)
        table.add_column(label("Event / alert", "Evento / alerta"), overflow="ellipsis",
                         no_wrap=True, ratio=1)
        self.capacity = max(1, console.height - (17 if console.width >= 54 else 18))
        start = max(0, self.selection - self.capacity + 1)
        count = 0
        for index, (event, alerts) in enumerate(
            islice(self._entries(recent), start, start + self.capacity), start
        ):
            selected = index == self.selection
            table.add_row(
                Text("›" if selected else "", style="bold bright_cyan"), *event_row(event, alerts),
                style="on grey15" if selected else None,
            )
            count += 1
        body = table if count else Text(
            label("Waiting for events matching the filters…", "Aguardando eventos que correspondam aos filtros…"),
            "dim",
        )
        sources = ", ".join(_("src." + s) for s in sorted(self.filters.sources)) or label("all sources", "todas as fontes")
        summary = [severity_name(self.filters.min_level) + "+", sources]
        if self.filters.grep:
            summary.append("/" + self.filters.grep.pattern + "/")
        if self.filters.ip:
            summary.append(self.filters.ip)
        if self.filters.ignore:
            summary.append(label("excluded ", "exclusões ") + str(len(self.filters.ignore)))
        return Panel(Group(tabs, body, Text(_clean(" · ".join(summary)), "dim", no_wrap=True,
                                           overflow="ellipsis")), border_style="grey42", box=box.ROUNDED)

    def _footer(self):
        nav = label("←→ Views   ↑↓ Browse   Enter Details", "←→ Visões   ↑↓ Navegar   Enter Detalhes")
        actions = label("F Filters   Space Freeze/Live   I Language   ? Help   Q Quit",
                        "F Filtros   Espaço Histórico/Ao vivo   I Idioma   ? Ajuda   Q Sair")
        return Text.assemble((nav, "cyan"), "\n", (actions, "white"))

    def _filter_panel(self):
        patterns = self.filters.ignore
        ignored = (_clean(patterns[self.ignore_cursor].pattern) if patterns else "—")
        if patterns:
            ignored = f"{self.ignore_cursor + 1}/{len(patterns)}  {ignored}"
        source = SOURCES[self.source_cursor]
        chosen = ", ".join(_("src." + s) for s in sorted(self.filters.sources)) or label("all", "todas")
        values = {
            "level": (label("Minimum level", "Nível mínimo"), severity_name(self.filters.min_level)),
            "source": (label("Sources", "Fontes"), f"{chosen}   ‹ {_('src.' + source)} ›"),
            "grep": (label("Message regex", "Regex da mensagem"), self.filters.grep.pattern if self.filters.grep else "—"),
            "ip": (label("IP address", "Endereço IP"), self.filters.ip or "—"),
            "ignore": (label("Excluded regex", "Regex de exclusão"), ignored),
        }
        if self.config.profiles:
            values["profile"] = (label("Apply profile", "Aplicar perfil"), sorted(self.config.profiles)[self.profile_cursor])
        table = Table.grid(expand=True, padding=(0, 1))
        table.add_column(no_wrap=True)
        table.add_column(ratio=1, no_wrap=True, overflow="ellipsis")
        for index, (name, value) in enumerate(values.values()):
            active = index == self.filter_cursor
            table.add_row(Text(("› " if active else "  ") + name, "bold cyan" if active else ""),
                          Text(_clean(value)))
        if self.editor:
            footer = Group(
                Text(_clean(self.draft[-100:]) + "▏", "bold bright_cyan"),
                Text(label("Enter Apply   Ctrl+U Clear text   Esc Cancel",
                           "Enter Aplicar   Ctrl+U Limpar texto   Esc Cancelar"), "dim"),
            )
        else:
            footer = Text(label("↑↓ Field   ←→ Options   Enter Select/edit   Del Remove/clear   Esc Back",
                                "↑↓ Campo   ←→ Opções   Enter Selecionar/editar   Del Remover/limpar   Esc Voltar"), "dim")
        body = [table, footer]
        if self.error:
            body.append(Text(self.error, "bright_red"))
        return Panel(Group(*body), title=label("Filters", "Filtros"),
                     border_style="bright_cyan", box=box.ROUNDED)

    def _detail_panel(self, height):
        event, alerts = self.details
        time, level, source, _message = event_row(event, alerts)
        metadata = Text.assemble(time, "  ", level, "  ", source, "  ", _clean(event.category))
        addresses = " → ".join(address for address in (event.src_ip, event.dst_ip) if address)
        group = [metadata, Text(_clean(" · ".join(v for v in (event.host, event.user, addresses) if v)), "dim")]
        for alert in _display_alerts(alerts)[:max(1, (height - 15) // 2)]:
            sources = ", ".join(_("src." + source) for source in alert.sources_matched)
            group.extend((_alert_text(alert), Text(
                f"{label('Evidence', 'Evidências')}: {alert.event_count} · {sources} · "
                f"{label('confidence', 'confiança')} {alert.confidence:.0%}", "dim",
            )))
        group.extend((Text(_clean(event.message[:300]), "white"),
                      Text(label("Esc Back", "Esc Voltar"), "dim")))
        return Panel(Group(*group), title=label("Event details", "Detalhes do evento"),
                     border_style="bright_cyan", box=box.ROUNDED)

    def _help_panel(self):
        body = label(
            "← → or 1–3   Switch view\n↑ ↓ / Page keys   Browse a snapshot while monitoring continues\n"
            "Enter   Inspect event and correlated evidence\nSpace / Home   Return to live view\n"
            "F   Filters    /   Search message    C   Collectors\nI   Switch language for this session\nEsc   Back",
            "← → ou 1–3   Trocar de visão\n↑ ↓ / Page Up e Page Down   Navegar no histórico com a coleta ativa\n"
            "Enter   Abrir evento e evidências correlacionadas\nEspaço / Home   Voltar ao vivo\n"
            "F   Filtros    /   Buscar na mensagem    C   Coletores\nI   Trocar o idioma desta sessão\nEsc   Voltar",
        )
        return Panel(Text(body), title=label("Keyboard shortcuts", "Atalhos"),
                     border_style="bright_cyan", box=box.ROUNDED)

    def _collectors_panel(self, manager):
        rows = []
        for collector in manager.stats()["collectors"]:
            alive = collector["alive"]
            state = label("active", "ativo") if alive else label("inactive", "inativo")
            row = Text.assemble(
                ("● " + state, "bright_green" if alive else "bright_yellow"),
                "   ", (collector["name"], "bold"), f"   {collector['events']}",
            )
            if collector.get("rejected"):
                row.append(f"   {collector['rejected']} " + label("rejected", "rejeitados"),
                           "bright_yellow")
            if collector["error"]:
                row.append("   " + _clean(collector["error"]), "bright_red")
            rows.append(row)
        if not rows:
            rows.append(Text(label("No collectors available", "Nenhum coletor disponível"), "dim"))
        rows.append(Text(label("Esc Back", "Esc Voltar"), "dim"))
        return Panel(Group(*rows), title=label("Collectors", "Coletores"),
                     border_style="bright_cyan", box=box.ROUNDED)
