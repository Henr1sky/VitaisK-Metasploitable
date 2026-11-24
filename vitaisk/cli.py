"""VitaisK CLI entry point.

Command map:
  vitaisk watch          live monitoring (dashboard or stream)       [P2–P4]
  vitaisk summary        summary of a saved session                  [P4]
  vitaisk capture        on-demand packet capture → .pcap            [P4]
  vitaisk export         export a session to JSON or CSV             [P4]
  vitaisk sessions       list / show / prune / rm saved sessions     [P4]
  vitaisk rules          list / show / test detection rules          [P3]
  vitaisk config         show / path / edit / set / reset            [P1]
  vitaisk doctor         dependency & privilege check                [P1]
  vitaisk version        print version                               [P1]
"""
from __future__ import annotations

import csv
import json
import os
import re
import platform
import sys
from pathlib import Path
from functools import partial

import click
from rich.console import Console
from rich.table import Table

from . import __version__
from .cli_help import LocalizedGroup, LocalizedOption
from .config import Config
from .events import SOURCES
from .i18n import _, set_lang, current_lang, SUPPORTED
from . import sessions
from .utils import is_root, which, humanize_bytes, parse_size

console = Console()
err_console = Console(stderr=True)
option = partial(click.option, cls=LocalizedOption)


# ── helpers ────────────────────────────────────────────────────────
def _apply_lang_from_argv() -> None:
    """Extract --lang before Click parses so i18n strings are ready."""
    argv = sys.argv[1:]
    for i, arg in enumerate(argv):
        if arg == "--lang" and i + 1 < len(argv):
            try:
                set_lang(argv[i + 1])
            except ValueError:
                pass
            return
        if arg.startswith("--lang="):
            try:
                set_lang(arg.split("=", 1)[1])
            except ValueError:
                pass
            return


def _require_root() -> None:
    if not is_root():
        err_console.print(f"[red]✗[/] {_('app.requires_root')}")
        sys.exit(2)


def _not_implemented(part: str) -> None:
    err_console.print(f"[yellow]·[/] {_('app.not_implemented', part=part)}")
    sys.exit(0)


def _load_config(ctx: click.Context, lang: str, config_path: str | None) -> Config:
    cfg = Config.load(Path(config_path) if config_path else None)
    set_lang(lang if lang and lang != "auto" else cfg.lang)
    return cfg


# ── top-level group ────────────────────────────────────────────────
@click.group(cls=LocalizedGroup, context_settings={"help_option_names": ["-h", "--help"]})
@option(
    "--lang", type=click.Choice(["auto", *SUPPORTED]), default="auto", show_default=True,
    help="Interface language / Idioma da interface",
)
@option(
    "--config", "config_path", type=click.Path(dir_okay=False, path_type=str),
    help="Specify a configuration file.",
)
@click.version_option(__version__, "-V", "--version", prog_name="vitaisk")
@click.pass_context
def cli(ctx: click.Context, lang: str, config_path: str | None) -> None:
    """VitaisK — multi-parameter vital signs monitor for Linux."""
    ctx.ensure_object(dict)
    if lang == "auto":
        try:
            cfg = Config.load(Path(config_path) if config_path else None, create=False)
            set_lang(cfg.lang)
        except (OSError, ValueError, AttributeError):
            set_lang("auto")
    else:
        set_lang(lang)
    ctx.obj["lang"] = lang
    ctx.obj["config_path"] = config_path


# ── version ────────────────────────────────────────────────────────
@cli.command("version")
@click.pass_context
def cmd_version(ctx: click.Context) -> None:
    """Print VitaisK version and environment."""
    lang = ctx.obj.get("lang", "auto") if ctx.obj else "auto"
    set_lang(lang)
    click.echo(f"vitaisk {__version__}")
    click.echo(f"  python : {platform.python_version()}")
    click.echo(f"  kernel : {platform.release()}")
    click.echo(f"  arch   : {platform.machine()}")
    click.echo(f"  root   : {'yes' if is_root() else 'no'}")
    click.echo(f"  lang   : {current_lang()}")


# ── doctor ─────────────────────────────────────────────────────────
@cli.command("doctor")
@click.pass_context
def cmd_doctor(ctx: click.Context) -> None:
    """Check dependencies, privileges, and paths."""
    cfg = _load_config(ctx, ctx.obj["lang"], ctx.obj["config_path"])

    table = Table(title=f"VitaisK · {_('doctor.title')}", show_lines=False)
    table.add_column(_("doctor.check"), style="bold")
    table.add_column(_("doctor.status"))
    table.add_column(_("doctor.detail"), style="dim")

    optional = {
        "journalctl": _("src.system"),
        "ss": _("src.network"),
        "tcpdump": _("capture.collector"),
    }
    audit_path = Path(cfg.audit_log_path)
    audit_ok = audit_path.is_file() and os.access(audit_path, os.R_OK)
    if audit_ok:
            optional["auditctl"] = "audit"
    else:
            table.add_row(
                "auditd",
                f"[dim]{_('doctor.optional')}[/]",
                _("doctor.audit_unavailable"),
        )

    ok = opt_missing = 0
    for cmd, purpose in optional.items():
        path = which(cmd)
        if path:
            table.add_row(cmd, f"[green]{_('doctor.ok')}[/]", path)
            ok += 1
        else:
            table.add_row(cmd, f"[yellow]{_('doctor.optional')}[/]", purpose)
            opt_missing += 1

    root_label = _("doctor.root_yes") if is_root() else _("doctor.root_no")
    root_color = "green" if is_root() else "yellow"
    table.add_row(_("doctor.root"), f"[{root_color}]{root_label}[/]", "")

    table.add_row(_("doctor.python"), f"[green]{platform.python_version()}[/]", "")
    table.add_row(_("doctor.distro"), f"[green]{platform.platform(terse=True)}[/]", "")
    table.add_row(_("doctor.kernel"), f"[green]{platform.release()}[/]", "")

    cfg.ensure_dirs()
    table.add_row(_("config.path"), f"[green]{cfg.path()}[/]", "")
    table.add_row(_("config.data"), f"[green]{cfg.data_path()}[/]",
                  humanize_bytes(_dir_size(cfg.data_path())))

    console.print(table)
    console.print(
        f"[dim]{_('doctor.summary', ok=ok, missing=0, optional=opt_missing)}[/]"
    )


def _dir_size(path: Path) -> int:
    total = 0
    for root, _dirs, files in os.walk(path, followlinks=False):
        for name in files:
            try:
                total += (Path(root) / name).stat().st_size
            except OSError:
                pass
    return total


# ── config ─────────────────────────────────────────────────────────
@cli.group("config")
def cmd_config() -> None:
    """Inspect and modify configuration."""


@cmd_config.command("path")
@click.pass_context
def config_path(ctx: click.Context) -> None:
    """Print config and data directory paths."""
    cfg = _load_config(ctx, ctx.obj["lang"], ctx.obj["config_path"])
    click.echo(str(ctx.obj["config_path"] or cfg.path()))
    click.echo(str(cfg.data_path()))


@cmd_config.command("show")
@click.pass_context
def config_show(ctx: click.Context) -> None:
    """Print effective configuration."""
    cfg = _load_config(ctx, ctx.obj["lang"], ctx.obj["config_path"])
    import yaml
    from dataclasses import asdict
    click.echo(yaml.safe_dump(asdict(cfg), sort_keys=True, allow_unicode=True))


@cmd_config.command("set")
@click.argument("key")
@click.argument("value")
@click.pass_context
def config_set(ctx: click.Context, key: str, value: str) -> None:
    """Set a dotted config key, e.g. `vitaisk config set sensitivity high`."""
    cfg = _load_config(ctx, ctx.obj["lang"], ctx.obj["config_path"])
    try:
        cfg.set(key, value)
    except KeyError:
        err_console.print(f"[red]✗[/] {_('config.unknown_key', key=key)}")
        sys.exit(2)
    except ValueError as e:
        err_console.print(f"[red]✗[/] {_('config.invalid_value', key=key, value=value)}: {e}")
        sys.exit(2)
    path = cfg.save(Path(ctx.obj["config_path"]) if ctx.obj["config_path"] else None)
    console.print(f"[green]✓[/] {_('config.saved', path=path)}")


@cmd_config.command("reset")
@click.confirmation_option(prompt="Reset config to defaults?")
@click.pass_context
def config_reset(ctx: click.Context) -> None:
    """Restore configuration to defaults."""
    cfg = _load_config(ctx, ctx.obj["lang"], ctx.obj["config_path"])
    cfg.reset()
    path = cfg.save(Path(ctx.obj["config_path"]) if ctx.obj["config_path"] else None)
    console.print(f"[green]✓[/] {_('config.reset')} ({path})")


def _lab_endpoint(command):
    command = option("--lab-user", default="msfadmin", show_default=True,
                     help="VM SSH username.")(command)
    command = option("--lab-bind", default="192.168.56.102", show_default=True,
                     help="Kali lab IPv4 address.")(command)
    return option("--lab-host", default="192.168.56.101", show_default=True,
                  help="VM IPv4 address.")(command)


@cli.command("lab-doctor")
@_lab_endpoint
def cmd_lab_doctor(lab_host, lab_bind, lab_user):
    """Check SSH, disk state and log access for Metasploitable 2."""
    from .metasploitable import lab_doctor

    try:
        lab_doctor(lab_host, lab_bind, lab_user)
    except (OSError, ValueError) as exc:
        raise click.ClickException(str(exc)) from exc


# ── watch ──────────────────────────────────────────────────────────
@cli.command("watch")
@option("--mode", type=click.Choice(["dashboard", "stream"]), default=None,
              help="UI mode (overrides config).")
@option("--signal-file", "signal_files", multiple=True,
        type=click.Path(dir_okay=False, readable=True, path_type=Path),
        help="Follow a trusted JSONL file of observations or classified signals. Repeatable.")
@option("--profile", help="Use a named filter profile from config.")
@option("--view", type=click.Choice(["important", "all", "anomalies"]),
        help="Select which events to display.")
@option("--only-anomalies", is_flag=True, default=None,
              help="Show only alerts flagged as anomalies.")
@option("--level", "min_level",
              type=click.Choice(["DEBUG", "INFO", "WARN", "ERROR", "CRITICAL"]),
              default=None, help="Minimum severity to display.")
@option("--source", "sources", multiple=True,
              type=click.Choice(["system", "network", "metrics", "audit", "kernel", "auth", "firewall"]),
              help="Limit to these sources (repeatable).")
@option("--grep", "grep", default=None, help="Only show events matching this regex.")
@option("--ip", "ip", default=None, help="Only show events involving this IP.")
@option("--ignore", "ignore", multiple=True, help="Regex of lines to ignore (repeatable).")
@option("--sensitivity", type=click.Choice(["low", "medium", "high"]), default=None)
@option("--save/--no-save", "save", default=None,
              help="Write the session during monitoring (default from config).")
@option("--metasploitable", is_flag=True, help="Use the isolated Metasploitable 2 VM over SSH.")
@option("--lab-packets", is_flag=True, help="Show inbound TCP SYN, UDP and ping on the VM (requires VM sudo).")
@_lab_endpoint
@click.pass_context
def cmd_watch(ctx: click.Context, metasploitable, lab_packets, lab_host, lab_bind, lab_user, **opts) -> None:
    """Live monitoring. Press Ctrl+C to stop."""
    from .watch import watch

    try:
        cfg = _load_config(ctx, ctx.obj["lang"], ctx.obj["config_path"])
        if lab_packets and not metasploitable:
            raise ValueError("--lab-packets requires --metasploitable")
        if lab_packets and not sys.stdin.isatty():
            raise ValueError("--lab-packets requires an interactive terminal for VM sudo")
        if metasploitable:
            from .metasploitable import lab_manager

            with lab_manager(cfg, lab_host, lab_bind, lab_user, packets=lab_packets) as manager:
                saved = watch(cfg, console, manager=manager,
                              baseline_name=f"baseline-lab-{lab_host}.json", **opts)
        else:
            saved = watch(cfg, console, **opts)
    except (OSError, ValueError, re.error) as exc:
        raise click.ClickException(str(exc)) from exc
    if saved:
        err_console.print(_("watch.saved_to", path=saved), markup=False)


# ── summary / capture / export / sessions / rules ─────────────────
@cli.command("summary")
@option("--session", default="latest", help="Session ID or 'latest'.")
@click.pass_context
def cmd_summary(ctx: click.Context, session: str) -> None:
    """Summarize a saved session."""
    path = _session_path(session)
    click.echo(json.dumps(sessions.summary(path), ensure_ascii=False, indent=2))


@cli.command("capture")
@option("--interface", "-i", default="any")
@option("--filter", "bpf", default="", help="BPF filter, e.g. 'host 1.2.3.4'.")
@option("--duration", "-d", default=None, type=str, help="e.g. 60, 30s, 2m.")
@option("--output", "-o", default=None, type=click.Path(dir_okay=False))
@option("--max-size", default=None, type=str, help="e.g. 100M.")
@click.pass_context
def cmd_capture(ctx: click.Context, **opts) -> None:
    """Capture packets to a .pcap file (on demand)."""
    from .capture import capture

    try:
        cfg = _load_config(ctx, ctx.obj["lang"], ctx.obj["config_path"])
        path = capture(cfg, **opts)
    except (OSError, ValueError, OverflowError) as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(_("capture.done", path=path, size=humanize_bytes(path.stat().st_size)))


@cli.command("export")
@option("--session", default="latest")
@option("--format", "fmt", type=click.Choice(["json", "csv"]), default="json")
@option("--output", "-o", default=None, type=click.Path(dir_okay=False))
@click.pass_context
def cmd_export(ctx: click.Context, session: str, fmt: str, output: str | None) -> None:
    """Export a session to JSON or CSV."""
    path = _session_path(session)
    if output and Path(output).exists() and Path(output).samefile(path):
        raise click.ClickException(_("export.same_file"))
    with click.open_file(output or "-", mode="w", encoding="utf-8", atomic=bool(output and output != "-")) as handle:
        if fmt == "json":
            handle.write("[")
            for index, row in enumerate(sessions.records(path)):
                if index:
                    handle.write(",")
                handle.write("\n" + json.dumps(row, ensure_ascii=False))
            handle.write("\n]\n")
        else:
            from .events import Event

            fields = [*Event.__dataclass_fields__, "severity_name", "anomalies"]
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            for row in sessions.records(path):
                row["extra"] = json.dumps(row["extra"], ensure_ascii=False)
                row["anomalies"] = json.dumps(row.get("anomalies", []), ensure_ascii=False)
                writer.writerow(row)


def _session_dir() -> Path:
    return Config.data_path() / "sessions"


def _session_path(name: str) -> Path:
    try:
        return sessions.resolve(_session_dir(), name)
    except FileNotFoundError as exc:
        raise click.ClickException(f"{_('sessions.not_found')}: {name}") from exc


@cli.group("sessions")
def cmd_sessions() -> None:
    """Manage saved sessions."""


@cmd_sessions.command("list")
def sessions_list() -> None:
    """List saved sessions."""
    paths = sessions.session_files(_session_dir())
    if not paths:
        click.echo(_("sessions.empty"))
    for path in reversed(paths):
        click.echo(f"{sessions.session_id(path)}  {humanize_bytes(path.stat().st_size)}")


@cmd_sessions.command("show")
@click.argument("session_id")
def sessions_show(session_id: str) -> None:
    """Show session metadata."""
    path = _session_path(session_id)
    info = {"size_bytes": path.stat().st_size, **sessions.summary(path)}
    click.echo(json.dumps(info, ensure_ascii=False, indent=2))


@cmd_sessions.command("prune")
@option("--keep", type=click.IntRange(min=0), default=None, help="Keep only N most recent.")
@option("--max-size", type=str, default=None, help="Prune until total size <= X.")
def sessions_prune(keep: int | None, max_size: str | None) -> None:
    """Delete old sessions."""
    if keep is None and max_size is None:
        raise click.UsageError(_("sessions.prune_limit"))
    try:
        max_bytes = parse_size(max_size) if max_size else None
    except ValueError as exc:
        raise click.BadParameter(str(exc), param_hint="--max-size") from exc
    if max_bytes is not None and max_bytes < 0:
        raise click.BadParameter(_("sessions.prune_limit"), param_hint="--max-size")
    removed = sessions.prune(_session_dir(), keep=keep, max_bytes=max_bytes)
    click.echo(_("sessions.removed", count=removed))


@cmd_sessions.command("rm")
@click.argument("session_id")
@click.confirmation_option(prompt="Delete this session?")
def sessions_rm(session_id: str) -> None:
    """Delete a session."""
    _session_path(session_id).unlink()
    click.echo(_("sessions.removed", count=1))


def _rules():
    from .rules.loader import load_rules

    try:
        return load_rules()
    except (OSError, ValueError) as exc:
        raise click.ClickException(str(exc)) from exc


@cli.group("rules")
def cmd_rules() -> None:
    """Inspect detection rules."""


@cmd_rules.command("list")
def rules_list() -> None:
    """List available detection rules."""
    for rule_id in _rules():
        click.echo(rule_id)


@cmd_rules.command("correlations")
def rules_correlations() -> None:
    """List executable correlations and their input requirements."""
    from .rules.loader import load_correlations, rule_input

    rules = _rules()
    for entry in load_correlations():
        signals = entry["requires"]
        external = [signal for signal in signals if rule_input(rules.get(signal)) == "external"]
        structured = [signal for signal in signals if rule_input(rules.get(signal)) == "structured"]
        if external:
            status = "external classification: " + ", ".join(external)
        elif structured:
            status = "structured telemetry: " + ", ".join(structured)
        elif entry["requires_scope"]:
            status = "shared scope required"
        else:
            status = "native"
        click.echo(f"{entry['id']}  {status}")


@cmd_rules.command("coverage")
def rules_coverage() -> None:
    """List native and externally supplied detection identifiers."""
    from .rules.loader import load_correlations, rule_input, signal_levels

    rules = _rules()
    for rule_id in sorted(signal_levels(rules, load_correlations())):
        click.echo(f"{rule_id}  {rule_input(rules.get(rule_id))}")


@cmd_rules.command("priorities")
def rules_priorities() -> None:
    """List alert triage policies."""
    from .rules.loader import load_priorities

    for rule in load_priorities():
        click.echo(f"{rule['id']}  {rule['action']}  {rule['when']}")


@cmd_rules.command("show")
@click.argument("rule_id")
def rules_show(rule_id: str) -> None:
    """Show a rule's definition."""
    import yaml
    from .rules.loader import load_correlations, load_priorities, signal_levels

    rules = _rules()
    correlations = load_correlations()
    rule = rules.get(rule_id) or next(
        (entry for entry in [*correlations, *load_priorities()] if entry["id"] == rule_id), None,
    )
    if rule is None:
        external = signal_levels(rules, correlations).get(rule_id)
        if external is None:
            raise click.ClickException(f"{_('rules.not_found')}: {rule_id}")
        rule = {"id": rule_id, "input": "external", **external}
    click.echo(yaml.safe_dump(rule, sort_keys=False, allow_unicode=True), nl=False)


@cmd_rules.command("test")
@option("--source", type=click.Choice(SOURCES), help="Source for an unstructured sample.")
@click.argument("sample")
def rules_test(sample: str, source: str | None) -> None:
    """Test a rule against a sample line."""
    from .engine.pipeline import Pipeline
    from .events import Event, make_event
    from .collectors.base import EventQueue
    from .collectors.journal import JournalCollector
    from .collectors.parsers import parse_auth_line, parse_kernel_line, parse_firewall_line

    journal = JournalCollector(EventQueue(1), Config())

    from .rules.loader import load_correlations, load_priorities, signal_levels
    from .telemetry import telemetry_from_record

    rules = _rules()
    correlations = load_correlations()
    allowed = signal_levels(rules, correlations)
    pipeline = Pipeline(rules, correlations=correlations, priorities=load_priorities())

    def parse(line):
        if line.lstrip().startswith("{"):
            data = json.loads(line)
            if not isinstance(data, dict):
                raise ValueError("expected a JSON object")
            if data.get("record_type") in ("event", "signal"):
                return telemetry_from_record(data, allowed, line)
            if "MESSAGE" in data:
                return journal._to_event(data)
            return Event.from_dict(data)
        for candidate, fields in (
            ("auth", parse_auth_line(line, "")),
            ("kernel", parse_kernel_line(line)),
            ("firewall", parse_firewall_line(line)),
        ):
            if fields and source in (None, candidate):
                return make_event(source=candidate, message=line, **fields)
        return make_event(source=source or "system", category="raw", severity="INFO", message=line)

    lines = click.get_text_stream("stdin") if sample == "-" else [sample]
    try:
        for line in lines:
            if line.strip():
                event = parse(line.rstrip("\n"))
                if event is not None:
                    for anomaly in pipeline.process(event, current_lang()):
                        click.echo(json.dumps(anomaly.to_dict(), ensure_ascii=False))
    except (KeyError, TypeError, ValueError, RecursionError) as exc:
        raise click.ClickException(str(exc)) from exc


# ── main ───────────────────────────────────────────────────────────
def main(argv: list[str] | None = None) -> None:
    _apply_lang_from_argv()
    try:
        cli.main(args=argv, prog_name="vitaisk", standalone_mode=True)
    except KeyboardInterrupt:
        console.print(f"\n[dim]{_('watch.stopping')}[/]")
        sys.exit(130)


if __name__ == "__main__":
    main()