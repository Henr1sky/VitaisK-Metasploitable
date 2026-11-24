"""Exercise catalog rules through the same validated signals used by watch."""
import csv
import io
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Event as ThreadEvent
from unittest import TestCase

from click.testing import CliRunner

from vitaisk.cli import cli
from vitaisk.collectors.base import EventQueue
from vitaisk.collectors.signals import SignalCollector
from vitaisk.config import Config
from vitaisk.dashboard import effective_level
from vitaisk.engine.pipeline import Pipeline
from vitaisk.events import Severity
from vitaisk.rules.loader import load_correlations, load_priorities, load_rules, signal_levels
from vitaisk.sessions import SessionWriter
from vitaisk.telemetry import MAX_RECORD_BYTES, decode_telemetry


def record(rule_id, ts=10, **overrides):
    return {
        "record_type": "signal", "rule_id": rule_id, "producer": "fixture",
        "observation_id": str(ts), "scope": "case-test", "host": "test-host",
        "ts": ts, "source": "system", "message": "Synthetic evidence",
        "unit": "example.service", "device": "sda1", "user": "test",
        "src_ip": "192.0.2.10", **overrides,
    }


class TelemetryTests(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rules = load_rules()
        cls.correlations = load_correlations()
        cls.priorities = load_priorities()
        cls.allowed = signal_levels(cls.rules, cls.correlations)

    def decode(self, data):
        return decode_telemetry(json.dumps(data), self.allowed)

    def test_every_catalog_correlation_executes_with_compatible_signals(self):
        self.assertEqual(len(self.correlations), 230)
        for rule in self.correlations:
            with self.subTest(rule=rule["id"]):
                pipe = Pipeline(self.rules, correlations=[rule])
                for index, signal in enumerate(rule["requires"], start=20):
                    alerts = list(pipe.process(self.decode(record(signal, index))))
                compound = [alert for alert in alerts if alert.rule_id == rule["id"]]
                self.assertEqual(len(compound), 1)
                self.assertEqual([item["rule_id"] for item in compound[0].evidence], rule["requires"])
                self.assertTrue(all(item["producer"] == "fixture" for item in compound[0].evidence))

    def test_scope_window_and_observation_identity(self):
        rule = next(item for item in self.correlations if item["requires_scope"])
        first, second, *_ = rule["requires"]
        self.assertEqual(len(rule["requires"]), 2)
        pipe = Pipeline(self.rules, correlations=[rule])
        list(pipe.process(self.decode(record(first, 10))))
        affected = (
            record(second, 11, scope="another"),
            record(second, 12, host="another"),
            record(second, 13, observation_id="10"),
            record(second, 311),
        )
        for data in affected:
            alerts = list(pipe.process(self.decode(data)))
            self.assertNotIn(rule["id"], [alert.rule_id for alert in alerts])
        alerts = list(pipe.process(self.decode(record(second, 15))))
        self.assertIn(rule["id"], [alert.rule_id for alert in alerts])
        self.assertEqual(list(pipe.process(self.decode(record(second, 15)))), [])

    def test_all_priorities_are_annotated_and_other_hosts_are_kept_separate(self):
        self.assertEqual(len(self.priorities), 10)
        for policy in self.priorities:
            with self.subTest(policy=policy["id"]):
                target = policy["target"][0]
                if target.endswith("*"):
                    target = {"pam-*": "pam-fail", "service-*": "service-fail"}[target]
                pipe = Pipeline(self.rules, priorities=[policy])
                list(pipe.process(self.decode(record(policy["when"], 10))))
                alert, = pipe.process(self.decode(record(target, 11)))
                self.assertEqual(alert.triage[0]["action"], policy["action"])
                if policy["action"] in ("raise", "human_review"):
                    self.assertEqual(effective_level(alert.event, [alert]), Severity.CRITICAL)
                if policy["action"] == "human_review":
                    self.assertFalse(alert.triage[0]["automation_allowed"])
                other, = pipe.process(self.decode(record(target, 400, host="another")))
                if target != policy["when"]:
                    self.assertFalse(other.triage)

    def test_maintenance_lowering_respects_the_explicit_deadline(self):
        policy = next(item for item in self.priorities if item["action"] == "lower")
        pipe = Pipeline(self.rules, priorities=[policy])
        list(pipe.process(self.decode(record(policy["when"], 10, valid_until=20))))
        during, = pipe.process(self.decode(record("baseline-drift-prod", 20, severity="CRITICAL")))
        after, = pipe.process(self.decode(record("baseline-drift-prod", 21, severity="CRITICAL")))
        self.assertEqual(effective_level(during.event, [during]), Severity.INFO)
        self.assertEqual(effective_level(after.event, [after]), Severity.CRITICAL)

    def test_rejects_unknown_ids_missing_scope_and_oversized_records(self):
        for data in (record("unknown-rule"), record("ssh-brute-force", scope=""),
                     record("ssh-brute-force", ts=float("nan")),
                     record("ssh-brute-force", confidence=10**400),
                     record("ssh-brute-force", message="x" * MAX_RECORD_BYTES)):
            with self.subTest(rule=data["rule_id"]), self.assertRaises(ValueError):
                self.decode(data)

    def test_live_file_handles_partial_and_oversized_lines_and_rotation(self):
        with TemporaryDirectory() as folder:
            path = Path(folder) / "signals.jsonl"
            path.write_bytes(json.dumps(record("ssh-brute-force", 1)).encode() + b"\n")
            ready = ThreadEvent()

            class ReadyCollector(SignalCollector):
                def _read(self, handle):
                    ready.set()
                    return super()._read(handle)

            queue = EventQueue()
            collector = ReadyCollector(queue, Config(), ThreadEvent(), path, self.allowed)
            collector.start()
            try:
                self.assertTrue(ready.wait(2))
                data = json.dumps(record("ssh-brute-force", 5)).encode()
                with path.open("ab") as handle:
                    handle.write(b"x" * (MAX_RECORD_BYTES + 64) + b"\n" + data[:30])
                self.assertIsNone(queue.get(0.3))
                with path.open("ab") as handle:
                    handle.write(data[30:] + b"\n")
                self.assertEqual(queue.get(2).ts, 5)
                self.assertEqual(collector.rejected, 1)
                path.rename(path.with_suffix(".old"))
                path.write_text(json.dumps(record("ssh-brute-force", 7)) + "\n")
                self.assertEqual(queue.get(2).ts, 7)
            finally:
                collector.stop()
            self.assertFalse(collector.is_alive())

    def test_cli_replay_and_exports_include_classified_signal_and_evidence(self):
        correlation = next(item for item in self.correlations if item["requires_scope"])
        data = [record(rule, index) for index, rule in enumerate(correlation["requires"], start=1)]
        payload = "\n".join(json.dumps(signal) for signal in data) + "\n"
        runner = CliRunner()
        with TemporaryDirectory() as folder:
            env = {"XDG_CONFIG_HOME": folder, "XDG_DATA_HOME": folder}
            replay = runner.invoke(cli, ["rules", "test", "-"], input=payload, env=env)
            self.assertEqual(replay.exit_code, 0, replay.output)
            alerts = [json.loads(line) for line in replay.stdout.splitlines()]
            self.assertIn(correlation["id"], {alert["rule_id"] for alert in alerts})

            config = Config()
            config.data_path = lambda: Path(folder) / "vitaisk"
            writer = SessionWriter(config)
            pipe = Pipeline(self.rules, correlations=[correlation])
            for signal in data:
                event = self.decode(signal)
                writer.write(event, list(pipe.process(event)))
            writer.close()
            export = runner.invoke(cli, ["export", "--format", "csv"], env=env)
            self.assertEqual(export.exit_code, 0, export.output)
            rows = list(csv.DictReader(io.StringIO(export.stdout)))
            exported = json.loads(rows[-1]["anomalies"])
            self.assertEqual(exported[-1]["rule_id"], correlation["id"])
            self.assertEqual(len(exported[-1]["evidence"]), len(data))

    def test_each_structured_rule_matches_its_schema_and_rejects_replayed_records(self):
        from vitaisk.rules.loader import rule_input

        for definition in self.rules.values():
            if rule_input(definition) != "structured":
                continue
            with self.subTest(rule=definition["id"]):
                base = record("placeholder")
                base.pop("rule_id")
                base.pop("source")
                base.update(record_type="event", kind=definition["category"].removeprefix("telemetry_"))
                facts = {}
                for requirement, value in definition.get("equals", {}).items():
                    if requirement.startswith("extra."):
                        facts[requirement[6:]] = value
                    else:
                        base[requirement] = value
                for requirement, choices in definition.get("one_of", {}).items():
                    facts[requirement[6:]] = choices[0]
                for requirement, limits in definition.get("number", {}).items():
                    value = max(0, limits.get("gt", -1) + 1, limits.get("gte", 0))
                    if requirement.startswith("extra."):
                        facts[requirement[6:]] = value
                    else:
                        base[requirement] = value
                if not facts:
                    facts = {"operation": "query"} if base["kind"] == "dns" else {"method": "GET"}
                base.update(facts=facts, dst_ip="192.0.2.11")
                pipeline = Pipeline({definition["id"]: definition})
                threshold = definition.get("threshold", 1)
                width = definition.get("window", 1)
                for index in range(threshold):
                    event = self.decode({**base, "observation_id": str(index),
                                         "ts": 10 + index * width / (2 * threshold)})
                    alerts = list(pipeline.process(event))
                    self.assertEqual(len(alerts), int(index == threshold - 1))
                    self.assertEqual(list(pipeline.process(event)), [])

    def test_two_following_structured_observations_respect_shared_scope(self):
        first, second = "service-health-endpoint-down", "service-functional-probe-fail"
        rule = next(item for item in self.correlations if item["requires"] == [first, second])
        pipeline = Pipeline(self.rules, correlations=[rule])
        base = record("placeholder")
        base.pop("rule_id")
        base.update(record_type="event", kind="service", facts={"state": "active",
                                                               "health_reachable": False})
        a = self.decode(base)
        b = self.decode({**base, "ts": 11, "observation_id": "b", "scope": "different",
                         "facts": {"functional_probe_ok": False}})
        c = self.decode({**base, "ts": 12, "observation_id": "c",
                         "facts": {"functional_probe_ok": False}})
        self.assertEqual([alert.rule_id for alert in pipeline.process(a)], [first])
        self.assertEqual([alert.rule_id for alert in pipeline.process(b)], [second])
        self.assertEqual([alert.rule_id for alert in pipeline.process(c)], [second, rule["id"]])
