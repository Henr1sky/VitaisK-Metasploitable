"""Regression tests for overlapping collectors and correlation field boundaries."""
from unittest import TestCase

from vitaisk.engine.pipeline import Pipeline
from vitaisk.events import make_event
from vitaisk.rules.loader import load_rules


def ssh(ts, category="ssh_failed", user="example", collector="authlog"):
    return make_event(
        ts=ts, source="auth", host="host", category=category, severity="WARN",
        message=category, src_ip="192.0.2.3", user=user,
        extra={"collector": collector},
    )


class DetectionTests(TestCase):
    def setUp(self):
        self.pipeline = Pipeline(load_rules())

    def test_same_record_seen_by_journal_and_authlog_only_counts_once(self):
        for ts in (2, 4, 6, 8):
            self.assertFalse(list(self.pipeline.process(ssh(ts))))
            self.assertFalse(list(self.pipeline.process(ssh(ts, collector="journal"))))

        alerts = list(self.pipeline.process(ssh(10)))
        self.assertEqual([(alert.rule_id, alert.event_count) for alert in alerts],
                         [("ssh-brute-force", 5)])

    def test_login_after_failures_requires_same_user(self):
        for ts in (2, 4, 6, 8, 10):
            list(self.pipeline.process(ssh(ts)))

        wrong_user = ssh(11, "ssh_login", user="another")
        self.assertFalse(list(self.pipeline.process(wrong_user)))

        login = ssh(12, "ssh_login")
        alerts = list(self.pipeline.process(login))
        self.assertEqual([(alert.rule_id, alert.event_count) for alert in alerts],
                         [("ssh-fail-then-success", 6)])


class CorrelationTests(TestCase):
    def setUp(self):
        from vitaisk.rules.loader import load_correlations

        self.pipeline = Pipeline(load_rules(), correlations=load_correlations())

    def test_ssh_combines_detections_and_exports_evidence(self):
        for ts in (2, 4, 6, 8, 10):
            list(self.pipeline.process(ssh(ts)))
        results = list(self.pipeline.process(ssh(12, "ssh_login"), lang="pt"))
        raw, composite = [alert.to_dict() for alert in results]
        self.assertEqual(raw["rule_id"], "ssh-fail-then-success")
        self.assertEqual(composite["rule_id"], "ssh-success-after-brute-force")
        self.assertEqual(composite["severity"], "CRITICAL")
        self.assertEqual([item["ts"] for item in composite["evidence"]], [10, 12])
        self.assertIn("ssh-brute-force", composite["supersedes"])
        self.assertIn("Correlação", composite["reasons"][0])

    def test_systemd_restarts_correlate_only_with_same_unit_and_time(self):
        from vitaisk.collectors.base import EventQueue
        from vitaisk.collectors.journal import JournalCollector
        from vitaisk.config import Config

        journal = JournalCollector(EventQueue(1), Config())

        def observe(ts, unit, message):
            record = {"__REALTIME_TIMESTAMP": str(ts * 1000000), "_HOSTNAME": "host",
                      "SYSLOG_IDENTIFIER": "systemd", "_SYSTEMD_UNIT": "init.scope",
                      "UNIT": unit, "MESSAGE": message}
            return [alert.rule_id for alert in self.pipeline.process(journal._to_event(record))]

        for ts in range(10, 35, 2):
            observe(ts, "app.service", "Scheduled restart job")
        oom = "Failed with result 'oom-kill'"
        self.assertNotIn("service-restarts-with-oom", observe(35, "other.service", oom))
        self.assertIn("service-restarts-with-oom", observe(40, "app.service", oom))
        self.assertNotIn("service-restarts-with-oom", observe(45, "app.service", oom))
        for ts in range(640, 665, 2):
            observe(ts, "app.service", "Scheduled restart job")
        self.assertNotIn("service-restarts-with-oom", observe(785, "app.service", oom))

    def test_observed_syn_rules_change_severity_and_pulse_color(self):
        from vitaisk.dashboard import PulseSample, effective_level, event_row, pulse_trace

        observed = []
        for index in range(100):
            event = make_event(
                source="network", category="syn", host="host", ts=index / 12,
                severity="INFO", src_ip="192.0.2.15", dst_ip="192.0.2.42",
                dst_port=10000 + index, message="Synthetic observed TCP SYN",
            )
            alerts = list(self.pipeline.process(event))
            if index in (0, 19, 99):
                observed.append(PulseSample(index + 1, effective_level(event, alerts)))
        self.assertEqual([item.severity.name for item in observed], ["INFO", "WARN", "CRITICAL"])
        self.assertIn("scan-syn-with-aggressive-burst", {alert.rule_id for alert in alerts})
        self.assertEqual(event_row(event, alerts)[1].style, "bold bright_red")
        self.assertEqual([span.style for span in pulse_trace(observed, 3).spans[:3]],
                         ["bright_green", "bright_yellow", "bold bright_red"])


class NativeRuleCoverageTests(TestCase):
    def test_each_local_detector_processes_a_matching_observation(self):
        from pathlib import Path
        from tempfile import TemporaryDirectory

        from vitaisk.rules.loader import rule_input

        regex_samples = {
            "service-timeout-start": "start operation timed out",
            "service-exit-signal": "main process exited, code=killed, status=11/SEGV",
            "service-port-bind-fail": "bind: Address already in use",
            "kernel-edac": "EDAC corrected memory error",
            "kernel-ata-error": "ata1: unrecoverable read error",
            "kernel-fs-readonly": "remounting filesystem read-only",
            "kernel-module-fail": "module: verification failed",
            "kernel-calltrace": "WARNING: CPU: 0 at file.c:",
            "kernel-conntrack-error": "conntrack allocation error",
            "kernel-icmp-invalid": "invalid ICMP type",
            "service-exit-sigsegv": "main process exited, code=dumped, status=11/SEGV",
            "service-exit-sigkill": "main process exited, code=killed, status=9/KILL",
            "service-unit-not-found": "Unit example.service not found",
            "mount-fail": "example.mount: Failed with result 'exit-code'",
            "socket-accept-fail": "example.socket: Failed to accept",
            "timer-fail": "example.timer: Failed with result 'resources'",
            "burst-connections-50": "TCP ESTAB from observation",
            "burst-connections-200": "TCP ESTAB from observation",
            "shell-bind-port": "TCP LISTEN 127.0.0.1:4444 → *:*",
        }
        with TemporaryDirectory() as directory:
            native = {id_: rule for id_, rule in load_rules(Path(directory)).items()
                      if rule_input(rule) == "native"}
        self.assertGreaterEqual(len(native), 75)
        for rule_id, definition in native.items():
            with self.subTest(rule=rule_id):
                pipeline = Pipeline({rule_id: definition})

                def observation(selector, ts, port):
                    categories = selector.get("category", "synthetic")
                    category = categories[0] if isinstance(categories, list) else categories
                    message = regex_samples[rule_id] if "regex" in selector else (
                        selector.get("contains") or ["Synthetic event"]
                    )[0]
                    values = {
                        "host": "host", "user": "example", "src_ip": "192.0.2.1",
                        "dst_ip": "192.0.2.2", "dst_port": port, "protocol": "tcp",
                    }
                    extra = {"unit": "example.service", "lab_host": "192.0.2.2"}
                    for name, value in selector.get("equals", {}).items():
                        if name.startswith("extra."):
                            extra[name[6:]] = value
                        else:
                            values[name] = value
                    return make_event(source=selector["source"], category=category, severity="INFO",
                                      message=message, ts=ts, extra=extra, **values)

                threshold = definition.get("threshold", 1)
                alerts = []
                for index in range(threshold):
                    ts = 1 + index * min(definition.get("window", 1), 2) / (2 * threshold)
                    alerts = list(pipeline.process(observation(definition, ts, 1000 + index)))
                    if index < threshold - 1:
                        self.assertFalse(alerts)
                if "followed_by" in definition:
                    self.assertFalse(alerts)
                    alerts = list(pipeline.process(observation(definition["followed_by"], 2, 1000)))
                self.assertEqual([alert.rule_id for alert in alerts], [rule_id])
