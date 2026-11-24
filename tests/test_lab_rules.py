"""Exercise the installed lab rule catalog through the collectors and rule engine."""

import base64
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch

from vitaisk.collectors.base import EventQueue
from vitaisk.config import Config
from vitaisk.engine.pipeline import Pipeline
from vitaisk.metasploitable import LabPacketCollector, MetasploitableCollector
from vitaisk.rules.loader import load_correlations, load_priorities, load_rules
from vitaisk.sessions import SessionWriter, records

HOST = "192.0.2.2"
PEER = "192.0.2.1"

REGEX_MESSAGES = {
    "service-timeout-start": "example.service: Start operation timed out",
    "service-exit-signal": "main process exited, code=killed, status=11/SEGV",
    "service-port-bind-fail": "bind() failed: Address already in use",
    "kernel-edac": "EDAC MC0: corrected memory error",
    "kernel-ata-error": "ata1.00: error status",
    "kernel-fs-readonly": "Remounting filesystem read-only",
    "kernel-module-fail": "module example verification failed",
    "kernel-calltrace": "WARNING: CPU: 0 PID: 42 at example.c:20",
    "kernel-conntrack-error": "conntrack table error",
    "kernel-icmp-invalid": "ICMP: bad checksum",
}

AUTH_MESSAGES = {
    "ssh_failed": ("sshd[42]", "Failed password for example from {peer} port 40500 ssh2"),
    "ssh_key_failed": ("sshd[42]", "Failed publickey for example from {peer} port 40500 ssh2"),
    "pam_lockout": ("login", "pam_faillock(login:auth): account temporarily locked"),
    "ssh_invalid_user": ("sshd[42]", "Invalid user example from {peer}"),
    "ssh_login": ("sshd[42]", "Accepted password for {user} from {peer} port 40500 ssh2"),
    "sudo_auth_fail": ("sudo", "pam_unix(sudo:auth): authentication failure; user={user}"),
    "user_added": ("useradd[42]", "new user: name={user}, UID=1002"),
    "user_removed": ("userdel[42]", "delete user '{user}'"),
    "pam_fail": ("login", "pam_unix(login:auth): authentication failure; user={user}"),
}

KERNEL_PREFIXES = {
    "oom": "Out of memory: Killed process 42 (fixture)",
    "kernel_panic": "Kernel panic - not syncing: ",
    "segfault": "fixture[42]: segfault at 0",
    "kernel_oops": "Oops: kernel exception",
}


class LabRuleCatalogTests(TestCase):
    @classmethod
    def setUpClass(cls):
        with TemporaryDirectory() as directory:
            cls.rules = load_rules(Path(directory))

    def setUp(self):
        self.queue = EventQueue()
        self.collector = MetasploitableCollector(self.queue, Config(), None, [], HOST)
        self.collector._record(["hello", "1"])
        self.packets = LabPacketCollector(self.queue, Config(), None, [], HOST, bytearray())

    def log(self, source, ident, message, ts):
        line = f"Nov 24 2026 10:00:00 fixture {ident}: {message}"
        payload = base64.b64encode(line.encode()).decode()
        self.collector._record(["log", source, str(ts), payload])
        event = self.queue.get(timeout=0)
        self.assertIsNotNone(event, line)
        return event

    def event(self, rule, ts, port=1000, peer=PEER):
        source = rule["source"]
        category = rule.get("category")
        if isinstance(category, list):
            category = category[0]
        if source == "network" and category == "new_connection":
            state = rule.get("equals", {}).get("extra.state", "ESTAB")
            local = "020200C0:115C" if state == "LISTEN" else f"020200C0:{port:04X}"
            peer_hex = "00000000:0000" if state == "LISTEN" else "010200C0:9E34"
            self.collector._record(["connection", "new", "tcp", local, peer_hex, state])
            return self.queue.get(timeout=0)
        if source == "network":
            return self.packets._parse(f"{ts}.000 IP {PEER}.40500 > {HOST}.{port}: S")
        if source == "firewall":
            proto = rule["equals"]["protocol"]
            message = f"[UFW BLOCK] IN=eth0 OUT= SRC={peer} DST={HOST} PROTO={proto} SPT=40500 DPT={port}"
            return self.log("kernel", "kernel", message, ts)
        if source == "auth":
            ident, message = AUTH_MESSAGES[category]
            user = rule.get("equals", {}).get("user", "example")
            return self.log(source, ident, message.format(peer=peer, user=user), ts)
        example = REGEX_MESSAGES.get(rule.get("id", ""))
        if not example:
            example = rule.get("contains", [""])[0]
        if source == "kernel":
            return self.log(source, "kernel", KERNEL_PREFIXES.get(category, "") + example, ts)
        return self.log(source, category or "fixture", example, ts)

    def test_rules_with_lab_fixtures_trigger_at_their_threshold(self):
        for rule_id, rule in self.rules.items():
            source, category = rule["source"], rule.get("category")
            categories = category if isinstance(category, list) else [category]
            has_fixture = (
                source in ("kernel", "firewall")
                or source == "auth" and categories[0] in AUTH_MESSAGES
                or source == "network" and category in ("syn", "new_connection")
                or source == "system" and (rule_id in REGEX_MESSAGES or "contains" in rule)
                and not any(field.startswith("extra.") for field in (*rule.get("group_by", ()), *rule.get("equals", {})))
            )
            if not has_fixture:
                continue
            with self.subTest(rule=rule_id):
                pipeline = Pipeline({rule_id: rule})
                count = rule.get("threshold", 1)
                terminal = rule.get("followed_by")
                alerts = []
                for port in range(count):
                    received = list(pipeline.process(self.event(rule, 100, port=1000 + port)))
                    if port + 1 < count or terminal:
                        self.assertFalse(received)
                    alerts.extend(received)
                if terminal:
                    alerts.extend(pipeline.process(self.event(terminal, 101)))
                self.assertEqual([(item.rule_id, item.event_count) for item in alerts],
                                 [(rule_id, count + int(bool(terminal)))])
                if terminal:
                    self.assertEqual(set(alerts[0].sources_matched), {rule["source"], terminal["source"]})

    def test_network_and_firewall_correlations_reject_wrong_peer_and_expired_sequence(self):
        for rule_id in ("tcp-syn-many-ports-then-ssh-fail", "inbound-scan-then-ssh-fail"):
            rule = self.rules[rule_id]
            with self.subTest(rule=rule_id):
                pipeline = Pipeline({rule_id: rule})
                for port in range(rule["threshold"]):
                    list(pipeline.process(self.event(rule, 100, port=1000 + port)))
                terminal = rule["followed_by"]
                self.assertFalse(list(pipeline.process(self.event(terminal, 101, peer="192.0.2.9"))))
                self.assertFalse(list(pipeline.process(self.event(terminal, 100 + rule["window"] + 1))))

    def test_unauthorized_access_is_visible_and_saved(self):
        pipeline = Pipeline(self.rules, correlations=load_correlations(),
                            priorities=load_priorities())
        with TemporaryDirectory() as directory:
            with patch.object(Config, "data_path", return_value=Path(directory)):
                writer = SessionWriter(Config())
            for port in range(1000, 1012):
                event = self.event({"source": "network", "category": "syn"}, 100, port=port)
                writer.write(event, tuple(pipeline.process(event)))
            failure = self.event({"source": "auth", "category": "ssh_failed"}, 101)
            writer.write(failure, tuple(pipeline.process(failure)))
            for ts in range(102, 106):
                event = self.event({"source": "auth", "category": "ssh_failed"}, ts)
                writer.write(event, tuple(pipeline.process(event)))
            event = self.event({"source": "auth", "category": "ssh_login"}, 106)
            writer.write(event, tuple(pipeline.process(event)))
            saved = list(records(writer.close()))

        ids = {alert["rule_id"]: alert for record in saved
               for alert in record.get("anomalies", ())}
        self.assertEqual(ids["lab-ssh-access-denied"]["severity"], "WARN")
        self.assertEqual(ids["ssh-brute-force"]["severity"], "CRITICAL")
        self.assertEqual(ids["ssh-fail-then-success"]["severity"], "CRITICAL")
        self.assertEqual(set(ids["tcp-syn-many-ports-then-ssh-fail"]["sources_matched"]),
                         {"network", "auth"})
        self.assertEqual(saved[12]["src_ip"], PEER)
        self.assertEqual(saved[12]["dst_ip"], HOST)

    def test_ext3_messages_match_kernel_corruption_rule(self):
        rule_id = "kernel-fs-corruption"
        pipeline = Pipeline({rule_id: self.rules[rule_id]})
        for message in ("EXT3-fs error (device dm-0)", "Aborting journal on device dm-0",
                        "Journal has aborted"):
            with self.subTest(message=message):
                event = self.log("kernel", "kernel", message, 100)
                self.assertEqual([alert.rule_id for alert in pipeline.process(event)], [rule_id])
