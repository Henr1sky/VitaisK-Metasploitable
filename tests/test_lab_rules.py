"""Exercise the installed lab rule catalog through the collectors and rule engine."""

import base64
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase

from vitaisk.collectors.base import EventQueue
from vitaisk.config import Config
from vitaisk.engine.pipeline import Pipeline
from vitaisk.metasploitable import LabPacketCollector, MetasploitableCollector
from vitaisk.rules.loader import load_rules

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
        self.packets = LabPacketCollector(self.queue, Config(), None, [], HOST, PEER, bytearray())

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

    def test_each_bundled_rule_triggers_at_its_threshold(self):
        for rule_id, rule in self.rules.items():
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

    def test_ext3_messages_match_kernel_corruption_rule(self):
        rule_id = "kernel-fs-corruption"
        pipeline = Pipeline({rule_id: self.rules[rule_id]})
        for message in ("EXT3-fs error (device dm-0)", "Aborting journal on device dm-0",
                        "Journal has aborted"):
            with self.subTest(message=message):
                event = self.log("kernel", "kernel", message, 100)
                self.assertEqual([alert.rule_id for alert in pipeline.process(event)], [rule_id])
