import base64
import json
import unittest
from unittest.mock import patch
from pathlib import Path
from tempfile import TemporaryDirectory

from legacy import vitaisk as guest
from vitaisk.collectors.base import EventQueue
from vitaisk.config import Config
from vitaisk.events import Severity
from vitaisk.engine.pipeline import Pipeline
from vitaisk.metasploitable import LabPacketCollector, MetasploitableCollector, lab_interface
from vitaisk.rules.loader import load_rules


class MetasploitableTests(unittest.TestCase):
    def setUp(self):
        self.queue = EventQueue()
        self.collector = MetasploitableCollector(self.queue, Config(), None, [], "192.168.56.101")
        self.collector._record(["hello", "1"])

    def test_guest_status_deduplicates_and_marks_read_only(self):
        self.collector._record(["status", "1", "auth,system"])
        event = self.queue.get(timeout=0)
        self.assertEqual(event.extra["lab_host"], "192.168.56.101")
        self.assertEqual(event.severity, Severity.ERROR)
        self.assertIn("read-only", event.message)
        self.collector._record(["status", "1", "auth,system"])
        self.assertIsNone(self.queue.get(timeout=0))

    def test_guest_log_uses_original_parser_and_guest_timestamp(self):
        line = b"Nov 23 15:43:00 vm sshd[42]: Accepted password for test from 192.0.2.1 port 123 ssh2"
        self.collector._record(["log", "auth", "1795468800", base64.b64encode(line).decode()])
        event = self.queue.get(timeout=0)
        self.assertEqual(event.category, "ssh_login")
        self.assertEqual(event.src_ip, "192.0.2.1")
        self.assertEqual(event.ts, 1795468800)

    def test_guest_metrics_and_network_use_observations_from_vm(self):
        self.collector._record(["metrics", "100", "55", "1000", "500", "20", "100", "12", "2", "10"])
        self.collector._record(["metrics", "200", "105", "1000", "500", "20", "100", "12", "2", "10"])
        self.assertEqual(self.collector.vitals, (50, 50, 20))
        self.collector._record(["connection", "new", "tcp", "6538A8C0:0016", "6638A8C0:1234"])
        event = self.queue.get(timeout=0)
        self.assertEqual(event.src_ip, "192.168.56.102")
        self.assertEqual(event.dst_port, 22)

    def test_guest_reads_ipv4_sockets_mapped_into_tcp6(self):
        mapped = "0000000000000000FFFF0000"
        rows = {
            "/proc/net/tcp6": [
                "header",
                f"0: {mapped}6538A8C0:0016 {mapped}6638A8C0:ABCD 01",
                "1: 00000000000000000000000000000000:0016 "
                "00000000000000000000000000000000:0000 0A",
            ],
        }
        with patch.object(guest, "proc_lines", side_effect=lambda path: rows.get(path, [])):
            self.assertEqual(guest.ipv4_connections(), {
                ("tcp", "6538A8C0:0016", "6638A8C0:ABCD"): "ESTAB",
            })

    def test_rejects_default_route_and_public_destination_before_ssh(self):
        with patch("vitaisk.metasploitable.subprocess.check_output") as query:
            with self.assertRaises(ValueError):
                lab_interface("8.8.8.8", "192.168.56.102")
            query.assert_not_called()
            query.return_value = json.dumps([{"dev": "eth0", "gateway": "192.168.56.1"}])
            with self.assertRaises(ValueError):
                lab_interface("192.168.56.101", "192.168.56.102")

    def test_passive_syn_rule_counts_distinct_guest_ports(self):
        collector = LabPacketCollector(
            self.queue, Config(), None, [], "192.168.56.101", bytearray(),
        )
        rule = load_rules()["tcp-syn-many-ports"]
        pipeline = Pipeline({rule["id"]: rule})
        other_peer = collector._parse("1700000000.01 IP 192.0.2.1.33333 > 192.168.56.101.22: S")
        self.assertEqual(other_peer.src_ip, "192.0.2.1")
        self.assertIsNone(collector._parse("1700000000.01 IP 192.0.2.1.33333 > 192.168.56.100.22: S"))
        old_format = "1700000000.01 IP 192.168.56.102.33333 > 192.168.56.101.22: S"
        for _ in range(15):
            self.assertFalse(list(pipeline.process(collector._parse(old_format))))
        alerts = []
        for port in range(1000, 1011):
            record = f"1700000001.01 IP 192.168.56.102.33333 > 192.168.56.101.{port}: Flags [S]"
            alerts.extend(pipeline.process(collector._parse(record)))
        self.assertEqual([alert.rule_id for alert in alerts], ["tcp-syn-many-ports"])

    def test_guest_history_leaves_partial_line_for_live_updates(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "auth.log"
            path.write_text("old\npartial", encoding="ascii")
            events = []
            with path.open(encoding="ascii") as handle:
                guest.read_history(handle, "auth", lambda source, line: events.append(line))
                self.assertEqual(events, ["old\n"])
                with path.open("a", encoding="ascii") as writer:
                    writer.write(" line\n")
                guest.read_lines(handle, "auth", True, lambda source, line: events.append(line))
            self.assertEqual(events, ["old\n", "partial line\n"])
