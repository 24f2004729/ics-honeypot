# =============================================================================
#  tests / test_reporter.py
#  ---------------------------------------------------------------------------
#  Unit tests for Threat Intelligence Report generation and aggregation.
# =============================================================================

import unittest
import os
import tempfile
import json
from honeypot.reporter.report import _compute_stats, _render_html


class TestReporter(unittest.TestCase):

    def test_compute_stats_aggregation(self):
        sample_events = [
            {
                "timestamp": "2026-05-30T10:00:00Z",
                "protocol": "MODBUS",
                "event": "attack",
                "src_ip": "192.168.1.100",
                "src_port": 50123,
                "action": "read_holding_registers",
                "severity": "MEDIUM",
                "mitre_id": "T0801",
                "mitre_name": "Monitor Process State",
                "mitre_tactic": "Collection"
            },
            {
                "timestamp": "2026-05-30T10:05:00Z",
                "protocol": "MODBUS",
                "event": "attack",
                "src_ip": "192.168.1.100",
                "src_port": 50123,
                "action": "WRITE_single_coil [CRITICAL]",
                "severity": "CRITICAL",
                "mitre_id": "T0855",
                "mitre_name": "Unauthorized Command Message",
                "mitre_tactic": "Impair Process Control"
            }
        ]

        stats = _compute_stats(sample_events)
        self.assertEqual(stats["total_events"], 2)
        self.assertEqual(stats["total_attacks"], 2)
        self.assertEqual(stats["unique_ips"], 1)
        self.assertEqual(stats["severity"]["CRITICAL"], 1)
        self.assertEqual(stats["severity"]["MEDIUM"], 1)

    def test_render_html_output(self):
        stats = {
            "total_events": 10,
            "total_attacks": 8,
            "unique_ips": 3,
            "protocols": {"MODBUS": 5, "MQTT": 3},
            "severity": {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 5},
            "mitre_techniques": [("T0855 - Unauthorized Command Message", 1)],
            "mitre_tactics": {"Impair Process Control": 1},
            "top_ips": [("1.2.3.4", 5)],
            "first_seen": "2026-01-01T00:00:00Z",
            "last_seen": "2026-01-01T01:00:00Z"
        }
        telemetry = {
            "voltage_v": 230.1,
            "current_a": 45.0,
            "oil_temp_c": 58.2,
            "pressure_hpa": 1013.2,
            "cooling_fan": "OFF",
            "emergency_cutoff": "NORMAL"
        }
        html = _render_html([], stats, telemetry, "2026-01-01 02:00:00 UTC")
        self.assertIn("MITRE ATT&CK", html)
        self.assertIn("Simulated Process Telemetry", html)
        self.assertIn("230.1 V", html)


if __name__ == "__main__":
    unittest.main()
