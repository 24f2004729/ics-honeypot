# =============================================================================
#  tests / test_mitre.py
#  ---------------------------------------------------------------------------
#  Unit tests for MITRE ATT&CK for ICS classification.
# =============================================================================

import unittest
from honeypot.shared.mitre import classify_mitre_attack


class TestMitreClassification(unittest.TestCase):

    def test_unauthorized_command_message(self):
        """Modbus writes and DNP3 OPERATE should map to T0855."""
        res1 = classify_mitre_attack("WRITE_single_coil")
        self.assertEqual(res1["mitre_id"], "T0855")
        self.assertEqual(res1["mitre_tactic"], "Impair Process Control")

        res2 = classify_mitre_attack("OPERATE [CRITICAL]")
        self.assertEqual(res2["mitre_id"], "T0855")

    def test_default_credentials(self):
        """MQTT connect with credentials should map to T0812."""
        res = classify_mitre_attack("mqtt_connect", {"username": "admin", "password": "password"})
        self.assertEqual(res["mitre_id"], "T0812")
        self.assertEqual(res["mitre_tactic"], "Initial Access")

    def test_monitor_process_state(self):
        """Reads and polls should map to T0801."""
        res = classify_mitre_attack("read_holding_registers")
        self.assertEqual(res["mitre_id"], "T0801")
        self.assertEqual(res["mitre_tactic"], "Collection")

    def test_remote_system_discovery(self):
        """Device identification requests (MEI) should map to T0846."""
        res = classify_mitre_attack("device_identification_MEI")
        self.assertEqual(res["mitre_id"], "T0846")
        self.assertEqual(res["mitre_tactic"], "Discovery")


if __name__ == "__main__":
    unittest.main()
