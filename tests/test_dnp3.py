# =============================================================================
#  tests / test_dnp3.py
#  ---------------------------------------------------------------------------
#  Unit tests for DNP3 protocol listener and CRC-16 calculation.
# =============================================================================

import unittest
import struct
from honeypot.dnp3.listener import (
    DNP3Listener,
    dnp3_crc,
    _append_crc,
    DNP3_START_BYTE_1,
    DNP3_START_BYTE_2,
    FC_READ,
    FC_OPERATE
)
from honeypot.simulation.process import simulator


class TestDNP3Listener(unittest.TestCase):

    def setUp(self):
        self.listener = DNP3Listener(port=20001)

    def test_crc16_known_vector(self):
        """Verify DNP3 CRC calculation with known header bytes."""
        # 0x05 0x64 (start) + len(0x05) + ctrl(0xC0) + dst(0x01 0x00) + src(0x02 0x00)
        test_header = bytes([0x05, 0x64, 0x05, 0xC0, 0x01, 0x00, 0x02, 0x00])
        crc = dnp3_crc(test_header)
        self.assertIsInstance(crc, int)
        self.assertGreater(crc, 0)

        # Appending CRC should make 10-byte DNP3 header
        full_header = _append_crc(test_header)
        self.assertEqual(len(full_header), 10)

    def test_class0_integrity_poll(self):
        """Test Class 0 read returns valid Group 30 Var 5 analogue response."""
        # Build valid DNP3 Data Link frame requesting Class 0 (Group 60 Var 1 Qual 0x06)
        app_layer = bytes([0xC0, FC_READ, 60, 1, 0x06])
        data_block = _append_crc(app_layer)

        dl_len = 5 + len(data_block)
        dl_ctrl = 0xC4
        header_body = bytes([
            DNP3_START_BYTE_1, DNP3_START_BYTE_2,
            dl_len, dl_ctrl
        ]) + struct.pack("<H", 2) + struct.pack("<H", 1)
        full_frame = _append_crc(header_body) + data_block

        resp = self.listener._process_frame("127.0.0.1", 20000, full_frame)
        self.assertIsNotNone(resp)
        self.assertEqual(resp[0], DNP3_START_BYTE_1)
        self.assertEqual(resp[1], DNP3_START_BYTE_2)

    def test_operate_trips_emergency_cutoff(self):
        """DNP3 OPERATE command must trip simulator emergency cutoff."""
        app_layer = bytes([0xC0, FC_OPERATE])
        data_block = _append_crc(app_layer)

        dl_len = 5 + len(data_block)
        dl_ctrl = 0xC4
        header_body = bytes([
            DNP3_START_BYTE_1, DNP3_START_BYTE_2,
            dl_len, dl_ctrl
        ]) + struct.pack("<H", 2) + struct.pack("<H", 1)
        full_frame = _append_crc(header_body) + data_block

        resp = self.listener._process_frame("127.0.0.1", 20000, full_frame)
        self.assertIsNotNone(resp)
        # Check actuator state in simulator
        self.assertTrue(simulator.get_coil(1))


if __name__ == "__main__":
    unittest.main()
