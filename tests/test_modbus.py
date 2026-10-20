# =============================================================================
#  tests / test_modbus.py
#  ---------------------------------------------------------------------------
#  Unit tests for Modbus TCP Honeypot framing, handlers, and reassembly.
# =============================================================================

import unittest
import struct
from honeypot.modbus.listener import (
    ModbusListener,
    FC_READ_HOLDING_REGISTERS,
    FC_READ_COILS,
    FC_WRITE_SINGLE_COIL,
    FC_WRITE_MULTIPLE_REGISTERS,
    FC_MEI_TRANSPORT
)
from honeypot.simulation.process import simulator


class TestModbusListener(unittest.TestCase):

    def setUp(self):
        self.listener = ModbusListener(port=5020)

    def test_fc03_read_holding_registers(self):
        """Test FC03 returns MBAP header + PDU with register byte count and values."""
        # MBAP: TxnID=1, ProtoID=0, Length=6, UnitID=1 | PDU: FC=0x03, Start=0, Qty=2
        request = struct.pack(">HHHBBHH", 1, 0, 6, 1, FC_READ_HOLDING_REGISTERS, 0, 2)
        resp = self.listener._process_frame("127.0.0.1", 12345, request)

        self.assertIsNotNone(resp)
        txn_id, proto, length, uid = struct.unpack_from(">HHHB", resp, 0)
        self.assertEqual(txn_id, 1)
        self.assertEqual(proto, 0)
        self.assertEqual(uid, 1)

        pdu = resp[7:]
        self.assertEqual(pdu[0], FC_READ_HOLDING_REGISTERS)
        byte_count = pdu[1]
        self.assertEqual(byte_count, 4)  # 2 registers * 2 bytes = 4 bytes

    def test_fc05_write_single_coil_interactive_actuator(self):
        """Test FC05 Write Single Coil toggles simulated actuator."""
        # Coil 0 = Cooling fan, turn ON (0xFF00)
        request = struct.pack(">HHHBBHH", 2, 0, 6, 1, FC_WRITE_SINGLE_COIL, 0, 0xFF00)
        resp = self.listener._process_frame("127.0.0.1", 12345, request)

        self.assertIsNotNone(resp)
        # Check actuator state in simulator
        self.assertTrue(simulator.get_coil(0))

        # Turn OFF (0x0000)
        request_off = struct.pack(">HHHBBHH", 3, 0, 6, 1, FC_WRITE_SINGLE_COIL, 0, 0x0000)
        self.listener._process_frame("127.0.0.1", 12345, request_off)
        self.assertFalse(simulator.get_coil(0))

    def test_fc16_write_multiple_registers(self):
        """Test FC16 bulk register write."""
        # TxnID=4, Proto=0, Len=11, Unit=1, FC=0x10, Start=0, Qty=2, ByteCount=4, Data=[100, 200]
        request = struct.pack(">HHHBBHHBHH", 4, 0, 11, 1, FC_WRITE_MULTIPLE_REGISTERS, 0, 2, 4, 100, 200)
        resp = self.listener._process_frame("127.0.0.1", 12345, request)

        self.assertIsNotNone(resp)
        pdu = resp[7:]
        self.assertEqual(pdu[0], FC_WRITE_MULTIPLE_REGISTERS)
        start_addr, qty = struct.unpack_from(">HH", pdu, 1)
        self.assertEqual(start_addr, 0)
        self.assertEqual(qty, 2)

    def test_fc43_mei_device_identification(self):
        """Test FC43 MEI Read Device Identification returns vendor strings."""
        # MEI: FC=0x2B, MEI_type=0x0E, ReadDevID=0x01, ObjID=0x00
        pdu_req = bytes([FC_MEI_TRANSPORT, 0x0E, 0x01, 0x00])
        request = struct.pack(">HHHB", 5, 0, len(pdu_req) + 1, 1) + pdu_req
        resp = self.listener._process_frame("127.0.0.1", 12345, request)

        self.assertIsNotNone(resp)
        pdu_resp = resp[7:]
        self.assertEqual(pdu_resp[0], FC_MEI_TRANSPORT)
        self.assertEqual(pdu_resp[1], 0x0E)  # MEI Type
        # Ensure vendor string is in response
        self.assertTrue(b"Moxa" in resp or b"Siemens" in resp or b"Schneider" in resp)

    def test_unknown_function_code_returns_exception(self):
        """Unknown FC should return Modbus Exception 0x01 (Illegal Function)."""
        request = struct.pack(">HHHBB", 6, 0, 2, 1, 0x19)  # FC 0x19 is not supported
        resp = self.listener._process_frame("127.0.0.1", 12345, request)

        self.assertIsNotNone(resp)
        pdu_resp = resp[7:]
        self.assertEqual(pdu_resp[0], 0x19 | 0x80)  # Exception flag set
        self.assertEqual(pdu_resp[1], 0x01)         # EX_ILLEGAL_FUNCTION


if __name__ == "__main__":
    unittest.main()
