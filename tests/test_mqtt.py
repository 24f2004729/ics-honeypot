# =============================================================================
#  tests / test_mqtt.py
#  ---------------------------------------------------------------------------
#  Unit tests for MQTT Honeypot & credential harvester.
# =============================================================================

import unittest
import struct
from honeypot.mqtt.listener import (
    MQTTListener,
    _decode_remaining_length,
    _decode_utf8_string,
    PKT_CONNECT,
    PKT_CONNACK,
    PKT_PUBLISH,
    PKT_SUBSCRIBE,
    PKT_SUBACK
)


class TestMQTTListener(unittest.TestCase):

    def setUp(self):
        self.listener = MQTTListener(port=1884)

    def test_variable_length_decoder(self):
        """Test MQTT variable length integer decoding."""
        # Single byte length
        val, consumed = _decode_remaining_length(bytes([0x40]), 0)
        self.assertEqual(val, 64)
        self.assertEqual(consumed, 1)

        # Multi-byte length: 0xC1 0x02 = 1 + (2 * 128) = 257
        val2, consumed2 = _decode_remaining_length(bytes([0xC1, 0x02]), 0)
        self.assertEqual(val2, 321)
        self.assertEqual(consumed2, 2)

    def test_utf8_string_decoder(self):
        """Test 2-byte length-prefixed UTF-8 decoding."""
        raw = struct.pack(">H", 5) + b"admin"
        text, offset = _decode_utf8_string(raw, 0)
        self.assertEqual(text, "admin")
        self.assertEqual(offset, 7)

    def test_connect_credential_harvesting(self):
        """Test MQTT CONNECT harvests plaintext username and password."""
        # CONNECT Variable Header: "MQTT" (4B), Level 4 (v3.1.1), Flags 0xC2 (User + Pass + CleanSession), Keepalive 60s
        proto_name = struct.pack(">H", 4) + b"MQTT"
        vh = proto_name + bytes([0x04, 0xC2]) + struct.pack(">H", 60)

        # CONNECT Payload: ClientID "test-client", User "admin", Pass "Secret123"
        cid = struct.pack(">H", 11) + b"test-client"
        user = struct.pack(">H", 5) + b"admin"
        pwd = struct.pack(">H", 9) + b"Secret123"
        payload = vh + cid + user + pwd

        packet = bytes([PKT_CONNECT, len(payload)]) + payload

        consumed, resp = self.listener._process_packet("127.0.0.1", 54321, packet)
        self.assertEqual(consumed, len(packet))
        self.assertIsNotNone(resp)
        # Should return CONNACK (0x20, 0x02, 0x00, 0x00)
        self.assertEqual(resp[0], PKT_CONNACK)
        self.assertEqual(resp[3], 0x00)  # Accepted

    def test_subscribe_handling(self):
        """Test MQTT SUBSCRIBE returns SUBACK with granted QoS."""
        # Packet ID 1, Topic "sensors/temperature", requested QoS 0
        topic_bytes = struct.pack(">H", 19) + b"sensors/temperature" + bytes([0])
        payload = struct.pack(">H", 1) + topic_bytes
        packet = bytes([PKT_SUBSCRIBE, len(payload)]) + payload

        consumed, resp = self.listener._process_packet("127.0.0.1", 54321, packet)
        self.assertIsNotNone(resp)
        self.assertEqual(resp[0], PKT_SUBACK)


if __name__ == "__main__":
    unittest.main()
