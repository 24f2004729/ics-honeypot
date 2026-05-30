# =============================================================================
#  ics_honeypot / mqtt / listener.py
#  ---------------------------------------------------------------------------
#  MQTT Honeypot Listener
#  ---------------------------------------------------------------------------
#  Implements a minimal fake MQTT broker that:
#    • Accepts TCP connections on port 1883
#    • Parses MQTT fixed headers to identify packet types
#    • Handles CONNECT (extracts client ID, username, password)
#    • Handles SUBSCRIBE (logs all subscribed topics)
#    • Handles PUBLISH (logs all messages published by attacker)
#    • Responds with correct CONNACK / SUBACK / PUBACK so attackers
#      believe they have successfully connected to a real broker
#    • Logs everything — CONNECT credentials are especially valuable intel
#
#  MQTT Fixed Header (2+ bytes):
#  ┌──────────────────────┬──────────────────────┐
#  │  Byte 0              │  Byte 1+              │
#  │  [PacketType(4b)]    │  Remaining Length     │
#  │  [Flags(4b)]         │  (variable length)    │
#  └──────────────────────┴──────────────────────┘
#
#  Variable Header and Payload depend on packet type.
# =============================================================================

import socket
import struct
import threading

from honeypot.shared.config import MQTT_PORT, SOCKET_BACKLOG, SOCKET_TIMEOUT, RECV_BUFFER
from honeypot.shared.logger import HoneypotLogger

log = HoneypotLogger("MQTT")

# ---------------------------------------------------------------------------
# MQTT Packet Type constants (upper nibble of byte 0)
# ---------------------------------------------------------------------------
PKT_CONNECT     = 0x10
PKT_CONNACK     = 0x20
PKT_PUBLISH     = 0x30
PKT_PUBACK      = 0x40
PKT_SUBSCRIBE   = 0x82   # includes required flags
PKT_SUBACK      = 0x90
PKT_UNSUBSCRIBE = 0xA2
PKT_UNSUBACK    = 0xB0
PKT_PINGREQ     = 0xC0
PKT_PINGRESP    = 0xD0
PKT_DISCONNECT  = 0xE0


# =============================================================================
#  MQTT Variable Length Encoding / Decoding
# =============================================================================

def _decode_remaining_length(data: bytes, offset: int) -> tuple[int, int]:
    """
    Decode MQTT variable-length remaining length field starting at `offset`.

    MQTT uses a multi-byte encoding where the MSB of each byte indicates
    whether more bytes follow.  Maximum 4 bytes (max value = 268,435,455).

    Returns (remaining_length, bytes_consumed).
    Returns (-1, 0) if incomplete.
    """
    multiplier = 1
    value      = 0
    consumed   = 0

    for _ in range(4):
        if offset + consumed >= len(data):
            return -1, 0   # incomplete
        byte      = data[offset + consumed]
        consumed += 1
        value    += (byte & 0x7F) * multiplier
        multiplier *= 128
        if not (byte & 0x80):
            break   # MSB = 0 means this is the last byte

    return value, consumed


def _decode_utf8_string(data: bytes, offset: int) -> tuple[str, int]:
    """
    Decode a 2-byte length-prefixed UTF-8 string from `data` at `offset`.
    Returns (string, new_offset).  Returns ("", offset) on error.
    """
    if offset + 2 > len(data):
        return "", offset
    length = struct.unpack_from(">H", data, offset)[0]
    offset += 2
    if offset + length > len(data):
        return "", offset
    text    = data[offset:offset + length].decode("utf-8", errors="replace")
    return text, offset + length


# =============================================================================
#  MQTTListener
# =============================================================================

class MQTTListener:
    """
    Fake MQTT broker.  Handles CONNECT, SUBSCRIBE, PUBLISH, PING.
    Logs credentials, subscribed topics, and published payloads.
    """

    def __init__(self, host: str = "0.0.0.0", port: int = MQTT_PORT):
        self.host = host
        self.port = port
        self._stop_event = threading.Event()

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def start(self):
        t = threading.Thread(target=self._serve, daemon=True, name="MQTTListener")
        t.start()
        log.info(f"Listening on {self.host}:{self.port}")

    def stop(self):
        self._stop_event.set()

    # ------------------------------------------------------------------
    # Server loop
    # ------------------------------------------------------------------

    def _serve(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((self.host, self.port))
            server.listen(SOCKET_BACKLOG)
            server.settimeout(1.0)

            while not self._stop_event.is_set():
                try:
                    conn, addr = server.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break

                t = threading.Thread(
                    target=self._handle_client,
                    args=(conn, addr),
                    daemon=True,
                    name=f"MQTT-{addr[0]}"
                )
                t.start()

    # ------------------------------------------------------------------
    # Per-client session handler
    # ------------------------------------------------------------------

    def _handle_client(self, conn: socket.socket, addr: tuple):
        ip, port = addr
        log.connection(ip, port)
        conn.settimeout(SOCKET_TIMEOUT)

        # Accumulate bytes across recv() calls in case a packet arrives split
        buffer = b""

        try:
            while True:
                chunk = conn.recv(RECV_BUFFER)
                if not chunk:
                    break
                buffer += chunk

                # Process all complete packets in the buffer
                while True:
                    consumed, response = self._process_packet(ip, port, buffer)
                    if consumed == 0:
                        break   # need more data
                    buffer = buffer[consumed:]
                    if response:
                        conn.sendall(response)

        except socket.timeout:
            pass
        except ConnectionResetError:
            pass
        except Exception as exc:
            log.error(ip, port, f"Unexpected exception: {exc}")
        finally:
            conn.close()
            log.disconnection(ip, port)

    # ------------------------------------------------------------------
    # Packet parser
    # ------------------------------------------------------------------

    def _process_packet(self, ip: str, port: int, data: bytes) -> tuple[int, bytes | None]:
        """
        Parse one MQTT packet from `data`.
        Returns (bytes_consumed, response) or (0, None) if incomplete.
        """
        if len(data) < 2:
            return 0, None

        packet_type = data[0]

        # Decode variable-length remaining length (starts at byte 1)
        remaining_length, len_bytes = _decode_remaining_length(data, 1)
        if remaining_length < 0:
            return 0, None   # incomplete length field

        header_size  = 1 + len_bytes
        total_size   = header_size + remaining_length

        if len(data) < total_size:
            return 0, None   # incomplete packet

        payload = data[header_size:total_size]

        # Dispatch to handler based on packet type
        # Note: MQTT uses the full first byte for type+flags; we mask the upper nibble
        pkt_upper = packet_type & 0xF0

        if pkt_upper == 0x10:   # CONNECT
            response = self._handle_connect(ip, port, payload, data[:total_size])

        elif pkt_upper == 0x30:   # PUBLISH (flags in lower nibble)
            response = self._handle_publish(ip, port, payload, packet_type, data[:total_size])

        elif pkt_upper == 0x80:   # SUBSCRIBE
            response = self._handle_subscribe(ip, port, payload, data[:total_size])

        elif pkt_upper == 0xA0:   # UNSUBSCRIBE
            log.attack(ip, port, "mqtt_unsubscribe", data[:total_size], {})
            # UNSUBACK: 0xB0 | 0x02 + 2-byte packet ID
            pkt_id = struct.unpack_from(">H", payload, 0)[0] if len(payload) >= 2 else 0
            response = bytes([0xB0, 0x02]) + struct.pack(">H", pkt_id)

        elif pkt_upper == 0xC0:   # PINGREQ
            # Keepalive ping — respond immediately to keep the session alive
            # (and keep the attacker connected longer for more data)
            response = bytes([0xD0, 0x00])   # PINGRESP

        elif pkt_upper == 0xE0:   # DISCONNECT
            log.attack(ip, port, "mqtt_disconnect", data[:total_size], {
                "note": "Client sent DISCONNECT packet — graceful close"
            })
            response = None

        else:
            log.error(ip, port, f"Unknown MQTT packet type: 0x{packet_type:02X}")
            response = None

        return total_size, response

    # ------------------------------------------------------------------
    # Packet handlers
    # ------------------------------------------------------------------

    def _handle_connect(self, ip: str, port: int, payload: bytes, raw: bytes) -> bytes:
        """
        Parse MQTT CONNECT packet.
        This is the most valuable packet — may contain plaintext credentials.

        CONNECT Variable Header:
          Protocol Name (UTF-8 string) + Protocol Level (1B) + Connect Flags (1B) + KeepAlive (2B)
        CONNECT Payload:
          Client ID + (optional) Will Topic + Will Message + Username + Password
        """
        offset = 0

        # Protocol name ("MQTT" or "MQIsdp" for v3.1)
        proto_name, offset = _decode_utf8_string(payload, offset)

        if offset >= len(payload):
            return self._connack(0)

        proto_level   = payload[offset];     offset += 1
        connect_flags = payload[offset];     offset += 1

        # Keep-alive timer (2 bytes, big-endian) — how often client sends PING
        keepalive = struct.unpack_from(">H", payload, offset)[0]; offset += 2

        # Connect flags bitmap:
        has_username  = bool(connect_flags & 0x80)
        has_password  = bool(connect_flags & 0x40)
        has_will      = bool(connect_flags & 0x04)
        clean_session = bool(connect_flags & 0x02)

        # Payload: Client ID (always present)
        client_id, offset = _decode_utf8_string(payload, offset)

        # Will Topic and Will Message (if flag set)
        will_topic = will_message = ""
        if has_will:
            will_topic,   offset = _decode_utf8_string(payload, offset)
            will_message, offset = _decode_utf8_string(payload, offset)

        # Username and Password (if flags set) — CRITICAL intel
        username = password = ""
        if has_username:
            username, offset = _decode_utf8_string(payload, offset)
        if has_password:
            password, offset = _decode_utf8_string(payload, offset)

        severity = "CRITICAL" if username or password else "MEDIUM"
        log.attack(ip, port, f"mqtt_connect [{severity}]", raw, {
            "protocol":     proto_name,
            "version":      proto_level,
            "client_id":    client_id,
            "username":     username or "(none)",
            "password":     password or "(none)",   # ← plaintext credential theft
            "will_topic":   will_topic or "(none)",
            "clean_session": clean_session,
            "keepalive_sec": keepalive,
            "severity":     severity
        })

        # CONNACK: return Connection Accepted (0x00) — let them in
        return self._connack(0)

    def _handle_publish(
        self,
        ip: str, port: int,
        payload: bytes,
        packet_type: int,
        raw: bytes
    ) -> bytes | None:
        """
        Parse MQTT PUBLISH packet.
        Attackers may publish fake sensor commands or probe topic structures.

        PUBLISH Variable Header: Topic Name (UTF-8) + [Packet ID if QoS > 0]
        """
        qos = (packet_type & 0x06) >> 1   # QoS level from flags bits 2-1
        retain = bool(packet_type & 0x01)

        offset = 0
        topic, offset = _decode_utf8_string(payload, offset)

        # Packet ID only present for QoS 1 and 2
        pkt_id = 0
        if qos > 0 and offset + 2 <= len(payload):
            pkt_id  = struct.unpack_from(">H", payload, offset)[0]
            offset += 2

        # Remaining payload is the message
        message_bytes = payload[offset:]
        try:
            message = message_bytes.decode("utf-8", errors="replace")
        except Exception:
            message = message_bytes.hex()

        log.attack(ip, port, "mqtt_publish", raw, {
            "topic":   topic,
            "message": message,
            "qos":     qos,
            "retain":  retain,
            "pkt_id":  pkt_id
        })

        # Send PUBACK for QoS 1
        if qos == 1:
            return bytes([PKT_PUBACK, 0x02]) + struct.pack(">H", pkt_id)
        return None

    def _handle_subscribe(self, ip: str, port: int, payload: bytes, raw: bytes) -> bytes:
        """
        Parse MQTT SUBSCRIBE packet.
        Reveals which topics an attacker is monitoring.

        SUBSCRIBE Payload: Packet ID (2B) + [Topic Filter (UTF-8) + QoS (1B)]*
        """
        if len(payload) < 2:
            return bytes([PKT_SUBACK, 0x03, 0x00, 0x00, 0x00])

        pkt_id  = struct.unpack_from(">H", payload, 0)[0]
        offset  = 2
        topics  = []
        granted_qos = b""

        # Parse all topic filters in this packet
        while offset < len(payload):
            topic, offset = _decode_utf8_string(payload, offset)
            if not topic:
                break
            requested_qos = payload[offset] if offset < len(payload) else 0
            offset += 1
            topics.append({"topic": topic, "requested_qos": requested_qos})
            granted_qos += bytes([requested_qos])   # grant whatever they ask for

        log.attack(ip, port, "mqtt_subscribe", raw, {
            "packet_id": pkt_id,
            "topics":    topics,
            "note":      "Attacker subscribing to sensor topics"
        })

        # SUBACK: ACK with granted QoS for each topic
        remaining = struct.pack(">H", pkt_id) + granted_qos
        return bytes([PKT_SUBACK, len(remaining)]) + remaining

    # ------------------------------------------------------------------
    # Helper: build CONNACK packet
    # ------------------------------------------------------------------

    @staticmethod
    def _connack(return_code: int) -> bytes:
        """
        Build a CONNACK packet.
        return_code 0x00 = Connection Accepted
        return_code 0x04 = Bad username/password (we never send this — always accept)
        """
        # CONNACK: Fixed header (0x20, 0x02) + Session Present (0) + Return Code
        return bytes([PKT_CONNACK, 0x02, 0x00, return_code])
