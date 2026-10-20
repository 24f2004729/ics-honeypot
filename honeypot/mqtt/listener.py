# =============================================================================
#  ics_honeypot / mqtt / listener.py
#  ---------------------------------------------------------------------------
#  MQTT (ISO/IEC 20922) Honeypot Listener & Credential Harvester
#  ---------------------------------------------------------------------------
#  Features:
#    • Plaintext credential harvesting on CONNECT (MITRE ATT&CK T0812)
#    • Topic monitoring and probe detection on SUBSCRIBE / PUBLISH
#    • Realistic CONNACK / SUBACK / PUBACK responses
#    • Memory limit safeguards and connection limits
# =============================================================================

import socket
import struct
import threading
from typing import Optional, Tuple

from honeypot.shared.config import (
    MQTT_PORT, SOCKET_BACKLOG, SOCKET_TIMEOUT, RECV_BUFFER, MAX_BUFFER_SIZE
)
from honeypot.shared.logger import HoneypotLogger
from honeypot.shared.guard import guard

log = HoneypotLogger("MQTT")

# MQTT Packet Types
PKT_CONNECT     = 0x10
PKT_CONNACK     = 0x20
PKT_PUBLISH     = 0x30
PKT_PUBACK      = 0x40
PKT_SUBSCRIBE   = 0x82
PKT_SUBACK      = 0x90
PKT_UNSUBSCRIBE = 0xA2
PKT_UNSUBACK    = 0xB0
PKT_PINGREQ     = 0xC0
PKT_PINGRESP    = 0xD0
PKT_DISCONNECT  = 0xE0


def _decode_remaining_length(data: bytes, offset: int) -> Tuple[int, int]:
    multiplier = 1
    value = 0
    consumed = 0

    for _ in range(4):
        if offset + consumed >= len(data):
            return -1, 0
        byte = data[offset + consumed]
        consumed += 1
        value += (byte & 0x7F) * multiplier
        multiplier *= 128
        if not (byte & 0x80):
            break

    return value, consumed


def _decode_utf8_string(data: bytes, offset: int) -> Tuple[str, int]:
    if offset + 2 > len(data):
        return "", offset
    length = struct.unpack_from(">H", data, offset)[0]
    offset += 2
    if offset + length > len(data):
        return "", offset
    text = data[offset:offset + length].decode("utf-8", errors="replace")
    return text, offset + length


class MQTTListener:
    """
    Fake MQTT Broker and Credential Harvester.
    """

    def __init__(self, host: str = "0.0.0.0", port: int = MQTT_PORT):
        self.host = host
        self.port = port
        self._stop_event = threading.Event()
        self._server_socket: Optional[socket.socket] = None

    def start(self):
        t = threading.Thread(target=self._serve, daemon=True, name="MQTTListener")
        t.start()
        log.info(f"Listening on {self.host}:{self.port}")

    def stop(self):
        self._stop_event.set()
        if self._server_socket:
            try:
                self._server_socket.close()
            except Exception:
                pass

    def _serve(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            self._server_socket = server
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

                ip, port = addr
                if not guard.acquire(ip):
                    try:
                        conn.close()
                    except Exception:
                        pass
                    continue

                t = threading.Thread(
                    target=self._handle_client,
                    args=(conn, addr),
                    daemon=True,
                    name=f"MQTT-{ip}:{port}"
                )
                t.start()

    def _handle_client(self, conn: socket.socket, addr: Tuple[str, int]):
        ip, port = addr
        log.connection(ip, port)
        conn.settimeout(SOCKET_TIMEOUT)

        buffer = b""

        try:
            while not self._stop_event.is_set():
                chunk = conn.recv(RECV_BUFFER)
                if not chunk:
                    break

                buffer += chunk

                if len(buffer) > MAX_BUFFER_SIZE:
                    log.error(ip, port, "Buffer threshold exceeded — dropping connection")
                    break

                while True:
                    consumed, response = self._process_packet(ip, port, buffer)
                    if consumed == 0:
                        break
                    buffer = buffer[consumed:]
                    if response:
                        conn.sendall(response)

        except (socket.timeout, ConnectionResetError):
            pass
        except Exception as exc:
            log.error(ip, port, f"Unexpected MQTT exception: {exc}")
        finally:
            guard.release(ip)
            try:
                conn.close()
            except Exception:
                pass
            log.disconnection(ip, port)

    def _process_packet(self, ip: str, port: int, data: bytes) -> Tuple[int, Optional[bytes]]:
        if len(data) < 2:
            return 0, None

        packet_type = data[0]
        remaining_length, len_bytes = _decode_remaining_length(data, 1)
        if remaining_length < 0:
            return 0, None

        header_size = 1 + len_bytes
        total_size = header_size + remaining_length

        if len(data) < total_size:
            return 0, None

        payload = data[header_size:total_size]
        pkt_upper = packet_type & 0xF0

        if pkt_upper == 0x10:
            response = self._handle_connect(ip, port, payload, data[:total_size])
        elif pkt_upper == 0x30:
            response = self._handle_publish(ip, port, payload, packet_type, data[:total_size])
        elif pkt_upper == 0x80:
            response = self._handle_subscribe(ip, port, payload, data[:total_size])
        elif pkt_upper == 0xA0:
            log.attack(ip, port, "mqtt_unsubscribe", data[:total_size], {})
            pkt_id = struct.unpack_from(">H", payload, 0)[0] if len(payload) >= 2 else 0
            response = bytes([0xB0, 0x02]) + struct.pack(">H", pkt_id)
        elif pkt_upper == 0xC0:
            response = bytes([0xD0, 0x00])  # PINGRESP
        elif pkt_upper == 0xE0:
            log.attack(ip, port, "mqtt_disconnect", data[:total_size], {
                "note": "Client sent DISCONNECT packet"
            })
            response = None
        else:
            log.error(ip, port, f"Unknown MQTT packet: 0x{packet_type:02X}")
            response = None

        return total_size, response

    def _handle_connect(self, ip: str, port: int, payload: bytes, raw: bytes) -> bytes:
        offset = 0
        proto_name, offset = _decode_utf8_string(payload, offset)

        if offset >= len(payload):
            return self._connack(0)

        proto_level = payload[offset]; offset += 1
        connect_flags = payload[offset]; offset += 1
        keepalive = struct.unpack_from(">H", payload, offset)[0] if offset + 2 <= len(payload) else 60
        offset += 2

        has_username  = bool(connect_flags & 0x80)
        has_password  = bool(connect_flags & 0x40)
        has_will      = bool(connect_flags & 0x04)
        clean_session = bool(connect_flags & 0x02)

        client_id, offset = _decode_utf8_string(payload, offset)
        will_topic = will_message = ""
        if has_will:
            will_topic, offset = _decode_utf8_string(payload, offset)
            will_message, offset = _decode_utf8_string(payload, offset)

        username = password = ""
        if has_username:
            username, offset = _decode_utf8_string(payload, offset)
        if has_password:
            password, offset = _decode_utf8_string(payload, offset)

        severity = "HIGH" if (username or password) else "MEDIUM"
        log.attack(ip, port, f"mqtt_connect [{severity}]", raw, {
            "protocol": proto_name,
            "version": proto_level,
            "client_id": client_id,
            "username": username or "(none)",
            "password": password or "(none)",
            "will_topic": will_topic or "(none)",
            "clean_session": clean_session,
            "keepalive_sec": keepalive,
            "severity": severity
        })

        # Return connection accepted (0x00)
        return self._connack(0)

    def _handle_publish(
        self,
        ip: str, port: int,
        payload: bytes,
        packet_type: int,
        raw: bytes
    ) -> Optional[bytes]:
        qos = (packet_type & 0x06) >> 1
        retain = bool(packet_type & 0x01)

        offset = 0
        topic, offset = _decode_utf8_string(payload, offset)

        pkt_id = 0
        if qos > 0 and offset + 2 <= len(payload):
            pkt_id = struct.unpack_from(">H", payload, offset)[0]
            offset += 2

        message_bytes = payload[offset:]
        try:
            message = message_bytes.decode("utf-8", errors="replace")
        except Exception:
            message = message_bytes.hex()

        log.attack(ip, port, "mqtt_publish", raw, {
            "topic": topic,
            "message": message,
            "qos": qos,
            "retain": retain,
            "pkt_id": pkt_id
        })

        if qos == 1:
            return bytes([PKT_PUBACK, 0x02]) + struct.pack(">H", pkt_id)
        return None

    def _handle_subscribe(self, ip: str, port: int, payload: bytes, raw: bytes) -> bytes:
        if len(payload) < 2:
            return bytes([PKT_SUBACK, 0x03, 0x00, 0x00, 0x00])

        pkt_id = struct.unpack_from(">H", payload, 0)[0]
        offset = 2
        topics = []
        granted_qos = b""

        while offset < len(payload):
            topic, offset = _decode_utf8_string(payload, offset)
            if not topic:
                break
            requested_qos = payload[offset] if offset < len(payload) else 0
            offset += 1
            topics.append({"topic": topic, "requested_qos": requested_qos})
            granted_qos += bytes([requested_qos])

        log.attack(ip, port, "mqtt_subscribe", raw, {
            "packet_id": pkt_id,
            "topics": topics
        })

        remaining = struct.pack(">H", pkt_id) + granted_qos
        return bytes([PKT_SUBACK, len(remaining)]) + remaining

    @staticmethod
    def _connack(return_code: int) -> bytes:
        return bytes([PKT_CONNACK, 0x02, 0x00, return_code])
