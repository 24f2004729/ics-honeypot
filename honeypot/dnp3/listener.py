# =============================================================================
#  ics_honeypot / dnp3 / listener.py
#  ---------------------------------------------------------------------------
#  DNP3 (IEEE 1815) SCADA Honeypot Listener
#  ---------------------------------------------------------------------------
#  Features:
#    • Full TCP stream reassembly with start-byte synchronization (0x05 0x64)
#    • Strict CRC-16 (polynomial 0xA6BC) verification on Data Link frames
#    • Live dynamic telemetry from Process Simulator (Group 30 Var 5)
#    • Detection and logging of OPERATE / DIRECT OPERATE (MITRE T0855)
#    • Anti-DoS connection limits and memory safeguards
# =============================================================================

import socket
import struct
import threading
from typing import Optional, Tuple

from honeypot.shared.config import (
    DNP3_PORT, SOCKET_BACKLOG, SOCKET_TIMEOUT, RECV_BUFFER, MAX_BUFFER_SIZE,
    DNP3_OUTSTATION_ADDR, DNP3_MASTER_ADDR
)
from honeypot.shared.logger import HoneypotLogger
from honeypot.shared.guard import guard
from honeypot.simulation.process import simulator

log = HoneypotLogger("DNP3")

# DNP3 Constants
DNP3_START_BYTE_1 = 0x05
DNP3_START_BYTE_2 = 0x64
DNP3_HEADER_SIZE  = 10

# Application Layer Function Codes
FC_CONFIRM        = 0x00
FC_READ           = 0x01   # Class 0/1/2/3 poll
FC_WRITE          = 0x02
FC_SELECT         = 0x03
FC_OPERATE        = 0x04   # CRITICAL
FC_DIRECT_OPERATE = 0x05   # CRITICAL
FC_RESPONSE       = 0x81

# Application Control Masks
AC_FIR_BIT        = 0x80
AC_FIN_BIT        = 0x40


def _build_crc_table() -> list:
    table = []
    for i in range(256):
        crc = i
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA6BC
            else:
                crc >>= 1
        table.append(crc)
    return table

_CRC_TABLE = _build_crc_table()


def dnp3_crc(data: bytes) -> int:
    crc = 0x0000
    for byte in data:
        crc = _CRC_TABLE[(crc ^ byte) & 0xFF] ^ (crc >> 8)
    return (~crc) & 0xFFFF


def _append_crc(data: bytes) -> bytes:
    crc = dnp3_crc(data)
    return data + struct.pack("<H", crc)


class DNP3Listener:
    """
    Fake DNP3 Outstation with streaming frame reassembly and CRC verification.
    """

    def __init__(self, host: str = "0.0.0.0", port: int = DNP3_PORT):
        self.host = host
        self.port = port
        self._stop_event = threading.Event()
        self._server_socket: Optional[socket.socket] = None

    def start(self):
        t = threading.Thread(target=self._serve, daemon=True, name="DNP3Listener")
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
                    name=f"DNP3-{ip}:{port}"
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

                # Frame Reassembly with Synchronization Search
                while len(buffer) >= DNP3_HEADER_SIZE:
                    # Look for DNP3 sync pattern (0x05 0x64)
                    sync_idx = -1
                    for i in range(len(buffer) - 1):
                        if buffer[i] == DNP3_START_BYTE_1 and buffer[i + 1] == DNP3_START_BYTE_2:
                            sync_idx = i
                            break

                    if sync_idx == -1:
                        # No sync pattern found in buffer; discard garbage except last byte
                        buffer = buffer[-1:]
                        break

                    if sync_idx > 0:
                        # Drop pre-sync bytes
                        buffer = buffer[sync_idx:]

                    if len(buffer) < DNP3_HEADER_SIZE:
                        break

                    dl_length = buffer[2]
                    if dl_length < 5:
                        # Corrupted/fuzzed length: discard sync bytes and search for next frame
                        buffer = buffer[2:]
                        continue

                    # Total frame length = 3 bytes (sync1, sync2, len) + dl_length
                    total_frame = 3 + dl_length

                    if len(buffer) < total_frame:
                        # Incomplete frame — wait for more segments
                        break

                    frame_data = buffer[:total_frame]
                    buffer = buffer[total_frame:]

                    response = self._process_frame(ip, port, frame_data)
                    if response:
                        conn.sendall(response)

        except (socket.timeout, ConnectionResetError):
            pass
        except Exception as exc:
            log.error(ip, port, f"Unexpected DNP3 client exception: {exc}")
        finally:
            guard.release(ip)
            try:
                conn.close()
            except Exception:
                pass
            log.disconnection(ip, port)

    def _process_frame(self, ip: str, port: int, data: bytes) -> Optional[bytes]:
        if len(data) < DNP3_HEADER_SIZE:
            return None

        # Verify header CRC
        header_data = data[:8]
        expected_crc = struct.unpack_from("<H", data, 8)[0]
        actual_crc   = dnp3_crc(header_data)
        if expected_crc != actual_crc:
            log.error(ip, port, f"DNP3 header CRC mismatch (expected: 0x{expected_crc:04X}, calculated: 0x{actual_crc:04X})")
            return None

        dst_addr = struct.unpack_from("<H", data, 4)[0]
        src_addr = struct.unpack_from("<H", data, 6)[0]

        app_bytes = self._extract_app_layer(data[10:])
        if not app_bytes or len(app_bytes) < 2:
            return None

        app_control = app_bytes[0]
        app_fc      = app_bytes[1]
        app_objects = app_bytes[2:]

        return self._dispatch_app(ip, port, app_fc, app_objects, src_addr, app_control, data)

    def _extract_app_layer(self, block_data: bytes) -> bytes:
        """Extract application payload from 16-byte blocks with CRC stripping."""
        app_bytes = b""
        offset = 0
        while offset + 2 <= len(block_data):
            payload_end = min(offset + 16, len(block_data) - 2)
            app_bytes  += block_data[offset:payload_end]
            offset     += 18
        return app_bytes

    def _dispatch_app(
        self,
        ip: str, port: int,
        fc: int, objects: bytes,
        master_addr: int,
        app_ctrl: int,
        raw: bytes
    ) -> Optional[bytes]:
        if fc == FC_READ:
            return self._handle_read(ip, port, objects, master_addr, app_ctrl, raw)

        elif fc == FC_CONFIRM:
            log.attack(ip, port, "dnp3_confirm", raw, {
                "function_code": "0x00",
                "note": "Master confirmed previous response"
            })
            return None

        elif fc == FC_WRITE:
            log.attack(ip, port, "WRITE_attempt [HIGH]", raw, {
                "function_code": "0x02",
                "severity": "HIGH",
                "note": "Attacker attempting DNP3 point write"
            })
            return self._build_response(master_addr, app_ctrl, FC_RESPONSE, b"")

        elif fc in (FC_OPERATE, FC_DIRECT_OPERATE):
            label = "OPERATE" if fc == FC_OPERATE else "DIRECT_OPERATE"
            log.attack(ip, port, f"{label} [CRITICAL]", raw, {
                "function_code": f"0x{fc:02X}",
                "severity": "CRITICAL",
                "note": "Attacker attempting physical relay/breaker trip"
            })
            # Interactive response: trip emergency cutoff in simulated plant
            simulator.set_coil(1, True)
            return self._build_response(master_addr, app_ctrl, FC_RESPONSE, b"")

        elif fc == FC_SELECT:
            log.attack(ip, port, "SELECT_before_operate [HIGH]", raw, {
                "function_code": "0x03",
                "severity": "HIGH",
                "note": "SELECT phase of Select-Before-Operate sequence"
            })
            return self._build_response(master_addr, app_ctrl, FC_RESPONSE, b"")

        else:
            log.attack(ip, port, f"unknown_fc_0x{fc:02X}", raw, {"function_code": f"0x{fc:02X}"})
            return None

    def _handle_read(
        self,
        ip: str, port: int,
        objects: bytes,
        master_addr: int,
        app_ctrl: int,
        raw: bytes
    ) -> bytes:
        group     = objects[0] if len(objects) > 0 else 0
        variation = objects[1] if len(objects) > 1 else 0
        qualifier = objects[2] if len(objects) > 2 else 0

        poll_type = "class0_integrity_poll"
        if group == 60:
            class_map = {1: "class0", 2: "class1", 3: "class2", 4: "class3"}
            poll_type = class_map.get(variation, f"class_group60_var{variation}")

        log.attack(ip, port, f"dnp3_read_{poll_type}", raw, {
            "function_code": "0x01",
            "group": group,
            "variation": variation,
            "qualifier": f"0x{qualifier:02X}"
        })

        # Dynamic telemetry: Group 30 Var 5 (32-bit float analogue input)
        temp_val = simulator.current_oil_temp
        obj_header = bytes([
            0x1E, 0x05,   # Group 30, Variation 5
            0x28,         # Qualifier: 16-bit count, 16-bit index
            0x01, 0x00,   # Count = 1
            0x00, 0x00    # Index = 0 (Oil Temp Sensor)
        ])
        obj_data = bytes([0x01]) + struct.pack("<f", temp_val)
        response_objects = obj_header + obj_data

        log.response(ip, port, f"dnp3_read_{poll_type}", {
            "group30_var5_temp": f"{round(temp_val, 2)}°C"
        })

        return self._build_response(master_addr, app_ctrl, FC_RESPONSE, response_objects)

    def _build_response(
        self,
        master_addr: int,
        req_app_ctrl: int,
        fc: int,
        app_objects: bytes
    ) -> bytes:
        seq_num  = req_app_ctrl & 0x0F
        app_ctrl = AC_FIR_BIT | AC_FIN_BIT | seq_num
        app_layer = bytes([app_ctrl, fc, 0x00, 0x00]) + app_objects

        data_blocks = b""
        for i in range(0, len(app_layer), 16):
            block = app_layer[i:i + 16]
            data_blocks += _append_crc(block)

        dl_length = 5 + len(data_blocks)
        dl_control = 0x44
        header_body = bytes([
            DNP3_START_BYTE_1, DNP3_START_BYTE_2,
            dl_length,
            dl_control
        ]) + struct.pack("<H", master_addr) + struct.pack("<H", DNP3_OUTSTATION_ADDR)

        return _append_crc(header_body) + data_blocks
