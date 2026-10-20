# =============================================================================
#  ics_honeypot / modbus / listener.py
#  ---------------------------------------------------------------------------
#  Modbus TCP (IEC 61158) Honeypot Listener
#  ---------------------------------------------------------------------------
#  Features:
#    • Full TCP stream reassembly (handles segmented / concatenated frames)
#    • Dynamic process simulator integration (thermodynamic drift & actuator loop)
#    • Interactive actuator state: FC05 writes dynamically change physical telemetry!
#    • Function codes: FC01, FC02, FC03, FC04, FC05, FC06, FC16, FC08, FC43 (MEI)
#    • Anti-DoS connection limits and buffer boundaries
#    • Full MITRE ATT&CK for ICS classification
# =============================================================================

import socket
import struct
import threading
from typing import Tuple, Optional, Dict, Any

from honeypot.shared.config import (
    MODBUS_PORT, SOCKET_BACKLOG, SOCKET_TIMEOUT, RECV_BUFFER, MAX_BUFFER_SIZE,
    MODBUS_VENDOR, MODBUS_PRODUCT, MODBUS_VERSION
)
from honeypot.shared.logger import HoneypotLogger
from honeypot.shared.guard import guard
from honeypot.simulation.process import simulator

log = HoneypotLogger("Modbus")

# Modbus Function Codes
FC_READ_COILS               = 0x01
FC_READ_DISCRETE_INPUTS     = 0x02
FC_READ_HOLDING_REGISTERS   = 0x03
FC_READ_INPUT_REGISTERS     = 0x04
FC_WRITE_SINGLE_COIL        = 0x05
FC_WRITE_SINGLE_REGISTER    = 0x06
FC_DIAGNOSTICS              = 0x08
FC_WRITE_MULTIPLE_REGISTERS = 0x10
FC_MEI_TRANSPORT            = 0x2B

# Exception Codes
FC_EXCEPTION_FLAG           = 0x80
EX_ILLEGAL_FUNCTION         = 0x01
EX_ILLEGAL_DATA_ADDRESS     = 0x02
EX_ILLEGAL_DATA_VALUE       = 0x03


class ModbusListener:
    """
    Industrial-grade Modbus TCP Honeypot with streaming frame reassembly.
    """

    def __init__(self, host: str = "0.0.0.0", port: int = MODBUS_PORT):
        self.host = host
        self.port = port
        self._stop_event = threading.Event()
        self._server_socket: Optional[socket.socket] = None

    def start(self):
        t = threading.Thread(target=self._serve, daemon=True, name="ModbusListener")
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
                    # Connection limit exceeded — protect honeypot against DoS
                    try:
                        conn.close()
                    except Exception:
                        pass
                    continue

                t = threading.Thread(
                    target=self._handle_client,
                    args=(conn, addr),
                    daemon=True,
                    name=f"Modbus-{ip}:{port}"
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

                # Anti-DoS: drop connection if buffer exceeds maximum threshold without valid framing
                if len(buffer) > MAX_BUFFER_SIZE:
                    log.error(ip, port, "Buffer threshold exceeded — dropping connection to prevent DoS")
                    break

                # Frame Reassembly Loop: Parse all complete Modbus frames in buffer
                while len(buffer) >= 7:
                    txn_id, proto_id, length = struct.unpack_from(">HHH", buffer, 0)

                    # Protocol ID must be 0x0000 for Modbus TCP
                    if proto_id != 0x0000:
                        log.error(ip, port, f"Invalid Modbus protocol ID: 0x{proto_id:04X} — non-Modbus probe")
                        buffer = b""
                        break

                    total_frame = 6 + length
                    if len(buffer) < total_frame:
                        # Fragmented TCP packet: wait for remaining bytes
                        break

                    # Extract one complete Modbus frame
                    frame_data = buffer[:total_frame]
                    buffer = buffer[total_frame:]

                    response = self._process_frame(ip, port, frame_data)
                    if response:
                        conn.sendall(response)

        except (socket.timeout, ConnectionResetError):
            pass
        except Exception as exc:
            log.error(ip, port, f"Unexpected exception in client handler: {exc}")
        finally:
            guard.release(ip)
            try:
                conn.close()
            except Exception:
                pass
            log.disconnection(ip, port)

    def _process_frame(self, ip: str, port: int, data: bytes) -> Optional[bytes]:
        """Process a complete, reassembled Modbus frame."""
        txn_id, proto_id, length = struct.unpack_from(">HHH", data, 0)
        unit_id = data[6]
        pdu = data[7:]

        if not pdu:
            return None

        fc = pdu[0]
        payload = pdu[1:]

        response_pdu = self._dispatch(ip, port, fc, payload, data)
        if response_pdu is None:
            return None

        resp_length = len(response_pdu) + 1
        return struct.pack(">HHHB", txn_id, 0x0000, resp_length, unit_id) + response_pdu

    def _dispatch(self, ip: str, port: int, fc: int, payload: bytes, raw: bytes) -> Optional[bytes]:
        if fc == FC_READ_HOLDING_REGISTERS:
            return self._fc03_read_holding(ip, port, payload, raw)
        elif fc == FC_READ_INPUT_REGISTERS:
            return self._fc04_read_input(ip, port, payload, raw)
        elif fc == FC_READ_COILS:
            return self._fc01_read_coils(ip, port, payload, raw)
        elif fc == FC_READ_DISCRETE_INPUTS:
            return self._fc02_read_discrete(ip, port, payload, raw)
        elif fc == FC_WRITE_SINGLE_COIL:
            return self._fc05_write_coil(ip, port, payload, raw)
        elif fc == FC_WRITE_SINGLE_REGISTER:
            return self._fc06_write_register(ip, port, payload, raw)
        elif fc == FC_WRITE_MULTIPLE_REGISTERS:
            return self._fc16_write_multiple_registers(ip, port, payload, raw)
        elif fc == FC_DIAGNOSTICS:
            return self._fc08_diagnostics(ip, port, payload, raw)
        elif fc == FC_MEI_TRANSPORT:
            return self._fc43_mei(ip, port, payload, raw)
        else:
            log.attack(ip, port, f"unknown_fc_0x{fc:02X}", raw, {
                "function_code": f"0x{fc:02X}",
                "note": "Illegal Function exception returned"
            })
            return bytes([FC_EXCEPTION_FLAG | fc, EX_ILLEGAL_FUNCTION])

    # -------------------------------------------------------------------------
    # Handlers with Dynamic Physics Simulation
    # -------------------------------------------------------------------------

    def _fc03_read_holding(self, ip: str, port: int, payload: bytes, raw: bytes) -> bytes:
        if len(payload) < 4:
            return bytes([FC_EXCEPTION_FLAG | FC_READ_HOLDING_REGISTERS, EX_ILLEGAL_DATA_VALUE])

        start_addr, quantity = struct.unpack_from(">HH", payload, 0)
        if quantity < 1 or quantity > 125:
            return bytes([FC_EXCEPTION_FLAG | FC_READ_HOLDING_REGISTERS, EX_ILLEGAL_DATA_VALUE])

        log.attack(ip, port, "read_holding_registers", raw, {
            "function_code": "0x03",
            "start_address": start_addr,
            "quantity": quantity
        })

        # Fetch live dynamic telemetry from physics process simulation
        reg_map = simulator.get_holding_registers(start_addr, quantity)
        reg_bytes = b""
        logged_data = {}

        for i in range(quantity):
            addr = start_addr + i
            name, val = reg_map[addr]
            reg_bytes += struct.pack(">H", val)
            if i < 8:
                logged_data[name] = val

        log.response(ip, port, "read_holding_registers", logged_data)
        return bytes([FC_READ_HOLDING_REGISTERS, len(reg_bytes)]) + reg_bytes

    def _fc04_read_input(self, ip: str, port: int, payload: bytes, raw: bytes) -> bytes:
        if len(payload) < 4:
            return bytes([FC_EXCEPTION_FLAG | FC_READ_INPUT_REGISTERS, EX_ILLEGAL_DATA_VALUE])

        start_addr, quantity = struct.unpack_from(">HH", payload, 0)
        if quantity < 1 or quantity > 125:
            return bytes([FC_EXCEPTION_FLAG | FC_READ_INPUT_REGISTERS, EX_ILLEGAL_DATA_VALUE])

        log.attack(ip, port, "read_input_registers", raw, {
            "function_code": "0x04",
            "start_address": start_addr,
            "quantity": quantity
        })

        reg_map = simulator.get_holding_registers(start_addr, quantity)
        reg_bytes = b"".join(struct.pack(">H", reg_map[start_addr + i][1]) for i in range(quantity))
        return bytes([FC_READ_INPUT_REGISTERS, len(reg_bytes)]) + reg_bytes

    def _fc01_read_coils(self, ip: str, port: int, payload: bytes, raw: bytes) -> bytes:
        if len(payload) < 4:
            return bytes([FC_EXCEPTION_FLAG | FC_READ_COILS, EX_ILLEGAL_DATA_VALUE])

        start_addr, quantity = struct.unpack_from(">HH", payload, 0)
        if quantity < 1 or quantity > 2000:
            return bytes([FC_EXCEPTION_FLAG | FC_READ_COILS, EX_ILLEGAL_DATA_VALUE])

        log.attack(ip, port, "read_coils", raw, {
            "function_code": "0x01",
            "start_address": start_addr,
            "quantity": quantity
        })

        # Build bitfield from real simulated actuator states
        byte_count = (quantity + 7) // 8
        bitfield = 0
        for i in range(quantity):
            if simulator.get_coil(start_addr + i):
                bitfield |= (1 << i)

        coil_bytes = bitfield.to_bytes(byte_count, byteorder="little")
        return bytes([FC_READ_COILS, byte_count]) + coil_bytes

    def _fc02_read_discrete(self, ip: str, port: int, payload: bytes, raw: bytes) -> bytes:
        if len(payload) < 4:
            return bytes([FC_EXCEPTION_FLAG | FC_READ_DISCRETE_INPUTS, EX_ILLEGAL_DATA_VALUE])

        start_addr, quantity = struct.unpack_from(">HH", payload, 0)
        if quantity < 1 or quantity > 2000:
            return bytes([FC_EXCEPTION_FLAG | FC_READ_DISCRETE_INPUTS, EX_ILLEGAL_DATA_VALUE])

        log.attack(ip, port, "read_discrete_inputs", raw, {
            "function_code": "0x02",
            "start_address": start_addr,
            "quantity": quantity
        })

        byte_count = (quantity + 7) // 8
        bitfield = 0
        for i in range(quantity):
            if simulator.get_discrete_input(start_addr + i):
                bitfield |= (1 << i)

        return bytes([FC_READ_DISCRETE_INPUTS, byte_count]) + bitfield.to_bytes(byte_count, byteorder="little")

    def _fc05_write_coil(self, ip: str, port: int, payload: bytes, raw: bytes) -> bytes:
        """
        FC 0x05 — Write Single Coil (Interactive actuator control).
        Attacker command dynamically impacts simulated physical process!
        """
        if len(payload) < 4:
            return bytes([FC_EXCEPTION_FLAG | FC_WRITE_SINGLE_COIL, EX_ILLEGAL_DATA_VALUE])

        coil_addr, coil_val = struct.unpack_from(">HH", payload, 0)
        is_on = (coil_val == 0xFF00)

        # Update physical process state
        simulator.set_coil(coil_addr, is_on)

        action_name = "Cooling Fan" if coil_addr == 0 else ("Emergency Cutoff" if coil_addr == 1 else f"Actuator #{coil_addr}")
        log.attack(ip, port, "WRITE_single_coil [CRITICAL]", raw, {
            "function_code": "0x05",
            "coil_address": coil_addr,
            "value": "ON" if is_on else "OFF",
            "actuator_target": action_name,
            "severity": "CRITICAL"
        })

        return bytes([FC_WRITE_SINGLE_COIL]) + payload[:4]

    def _fc06_write_register(self, ip: str, port: int, payload: bytes, raw: bytes) -> bytes:
        if len(payload) < 4:
            return bytes([FC_EXCEPTION_FLAG | FC_WRITE_SINGLE_REGISTER, EX_ILLEGAL_DATA_VALUE])

        reg_addr, value = struct.unpack_from(">HH", payload, 0)
        log.attack(ip, port, "WRITE_single_register [HIGH]", raw, {
            "function_code": "0x06",
            "register": reg_addr,
            "value_written": value,
            "severity": "HIGH"
        })
        return bytes([FC_WRITE_SINGLE_REGISTER]) + payload[:4]

    def _fc16_write_multiple_registers(self, ip: str, port: int, payload: bytes, raw: bytes) -> bytes:
        if len(payload) < 5:
            return bytes([FC_EXCEPTION_FLAG | FC_WRITE_MULTIPLE_REGISTERS, EX_ILLEGAL_DATA_VALUE])

        start_addr, quantity = struct.unpack_from(">HH", payload, 0)
        log.attack(ip, port, "WRITE_multiple_registers [CRITICAL]", raw, {
            "function_code": "0x10",
            "start_address": start_addr,
            "quantity": quantity,
            "severity": "CRITICAL"
        })
        return bytes([FC_WRITE_MULTIPLE_REGISTERS]) + struct.pack(">HH", start_addr, quantity)

    def _fc08_diagnostics(self, ip: str, port: int, payload: bytes, raw: bytes) -> Optional[bytes]:
        sub_func = struct.unpack_from(">H", payload, 0)[0] if len(payload) >= 2 else 0
        if sub_func == 0x0004:
            log.attack(ip, port, "FORCE_LISTEN_ONLY [HIGH]", raw, {
                "function_code": "0x08",
                "sub_function": "0x0004",
                "note": "Force Listen Only Mode DoS attempt"
            })
            return None  # Standard Modbus: In Listen Only Mode, slave returns no response

        log.attack(ip, port, "diagnostics_request", raw, {
            "function_code": "0x08",
            "sub_function": sub_func,
            "note": "PLC diagnostics / fingerprinting"
        })
        return bytes([FC_DIAGNOSTICS]) + payload

    def _fc43_mei(self, ip: str, port: int, payload: bytes, raw: bytes) -> bytes:
        """
        FC 0x2B / MEI 0x0E — Read Device Identification.
        Returns authentic vendor and model strings configured in active profile.
        """
        log.attack(ip, port, "device_identification_MEI", raw, {
            "function_code": "0x2B",
            "profile_vendor": MODBUS_VENDOR,
            "profile_product": MODBUS_PRODUCT
        })

        def mei_object(obj_id: int, value: str) -> bytes:
            encoded = value.encode("ascii")
            return bytes([obj_id, len(encoded)]) + encoded

        objects = (
            mei_object(0x00, MODBUS_VENDOR) +
            mei_object(0x01, MODBUS_PRODUCT) +
            mei_object(0x02, MODBUS_VERSION)
        )

        header = bytes([
            FC_MEI_TRANSPORT,
            0x0E,   # MEI type: Read Device Identification
            0x01,   # Read Device ID code: Basic identification
            0x01,   # Conformity level: Basic stream access
            0x00,   # More follows: No
            0x00,   # Next Object Id: 0
            0x03    # Number of objects: 3
        ])
        return header + objects
