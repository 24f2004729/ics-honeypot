# =============================================================================
#  ics_honeypot / modbus / listener.py
#  ---------------------------------------------------------------------------
#  Modbus TCP Honeypot Listener
#  ---------------------------------------------------------------------------
#  Implements a convincing fake Modbus TCP slave that:
#    • Accepts connections on port 502 (configurable)
#    • Parses the 7-byte MBAP header + PDU correctly
#    • Handles the most common function codes an attacker would use
#    • Returns realistic fake sensor register values
#    • Logs every request with full decoded fields to both log file and JSONL
#
#  Modbus TCP Frame Structure (for reference):
#  ┌─────────────────────────────────────────────────────────┐
#  │  MBAP Header (7 bytes)          │  PDU (variable)       │
#  │  ┌──────┬──────┬────────┬────┐  │  ┌──────┬──────────┐  │
#  │  │TxnID │Proto │Length  │UID │  │  │ FC   │ Data     │  │
#  │  │2B    │2B    │2B      │1B  │  │  │ 1B   │ variable │  │
#  │  └──────┴──────┴────────┴────┘  │  └──────┴──────────┘  │
#  └─────────────────────────────────────────────────────────┘
#  TxnID  = Transaction Identifier (echoed back in response)
#  Proto  = Protocol Identifier (always 0x0000 for Modbus)
#  Length = byte count of remaining message (UID + PDU)
#  UID    = Unit Identifier (slave/device address)
#  FC     = Function Code
# =============================================================================

import socket
import struct
import threading

from honeypot.shared.config  import MODBUS_PORT, SOCKET_BACKLOG, SOCKET_TIMEOUT, RECV_BUFFER
from honeypot.shared.config  import MODBUS_REGISTER_MAP, MODBUS_VENDOR, MODBUS_PRODUCT, MODBUS_VERSION
from honeypot.shared.logger  import HoneypotLogger

log = HoneypotLogger("Modbus")

# ---------------------------------------------------------------------------
# Modbus Function Code constants — only the codes relevant to a honeypot
# ---------------------------------------------------------------------------
FC_READ_COILS               = 0x01
FC_READ_DISCRETE_INPUTS     = 0x02
FC_READ_HOLDING_REGISTERS   = 0x03   # most common scan target
FC_READ_INPUT_REGISTERS     = 0x04
FC_WRITE_SINGLE_COIL        = 0x05
FC_WRITE_SINGLE_REGISTER    = 0x06
FC_WRITE_MULTIPLE_REGISTERS = 0x10
FC_DIAGNOSTICS              = 0x08
FC_MEI_TRANSPORT            = 0x2B   # device identification request

# Exception code — OR'd with FC to indicate an error response
FC_EXCEPTION_FLAG           = 0x80

# Modbus exception codes
EX_ILLEGAL_FUNCTION         = 0x01
EX_ILLEGAL_DATA_ADDRESS     = 0x02
EX_ILLEGAL_DATA_VALUE       = 0x03


# =============================================================================
#  ModbusListener — TCP server that spawns a thread per client connection
# =============================================================================

class ModbusListener:
    """
    Fake Modbus TCP slave.  Runs in its own daemon thread.
    Spawns a child thread for each attacker connection so multiple
    scanners can be handled concurrently without blocking each other.
    """

    def __init__(self, host: str = "0.0.0.0", port: int = MODBUS_PORT):
        self.host = host
        self.port = port
        self._stop_event = threading.Event()

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def start(self):
        """Start the listener in a background daemon thread."""
        t = threading.Thread(target=self._serve, daemon=True, name="ModbusListener")
        t.start()
        log.info(f"Listening on {self.host}:{self.port}")

    def stop(self):
        """Signal the listener to stop accepting new connections."""
        self._stop_event.set()

    # ------------------------------------------------------------------
    # Server loop
    # ------------------------------------------------------------------

    def _serve(self):
        """
        Main accept loop.  Creates the server socket, then blocks on
        accept() until a client connects.  Each client gets its own thread.
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            # SO_REUSEADDR lets us restart the honeypot without waiting
            # for the OS TIME_WAIT state to expire on port 502
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((self.host, self.port))
            server.listen(SOCKET_BACKLOG)
            server.settimeout(1.0)   # 1 s timeout so _stop_event is checked

            while not self._stop_event.is_set():
                try:
                    conn, addr = server.accept()
                except socket.timeout:
                    continue   # loop back and check stop event
                except OSError:
                    break

                # Spawn a dedicated thread for this attacker session
                t = threading.Thread(
                    target=self._handle_client,
                    args=(conn, addr),
                    daemon=True,
                    name=f"Modbus-{addr[0]}"
                )
                t.start()

    # ------------------------------------------------------------------
    # Per-client session handler
    # ------------------------------------------------------------------

    def _handle_client(self, conn: socket.socket, addr: tuple):
        """
        Receive Modbus frames from one attacker, decode them, respond with
        fake data, and log everything.  Runs until the attacker disconnects
        or the socket times out.
        """
        ip, port = addr
        log.connection(ip, port)

        conn.settimeout(SOCKET_TIMEOUT)

        try:
            while True:
                raw = conn.recv(RECV_BUFFER)
                if not raw:
                    break   # attacker closed the connection

                # A single recv() may deliver multiple concatenated frames
                # (TCP is a stream protocol).  Process all frames in the buffer.
                offset = 0
                while offset < len(raw):
                    consumed, response = self._process_frame(ip, port, raw[offset:])
                    if consumed == 0:
                        break   # incomplete frame — wait for more data
                    offset += consumed
                    if response:
                        conn.sendall(response)

        except socket.timeout:
            pass   # attacker went idle — normal, not an error
        except ConnectionResetError:
            pass   # attacker hard-reset the TCP connection
        except Exception as exc:
            log.error(ip, port, f"Unexpected exception: {exc}")
        finally:
            conn.close()
            log.disconnection(ip, port)

    # ------------------------------------------------------------------
    # Frame parser and dispatcher
    # ------------------------------------------------------------------

    def _process_frame(self, ip: str, port: int, data: bytes) -> tuple[int, bytes | None]:
        """
        Parse one Modbus TCP frame from `data`.

        Returns
        -------
        (bytes_consumed, response_bytes)
            bytes_consumed == 0 means the frame is incomplete (need more data).
            response_bytes == None means we deliberately send no reply.
        """
        # MBAP header is exactly 7 bytes — if we have fewer, wait for more
        if len(data) < 7:
            return 0, None

        # Unpack MBAP header
        # >HHH = big-endian: uint16, uint16, uint16
        txn_id, proto_id, length = struct.unpack_from(">HHH", data, 0)
        unit_id = data[6]

        # Protocol ID must always be 0x0000 for Modbus TCP.
        # Non-zero values indicate a garbled frame or a protocol scanner.
        if proto_id != 0x0000:
            log.error(ip, port, f"Non-Modbus protocol ID: 0x{proto_id:04X} — possible scanner")
            return len(data), None   # consume and discard

        # 'length' includes the Unit ID byte, so total frame = 6 (MBAP without length) + length
        total_frame = 6 + length
        if len(data) < total_frame:
            return 0, None   # incomplete frame

        # PDU starts at byte 7 (after the 7-byte MBAP header)
        pdu = data[7:total_frame]
        if not pdu:
            return total_frame, None

        function_code = pdu[0]
        payload       = pdu[1:]   # everything after the function code

        # Dispatch to the appropriate handler based on function code
        response_pdu = self._dispatch(ip, port, function_code, payload, txn_id, unit_id, data[:total_frame])

        if response_pdu is None:
            return total_frame, None

        # Build the response MBAP header:
        # TxnID (echo) | ProtoID 0x0000 | Length (PDU size + 1 for UID) | UID
        resp_length = len(response_pdu) + 1
        response = struct.pack(">HHHB", txn_id, 0x0000, resp_length, unit_id) + response_pdu

        return total_frame, response

    def _dispatch(
        self,
        ip: str, port: int,
        fc: int, payload: bytes,
        txn_id: int, unit_id: int,
        raw_frame: bytes
    ) -> bytes | None:
        """
        Route a decoded PDU to the correct function-code handler.
        Returns the response PDU (without MBAP header).
        """
        if fc == FC_READ_HOLDING_REGISTERS:
            return self._fc03_read_holding_registers(ip, port, payload, raw_frame)

        elif fc == FC_READ_INPUT_REGISTERS:
            return self._fc04_read_input_registers(ip, port, payload, raw_frame)

        elif fc == FC_READ_COILS:
            return self._fc01_read_coils(ip, port, payload, raw_frame)

        elif fc == FC_READ_DISCRETE_INPUTS:
            return self._fc02_read_discrete_inputs(ip, port, payload, raw_frame)

        elif fc == FC_WRITE_SINGLE_REGISTER:
            return self._fc06_write_single_register(ip, port, payload, raw_frame)

        elif fc == FC_WRITE_MULTIPLE_REGISTERS:
            return self._fc16_write_multiple_registers(ip, port, payload, raw_frame)

        elif fc == FC_WRITE_SINGLE_COIL:
            return self._fc05_write_single_coil(ip, port, payload, raw_frame)

        elif fc == FC_DIAGNOSTICS:
            return self._fc08_diagnostics(ip, port, payload, raw_frame)

        elif fc == FC_MEI_TRANSPORT:
            return self._fc43_mei(ip, port, payload, raw_frame)

        else:
            # Unknown function code — return Illegal Function exception
            log.attack(ip, port, f"unknown_fc_0x{fc:02X}", raw_frame, {
                "function_code": fc,
                "note": "Illegal Function exception returned"
            })
            return bytes([FC_EXCEPTION_FLAG | fc, EX_ILLEGAL_FUNCTION])

    # ------------------------------------------------------------------
    # Function Code Handlers
    # ------------------------------------------------------------------

    def _fc03_read_holding_registers(self, ip, port, payload, raw):
        """
        FC 0x03 — Read Holding Registers.
        Most common Modbus scan.  Returns fake sensor register values.

        Request payload: start_address (2B) + quantity (2B)
        Response:        byte_count (1B) + register_values (quantity × 2B)
        """
        if len(payload) < 4:
            return bytes([FC_EXCEPTION_FLAG | FC_READ_HOLDING_REGISTERS, EX_ILLEGAL_DATA_VALUE])

        start_addr = struct.unpack_from(">H", payload, 0)[0]
        quantity   = struct.unpack_from(">H", payload, 2)[0]

        log.attack(ip, port, "read_holding_registers", raw, {
            "function_code": "0x03",
            "start_address": start_addr,
            "quantity":      quantity
        })

        # Build response: return fake values for requested registers
        register_bytes = b""
        for i in range(quantity):
            reg_idx = start_addr + i
            if reg_idx in MODBUS_REGISTER_MAP:
                _, value = MODBUS_REGISTER_MAP[reg_idx]
                register_bytes += struct.pack(">H", value)
            else:
                register_bytes += struct.pack(">H", 0x0000)   # unallocated register = 0

        byte_count = len(register_bytes)
        response_pdu = bytes([FC_READ_HOLDING_REGISTERS, byte_count]) + register_bytes

        # Build a human-readable dict of what we sent back for the log
        fake_values = {
            MODBUS_REGISTER_MAP[start_addr + i][0]: struct.unpack_from(">H", register_bytes, i * 2)[0]
            for i in range(quantity) if (start_addr + i) in MODBUS_REGISTER_MAP
        }
        log.response(ip, port, "read_holding_registers", fake_values)

        return response_pdu

    def _fc04_read_input_registers(self, ip, port, payload, raw):
        """
        FC 0x04 — Read Input Registers.
        Same register map as FC03 for our honeypot — attackers can't tell the difference.
        """
        if len(payload) < 4:
            return bytes([FC_EXCEPTION_FLAG | FC_READ_INPUT_REGISTERS, EX_ILLEGAL_DATA_VALUE])

        start_addr = struct.unpack_from(">H", payload, 0)[0]
        quantity   = struct.unpack_from(">H", payload, 2)[0]

        log.attack(ip, port, "read_input_registers", raw, {
            "function_code": "0x04",
            "start_address": start_addr,
            "quantity":      quantity
        })

        register_bytes = b""
        for i in range(quantity):
            reg_idx = start_addr + i
            _, value = MODBUS_REGISTER_MAP.get(reg_idx, ("unknown", 0))
            register_bytes += struct.pack(">H", value)

        return bytes([FC_READ_INPUT_REGISTERS, len(register_bytes)]) + register_bytes

    def _fc01_read_coils(self, ip, port, payload, raw):
        """
        FC 0x01 — Read Coils (digital outputs).
        We return a fixed pattern of coil states to appear realistic.
        """
        if len(payload) < 4:
            return bytes([FC_EXCEPTION_FLAG | FC_READ_COILS, EX_ILLEGAL_DATA_VALUE])

        start_addr = struct.unpack_from(">H", payload, 0)[0]
        quantity   = struct.unpack_from(">H", payload, 2)[0]

        log.attack(ip, port, "read_coils", raw, {
            "function_code": "0x01",
            "start_address": start_addr,
            "quantity":      quantity
        })

        # Pack fake coil states as bits — 0xAA = 10101010 pattern
        byte_count    = (quantity + 7) // 8
        coil_bytes    = bytes([0xAA] * byte_count)
        return bytes([FC_READ_COILS, byte_count]) + coil_bytes

    def _fc02_read_discrete_inputs(self, ip, port, payload, raw):
        """FC 0x02 — Read Discrete Inputs (digital inputs)."""
        if len(payload) < 4:
            return bytes([FC_EXCEPTION_FLAG | FC_READ_DISCRETE_INPUTS, EX_ILLEGAL_DATA_VALUE])

        start_addr = struct.unpack_from(">H", payload, 0)[0]
        quantity   = struct.unpack_from(">H", payload, 2)[0]

        log.attack(ip, port, "read_discrete_inputs", raw, {
            "function_code": "0x02",
            "start_address": start_addr,
            "quantity":      quantity
        })

        byte_count = (quantity + 7) // 8
        return bytes([FC_READ_DISCRETE_INPUTS, byte_count]) + bytes([0x55] * byte_count)

    def _fc06_write_single_register(self, ip, port, payload, raw):
        """
        FC 0x06 — Write Single Register.
        An attacker trying to write to us — high severity event.
        We ACK the write (appear to accept it) but don't actually change anything.
        """
        if len(payload) < 4:
            return bytes([FC_EXCEPTION_FLAG | FC_WRITE_SINGLE_REGISTER, EX_ILLEGAL_DATA_VALUE])

        reg_addr = struct.unpack_from(">H", payload, 0)[0]
        value    = struct.unpack_from(">H", payload, 2)[0]

        log.attack(ip, port, "WRITE_single_register [HIGH SEVERITY]", raw, {
            "function_code":  "0x06",
            "register":       reg_addr,
            "value_written":  value,
            "severity":       "HIGH"
        })

        # Echo back the address and value — standard Modbus ACK for FC06
        return bytes([FC_WRITE_SINGLE_REGISTER]) + payload[:4]

    def _fc16_write_multiple_registers(self, ip, port, payload, raw):
        """
        FC 0x10 — Write Multiple Registers.
        Highest severity — attacker attempting bulk register write.
        """
        if len(payload) < 5:
            return bytes([FC_EXCEPTION_FLAG | FC_WRITE_MULTIPLE_REGISTERS, EX_ILLEGAL_DATA_VALUE])

        start_addr = struct.unpack_from(">H", payload, 0)[0]
        quantity   = struct.unpack_from(">H", payload, 2)[0]

        log.attack(ip, port, "WRITE_multiple_registers [CRITICAL SEVERITY]", raw, {
            "function_code": "0x10",
            "start_address": start_addr,
            "quantity":      quantity,
            "severity":      "CRITICAL"
        })

        # ACK: echo start address and quantity
        return bytes([FC_WRITE_MULTIPLE_REGISTERS]) + struct.pack(">HH", start_addr, quantity)

    def _fc05_write_single_coil(self, ip, port, payload, raw):
        """FC 0x05 — Write Single Coil."""
        if len(payload) < 4:
            return bytes([FC_EXCEPTION_FLAG | FC_WRITE_SINGLE_COIL, EX_ILLEGAL_DATA_VALUE])

        coil_addr = struct.unpack_from(">H", payload, 0)[0]
        coil_val  = struct.unpack_from(">H", payload, 2)[0]  # 0xFF00 = ON, 0x0000 = OFF

        log.attack(ip, port, "WRITE_single_coil [HIGH SEVERITY]", raw, {
            "function_code": "0x05",
            "coil_address":  coil_addr,
            "value":         "ON" if coil_val == 0xFF00 else "OFF",
            "severity":      "HIGH"
        })

        return bytes([FC_WRITE_SINGLE_COIL]) + payload[:4]

    def _fc08_diagnostics(self, ip, port, payload, raw):
        """
        FC 0x08 — Diagnostics.
        Commonly used by scanners to fingerprint devices.
        We respond with plausible counters to appear authentic.
        """
        sub_func = struct.unpack_from(">H", payload, 0)[0] if len(payload) >= 2 else 0

        log.attack(ip, port, "diagnostics_request", raw, {
            "function_code":   "0x08",
            "sub_function":    sub_func,
            "note":            "Device fingerprinting attempt"
        })

        # Sub-function 0x0000 = Return Query Data (echo)
        return bytes([FC_DIAGNOSTICS]) + payload

    def _fc43_mei(self, ip, port, payload, raw):
        """
        FC 0x2B — MEI Transport (Device Identification).
        Scanners use this to read vendor name, product code, firmware version.
        We return our fake Siemens SIMATIC identity strings.
        """
        log.attack(ip, port, "device_identification_MEI", raw, {
            "function_code": "0x2B",
            "note":          "Attacker requesting device identity — returning fake Siemens identity"
        })

        # Build MEI response with fake identity objects
        def mei_object(obj_id: int, value: str) -> bytes:
            encoded = value.encode("ascii")
            return bytes([obj_id, len(encoded)]) + encoded

        objects = (
            mei_object(0x00, MODBUS_VENDOR)  +
            mei_object(0x01, MODBUS_PRODUCT) +
            mei_object(0x02, MODBUS_VERSION)
        )

        # MEI response header: FC | MEI type | Read Device ID code | conformity | reserved | reserved | object count
        header = bytes([
            FC_MEI_TRANSPORT,
            0x0E,          # MEI type: Read Device Identification
            0x01,          # Read Device ID code
            0x01,          # Conformity level
            0x00,          # More follows: No
            0x00,          # Next Object Id
            0x03           # Number of objects
        ])
        return header + objects
