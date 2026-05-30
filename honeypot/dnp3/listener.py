# =============================================================================
#  ics_honeypot / dnp3 / listener.py
#  ---------------------------------------------------------------------------
#  DNP3 (IEEE 1815) Honeypot Listener
#  ---------------------------------------------------------------------------
#  Implements a convincing fake DNP3 outstation (field device) that:
#    • Accepts connections on port 20000
#    • Parses DNP3 Data Link Layer frames correctly
#    • Handles Class 0 data polls (most common scan/read operation)
#    • Returns fake analogue input values (temperature readings)
#    • Detects and logs OPERATE commands (write attempts — critical severity)
#    • Logs every frame with full decoded fields
#
#  DNP3 Frame Structure (Data Link Layer):
#  ┌────────────────────────────────────────────────────────────────┐
#  │  Start (2B) │ Len (1B) │ Ctrl (1B) │ Dst (2B) │ Src (2B) │CRC│
#  │  0x05 0x64  │          │           │ LE       │ LE       │2B │
#  └────────────────────────────────────────────────────────────────┘
#  Data blocks follow (16 bytes of data + 2 bytes CRC each block).
#
#  Application Layer (inside the data blocks):
#  ┌──────────────────────────────────────────────────────┐
#  │  App Ctrl (1B) │ Function Code (1B) │ Objects (var) │
#  └──────────────────────────────────────────────────────┘
# =============================================================================

import socket
import struct
import threading

from honeypot.shared.config import DNP3_PORT, SOCKET_BACKLOG, SOCKET_TIMEOUT, RECV_BUFFER
from honeypot.shared.config import DNP3_OUTSTATION_ADDR, DNP3_MASTER_ADDR, FAKE_TEMP
from honeypot.shared.logger import HoneypotLogger

log = HoneypotLogger("DNP3")

# ---------------------------------------------------------------------------
# DNP3 Constants
# ---------------------------------------------------------------------------

# Data Link Layer
DNP3_START_BYTE_1   = 0x05
DNP3_START_BYTE_2   = 0x64
DNP3_HEADER_SIZE    = 10    # 2 start + 1 len + 1 ctrl + 2 dst + 2 src + 2 CRC

# Application Layer Function Codes
FC_CONFIRM          = 0x00
FC_READ             = 0x01   # most common — Class 0/1/2/3 poll
FC_WRITE            = 0x02
FC_SELECT           = 0x03
FC_OPERATE          = 0x04   # CRITICAL — attacker trying to control output
FC_DIRECT_OPERATE   = 0x05   # CRITICAL — same but without SELECT step
FC_RESPONSE         = 0x81   # outstation → master response
FC_UNSOLICITED_RESP = 0x82

# Data Link Control byte masks
DL_DIR_BIT          = 0x80   # 1 = master→outstation
DL_PRIMARY_BIT      = 0x40
DL_FCB_BIT          = 0x20
DL_FCV_BIT          = 0x10

# Application Control byte masks
AC_FIR_BIT          = 0x80   # First fragment
AC_FIN_BIT          = 0x40   # Final fragment
AC_CON_BIT          = 0x20   # Confirm requested
AC_UNS_BIT          = 0x10   # Unsolicited


# =============================================================================
#  CRC-16 for DNP3 (polynomial 0xA6BC)
# =============================================================================

def _build_crc_table() -> list:
    """Pre-compute the 256-entry CRC-16 lookup table for DNP3."""
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
    """
    Compute DNP3 CRC-16 over `data`.
    Returns the CRC as an integer (stored little-endian in frames).
    """
    crc = 0x0000
    for byte in data:
        crc = _CRC_TABLE[(crc ^ byte) & 0xFF] ^ (crc >> 8)
    return (~crc) & 0xFFFF   # one's complement


def _append_crc(data: bytes) -> bytes:
    """Append a 2-byte little-endian DNP3 CRC to `data`."""
    crc = dnp3_crc(data)
    return data + struct.pack("<H", crc)


# =============================================================================
#  DNP3Listener
# =============================================================================

class DNP3Listener:
    """
    Fake DNP3 outstation.  Runs in a daemon thread, spawns per-client threads.
    """

    def __init__(self, host: str = "0.0.0.0", port: int = DNP3_PORT):
        self.host = host
        self.port = port
        self._stop_event = threading.Event()

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def start(self):
        t = threading.Thread(target=self._serve, daemon=True, name="DNP3Listener")
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
                    name=f"DNP3-{addr[0]}"
                )
                t.start()

    # ------------------------------------------------------------------
    # Per-client session handler
    # ------------------------------------------------------------------

    def _handle_client(self, conn: socket.socket, addr: tuple):
        ip, port = addr
        log.connection(ip, port)
        conn.settimeout(SOCKET_TIMEOUT)

        try:
            while True:
                raw = conn.recv(RECV_BUFFER)
                if not raw:
                    break

                # Validate DNP3 start bytes before any further processing
                if len(raw) < 2 or raw[0] != DNP3_START_BYTE_1 or raw[1] != DNP3_START_BYTE_2:
                    log.error(ip, port, f"Invalid start bytes: {raw[:4].hex()} — not a DNP3 frame")
                    continue

                response = self._process_frame(ip, port, raw)
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
    # Frame parser
    # ------------------------------------------------------------------

    def _process_frame(self, ip: str, port: int, data: bytes) -> bytes | None:
        """
        Parse a DNP3 Data Link Layer frame and extract the Application Layer.
        Returns a response frame or None.
        """
        if len(data) < DNP3_HEADER_SIZE:
            return None

        # Parse Data Link Layer header (before the CRC at bytes 8-9)
        # Byte 2: Length (number of bytes from control field to end including data CRCs)
        # Byte 3: Control
        # Bytes 4-5: Destination address (little-endian)
        # Bytes 6-7: Source address (little-endian)
        dl_length  = data[2]
        dl_control = data[3]
        dst_addr   = struct.unpack_from("<H", data, 4)[0]
        src_addr   = struct.unpack_from("<H", data, 6)[0]

        # Verify header CRC (bytes 0-7 covered by CRC at bytes 8-9)
        header_data = data[:8]
        expected_crc = struct.unpack_from("<H", data, 8)[0]
        actual_crc   = dnp3_crc(header_data)
        if expected_crc != actual_crc:
            log.error(ip, port, f"DNP3 header CRC mismatch — expected 0x{expected_crc:04X}, got 0x{actual_crc:04X}")
            return None

        # Extract Application Layer bytes from data blocks (skip 10-byte header)
        # Data blocks are 18 bytes each: 16 bytes data + 2 bytes CRC
        app_bytes = self._extract_app_layer(data[10:])
        if not app_bytes or len(app_bytes) < 2:
            return None

        app_control = app_bytes[0]
        app_fc      = app_bytes[1]
        app_objects = app_bytes[2:] if len(app_bytes) > 2 else b""

        return self._dispatch_app(ip, port, app_fc, app_objects, src_addr, app_control, data)

    def _extract_app_layer(self, block_data: bytes) -> bytes:
        """
        Extract and concatenate application layer bytes from DNP3 data blocks.
        Each block is 16 bytes of payload followed by 2 bytes of CRC.
        We skip CRC validation here for honeypot simplicity — we trust the data.
        """
        app_bytes = b""
        offset = 0
        while offset + 2 <= len(block_data):
            # Take up to 16 payload bytes (last block may be shorter)
            payload_end = min(offset + 16, len(block_data) - 2)
            app_bytes  += block_data[offset:payload_end]
            offset     += 18   # 16 payload + 2 CRC
        return app_bytes

    # ------------------------------------------------------------------
    # Application Layer dispatcher
    # ------------------------------------------------------------------

    def _dispatch_app(
        self,
        ip: str, port: int,
        fc: int, objects: bytes,
        master_addr: int,
        app_ctrl: int,
        raw_frame: bytes
    ) -> bytes | None:
        """Route the application layer function code to the right handler."""

        if fc == FC_READ:
            return self._handle_read(ip, port, objects, master_addr, app_ctrl, raw_frame)

        elif fc == FC_CONFIRM:
            # Master acknowledging our previous response — log and ignore
            log.attack(ip, port, "dnp3_confirm", raw_frame, {
                "function_code": "0x00",
                "note": "Master confirming receipt of previous response"
            })
            return None

        elif fc == FC_WRITE:
            log.attack(ip, port, "WRITE_attempt [HIGH SEVERITY]", raw_frame, {
                "function_code": "0x02",
                "severity":      "HIGH",
                "note":          "Attacker attempting DNP3 WRITE operation"
            })
            return self._build_response(master_addr, app_ctrl, FC_RESPONSE, b"")

        elif fc in (FC_OPERATE, FC_DIRECT_OPERATE):
            # An OPERATE or DIRECT OPERATE means the attacker is trying to
            # control a physical output (relay, valve, breaker).  CRITICAL.
            severity_label = "OPERATE" if fc == FC_OPERATE else "DIRECT_OPERATE"
            log.attack(ip, port, f"{severity_label} [CRITICAL SEVERITY]", raw_frame, {
                "function_code": f"0x{fc:02X}",
                "severity":      "CRITICAL",
                "note":          "Attacker attempting to control physical output"
            })
            # Return a response that appears to ACK but does nothing
            return self._build_response(master_addr, app_ctrl, FC_RESPONSE, b"")

        elif fc == FC_SELECT:
            log.attack(ip, port, "SELECT_before_operate [HIGH SEVERITY]", raw_frame, {
                "function_code": "0x03",
                "severity":      "HIGH",
                "note":          "SELECT step of SELECT-BEFORE-OPERATE sequence"
            })
            return self._build_response(master_addr, app_ctrl, FC_RESPONSE, b"")

        else:
            log.attack(ip, port, f"unknown_fc_0x{fc:02X}", raw_frame, {
                "function_code": f"0x{fc:02X}"
            })
            return None

    # ------------------------------------------------------------------
    # READ handler — Class 0/1/2/3 data poll
    # ------------------------------------------------------------------

    def _handle_read(
        self,
        ip: str, port: int,
        objects: bytes,
        master_addr: int,
        app_ctrl: int,
        raw_frame: bytes
    ) -> bytes | None:
        """
        Handle FC_READ (0x01) — typically a Class 0 integrity poll.

        Class 0 poll object header: Group=60, Variation=1, Qualifier=0x06
        We respond with Group 30 Variation 5 (32-bit float analogue input).
        """
        # Decode requested object group/variation if present
        group    = objects[0] if len(objects) > 0 else 0
        variation = objects[1] if len(objects) > 1 else 0
        qualifier = objects[2] if len(objects) > 2 else 0

        poll_type = "class0_integrity_poll"
        if group == 60:
            class_map = {1: "class0", 2: "class1", 3: "class2", 4: "class3"}
            poll_type = class_map.get(variation, f"class_group60_var{variation}")

        log.attack(ip, port, f"dnp3_read_{poll_type}", raw_frame, {
            "function_code": "0x01",
            "group":         group,
            "variation":     variation,
            "qualifier":     f"0x{qualifier:02X}"
        })

        # Build response: Group 30 Var 5 (32-bit float analogue input), index 0
        # Object header: Group(1B) | Variation(1B) | Qualifier(1B) | Start(2B) | Stop(2B)
        # Qualifier 0x00 = 8-bit start/stop index
        temp_float = FAKE_TEMP / 10.0   # convert back to float (35.2°C)
        obj_header = bytes([
            0x1E, 0x05,   # Group 30, Variation 5
            0x28,         # Qualifier: 16-bit count, 16-bit index
            0x01, 0x00,   # Count = 1
            0x00, 0x00    # Index = 0
        ])
        # Flag byte (0x01 = online) + 4-byte IEEE 754 float value
        obj_data = bytes([0x01]) + struct.pack("<f", temp_float)

        response_objects = obj_header + obj_data

        log.response(ip, port, f"dnp3_read_{poll_type}", {
            "group30_var5_index0": f"{temp_float}°C"
        })

        return self._build_response(master_addr, app_ctrl, FC_RESPONSE, response_objects)

    # ------------------------------------------------------------------
    # Response frame builder
    # ------------------------------------------------------------------

    def _build_response(
        self,
        master_addr: int,
        req_app_ctrl: int,
        fc: int,
        app_objects: bytes
    ) -> bytes:
        """
        Build a complete DNP3 response frame including:
          • Data Link Layer header with CRC
          • Application Layer inside data blocks (each block with its own CRC)

        The response is always: Outstation → Master
        """
        # Application Layer: AppCtrl | FC | IIN1 | IIN2 | Objects
        # IIN = Internal Indication — 0x00 0x00 means "all good, no events"
        seq_num  = req_app_ctrl & 0x0F          # echo the sequence number
        app_ctrl = AC_FIR_BIT | AC_FIN_BIT | seq_num   # single fragment, no confirm
        app_layer = bytes([app_ctrl, fc, 0x00, 0x00]) + app_objects

        # Split Application Layer into 16-byte blocks, each followed by CRC
        data_blocks = b""
        for i in range(0, len(app_layer), 16):
            block = app_layer[i:i + 16]
            data_blocks += _append_crc(block)

        # Data Link Layer header:
        # Start(2) + Length(1) + Control(1) + Dst(2,LE) + Src(2,LE) + CRC(2)
        # Length = 5 (ctrl+dst+src) + len(data_blocks)
        dl_length  = 5 + len(data_blocks)
        dl_control = 0x44   # DIR=0 (outstation→master), PRM=1, FCB=0, FCV=0, FC=4 (ACK)
        header_body = bytes([
            DNP3_START_BYTE_1, DNP3_START_BYTE_2,
            dl_length,
            dl_control
        ]) + struct.pack("<H", master_addr) + struct.pack("<H", DNP3_OUTSTATION_ADDR)

        return _append_crc(header_body) + data_blocks
