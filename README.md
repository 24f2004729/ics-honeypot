# ICS Honeypot — Multi-Protocol SCADA Threat Detection

A production-grade **Industrial Control System (ICS) honeypot** that simulates fake Modbus TCP, DNP3, and MQTT field devices to detect, log, and analyse attackers probing critical infrastructure.

Built entirely in **pure Python (stdlib only)** — no third-party dependencies.

---

## Architecture

```
                    ┌─────────────────────────────────────────┐
                    │            ICS Honeypot                  │
                    │                                         │
  Attacker ──────► │  ┌──────────┐  ┌───────┐  ┌──────────┐ │
  (Scanner /        │  │ Modbus   │  │ DNP3  │  │  MQTT    │ │
   Shodan /         │  │ TCP :502 │  │ :20000│  │  :1883   │ │
   Pen-tester)      │  └────┬─────┘  └───┬───┘  └────┬─────┘ │
                    │       │            │            │        │
                    │       └────────────┴────────────┘        │
                    │                   │                      │
                    │         ┌─────────▼──────────┐          │
                    │         │  Structured Logger  │          │
                    │         │  honeypot.log       │          │
                    │         │  events.jsonl       │          │
                    │         └─────────┬──────────┘          │
                    │                   │                      │
                    │         ┌─────────▼──────────┐          │
                    │         │   HTML Reporter     │          │
                    │         │   report.html       │          │
                    │         └────────────────────┘          │
                    └─────────────────────────────────────────┘
```

---

## Features

| Feature | Details |
|---|---|
| **Modbus TCP** | Handles FC01–FC06, FC08, FC10, FC43 (MEI Device ID). Returns fake Siemens S7-1200 identity |
| **DNP3** | Parses Data Link + Application layers. Handles Class 0/1/2/3 polls, OPERATE, DIRECT OPERATE |
| **MQTT** | Full CONNECT parsing (extracts credentials). SUBSCRIBE, PUBLISH, PING supported |
| **Scanner fingerprinting** | Detects Shodan, Censys, PLCScan from packet signatures |
| **Severity classification** | CRITICAL / HIGH / MEDIUM per event, based on action type |
| **Dual logging** | Human-readable `.log` + machine-parseable `.jsonl` for SIEM ingest |
| **HTML report** | Self-contained dashboard with attacker stats, timeline, filterable event log |
| **Zero dependencies** | Pure Python stdlib — no pip installs required |
| **Thread-per-client** | All three listeners run concurrently, each handles multiple attackers |

---

## Project Structure

```
ics_honeypot/
├── main.py                        ← Entry point
├── run_honeypot.sh                ← One-command launcher
├── logs/
│   ├── honeypot.log               ← Human-readable log (auto-created)
│   ├── events.jsonl               ← JSON Lines event stream (auto-created)
│   └── report.html                ← Generated after shutdown (auto-created)
└── honeypot/
    ├── shared/
    │   ├── config.py              ← All ports, timeouts, fake values
    │   └── logger.py              ← Dual-output structured logger
    ├── modbus/
    │   └── listener.py            ← Modbus TCP honeypot (port 502)
    ├── dnp3/
    │   └── listener.py            ← DNP3 honeypot (port 20000)
    ├── mqtt/
    │   └── listener.py            ← MQTT honeypot (port 1883)
    └── reporter/
        └── report.py              ← HTML threat intelligence report generator
```

---

## Requirements

- **Python 3.8+**
- **Linux** (Ubuntu/Debian recommended)
- **sudo** (for port 502 — Modbus standard port; see Dev Mode below)
- No pip packages required

---

## Quick Start

```bash
# Clone / extract the project
cd ics_honeypot/

# Full mode (standard ports — requires sudo for port 502)
sudo bash run_honeypot.sh

# Dev mode (no sudo — Modbus runs on port 5020 instead of 502)
bash run_honeypot.sh --no-sudo
```

Press **Ctrl+C** to stop. An HTML report is automatically generated at `logs/report.html`.

---

## Manual Run

```bash
cd ics_honeypot/
sudo python3 main.py
```

---

## Log Files

### `logs/honeypot.log` — Human-readable
```
10:45:12  [Modbus]  NEW CONNECTION      192.168.1.50:54231
10:45:12  [Modbus]  PROBE               192.168.1.50:54231  action=read_holding_registers  bytes=[00 00 00 00 00 06 01 03 00 00 00 08]  scanner=Shodan / Censys default probe
10:45:12  [Modbus]  RESPONDED           192.168.1.50:54231  action=read_holding_registers  data={'voltage_high': 9, 'voltage_low': 33, ...}
```

### `logs/events.jsonl` — SIEM-ready JSON Lines
```json
{"timestamp":"2026-01-15T10:45:12Z","protocol":"MODBUS","event":"attack","src_ip":"192.168.1.50","src_port":54231,"action":"read_holding_registers","function_code":"0x03","start_address":0,"quantity":8,"scanner":"Shodan / Censys default probe"}
```

---

## Detected Attack Types

| Severity | Action | Protocol |
|---|---|---|
| 🔴 CRITICAL | Write Multiple Registers | Modbus |
| 🔴 CRITICAL | OPERATE / DIRECT OPERATE | DNP3 |
| 🟠 HIGH | Write Single Register / Coil | Modbus |
| 🟠 HIGH | WRITE / SELECT command | DNP3 |
| 🟠 HIGH | CONNECT with credentials | MQTT |
| 🟡 MEDIUM | Read Holding/Input Registers | Modbus |
| 🟡 MEDIUM | Class 0/1/2/3 Data Poll | DNP3 |
| 🟡 MEDIUM | SUBSCRIBE / PUBLISH | MQTT |
| ℹ️ LOW | Device Identification (MEI) | Modbus |
| ℹ️ LOW | PING / CONFIRM | MQTT / DNP3 |

---

## Testing the Honeypot

```bash
# Test Modbus (requires nmap with modbus scripts)
nmap -p 502 --script modbus-discover 127.0.0.1

# Test Modbus with mbtget (if installed)
mbtget -r1 -a 0 -n 8 127.0.0.1

# Test MQTT
mosquitto_pub -h 127.0.0.1 -t "sensors/test" -m "hello"
mosquitto_sub -h 127.0.0.1 -t "#"

# Test DNP3 with raw netcat (sends valid DNP3 start bytes)
echo -ne '\x05\x64\x05\xc0\x01\x00\x02\x00\x00\x00' | nc 127.0.0.1 20000
```

---

## Customisation

All configuration is in `honeypot/shared/config.py`:

- **Change ports** — `MODBUS_PORT`, `DNP3_PORT`, `MQTT_PORT`
- **Change fake sensor values** — `FAKE_VOLTAGE`, `FAKE_TEMP`, etc.
- **Change fake device identity** — `MODBUS_VENDOR`, `MODBUS_PRODUCT`
- **Add scanner fingerprints** — `KNOWN_SCANNERS` dict

---
