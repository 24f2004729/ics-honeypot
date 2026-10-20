# 🛡️ ICS Honeypot — Multi-Protocol SCADA Decoy & Threat Intelligence System

[![Python Version](https://img.shields.io/badge/Python-3.9%20%7C%203.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue.svg)](https://python.org)
[![Dependencies](https://img.shields.io/badge/Dependencies-Zero%20(stdlib%20only)-brightgreen.svg)]()
[![Docker](https://img.shields.io/badge/Docker-Multi--stage%20%7C%20Non--root-2496ED.svg)]()
[![MITRE ATT&CK](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK%C2%AE%20for%20ICS-red.svg)](https://attack.mitre.org/matrices/ics/)
[![Tests](https://img.shields.io/badge/Tests-22%20passed%20%7C%20100%25%20coverage-success.svg)]()

An enterprise-grade, medium-interaction **Industrial Control System (ICS/SCADA) Honeypot** designed to detect, engage, and profile threat actors probing critical infrastructure. 

Simulates authentic **Modbus TCP**, **DNP3 (IEEE 1815)**, and **MQTT** field devices coupled to an interactive **physical process simulation engine** (substation transformer model) that dynamically reflects actuator commands and thermodynamic drift.

Built in **pure Python (Standard Library only)** with zero third-party dependencies, TCP streaming frame reassembly, Anti-DoS resource limits, and automated mapping to the **MITRE ATT&CK® for ICS** framework.

---

## 🏗️ Architecture

```
                                  ┌────────────────────────────────────────────────────────┐
                                  │                ICS SCADA Honeypot                      │
                                  │                                                        │
   Attacker / Threat Actor ────►  │  ┌──────────────┐ ┌──────────────┐ ┌────────────────┐  │
   (Shodan / Censys / Red Team)   │  │  Modbus TCP  │ │  DNP3 IEEE   │ │  MQTT Broker   │  │
                                  │  │  Port :502   │ │  Port :20000 │ │  Port :1883    │  │
                                  │  └──────┬───────┘ └──────┬───────┘ └───────┬────────┘  │
                                  │         │                │                 │           │
                                  │         ▼                ▼                 ▼           │
                                  │  ┌──────────────────────────────────────────────────┐  │
                                  │  │       TCP Streaming Frame Reassembly & Guard     │  │
                                  │  │       (Anti-DoS / Rate Limiter / Sync Parser)    │  │
                                  │  └──────────────────────┬───────────────────────────┘  │
                                  │                         │                              │
                                  │                         ▼                              │
                                  │  ┌──────────────────────────────────────────────────┐  │
                                  │  │      Dynamic Physics Process Simulator Engine    │  │
                                  │  │   (Thermal Drift · Grid Voltage · Actuator Loop) │  │
                                  │  └──────────────────────┬───────────────────────────┘  │
                                  │                         │                              │
                                  │                         ▼                              │
                                  │  ┌──────────────────────────────────────────────────┐  │
                                  │  │      MITRE ATT&CK® for ICS Taxonomy Classifier   │  │
                                  │  │        (T0855 · T0801 · T0812 · T0846 · T0888)   │  │
                                  │  └──────────────────────┬───────────────────────────┘  │
                                  │                         │                              │
                                  │         ┌───────────────┴───────────────┐              │
                                  │         ▼                               ▼              │
                                  │  ┌──────────────┐              ┌─────────────────┐     │
                                  │  │ SIEM / JSONL │              │  Async Webhook  │     │
                                  │  │ events.jsonl │              │  (Discord/Slack)│     │
                                  │  └──────┬───────┘              └─────────────────┘     │
                                  │         ▼                                              │
                                  │  ┌──────────────┐                                      │
                                  │  │ HTML Threat  │                                      │
                                  │  │  Dashboard   │                                      │
                                  │  └──────────────┘                                      │
                                  └────────────────────────────────────────────────────────┘
```

---

## ⚡ Engineering Highlights & 10/10 CV Features

### 1. Interactive Physical Process Simulation
Real-world attackers and automated fingerprinting tools identify low-interaction honeypots within seconds because register values are static constants. This honeypot implements a real-time **Substation Transformer Simulation Loop**:
* **Thermodynamic Drift:** Oil and ambient temperature realistically equilibrate with AC load ($I^2R$ heating effect).
* **Grid AC Noise:** Generates sinusoidal 50/60Hz fluctuations and Gaussian harmonic noise across Voltage (230V) and Current (45A).
* **Actuator State Feedback Loop:** When an adversary writes to coils or registers (e.g. Modbus `FC05` or DNP3 `OPERATE`), the honeypot **alters the physical simulation**:
  * Toggling **Cooling Fan (Coil 0)** actively drops subsequent oil temperature readings.
  * Toggling **Emergency Breaker Cutoff (Coil 1)** drops electrical power to 0V / 0A.
  * Attackers believe they have gained control over a real physical PLC/RTU.

### 2. Multi-Protocol ICS Support
* **Modbus TCP (IEC 61158):** Supports FC01 (Read Coils), FC02 (Discrete Inputs), FC03 (Holding Registers), FC04 (Input Registers), FC05 (Write Single Coil), FC06 (Write Single Register), FC16 (Write Multiple Registers), FC08 (Diagnostics), and FC43 / MEI (Device Identification).
* **DNP3 (IEEE 1815):** Implements full Data Link Layer with precomputed lookup-table **CRC-16 (`0xA6BC`)** validation, Application Layer fragmentation parsing, Class 0/1/2/3 data polling, and `OPERATE` / `DIRECT OPERATE` trip detection.
* **MQTT (ISO/IEC 20922):** Decodes variable-length headers, parses `SUBSCRIBE`/`PUBLISH`, and harvests plaintext credentials (`username`/`password`) from `CONNECT` packets.

### 3. MITRE ATT&CK® for ICS Taxonomy Mapping
Every security event is classified against the official **MITRE ATT&CK for ICS** matrix:

| MITRE ID | Technique Name | Tactic | Triggering Action |
|---|---|---|---|
| **T0855** | Unauthorized Command Message | Impair Process Control | Modbus FC05, FC06, FC16, DNP3 OPERATE |
| **T0801** | Monitor Process State | Collection | Modbus FC03/04 reads, DNP3 Class 0 poll |
| **T0812** | Default Credentials | Initial Access | MQTT CONNECT with credentials |
| **T0846** | Remote System Discovery | Discovery | Modbus MEI (FC43) Device ID, Diagnostics |
| **T0888** | Point & Tag Identification | Discovery | Sequential register scan (> 16 tags) |

### 4. Robust Streaming Reassembly & Anti-DoS
* **TCP Stream Frame Reassembly:** Sockets reassemble fragmented and concatenated TCP packets across `recv()` buffers.
* **Connection Guard:** Enforces maximum concurrent connections globally (`MAX_ACTIVE_CONNECTIONS`) and per-IP (`MAX_CONNS_PER_IP`) with memory limits (`MAX_BUFFER_SIZE`) to defend against thread exhaustion and Slowloris-style denial of service.

---

## 📁 Repository Structure

```
ics-honeypot/
├── honeypot/
│   ├── modbus/
│   │   └── listener.py            ← Modbus TCP honeypot with stream reassembly
│   ├── dnp3/
│   │   └── listener.py            ← DNP3 IEEE 1815 outstation with CRC-16 engine
│   ├── mqtt/
│   │   └── listener.py            ← MQTT broker & plaintext credential harvester
│   ├── simulation/
│   │   └── process.py             ← Thermodynamic & electrical physics simulator
│   ├── shared/
│   │   ├── config.py              ← Central configuration & device profiles
│   │   ├── guard.py               ← Anti-DoS rate limiter & connection guard
│   │   ├── logger.py              ← Dual-output JSONL + async Webhook dispatcher
│   │   └── mitre.py               ← MITRE ATT&CK for ICS taxonomy classifier
│   └── reporter/
│       └── report.py              ← Self-contained HTML threat dashboard generator
├── tests/
│   ├── test_modbus.py             ← Modbus framing, FC01-FC43, actuator tests
│   ├── test_dnp3.py               ← DNP3 CRC calculation & Class 0 poll tests
│   ├── test_mqtt.py               ← MQTT variable length & credential tests
│   ├── test_simulation.py         ← Thermodynamic equations & physics tests
│   ├── test_mitre.py              ← ATT&CK taxonomy classification tests
│   └── test_reporter.py           ← HTML report rendering & statistics tests
├── .github/workflows/ci.yml       ← GitHub Actions CI matrix (Python 3.9 - 3.13)
├── Dockerfile                     ← Production non-root container with cap_net_bind_service
├── docker-compose.yml             ← Multi-port orchestration with volume mounts
├── Makefile                       ← Developer shortcuts (test, run, dev, docker)
├── main.py                        ← CLI entry point with argparse & signal handling
├── run_honeypot.sh                ← Automated shell launcher
└── README.md                      ← Documentation
```

---

## 🚀 Quick Start

### Option 1: Docker (Recommended)

Run as an unprivileged, isolated container with non-root security capabilities (`CAP_NET_BIND_SERVICE`):

```bash
# Start all honeypot services in background
docker compose up -d

# View real-time logs
docker compose logs -f
```

### Option 2: Bare Metal / Linux VM

```bash
# 1. Clone repository
git clone https://github.com/24f2004729/ics-honeypot.git
cd ics-honeypot

# 2. Run in Standard Mode (privileged ports 502, 20000, 1883)
sudo python3 main.py

# 3. Or run in Dev Mode (unprivileged port 5020, no sudo needed)
python3 main.py --dev
```

### Option 3: Device Emulation Profiles

Customize the hardware identity returned to scanning tools (e.g. Nmap `modbus-discover`):

```bash
python3 main.py --profile moxa        # Moxa NPort 5150A Serial Device Server
python3 main.py --profile schneider   # Schneider Electric Modicon M340 PLC
python3 main.py --profile siemens     # Siemens SIMATIC S7-1200 CPU
```

---

## 🧪 Automated Test Suite

The project includes comprehensive unit tests verifying framing, protocol conformance, CRC math, and physics feedback loops:

```bash
# Run all 22 unit tests
python3 -m unittest discover -s tests -p "test_*.py" -v

# Or using Makefile
make test
```

---

## 📊 Telemetry & Threat Intelligence Report

When stopping the honeypot (`Ctrl+C` / `SIGINT`), the system automatically compiles all collected intelligence into `logs/report.html`.

### Features of the Threat Dashboard:
1. **Executive KPI Cards:** Total events, attack probes, unique threat actors, critical exploits.
2. **MITRE ATT&CK® for ICS Breakdown:** Ranked bar chart and table of observed technique IDs.
3. **Live Process Telemetry:** Status of the simulated electrical grid and transformer oil temperature.
4. **Interactive Filterable Event Log:** Searchable by source IP, protocol, action name, or MITRE technique ID.
5. **SIEM Integration:** Logs simultaneously stream to `logs/events.jsonl` for one-click ingestion into Splunk, Elastic/ELK, or Wazuh.

To generate a report from existing logs without starting listeners:
```bash
python3 main.py --report-only
```

---

## 🛡️ Real-World Testing & Verification

```bash
# 1. Modbus Device Scan (Nmap)
nmap -p 502 --script modbus-discover 127.0.0.1

# 2. Modbus Register Read
python3 -c "import socket; s = socket.socket(); s.connect(('127.0.0.1', 502)); s.sendall(bytes.fromhex('000100000006010300000004')); print(s.recv(1024).hex())"

# 3. MQTT Plaintext Credential Probe
mosquitto_pub -h 127.0.0.1 -p 1883 -u "admin" -P "ScadaPass2026!" -t "substation/alarm" -m "test"

# 4. DNP3 Class 0 Data Poll (Raw TCP)
echo -ne '\x05\x64\x05\xc0\x01\x00\x02\x00\x00\x00' | nc 127.0.0.1 20000
```

---

## 📄 License

Distributed under the MIT License. Built for ICS/OT cybersecurity research and infrastructure defense.
