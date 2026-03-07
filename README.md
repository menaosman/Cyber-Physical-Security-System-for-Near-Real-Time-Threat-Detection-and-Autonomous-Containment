<div align="center">

# Multi-Agent Security System
### Predictive Cyber-Physical Security for Smart Campuses

[![Tests](https://img.shields.io/badge/tests-76%2F76%20passing-brightgreen?style=flat-square)](tests/)
[![Phases](https://img.shields.io/badge/phases-4%2F4%20complete-blue?style=flat-square)](#architecture)
[![Agents](https://img.shields.io/badge/agents-9%20built-orange?style=flat-square)](#agents)
[![Python](https://img.shields.io/badge/python-3.12-yellow?style=flat-square)](https://python.org)
[![Kafka](https://img.shields.io/badge/kafka-event%20backbone-red?style=flat-square)](https://kafka.apache.org)
[![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK%20mapped-purple?style=flat-square)](https://attack.mitre.org)
[![License](https://img.shields.io/badge/license-MIT-lightgrey?style=flat-square)](LICENSE)

**A graduation project building a real-time, autonomous security system that protects a smart university campus — simultaneously watching IoT sensors, physical access doors, and network traffic, then correlating threats across all three to catch attacks no single system could detect alone.**

[Architecture](#architecture) · [Agents](#agents) · [Quick Start](#quick-start) · [Demo](#demo) · [Tests](#tests) · [Standards](#standards)

</div>

---

## 🎯 The Problem

Modern campuses are cyber-physical environments — sensors monitor temperature and gas levels, RFID cards control door access, and thousands of computers connect to the network. These systems are traditionally monitored in isolation:

- **The building management system** doesn't know someone just failed SSH 12 times on the server
- **The network monitoring tool** doesn't know an unknown RFID card tried the server room door 3 minutes ago
- **The endpoint security agent** doesn't know the IoT temperature sensor in the adjacent lab just spiked to 55°C

**An attacker who knows this exploits it.** They walk in through an unmonitored door, pivot through an IoT device onto the data network, dump credentials, and exfiltrate data — and no single monitoring system sees the full picture.

**MASS sees the full picture.**

---

## 🏛️ Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                    CAMPUS CYBER-PHYSICAL ENVIRONMENT                 │
│                                                                       │
│  ┌─────────────┐   ┌──────────────────┐   ┌─────────────────────┐  │
│  │  IoT Network │   │  Physical Access  │   │   Data Network      │  │
│  │             │   │     Network       │   │                     │  │
│  │ DHT22 Temp  │   │  RFID RC522       │   │  Campus Endpoints   │  │
│  │ MQ-2 Gas    │   │  Door Locks       │   │  Servers (VLAN 60)  │  │
│  │ PIR Motion  │   │  PIR Sensors      │   │  Network Flows      │  │
│  │             │   │  OpenLDAP Auth    │   │  Zeek / Suricata    │  │
│  └──────┬──────┘   └────────┬─────────┘   └──────────┬──────────┘  │
│         │                   │                          │             │
└─────────┼───────────────────┼──────────────────────────┼────────────┘
          │ MQTT/TLS           │ MQTT/TLS                 │ Kafka
          ▼                   ▼                          ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         AGENT LAYER                                  │
│                                                                       │
│  ┌──────────────────┐  ┌──────────────────┐  ┌───────────────────┐ │
│  │  PHASE 1 — IoT   │  │ PHASE 2 — PAC    │  │ PHASE 3 — DATA    │ │
│  │                  │  │                  │  │                   │ │
│  │ Gateway Agent    │  │ PAC-EDA Agent    │  │ NDR Agent         │ │
│  │ Behavioral Agent │  │ Credential       │  │ EDR Agent         │ │
│  │ IoT Local Mgr    │  │ Anomaly Agent    │  │ Data Local Mgr    │ │
│  │                  │  │ PAC Local Mgr    │  │                   │ │
│  └────────┬─────────┘  └────────┬─────────┘  └─────────┬─────────┘ │
│           │                     │                        │           │
└───────────┼─────────────────────┼────────────────────────┼──────────┘
            │ hq.incidents         │ hq.incidents            │ hq.incidents
            └─────────────────────┼────────────────────────┘
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     PHASE 4 — HQ INTELLIGENCE                        │
│                                                                       │
│   Analytical Agent ──► Orchestrator Agent ──► SOAR Commands          │
│        │                                                              │
│   Learning Agent (MLflow retraining pipeline)                        │
│   Central Manager  GET /status  /incidents  /correlations            │
└─────────────────────────────────────────────────────────────────────┘
```

**Communication stack:** MQTT (TLS port 8883) for sensors → agents · Kafka (13 topics) for all agent-to-agent messaging · FastAPI health/control endpoints on every agent · MongoDB + InfluxDB + PostgreSQL for persistence

---

## 🤖 Agents

### Phase 1 — IoT Network

| Agent | What it does | Port |
|---|---|---|
| **Gateway Agent** | Receives raw sensor readings over MQTT/TLS. Validates against allowlist, checks sequence numbers, classifies risk (LOW/MEDIUM/HIGH/CRITICAL). Fires sustained HIGH alert if gas stays above 450ppm for 10+ seconds. | 8000 |
| **Behavioral Analysis Agent** | Dual-layer ML detector. Layer 1: Modified Z-score (MAD-based) with frozen baseline — guarantees catching a 55°C spike after a 22°C baseline with 100% recall. Layer 2: Isolation Forest for subtle multi-variate anomalies. | 8001 |
| **IoT Local Manager** | Context-aware reclassification: HIGH temp + MEDIUM gas → CRITICAL fire risk. Heartbeat watchdog: sensor silent >20s → device dropout alert (MITRE T0829). 60s operator approval window before auto-escalation to HQ. | 8010 |

### Phase 2 — Physical Access Control

| Agent | What it does | Port |
|---|---|---|
| **PAC-EDA Agent** | Watches every door swipe. Detects: unknown card (not in LDAP → HIGH), unauthorized floor access (MEDIUM), tailgating (card swiped twice in 5s → MEDIUM), after-hours access (MEDIUM). Dual Kafka output: all events + confirmed attacks. | 8002 |
| **Credential Anomaly Agent** | Pattern detection across events: impossible travel (same card at 2 buildings in <60s → HIGH), credential sharing (3× same card+door in 30s → MEDIUM), brute force (5+ unknown cards at same door → HIGH), badge cloning (same UID at 2 doors in <10s → CRITICAL). | 8003 |
| **PAC Local Manager** | Area-sensitivity rules: any incident near HQ/server room → automatic CRITICAL upgrade. 3+ failed attempts at same door → lockdown command to SOAR. 60s approval window. | 8011 |

### Phase 3 — Data Network

| Agent | What it does | Port |
|---|---|---|
| **NDR Agent** | Analyzes network flows. Detects: port scan (T1046), SSH/HTTP brute force (T1110), data exfiltration >50MB (T1048, always CRITICAL), lateral movement across 3+ VLANs (T1021), C2 beaconing (T1071), unauthorized VLAN crossings (T1599). Alert deduplication prevents flooding. | 8004 |
| **EDR Agent** | Analyzes endpoint events. Detects: ransomware (mass file encryption → CRITICAL, T1486), credential dump /etc/shadow or LSASS (T1003), privilege escalation (T1548), persistence modifications (T1053), suspicious processes like mimikatz/netcat (T1059), 5 inline YARA rules including reverse shells (T1027). | 8005 |
| **Data Local Manager** | Cross-agent correlation: ransomware + credential dump same host in 5 min → CRITICAL; port scan + brute force same IP in 2 min → CRITICAL; lateral movement + privilege escalation in 10 min → CRITICAL (APT pattern). `/isolate/{host_id}` sends SOAR command. | 8012 |

### Phase 4 — HQ Intelligence

| Agent | What it does | Port |
|---|---|---|
| **Analytical Agent** | Cross-domain correlation engine. 5-minute fast window + 30-minute APT window. 5 rules: coordinated_attack (2+ domains active), campus_wide_threat (all 3 domains), insider_threat (PAC anomaly + data exfil), iot_cyber_bridge (IoT anomaly + lateral movement = attacker pivoting from IoT VLAN), physical_cyber_combo (unknown RFID + credential dump). | 8006 |
| **Orchestrator Agent** | SOAR engine. 4 playbooks: ransomware_response, intrusion_response, iot_compromise_response, access_control_lockdown. Auto-steps fire immediately; destructive steps (restore_from_backup, rotate_credentials) require operator approval. Tracks all executions. | 8007 |
| **Learning Agent** | MLflow-tracked retraining pipeline. Builds labeled dataset from confirmed incidents and dismissed false positives. Auto-retrains after 50 incidents or every 24 hours. Computes threshold recommendations and publishes them to SOAR commands for hot-update without restart. | 8008 |
| **Central Manager** | System dashboard API. Live threat level (LOW/MEDIUM/HIGH/CRITICAL). Agent heartbeat tracking. `GET /status` `GET /incidents` `GET /correlations` `POST /approve/{id}` | 8020 |

---

## ⚡ Quick Start

```bash
# 1. Clone
git clone https://github.com/menaosman/Cyber-Physical-Security-System-for-Near-Real-Time-Threat-Detection-and-Autonomous-Containment.git
cd campus-security-system

# 2. Start infrastructure
docker-compose -f docker/docker-compose.yml up -d

# 3. Create virtual environment
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# 4. Run all tests (76 tests, ~14 seconds)
pytest tests/ -v

# 5. Run the full attack demo
python scripts/full_attack_scenario.py --demo-mode
```

**Service endpoints after startup:**

| Service | URL |
|---|---|
| Grafana Dashboard | http://localhost:3000 |
| Kafka UI | http://localhost:8080 |
| Central Manager | http://localhost:8020/status |
| Analytical Agent | http://localhost:8006/correlations |
| Orchestrator | http://localhost:8007/executions |

---

## 🎬 Demo

The master demo script launches a coordinated 30-second multi-vector attack across all three network domains and shows the system respond autonomously:

```
T+00s  Unknown RFID card at server room door     ──► PAC-EDA Agent detects [T1078]
T+01s  4 more unknown RFID attempts              ──► Brute force pattern [T1110]
T+03s  Temperature spike: 55.2°C in Lab A        ──► Behavioral Agent detects [T0830]
T+04s  Gas anomaly: 520ppm                       ──► Gateway Agent sustained alert
T+10s  Port scan: 22 unique ports from attacker  ──► NDR Agent detects [T1046]
T+14s  SSH brute force: 12 failed attempts       ──► NDR correlates with scan → CRITICAL
T+18s  Lateral movement across 4 VLANs           ──► NDR Agent detects [T1021]
T+22s  Ransomware: 25 file encryptions on server ──► EDR Agent detects [T1486]
T+26s  Credential dump via mimikatz              ──► EDR Agent CRITICAL [T1003]
T+30s  Data exfiltration: 80MB to external IP    ──► NDR Agent CRITICAL [T1048]

                              ▼
            Analytical Agent fires 4 correlations:
              ✦ coordinated_attack   (IoT + Data active simultaneously)
              ✦ campus_wide_threat   (all 3 domains triggered)
              ✦ physical_cyber_combo (unknown RFID + credential dump)
              ✦ insider_threat       (PAC anomaly + data exfiltration)

                              ▼
            Orchestrator executes 3 playbooks automatically:
              ✦ ransomware_response      → isolate_host, kill_processes, snapshot
              ✦ intrusion_response       → block_attacker_ip, capture_full_traffic
              ✦ iot_compromise_response  → isolate_iot_vlan, restart_sensors
```

```bash
# Run it
python scripts/full_attack_scenario.py --demo-mode

# Then check the results
curl http://localhost:8006/correlations   # HQ correlations
curl http://localhost:8007/executions    # SOAR playbook executions
curl http://localhost:8020/status        # Full system threat level
```

---

## 🧪 Tests

**76 tests across 5 test files — all passing.**

```bash
pytest tests/ -v
```

| File | Suite | Tests |
|---|---|---|
| `phase1_gate_test.py` | IoT — Gateway, Behavioral, Local Manager | 18 ✅ |
| `phase2_gate_test.py` | PAC — EDA, Credential Anomaly, Local Manager | 15 ✅ |
| `phase3_gate_test.py` | Data — NDR, EDR, Local Manager + Kafka integration | 17 ✅ |
| `phase4_gate_test.py` | HQ — Analytical, Orchestrator, Central Manager + Kafka integration | 19 ✅ |
| `learning_agent_test.py` | Learning Agent — dataset labeling, retraining pipeline | 7 ✅ |
| | **Total** | **76 ✅** |

Every phase has a gate test that must pass 100% before the PR merges to main. Tests run without Kafka (mocked) except for the integration tests which detect Kafka automatically and skip gracefully if not running.

---

## 📁 Repository Structure

```
campus-security-system/
├── agents/
│   ├── iot/
│   │   ├── gateway_agent/          # Phase 1 — Risk classification + MQTT/TLS
│   │   ├── behavioral_agent/       # Phase 1 — Dual-layer ML (MAD Z-score + IF)
│   │   └── iot_simulator.py        # 3 sensors, 5 attack modes
│   ├── physical_access/
│   │   ├── pac_eda_agent/          # Phase 2 — Event detection (tailgating, brute force)
│   │   ├── credential_anomaly_agent/ # Phase 2 — Impossible travel, badge clone
│   │   └── pac_simulator.py        # 4 LDAP users, 5 attack modes
│   ├── data_network/
│   │   ├── ndr_agent/              # Phase 3 — Network flows (port scan, exfil, lateral)
│   │   ├── edr_agent/              # Phase 3 — Endpoints (ransomware, YARA, privesc)
│   │   └── data_network_simulator.py # 6 attack scenarios
│   └── hq/
│       ├── analytical_agent/       # Phase 4 — Cross-domain correlation (5 rules)
│       ├── orchestrator_agent/     # Phase 4 — SOAR (4 playbooks)
│       └── learning_agent/         # Phase 4 — MLflow retraining pipeline
├── managers/
│   ├── iot_local_manager/          # Phase 1
│   ├── pac_local_manager/          # Phase 2
│   ├── data_local_manager/         # Phase 3
│   └── central_manager/            # Phase 4 — /status /incidents /approve
├── common/
│   ├── kafka_client.py             # 13-topic architecture, producer + consumer
│   ├── models.py                   # Shared Pydantic schemas (Alert, SensorReading)
│   ├── mqtt_client.py              # SecureMQTTClient with TLS
│   └── security.py                 # TLSConfig
├── scripts/
│   └── full_attack_scenario.py     # Master demo — 30s coordinated attack
├── tests/
│   ├── phase1_gate_test.py         # 18 tests
│   ├── phase2_gate_test.py         # 15 tests
│   ├── phase3_gate_test.py         # 17 tests
│   ├── phase4_gate_test.py         # 19 tests
│   └── learning_agent_test.py      # 7 tests
├── docker/
│   ├── docker-compose.yml          # 10 services: Kafka, MQTT, DBs, Grafana, all agents
│   └── Dockerfile.agent            # Single image for all Python agents
├── docs/
│   ├── weekly-reports/             # week1.md through week10.md
│   └── DEMO_SCRIPT.md              # Exact commands + timing for presentation
└── managers_database/
    └── *.sql                       # Schema for all 4 manager databases
```

---

## 🔒 Security Standards

Every detection rule and design decision is mapped to an established security standard:

| Standard | Where applied |
|---|---|
| **MITRE ATT&CK for ICS** | T0829 (Loss of View), T0830 (Adversarial Sensor Reading) — IoT agents |
| **MITRE ATT&CK for Enterprise** | T1046, T1048, T1078, T1110, T1003, T1486, T1021, T1071, T1027, T1053, T1547, T1548, T1059, T1599 — Data/PAC agents |
| **NIST SP 800-82** | IoT/OT continuous monitoring — Gateway + Behavioral agents |
| **NIST SP 800-61 Rev2** | Incident response structure — all local managers + HQ |
| **NIST SP 800-53** | AU family (audit/logging), AC-3/AC-7/IA-4 (access control) — PAC agents |
| **NIST CSF 2.0** | DETECT + RESPOND functions — local managers |
| **NIST AI RMF** | GOVERN-1.4 (AI lifecycle) — Learning Agent |
| **IEC 62443-2-1** | Security management + reclassification rules — all local managers |
| **IEC 62443 Zones & Conduits** | VLAN segmentation design (VLANs 10-70) |
| **ISO 27001** | Reporting and operator oversight — approval windows |

---

## 🗺️ VLAN Architecture

```
VLAN 10-12, 15  Academic Data Network    ─┐
VLAN 20-23      IoT Network              ─┤  Isolated by firewall ACLs
VLAN 30-34      Physical Access Control  ─┤  NDR Agent monitors crossings
VLAN 50         DMZ                      ─┤
VLAN 60         Internal Servers         ─┘
VLAN 70         Visitors (isolated)
VLAN 99         Management
```

Unauthorized traffic between isolated VLAN pairs (e.g., IoT → Servers) fires an immediate HIGH alert (MITRE T1599).

---

## 📡 Kafka Topic Map

```
iot.telemetry     ◄── IoT Simulator / Raspberry Pi sensors
iot.alerts        ◄── Gateway Agent + Behavioral Agent
iot.incidents     ◄── IoT Local Manager  ──► Analytical Agent

pac.events        ◄── PAC Simulator / pi-physical
pac.alerts        ◄── PAC-EDA Agent + Credential Anomaly Agent
pac.incidents     ◄── PAC Local Manager  ──► Analytical Agent

data.telemetry    ◄── Data Network Simulator / Zeek / Suricata / EDR sensors
data.alerts       ◄── NDR Agent + EDR Agent
data.incidents    ◄── Data Local Manager  ──► Analytical Agent

hq.incidents      ◄── All 3 local managers  ──► Analytical Agent
hq.correlated     ◄── Analytical Agent  ──► Orchestrator Agent

soar.commands     ◄── Orchestrator Agent + Local Managers  ──► Response systems
soar.responses    ◄── Response systems  ──► Orchestrator Agent + Learning Agent
agents.heartbeats ◄── All agents  ──► Central Manager
```

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| Language | Python 3.12 |
| API Framework | FastAPI + Uvicorn |
| ML | scikit-learn (Isolation Forest), NumPy (MAD Z-score) |
| Event Streaming | Apache Kafka (confluent-kafka) |
| IoT Messaging | Mosquitto MQTT with TLS (paho-mqtt) |
| Data Validation | Pydantic v2 |
| Databases | MongoDB 7.0 · InfluxDB 2.7 · PostgreSQL 16 |
| Monitoring | Grafana 10.3 |
| Containers | Docker + Docker Compose |
| ML Tracking | MLflow |
| Testing | pytest + pytest-asyncio |
| Security | TLS 1.3 · AES-256 · LDAP (OpenLDAP) |

---

## 👨‍💻 About

Built as a graduation project for a Computer Science / Cybersecurity degree. The system is designed around a real smart campus topology with Raspberry Pi hardware nodes (pi-iot for sensors, pi-physical for access control) connected to a Mininet network simulation.

**Solo implementation** — all 9 agents, 4 managers, 76 tests, and the full infrastructure were designed and built by one student over 10 weeks. The network simulation layer (Mininet + Raspberry Pi configuration) was handled by a separate 2-person team.

---

<div align="center">

**If you found this interesting, give it a ⭐**

*Built with Python, Kafka, and a lot of late nights.*

</div>
