"""
scripts/full_attack_scenario.py
Phase 5 Week 11 — Master Demo Script

Demonstrates the complete end-to-end MASS system in a single coordinated run.
Chains all 3 simulators to produce a realistic multi-vector campus attack.

ATTACK TIMELINE:
  T+00s  Unknown RFID card at server room door    → PAC-EDA → PAC Local Manager
  T+03s  Temperature spike (55°C) in Lab A        → Gateway → Behavioral → IoT LM
  T+06s  Gas anomaly (520ppm)                     → Gateway → IoT Local Manager
  T+10s  Port scan from external IP               → NDR → Data Local Manager
  T+14s  Brute force SSH from same IP             → NDR correlates with scan → CRITICAL
  T+18s  Lateral movement across VLANs            → NDR → Data Local Manager
  T+22s  Ransomware on server (50 file encrypts)  → EDR → Data Local Manager
  T+26s  Credential dump attempt                  → EDR → CRITICAL
  T+30s  Data exfiltration (80MB to external)     → NDR → CRITICAL immediately

EXPECTED HQ CORRELATIONS (Analytical Agent):
  - coordinated_attack  (IoT + Data + PAC all active)
  - campus_wide_threat  (all 3 domains)
  - physical_cyber_combo (unknown RFID + credential_dump)
  - insider_threat      (PAC anomaly + data exfil)

EXPECTED SOAR RESPONSES (Orchestrator):
  - ransomware_response playbook  → isolate_host, kill_processes, snapshot
  - intrusion_response playbook   → block_attacker_ip, capture_traffic
  - iot_compromise_response       → isolate_iot_vlan

Usage:
  python scripts/full_attack_scenario.py [--bootstrap localhost:9092] [--delay 1.0]
  python scripts/full_attack_scenario.py --demo-mode   # slower pacing for presenter
"""
from __future__ import annotations
import argparse, json, logging, sys, time, uuid
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from common.kafka_client import KafkaProducerClient

logging.basicConfig(level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s")
logger = logging.getLogger("full_attack_scenario")

ATTACKER_IP  = "192.168.100.50"
SERVER_IP    = "10.0.60.10"
WORKSTATION  = "10.0.10.20"
IOT_IP       = "10.0.20.5"

BANNER = """
╔══════════════════════════════════════════════════════════════════════════════╗
║         MASS — Multi-Agent Security System for Smart Campus                 ║
║              FULL ATTACK SCENARIO DEMONSTRATION                              ║
║                                                                              ║
║  3 Attack Vectors:  IoT  │  Physical Access  │  Data Network                ║
║  Expected Result:   Cross-domain correlation → Automated SOAR Response      ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""


class FullAttackScenario:
    def __init__(self, bootstrap: str = "localhost:9092", delay: float = 1.0):
        self._prod = KafkaProducerClient(bootstrap)
        self._delay = delay
        self._step = 0
        self._events_published = 0

    def _pub(self, topic: str, payload: dict, label: str):
        self._step += 1
        self._prod.publish(topic, payload,
                           key=payload.get("src_ip",
                               payload.get("host_id",
                               payload.get("gateway_id", "demo"))))
        self._events_published += 1
        ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
        logger.warning(f"  [{ts}] Step {self._step:02d} ▶ {label}")
        time.sleep(self._delay)

    def _flow(self, src_ip, dst_ip, dst_port, status="established",
              bytes_out=1024, proto="tcp", extra=None):
        p = {"event_type": "network_flow", "src_ip": src_ip, "dst_ip": dst_ip,
             "dst_port": dst_port, "proto": proto, "status": status,
             "bytes_out": bytes_out, "sensor": "zeek",
             "flow_id": str(uuid.uuid4()),
             "timestamp": datetime.now(timezone.utc).isoformat()}
        if extra: p.update(extra)
        return p

    def _endpoint(self, host_id, event_type, proc_name="", cmd_line="",
                  file_path="", op="read", username="user", extra=None):
        p = {"event_type": event_type, "host_id": host_id,
             "process_name": proc_name, "command_line": cmd_line,
             "file_path": file_path, "operation": op, "username": username,
             "sensor": "edr_endpoint", "event_id": str(uuid.uuid4()),
             "timestamp": datetime.now(timezone.utc).isoformat()}
        if extra: p.update(extra)
        return p

    def _access(self, card_uid, door_id, floor, building, result,
                card_type="unknown", username="", extra=None):
        p = {"event_type": "access_event", "card_uid": card_uid,
             "door_id": door_id, "floor": floor, "building": building,
             "result": result, "card_type": card_type,
             "username": username, "gateway_id": "GW-PAC-ACADEMIC-F1-01",
             "event_id": str(uuid.uuid4()),
             "timestamp": datetime.now(timezone.utc).isoformat()}
        if extra: p.update(extra)
        return p

    def _sensor(self, sensor_id, sensor_type, value, unit, gateway_id,
                zone, topic_suffix, extra=None):
        p = {"sensor_id": sensor_id, "sensor_type": sensor_type,
             "value": value, "unit": unit, "gateway_id": gateway_id,
             "zone": zone, "sequence_number": int(time.time()) % 10000,
             "timestamp": datetime.now(timezone.utc).isoformat()}
        if extra: p.update(extra)
        return p

    # ── DEMO RUN ──────────────────────────────────────────────────────────────
    def run(self):
        print(BANNER)
        t0 = time.time()

        print("━" * 78)
        print("  PHASE A — Physical Access Attack (Unknown RFID at Server Room)")
        print("━" * 78)
        time.sleep(self._delay)

        # T+00: Unknown RFID card — not in LDAP
        self._pub("access/academic/floor2/door4",
                  self._access("DEADBEEF", "door4", 2, "Academic",
                               "denied", "unknown",
                               extra={"scenario": "unknown_card_server_room",
                                      "area": "server_room"}),
                  "Unknown RFID card at server room door [T1078]")

        # T+01: Same unknown card tries again — brute force pattern
        for i in range(4):
            self._pub("access/academic/floor2/door4",
                      self._access(f"UNKNOWN{i:02d}", "door4", 2, "Academic",
                                   "denied", "unknown",
                                   extra={"scenario": "brute_force_rfid"}),
                      f"Unknown RFID attempt {i+2}/5 — brute force building [T1110]")

        print()
        print("━" * 78)
        print("  PHASE B — IoT Sensor Attacks (Fire Scenario + Sensor Dropout)")
        print("━" * 78)
        time.sleep(self._delay)

        # T+03: Temperature spike
        self._pub("sensors/academic/floor1/temperature",
                  self._sensor("DHT22-ACADEMIC-F1-LABA-01", "temperature",
                               55.2, "celsius", "GW-ACADEMIC-F1-01",
                               "Academic/Floor1/LabA", "temperature",
                               extra={"scenario": "temperature_spike"}),
                  "Temperature spike: 55.2°C in Lab A [T0830]")

        # T+04: Gas anomaly
        self._pub("sensors/academic/floor1/gas",
                  self._sensor("MQ2-ACADEMIC-F1-LABA-01", "gas",
                               520, "ppm", "GW-ACADEMIC-F1-01",
                               "Academic/Floor1/LabA", "gas",
                               extra={"scenario": "gas_anomaly"}),
                  "Gas anomaly: 520ppm in Lab A [T0830]")

        # T+05: Sustained gas (triggers sustained alert)
        for i in range(3):
            self._pub("sensors/academic/floor1/gas",
                      self._sensor("MQ2-ACADEMIC-F1-LABA-01", "gas",
                                   490 + i*10, "ppm", "GW-ACADEMIC-F1-01",
                                   "Academic/Floor1/LabA", "gas"),
                      f"Sustained gas reading #{i+1}: {490+i*10}ppm")

        print()
        print("━" * 78)
        print("  PHASE C — Data Network Attack (Recon → Exploitation → Exfiltration)")
        print("━" * 78)
        time.sleep(self._delay)

        # T+10: Port scan
        for port in list(range(8000, 8022)):
            self._prod.publish("data.telemetry",
                               self._flow(ATTACKER_IP, SERVER_IP, port,
                                         status="S0", bytes_out=64,
                                         extra={"scenario": "port_scan"}),
                               key=ATTACKER_IP)
        self._step += 1; self._events_published += 22
        logger.warning(f"  [step {self._step:02d}] 22 port scan flows published "
                       f"to ports 8000-8021 [T1046]")
        time.sleep(self._delay)

        # T+14: Brute force SSH from same IP
        for i in range(12):
            self._prod.publish("data.telemetry",
                               self._flow(ATTACKER_IP, SERVER_IP, 22,
                                         status="REJ", bytes_out=128,
                                         extra={"scenario": "brute_force_ssh",
                                                "attempt": i+1}),
                               key=ATTACKER_IP)
        self._step += 1; self._events_published += 12
        logger.warning(f"  [step {self._step:02d}] 12 SSH brute force attempts [T1110]")
        time.sleep(self._delay)

        # T+18: Lateral movement across VLANs
        for src, dst, port in [(WORKSTATION, "10.0.11.50", 445),
                                (WORKSTATION, "10.0.12.30", 22),
                                (WORKSTATION, SERVER_IP,    3389),
                                (WORKSTATION, "10.0.15.10", 443)]:
            self._pub("data.telemetry",
                      self._flow(src, dst, port,
                                 extra={"scenario": "lateral_movement"}),
                      f"Lateral movement: {src} → {dst}:{port} [T1021]")

        # T+22: Ransomware
        for i in range(25):
            self._prod.publish("data.telemetry",
                               self._endpoint(SERVER_IP, "file_op",
                                             proc_name="cryptor.exe",
                                             file_path=f"/data/file_{i:04d}.locked",
                                             op="rename",
                                             extra={"scenario": "ransomware"}),
                               key=SERVER_IP)
        self._step += 1; self._events_published += 25
        logger.warning(f"  [step {self._step:02d}] 25 ransomware file encryptions [T1486]")
        time.sleep(self._delay)

        # T+26: Credential dump
        self._pub("data.telemetry",
                  self._endpoint(SERVER_IP, "process",
                                 proc_name="mimikatz.exe",
                                 cmd_line="mimikatz privilege::debug sekurlsa::logonpasswords",
                                 username="svc_backup",
                                 extra={"scenario": "credential_dump"}),
                  "Credential dump via mimikatz [T1003]")

        self._pub("data.telemetry",
                  self._endpoint(SERVER_IP, "file_op",
                                 proc_name="procdump.exe",
                                 file_path="/etc/shadow",
                                 op="read", username="www-data",
                                 extra={"scenario": "credential_dump"}),
                  "Shadow file read attempt [T1003.008]")

        # T+30: Data exfiltration — large outbound transfer
        self._pub("data.telemetry",
                  self._flow(SERVER_IP, "185.220.101.5", 443,
                             bytes_out=83886080,
                             extra={"scenario": "data_exfiltration",
                                    "dst_country": "unknown"}),
                  "DATA EXFILTRATION: 80MB to external IP [T1048] ← CRITICAL")

        # Final flush
        self._prod.flush()
        elapsed = round(time.time() - t0, 1)

        print()
        print("━" * 78)
        print("  ATTACK SEQUENCE COMPLETE")
        print("━" * 78)
        print(f"""
  Total events published : {self._events_published}
  Time elapsed           : {elapsed}s
  Attack vectors used    : 3 (IoT + Physical Access + Data Network)

  Now watch the agents respond:
  ─────────────────────────────────────────────────────────────────
  IoT Local Manager     http://localhost:8010/incidents
  PAC Local Manager     http://localhost:8011/incidents
  Data Local Manager    http://localhost:8012/incidents
  Analytical Agent      http://localhost:8006/correlations
  Orchestrator Agent    http://localhost:8007/executions
  Central Manager       http://localhost:8020/status
  ─────────────────────────────────────────────────────────────────

  Expected HQ correlations (check /correlations):
    ✦ coordinated_attack   — IoT + Data domains simultaneously active
    ✦ campus_wide_threat   — all 3 domains triggered
    ✦ physical_cyber_combo — unknown RFID + credential_dump
    ✦ insider_threat       — PAC anomaly + data exfiltration

  Expected SOAR playbooks (check /executions):
    ✦ ransomware_response      → isolate_host, kill_processes, snapshot
    ✦ intrusion_response       → block_attacker_ip, capture_traffic
    ✦ iot_compromise_response  → isolate_iot_vlan
""")
        self.stop()

    def stop(self):
        self._prod.flush()
        self._prod.close()
        logger.info("👋 Full attack scenario complete")


def main():
    p = argparse.ArgumentParser(
        description="MASS Full Attack Scenario — Demo Script")
    p.add_argument("--bootstrap",  default="localhost:9092",
                   help="Kafka bootstrap servers")
    p.add_argument("--delay",      type=float, default=1.0,
                   help="Seconds between attack steps (default 1.0)")
    p.add_argument("--demo-mode",  action="store_true",
                   help="Slower pacing for live presentation (3s delay)")
    args = p.parse_args()

    delay = 3.0 if args.demo_mode else args.delay
    scenario = FullAttackScenario(bootstrap=args.bootstrap, delay=delay)
    try:
        scenario.run()
    except KeyboardInterrupt:
        scenario.stop()

if __name__ == "__main__":
    main()
