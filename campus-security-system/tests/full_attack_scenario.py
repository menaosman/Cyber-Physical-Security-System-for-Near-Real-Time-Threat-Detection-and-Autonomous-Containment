"""
scripts/full_attack_scenario.py
Phase 5 Week 11 — Master Demo Script (fixed Kafka topic names)

IoT sensor events now publish to Kafka topic  iot.telemetry
PAC access events publish to Kafka topic       pac.events
Data network events publish to Kafka topic     data.telemetry
"""
from __future__ import annotations
import argparse, logging, sys, time, uuid
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from common.kafka_client import KafkaProducerClient, Topics

logging.basicConfig(level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s")
logger = logging.getLogger("full_attack_scenario")

ATTACKER_IP  = "192.168.100.50"
SERVER_IP    = "10.0.60.10"
WORKSTATION  = "10.0.10.20"

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
        self._prod  = KafkaProducerClient(bootstrap)
        self._delay = delay
        self._step  = 0
        self._events_published = 0

    def _pub(self, topic: str, payload: dict, label: str):
        self._step += 1
        self._prod.publish(topic, payload,
                           key=payload.get("src_ip",
                               payload.get("host_id",
                               payload.get("card_uid",
                               payload.get("sensor_id", "demo")))))
        self._events_published += 1
        ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
        logger.warning(f"  [{ts}] Step {self._step:02d} ▶ {label}")
        time.sleep(self._delay)

    # ── Event factories ───────────────────────────────────────────────────────
    def _flow(self, src_ip, dst_ip, dst_port, status="established",
              bytes_out=1024, proto="tcp", scenario=""):
        return {"event_type": "network_flow", "src_ip": src_ip,
                "dst_ip": dst_ip, "dst_port": dst_port, "proto": proto,
                "status": status, "bytes_out": bytes_out,
                "sensor": "zeek", "flow_id": str(uuid.uuid4()),
                "scenario": scenario,
                "timestamp": datetime.now(timezone.utc).isoformat()}

    def _endpoint(self, host_id, event_type, proc_name="", cmd_line="",
                  file_path="", op="read", username="user", scenario=""):
        return {"event_type": event_type, "host_id": host_id,
                "process_name": proc_name, "command_line": cmd_line,
                "file_path": file_path, "operation": op,
                "username": username, "sensor": "edr_endpoint",
                "event_id": str(uuid.uuid4()), "scenario": scenario,
                "timestamp": datetime.now(timezone.utc).isoformat()}

    def _access(self, card_uid, door_id, floor, building,
                result, card_type="unknown", username="", scenario=""):
        return {"event_type": "access_event", "card_uid": card_uid,
                "door_id": door_id, "floor": floor, "building": building,
                "result": result, "card_type": card_type,
                "username": username, "gateway_id": "GW-PAC-ACADEMIC-F1-01",
                "event_id": str(uuid.uuid4()), "scenario": scenario,
                "timestamp": datetime.now(timezone.utc).isoformat()}

    def _sensor(self, sensor_id, sensor_type, value, unit,
                gateway_id, zone, scenario=""):
        return {"sensor_id": sensor_id, "sensor_type": sensor_type,
                "value": value, "unit": unit,
                "gateway_id": gateway_id, "zone": zone,
                "sequence_number": int(time.time()) % 10000,
                "scenario": scenario,
                "timestamp": datetime.now(timezone.utc).isoformat()}

    # ── DEMO RUN ──────────────────────────────────────────────────────────────
    def run(self):
        print(BANNER)
        t0 = time.time()

        # ── PHASE A — Physical Access ─────────────────────────────────────────
        print("━" * 78)
        print("  PHASE A — Physical Access Attack (Unknown RFID at Server Room)")
        print("━" * 78)
        time.sleep(self._delay)

        self._pub(Topics.PAC_EVENTS,
                  self._access("DEADBEEF", "door4", 2, "Academic",
                               "denied", "unknown",
                               scenario="unknown_card_server_room"),
                  "Unknown RFID card at server room door [T1078]")

        for i in range(4):
            self._pub(Topics.PAC_EVENTS,
                      self._access(f"UNKNOWN{i:02d}", "door4", 2, "Academic",
                                   "denied", "unknown",
                                   scenario="brute_force_rfid"),
                      f"Unknown RFID attempt {i+2}/5 — brute force pattern [T1110]")

        # ── PHASE B — IoT ─────────────────────────────────────────────────────
        print()
        print("━" * 78)
        print("  PHASE B — IoT Sensor Attacks (Fire Scenario)")
        print("━" * 78)
        time.sleep(self._delay)

        self._pub(Topics.IOT_TELEMETRY,
                  self._sensor("DHT22-ACADEMIC-F1-LABA-01", "temperature",
                               55.2, "celsius", "GW-ACADEMIC-F1-01",
                               "Academic/Floor1/LabA",
                               scenario="temperature_spike"),
                  "Temperature spike: 55.2°C in Lab A [T0830]")

        self._pub(Topics.IOT_TELEMETRY,
                  self._sensor("MQ2-ACADEMIC-F1-LABA-01", "gas",
                               520, "ppm", "GW-ACADEMIC-F1-01",
                               "Academic/Floor1/LabA",
                               scenario="gas_anomaly"),
                  "Gas anomaly: 520ppm in Lab A [T0830]")

        for i in range(3):
            self._pub(Topics.IOT_TELEMETRY,
                      self._sensor("MQ2-ACADEMIC-F1-LABA-01", "gas",
                                   490 + i*10, "ppm", "GW-ACADEMIC-F1-01",
                                   "Academic/Floor1/LabA"),
                      f"Sustained gas reading #{i+1}: {490+i*10}ppm")

        # ── PHASE C — Data Network ────────────────────────────────────────────
        print()
        print("━" * 78)
        print("  PHASE C — Data Network Attack (Recon → Exploitation → Exfiltration)")
        print("━" * 78)
        time.sleep(self._delay)

        # Port scan — publish in bulk, count as one step
        for port in range(8000, 8022):
            self._prod.publish(Topics.DATA_TELEMETRY,
                               self._flow(ATTACKER_IP, SERVER_IP, port,
                                         status="S0", bytes_out=64,
                                         scenario="port_scan"),
                               key=ATTACKER_IP)
        self._step += 1; self._events_published += 22
        ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
        logger.warning(f"  [{ts}] Step {self._step:02d} ▶ "
                       f"Port scan: 22 unique ports from {ATTACKER_IP} [T1046]")
        time.sleep(self._delay)

        # Brute force SSH
        for i in range(12):
            self._prod.publish(Topics.DATA_TELEMETRY,
                               self._flow(ATTACKER_IP, SERVER_IP, 22,
                                         status="REJ", bytes_out=128,
                                         scenario="brute_force_ssh"),
                               key=ATTACKER_IP)
        self._step += 1; self._events_published += 12
        ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
        logger.warning(f"  [{ts}] Step {self._step:02d} ▶ "
                       f"SSH brute force: 12 failed attempts [T1110]")
        time.sleep(self._delay)

        # Lateral movement
        for src, dst, port in [(WORKSTATION, "10.0.11.50", 445),
                                (WORKSTATION, "10.0.12.30", 22),
                                (WORKSTATION, SERVER_IP,    3389),
                                (WORKSTATION, "10.0.15.10", 443)]:
            self._pub(Topics.DATA_TELEMETRY,
                      self._flow(src, dst, port, scenario="lateral_movement"),
                      f"Lateral movement: {src} → {dst}:{port} [T1021]")

        # Ransomware
        for i in range(25):
            self._prod.publish(Topics.DATA_TELEMETRY,
                               self._endpoint(SERVER_IP, "file_op",
                                             proc_name="cryptor.exe",
                                             file_path=f"/data/file_{i:04d}.locked",
                                             op="rename",
                                             scenario="ransomware"),
                               key=SERVER_IP)
        self._step += 1; self._events_published += 25
        ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
        logger.warning(f"  [{ts}] Step {self._step:02d} ▶ "
                       f"Ransomware: 25 file encryptions on {SERVER_IP} [T1486]")
        time.sleep(self._delay)

        # Credential dump
        self._pub(Topics.DATA_TELEMETRY,
                  self._endpoint(SERVER_IP, "process",
                                 proc_name="mimikatz.exe",
                                 cmd_line="mimikatz privilege::debug sekurlsa::logonpasswords",
                                 username="svc_backup",
                                 scenario="credential_dump"),
                  "Credential dump via mimikatz [T1003]")

        self._pub(Topics.DATA_TELEMETRY,
                  self._endpoint(SERVER_IP, "file_op",
                                 proc_name="procdump.exe",
                                 file_path="/etc/shadow",
                                 op="read", username="www-data",
                                 scenario="credential_dump"),
                  "Shadow file read attempt [T1003.008]")

        # Data exfiltration — the final blow
        self._pub(Topics.DATA_TELEMETRY,
                  self._flow(SERVER_IP, "185.220.101.5", 443,
                             bytes_out=83_886_080,
                             scenario="data_exfiltration"),
                  "DATA EXFILTRATION: 80MB → external IP 185.220.101.5 [T1048] ← CRITICAL")

        self._prod.flush()
        elapsed = round(time.time() - t0, 1)

        print()
        print("━" * 78)
        print("  ATTACK SEQUENCE COMPLETE")
        print("━" * 78)
        print(f"""
  Total events published : {self._events_published}
  Time elapsed           : {elapsed}s
  Attack vectors         : 3 (IoT + Physical Access + Data Network)
  Kafka topics used      : {Topics.IOT_TELEMETRY}, {Topics.PAC_EVENTS}, {Topics.DATA_TELEMETRY}

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
    ✦ intrusion_response       → block_attacker_ip, capture_full_traffic
    ✦ iot_compromise_response  → isolate_iot_vlan
""")
        self.stop()

    def stop(self):
        self._prod.flush()
        self._prod.close()
        logger.info("👋 Full attack scenario complete")


def main():
    p = argparse.ArgumentParser(description="MASS Full Attack Scenario")
    p.add_argument("--bootstrap",  default="localhost:9092")
    p.add_argument("--delay",      type=float, default=1.0,
                   help="Seconds between steps (default 1.0)")
    p.add_argument("--demo-mode",  action="store_true",
                   help="3s delay between steps — for live presentation")
    args = p.parse_args()
    delay = 3.0 if args.demo_mode else args.delay
    s = FullAttackScenario(bootstrap=args.bootstrap, delay=delay)
    try:
        s.run()
    except KeyboardInterrupt:
        s.stop()

if __name__ == "__main__":
    main()
