"""
agents/data_network/data_network_simulator.py
Phase 3 — Data Network Attack Simulator

Publishes flow/endpoint events to Kafka topic: data.telemetry
Modes: normal | port_scan | brute_force | lateral_movement |
       data_exfiltration | ransomware | credential_dump | all

Usage: python data_network_simulator.py --mode port_scan
"""
from __future__ import annotations
import argparse, logging, random, sys, time, uuid
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from common.kafka_client import KafkaProducerClient

logging.basicConfig(level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s")
logger = logging.getLogger("data_simulator")

ATTACKER_IP  = "192.168.100.50"   # external attacker
SERVER_IP    = "10.0.60.10"       # internal server (VLAN 60)
WORKSTATION1 = "10.0.10.20"       # academic VLAN 10
WORKSTATION2 = "10.0.11.30"       # academic VLAN 11
IOT_IP       = "10.0.20.5"        # IoT VLAN 20


def _flow(src_ip, dst_ip, dst_port, proto="tcp", status="established",
          bytes_out=1024, sensor="zeek", extra=None):
    payload = {
        "event_type": "network_flow",
        "src_ip":     src_ip, "dst_ip": dst_ip,
        "dst_port":   dst_port, "proto": proto,
        "status":     status, "bytes_out": bytes_out,
        "sensor":     sensor,
        "flow_id":    str(uuid.uuid4()),
        "timestamp":  datetime.now(timezone.utc).isoformat(),
    }
    if extra: payload.update(extra)
    return payload


def _endpoint(host_id, event_type, proc_name="", cmd_line="",
              file_path="", op="read", username="user", extra=None):
    payload = {
        "event_type":    event_type,
        "host_id":       host_id,
        "process_name":  proc_name,
        "command_line":  cmd_line,
        "file_path":     file_path,
        "operation":     op,
        "username":      username,
        "sensor":        "edr_endpoint",
        "event_id":      str(uuid.uuid4()),
        "timestamp":     datetime.now(timezone.utc).isoformat(),
    }
    if extra: payload.update(extra)
    return payload


class DataNetworkSimulator:
    def __init__(self, bootstrap="localhost:9092"):
        self._producer = KafkaProducerClient(bootstrap)
        logger.info("✅ Data Network Simulator ready")

    def _pub(self, payload):
        self._producer.publish("data.telemetry", payload,
                               key=payload.get("src_ip", payload.get("host_id","sim")))
        logger.info(f"  📤 {payload.get('event_type','?')} "
                    f"src={payload.get('src_ip', payload.get('host_id','?'))}")

    # ── Normal traffic ────────────────────────────────────────────────────────
    def scenario_normal(self, count=20, interval=1.0):
        logger.info("📊 SCENARIO: normal network traffic")
        pairs = [(WORKSTATION1, SERVER_IP, 443), (WORKSTATION2, SERVER_IP, 80),
                 (WORKSTATION1, WORKSTATION2, 22), (SERVER_IP, "8.8.8.8", 53)]
        for _ in range(count):
            src, dst, port = random.choice(pairs)
            self._pub(_flow(src, dst, port, bytes_out=random.randint(500, 50000)))
            time.sleep(interval)
        logger.info("✅ Normal done")

    # ── Attack 1: Port scan ───────────────────────────────────────────────────
    def scenario_port_scan(self, ports=25, interval=0.2):
        logger.info("🔍 SCENARIO: port_scan — nmap-style sweep")
        for port in random.sample(range(1, 65535), ports):
            self._pub(_flow(ATTACKER_IP, SERVER_IP, port, status="S0",
                            bytes_out=64, extra={"attack_scenario": "port_scan"}))
            time.sleep(interval)
        logger.info("✅ Port scan done")

    # ── Attack 2: Brute force SSH ─────────────────────────────────────────────
    def scenario_brute_force(self, attempts=12, interval=0.3):
        logger.info("🔑 SCENARIO: brute_force_ssh")
        for i in range(attempts):
            self._pub(_flow(ATTACKER_IP, SERVER_IP, 22, status="REJ",
                            bytes_out=128,
                            extra={"attack_scenario": "brute_force_ssh", "attempt": i+1}))
            time.sleep(interval)
        logger.info("✅ Brute force done")

    # ── Attack 3: Lateral movement ────────────────────────────────────────────
    def scenario_lateral_movement(self, interval=0.5):
        logger.info("🦀 SCENARIO: lateral_movement — cross-VLAN hops")
        hops = [
            (WORKSTATION1, "10.0.11.50", 445),   # VLAN 10 → 11
            (WORKSTATION1, "10.0.12.30", 22),    # VLAN 10 → 12
            (WORKSTATION1, SERVER_IP,    3389),   # VLAN 10 → 60 (servers)
            (WORKSTATION1, "10.0.15.10", 443),   # VLAN 10 → 15 (HQ)
        ]
        for src, dst, port in hops:
            self._pub(_flow(src, dst, port,
                            extra={"attack_scenario": "lateral_movement"}))
            time.sleep(interval)
        logger.info("✅ Lateral movement done")

    # ── Attack 4: Data exfiltration ───────────────────────────────────────────
    def scenario_data_exfiltration(self):
        logger.info("💾 SCENARIO: data_exfiltration — large outbound transfer")
        self._pub(_flow(SERVER_IP, "185.220.101.5", 443,
                        bytes_out=80 * 1024 * 1024,   # 80 MB
                        extra={"attack_scenario": "data_exfiltration",
                               "dst_country": "unknown"}))
        logger.info("✅ Data exfiltration done")

    # ── Attack 5: Ransomware (EDR events) ─────────────────────────────────────
    def scenario_ransomware(self, file_count=25, interval=0.1):
        logger.info("🔒 SCENARIO: ransomware — mass file encryption")
        for i in range(file_count):
            self._pub(_endpoint(SERVER_IP, "file_op",
                proc_name="cryptor.exe",
                file_path=f"/data/documents/file_{i:04d}.locked",
                op="rename",
                extra={"attack_scenario": "ransomware"}))
            time.sleep(interval)
        logger.info("✅ Ransomware done")

    # ── Attack 6: Credential dump (EDR events) ────────────────────────────────
    def scenario_credential_dump(self):
        logger.info("🗝️  SCENARIO: credential_dump — LSASS / shadow access")
        events = [
            _endpoint(SERVER_IP, "process", proc_name="procdump.exe",
                      cmd_line="procdump -ma lsass.exe lsass.dmp",
                      username="svc_backup",
                      extra={"attack_scenario": "credential_dump"}),
            _endpoint(SERVER_IP, "file_op", proc_name="mimikatz.exe",
                      file_path="/etc/shadow", op="read",
                      username="www-data",
                      extra={"attack_scenario": "credential_dump"}),
        ]
        for e in events:
            self._pub(e)
            time.sleep(0.5)
        logger.info("✅ Credential dump done")

    def run_all(self):
        try:
            for fn in [self.scenario_normal, self.scenario_port_scan,
                       self.scenario_brute_force, self.scenario_lateral_movement,
                       self.scenario_data_exfiltration, self.scenario_ransomware,
                       self.scenario_credential_dump]:
                fn()
                time.sleep(2)
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()

    def stop(self):
        self._producer.flush()
        self._producer.close()
        logger.info("👋 Data Network Simulator stopped")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--mode", choices=["normal","port_scan","brute_force",
                   "lateral_movement","data_exfiltration","ransomware",
                   "credential_dump","all"], default="normal")
    p.add_argument("--bootstrap", default="localhost:9092")
    args = p.parse_args()
    sim = DataNetworkSimulator(args.bootstrap)
    try:
        if args.mode == "all":
            sim.run_all()
        else:
            getattr(sim, f"scenario_{args.mode}")()
    finally:
        sim.stop()

if __name__ == "__main__":
    main()
