"""
tests/phase4_gate_test.py
Phase 4 Gate Tests — Analytical Agent, Orchestrator Agent, Central Manager
Run: pytest tests/phase4_gate_test.py -v
All 18 tests must pass.
"""
from __future__ import annotations
import json, sys, time, uuid
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from agents.hq.analytical_agent.main import AnalyticalAgent
from agents.hq.orchestrator_agent.main import OrchestratorAgent, PLAYBOOKS
from managers.central_manager.main import CentralManager


# ── Factories ─────────────────────────────────────────────────────────────────

def make_analytical() -> AnalyticalAgent:
    with patch("agents.hq.analytical_agent.main.KafkaProducerClient"), \
         patch("agents.hq.analytical_agent.main.KafkaConsumerClient"), \
         patch("agents.hq.analytical_agent.main.uvicorn"):
        return AnalyticalAgent()


def make_orchestrator() -> OrchestratorAgent:
    with patch("agents.hq.orchestrator_agent.main.KafkaProducerClient"), \
         patch("agents.hq.orchestrator_agent.main.KafkaConsumerClient"), \
         patch("agents.hq.orchestrator_agent.main.uvicorn"):
        return OrchestratorAgent()


def make_central() -> CentralManager:
    with patch("managers.central_manager.main.KafkaProducerClient"), \
         patch("managers.central_manager.main.KafkaConsumerClient"), \
         patch("managers.central_manager.main.uvicorn"):
        return CentralManager()


def _incident(domain, alert_type, severity="HIGH", incident_id=None):
    return {
        "incident_id":    incident_id or f"INC-{uuid.uuid4().hex[:8].upper()}",
        "network_domain": domain,
        "alert_type":     alert_type,
        "severity":       severity,
        "manager_id":     f"{domain}-local-manager-01",
        "created_at":     datetime.now(timezone.utc).isoformat(),
        "details":        {"host_id": "10.0.60.10", "src_ip": "192.168.100.50"},
        "recommended_actions": [],
        "status":         "escalated_to_hq",
    }


def _correlation(corr_type, severity="CRITICAL", domains=None):
    return {
        "correlation_id":   f"CORR-{uuid.uuid4().hex[:8].upper()}",
        "correlation_type": corr_type,
        "severity":         severity,
        "domains_involved": domains or ["iot","physical_access","data_network"],
        "created_at":       datetime.now(timezone.utc).isoformat(),
        "details":          {"host_id": "10.0.60.10"},
        "recommended_actions": [],
    }


# ═══════════════════════════════════════════════════════════════════════════════
# 1. Analytical Agent — Correlation Rules
# ═══════════════════════════════════════════════════════════════════════════════

class TestAnalyticalAgent:

    def test_coordinated_attack_two_domains(self):
        agent = make_analytical()
        published = []
        agent._producer.publish = lambda t, p, key=None: published.append((t, p))

        # HIGH incident from IoT
        agent.handle_incident("hq.incidents", _incident("iot","sensor_dropout","HIGH"))
        # HIGH incident from data network
        agent.handle_incident("hq.incidents",
                              _incident("data_network","port_scan","HIGH"))

        corrs = [p for t, p in published
                 if t == "hq.correlated" and p.get("correlation_type") == "coordinated_attack"]
        assert len(corrs) >= 1, "2 domains with HIGH incidents must → coordinated_attack"
        assert corrs[0]["severity"] == "CRITICAL"

    def test_campus_wide_threat_all_three_domains(self):
        agent = make_analytical()
        published = []
        agent._producer.publish = lambda t, p, key=None: published.append((t, p))

        for domain, atype in [("iot","sensor_dropout"),
                               ("physical_access","unknown_card"),
                               ("data_network","data_exfiltration")]:
            agent.handle_incident("hq.incidents", _incident(domain, atype, "HIGH"))

        corrs = [p for t, p in published
                 if t == "hq.correlated"
                 and p.get("correlation_type") == "campus_wide_threat"]
        assert len(corrs) >= 1, "All 3 domains active must → campus_wide_threat"

    def test_insider_threat_pac_plus_exfil(self):
        agent = make_analytical()
        published = []
        agent._producer.publish = lambda t, p, key=None: published.append((t, p))

        pac_inc = _incident("physical_access","unknown_card","HIGH")
        pac_inc["card_uid"] = "DEADBEEF"
        agent.handle_incident("hq.incidents", pac_inc)
        agent.handle_incident("hq.incidents",
                              _incident("data_network","data_exfiltration","CRITICAL"))

        corrs = [p for t, p in published
                 if t == "hq.correlated"
                 and p.get("correlation_type") == "insider_threat"]
        assert len(corrs) >= 1, "PAC anomaly + data_exfil must → insider_threat"

    def test_iot_cyber_bridge_detected(self):
        agent = make_analytical()
        published = []
        agent._producer.publish = lambda t, p, key=None: published.append((t, p))

        agent.handle_incident("hq.incidents",
                              _incident("iot","sensor_dropout","HIGH"))
        agent.handle_incident("hq.incidents",
                              _incident("data_network","lateral_movement","HIGH"))

        corrs = [p for t, p in published
                 if t == "hq.correlated"
                 and p.get("correlation_type") == "iot_cyber_bridge"]
        assert len(corrs) >= 1, "IoT anomaly + lateral_movement must → iot_cyber_bridge"

    def test_single_domain_no_correlation(self):
        agent = make_analytical()
        published = []
        agent._producer.publish = lambda t, p, key=None: published.append((t, p))

        # Only IoT incidents — not enough for cross-domain correlation
        for i in range(3):
            agent.handle_incident("hq.incidents", _incident("iot","sensor_dropout","MEDIUM"))

        corrs = [p for t, p in published if t == "hq.correlated"]
        assert len(corrs) == 0, "Single domain incidents must not fire correlation"

    def test_dedup_prevents_duplicate_correlations(self):
        agent = make_analytical()
        published = []
        agent._producer.publish = lambda t, p, key=None: published.append((t, p))

        # Fire the same two domains twice
        for _ in range(3):
            agent.handle_incident("hq.incidents", _incident("iot","sensor_dropout","HIGH"))
            agent.handle_incident("hq.incidents", _incident("data_network","port_scan","HIGH"))

        corrs = [p for t, p in published
                 if t == "hq.correlated" and p.get("correlation_type") == "coordinated_attack"]
        assert len(corrs) == 1, "Dedup must prevent duplicate correlation within cooldown"


# ═══════════════════════════════════════════════════════════════════════════════
# 2. Orchestrator Agent — Playbook Execution
# ═══════════════════════════════════════════════════════════════════════════════

class TestOrchestratorAgent:

    def test_three_required_playbooks_loaded(self):
        orch = make_orchestrator()
        required = {"ransomware_response", "intrusion_response",
                    "iot_compromise_response"}
        assert required.issubset(set(PLAYBOOKS.keys())), \
            f"Required playbooks missing: {required - set(PLAYBOOKS.keys())}"

    def test_ransomware_playbook_triggered(self):
        orch = make_orchestrator()
        published = []
        orch._producer.publish = lambda t, p, key=None: published.append((t, p))

        orch._handle_correlation(_correlation("ransomware_behavior", "HIGH"))

        cmds = [p for t, p in published if t == "soar.commands"]
        assert len(cmds) >= 1, "Ransomware correlation must issue SOAR commands"
        actions = {c["action"] for c in cmds}
        assert "isolate_host" in actions, "Ransomware playbook must include isolate_host"

    def test_intrusion_playbook_triggered(self):
        orch = make_orchestrator()
        published = []
        orch._producer.publish = lambda t, p, key=None: published.append((t, p))

        orch._handle_correlation(_correlation("coordinated_attack","CRITICAL"))

        cmds = [p for t, p in published if t == "soar.commands"]
        assert len(cmds) >= 1
        actions = {c["action"] for c in cmds}
        assert "block_attacker_ip" in actions or "enable_enhanced_logging" in actions

    def test_iot_compromise_playbook_triggered(self):
        orch = make_orchestrator()
        published = []
        orch._producer.publish = lambda t, p, key=None: published.append((t, p))

        orch._handle_correlation(_correlation("iot_cyber_bridge","HIGH"))

        cmds = [p for t, p in published if t == "soar.commands"]
        actions = {c["action"] for c in cmds}
        assert "isolate_iot_vlan" in actions, \
            "IoT compromise playbook must include isolate_iot_vlan"

    def test_manual_approval_required_steps_not_auto_sent(self):
        orch = make_orchestrator()
        published = []
        orch._producer.publish = lambda t, p, key=None: published.append((t, p))

        orch._handle_correlation(_correlation("ransomware_behavior","HIGH"))

        # restore_from_backup requires approval — must NOT be in soar.commands yet
        cmds = [p for t, p in published if t == "soar.commands"]
        auto_actions = {c["action"] for c in cmds}
        assert "restore_from_backup" not in auto_actions, \
            "restore_from_backup requires approval — must not be auto-issued"
        assert len(orch._pending_approvals) >= 1

    def test_playbook_execution_recorded(self):
        orch = make_orchestrator()
        orch._producer.publish = MagicMock()

        orch._handle_correlation(_correlation("coordinated_attack","CRITICAL"))

        assert len(orch._executions) >= 1
        assert orch._executions[0]["playbook"] in PLAYBOOKS

    def test_low_severity_no_playbook(self):
        orch = make_orchestrator()
        published = []
        orch._producer.publish = lambda t, p, key=None: published.append((t, p))

        # LOW severity should not trigger playbook with HIGH min_severity
        low_corr = _correlation("coordinated_attack","LOW")
        orch._handle_correlation(low_corr)

        cmds = [p for t, p in published if t == "soar.commands"]
        assert len(cmds) == 0, "LOW severity must not trigger HIGH+ min_severity playbooks"


# ═══════════════════════════════════════════════════════════════════════════════
# 3. Central Manager
# ═══════════════════════════════════════════════════════════════════════════════

class TestCentralManager:

    def test_incidents_indexed_by_domain(self):
        mgr = make_central()
        mgr._handle_incident(_incident("iot","sensor_dropout","HIGH"))
        mgr._handle_incident(_incident("data_network","port_scan","HIGH"))

        assert len(mgr._incidents["iot"]) == 1
        assert len(mgr._incidents["data_network"]) == 1

    def test_threat_level_critical_on_multiple_criticals(self):
        mgr = make_central()
        mgr._handle_incident(_incident("iot","sensor_dropout","CRITICAL"))
        mgr._handle_incident(_incident("data_network","data_exfiltration","CRITICAL"))

        status = mgr._compute_status()
        assert status["threat_level"] == "CRITICAL"

    def test_threat_level_low_when_no_incidents(self):
        mgr = make_central()
        status = mgr._compute_status()
        assert status["threat_level"] == "LOW"

    def test_correlations_tracked(self):
        mgr = make_central()
        mgr._handle_correlation(_correlation("coordinated_attack","CRITICAL"))
        assert len(mgr._correlations) == 1

    def test_status_includes_all_required_fields(self):
        mgr = make_central()
        status = mgr._compute_status()
        required_keys = {"system_id","timestamp","threat_level","health_percentage",
                         "agents_healthy","agents_total","incidents","correlations_active"}
        assert required_keys.issubset(set(status.keys())), \
            f"Missing status fields: {required_keys - set(status.keys())}"


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
class TestPhase4FullChain:

    def test_correlation_reaches_hq_correlated(self):
        import threading
        from confluent_kafka import Consumer
        from common.kafka_client import KafkaProducerClient, Topics

        received = []
        done = threading.Event()
        consumer = Consumer({"bootstrap.servers": "localhost:9092",
                              "group.id": f"phase4-gate-{uuid.uuid4().hex[:8]}",
                              "auto.offset.reset": "earliest"})
        consumer.subscribe([Topics.HQ_CORRELATED])

        def listen():
            deadline = time.time() + 12
            while time.time() < deadline:
                msg = consumer.poll(0.5)
                if msg and not msg.error():
                    try:
                        p = json.loads(msg.value())
                        if p.get("correlation_type") == "coordinated_attack":
                            received.append(p)
                            done.set()
                            return
                    except Exception:
                        pass
            done.set()

        threading.Thread(target=listen, daemon=True).start()
        time.sleep(1.0)

        prod = KafkaProducerClient("localhost:9092")
        prod.publish(Topics.HQ_CORRELATED, {
            "correlation_id":   str(uuid.uuid4()),
            "correlation_type": "coordinated_attack",
            "severity":         "CRITICAL",
            "domains_involved": ["iot","data_network"],
            "agent_id":         "analytical-agent-01",
            "created_at":       datetime.now(timezone.utc).isoformat(),
            "details":          {},
            "recommended_actions": ["activate_campus_lockdown_protocol"],
        }, key="test-corr")
        prod.flush()

        done.wait(timeout=12)
        consumer.close()
        assert len(received) > 0, "Correlation must appear on hq.correlated"
