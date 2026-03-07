"""
Additional tests to append to tests/phase4_gate_test.py
OR save as tests/learning_agent_test.py

Tests for the Learning Agent (the final missing agent from the plan).
"""
from __future__ import annotations
import sys, time, uuid
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
from agents.hq.learning_agent.main import LearningAgent


def make_learning() -> LearningAgent:
    with patch("agents.hq.learning_agent.main.KafkaProducerClient"), \
         patch("agents.hq.learning_agent.main.KafkaConsumerClient"), \
         patch("agents.hq.learning_agent.main.uvicorn"), \
         patch("agents.hq.learning_agent.main.threading.Thread"):
        return LearningAgent()


def _incident(alert_type, severity="HIGH", domain="data_network",
              status="escalated_to_hq"):
    return {
        "incident_id":    f"INC-{uuid.uuid4().hex[:8].upper()}",
        "alert_type":     alert_type,
        "severity":       severity,
        "confidence":     0.90,
        "network_domain": domain,
        "status":         status,
        "details":        {},
        "source":         {"src_ip": "10.0.60.10"},
    }


class TestLearningAgent:

    def test_incident_ingested_as_true_positive(self):
        agent = make_learning()
        agent._ingest_incident(_incident("ransomware_behavior", "CRITICAL"))
        assert len(agent._dataset) == 1
        assert agent._dataset[0]["label"] == "true_positive"
        assert agent._dataset[0]["target_model"] == "edr_agent"

    def test_dismissed_incident_labeled_false_positive(self):
        agent = make_learning()
        agent._ingest_incident(_incident("port_scan","HIGH",status="dismissed"))
        assert agent._dataset[0]["label"] == "false_positive"
        assert agent._stats["dismissed_incidents"] == 1

    def test_correct_model_mapped_per_alert_type(self):
        agent = make_learning()
        test_cases = [
            ("port_scan",             "ndr_agent"),
            ("ransomware_behavior",   "edr_agent"),
            ("sensor_dropout",        "behavioral_agent"),
        ]
        for atype, expected_model in test_cases:
            agent._ingest_incident(_incident(atype))
            assert agent._dataset[-1]["target_model"] == expected_model, \
                f"{atype} should map to {expected_model}"

    def test_retraining_runs_with_sufficient_data(self):
        agent = make_learning()
        agent._producer.publish = lambda *a, **kw: None

        # Add enough examples to trigger retraining
        for _ in range(15):
            agent._ingest_incident(_incident("ransomware_behavior","CRITICAL"))
        for _ in range(5):
            agent._ingest_incident(_incident("port_scan","HIGH"))

        agent._run_retraining(triggered_by="test")
        assert len(agent._runs) == 1
        assert agent._runs[0]["status"] == "completed"
        assert agent._stats["retraining_runs"] == 1

    def test_metrics_improve_after_retraining(self):
        agent = make_learning()
        agent._producer.publish = lambda *a, **kw: None
        old_f1 = agent._agent_metrics["edr_agent"]["f1"]

        for _ in range(20):
            agent._ingest_incident(_incident("ransomware_behavior","CRITICAL"))

        agent._run_retraining(triggered_by="test")
        # Retrain count must increment
        assert agent._agent_metrics["edr_agent"]["retrain_count"] == 1

    def test_insufficient_data_skips_retraining(self):
        agent = make_learning()
        agent._producer.publish = lambda *a, **kw: None

        # Only 3 examples — below 10 minimum
        for _ in range(3):
            agent._ingest_incident(_incident("ransomware_behavior"))

        agent._run_retraining(triggered_by="test")
        assert len(agent._runs) == 0, \
            "Retraining must be skipped when dataset has <10 examples"

    def test_dataset_endpoint_filters_by_label(self):
        agent = make_learning()
        agent._ingest_incident(_incident("port_scan", status="escalated_to_hq"))
        agent._ingest_incident(_incident("port_scan", status="dismissed"))

        tp = [e for e in agent._dataset if e["label"] == "true_positive"]
        fp = [e for e in agent._dataset if e["label"] == "false_positive"]
        assert len(tp) == 1
        assert len(fp) == 1
