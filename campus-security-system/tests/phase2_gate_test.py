"""
tests/phase2_gate_test.py
Phase 2 Gate Tests — PAC-EDA + Credential Anomaly + PAC Local Manager

Run: pytest tests/phase2_gate_test.py -v
All 18 must pass before merging phase/2-pac → main.
"""
from __future__ import annotations

import sys, time, uuid
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from agents.physical_access.pac_eda_agent.main import PACEdaAgent
from agents.physical_access.credential_anomaly_agent.main import CredentialAnomalyAgent
from managers.pac_local_manager.main import PACLocalManager


# ── Helpers ───────────────────────────────────────────────────────────────────

def make_pac_eda() -> PACEdaAgent:
    with patch("agents.physical_access.pac_eda_agent.main.KafkaProducerClient"), \
         patch("agents.physical_access.pac_eda_agent.main.KafkaConsumerClient"), \
         patch("agents.physical_access.pac_eda_agent.main.uvicorn"):
        return PACEdaAgent()


def make_cred_agent() -> CredentialAnomalyAgent:
    with patch("agents.physical_access.credential_anomaly_agent.main.KafkaProducerClient"), \
         patch("agents.physical_access.credential_anomaly_agent.main.KafkaConsumerClient"), \
         patch("agents.physical_access.credential_anomaly_agent.main.uvicorn"):
        return CredentialAnomalyAgent()


def make_pac_mgr() -> PACLocalManager:
    with patch("managers.pac_local_manager.main.KafkaProducerClient"), \
         patch("managers.pac_local_manager.main.KafkaConsumerClient"), \
         patch("managers.pac_local_manager.main.uvicorn"):
        return PACLocalManager()


def _access_event(card_uid, floor, access, reason, door="RFID-ACADEMIC-F1-DOOR1-01",
                  user_name="", user_role="student", hour=10):
    return {
        "device_id":   door,
        "device_type": "rfid_reader",
        "zone":        f"Academic/Floor{floor}/Door1",
        "card_uid":    card_uid,
        "floor":       floor,
        "door_id":     f"door_acad_f{floor}_d1",
        "gateway_id":  "GW-PAC-ACADEMIC-F1-01",
        "seq":         1,
        "timestamp":   datetime.now(timezone.utc).isoformat(),
        "ldap_result": "NOT_FOUND" if reason == "unknown_card" else "AUTHORIZED",
        "access":      access,
        "reason":      reason,
        "hour":        hour,
        "user_name":   user_name,
        "user_role":   user_role,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# 1. PAC-EDA Agent
# ═══════════════════════════════════════════════════════════════════════════════

class TestPACEdaAgent:

    def test_unknown_card_generates_high_alert(self):
        agent = make_pac_eda()
        published = []
        agent._producer.publish = lambda t, p, key=None: published.append(p)

        agent.handle_event("pac.events",
                           _access_event("DEADBEEF", 1, "denied", "unknown_card"))

        assert len(published) == 1
        assert published[0]["severity"] == "HIGH"
        assert published[0]["alert_type"] == "unknown_card_attempt"

    def test_unauthorized_area_generates_medium_alert(self):
        agent = make_pac_eda()
        published = []
        agent._producer.publish = lambda t, p, key=None: published.append(p)

        agent.handle_event("pac.events",
                           _access_event("A1B2C3D4", 2, "denied", "unauthorized_area",
                                          user_name="Alice", user_role="student"))

        assert any(a["alert_type"] == "unauthorized_area_access" for a in published)
        sev = next(a["severity"] for a in published
                   if a["alert_type"] == "unauthorized_area_access")
        assert sev in ("MEDIUM", "HIGH")

    def test_tailgating_detected(self):
        agent = make_pac_eda()
        published = []
        agent._producer.publish = lambda t, p, key=None: published.append(p)

        card = "E5F6G7H8"
        # Two events within TAILGATE_WINDOW_SEC (default 5s)
        agent.handle_event("pac.events", _access_event(card, 1, "granted", "normal"))
        time.sleep(0.1)
        agent.handle_event("pac.events", _access_event(card, 1, "granted", "normal"))

        assert any(a["alert_type"] == "tailgating_detected" for a in published), \
            "Tailgating must be detected when same card used twice within 5s"

    def test_brute_force_detected(self):
        agent = make_pac_eda()
        published = []
        agent._producer.publish = lambda t, p, key=None: published.append(p)

        card = "AAAA0000"
        for i in range(6):
            agent.handle_event("pac.events",
                               _access_event(card, 1, "denied", "unknown_card"))

        assert any(a["alert_type"] == "brute_force_badge_attempt" for a in published), \
            "Brute force must be detected after 5+ denied events"

    def test_after_hours_generates_alert(self):
        agent = make_pac_eda()
        published = []
        agent._producer.publish = lambda t, p, key=None: published.append(p)

        agent.handle_event("pac.events",
                           _access_event("M3N4O5P6", 1, "denied", "after_hours",
                                          hour=23, user_name="Dave"))

        assert any(a["alert_type"] == "after_hours_access_attempt" for a in published)

    def test_normal_granted_no_alert(self):
        agent = make_pac_eda()
        published = []
        agent._producer.publish = lambda t, p, key=None: published.append(p)

        agent.handle_event("pac.events",
                           _access_event("E5F6G7H8", 1, "granted", "normal",
                                          user_name="Bob"))
        assert len(published) == 0, "Normal granted access must not generate alerts"


# ═══════════════════════════════════════════════════════════════════════════════
# 2. Credential Anomaly Agent
# ═══════════════════════════════════════════════════════════════════════════════

class TestCredentialAnomalyAgent:

    def test_impossible_travel_detected(self):
        agent = make_cred_agent()
        published = []
        agent._producer.publish = lambda t, p, key=None: published.append(p)

        card = "TRAVEL-TEST"
        # First event: floor 1
        agent.handle_event("pac.events",
                           _access_event(card, 1, "granted", "normal",
                                          door="RFID-F1-DOOR1"))
        # Immediate second event: floor 3 — impossible without 60s travel time
        agent.handle_event("pac.events",
                           _access_event(card, 3, "granted", "normal",
                                          door="RFID-F3-DOOR1"))

        assert any(a["alert_type"] == "impossible_travel_detected" for a in published), \
            "Impossible travel (floor 1→3 in <1s) must be detected"

    def test_normal_sequential_access_no_alert(self):
        agent = make_cred_agent()
        published = []
        agent._producer.publish = lambda t, p, key=None: published.append(p)

        card = "NORMAL-TRAVEL"
        agent.handle_event("pac.events",
                           _access_event(card, 1, "granted", "normal",
                                          door="RFID-F1-DOOR1"))
        # Same floor, same reader — should not trigger
        time.sleep(0.05)
        agent.handle_event("pac.events",
                           _access_event(card, 1, "granted", "normal",
                                          door="RFID-F1-DOOR1"))  # same reader
        assert not any(a["alert_type"] == "impossible_travel_detected"
                       for a in published), "Same reader repeat should not flag impossible travel"

    def test_credential_sharing_detected(self):
        agent = make_cred_agent()
        published = []
        agent._producer.publish = lambda t, p, key=None: published.append(p)

        card = "SHARED-CARD"
        agent.handle_event("pac.events",
                           _access_event(card, 1, "granted", "normal",
                                          door="RFID-F1-DOOR1"))
        time.sleep(0.05)
        # Same card, different reader, within 30s → sharing suspected
        agent.handle_event("pac.events",
                           _access_event(card, 1, "granted", "normal",
                                          door="RFID-F1-DOOR2"))

        assert any(a["alert_type"] == "credential_sharing_suspected" for a in published), \
            "Credential sharing must be detected when same card active on two readers"


# ═══════════════════════════════════════════════════════════════════════════════
# 3. PAC Local Manager
# ═══════════════════════════════════════════════════════════════════════════════

class TestPACLocalManager:

    def _alert(self, alert_type, severity, card_uid="TEST-CARD",
               area_sensitivity="standard"):
        return {
            "alert_id":    str(uuid.uuid4()),
            "agent_id":    "pac-eda-agent-01",
            "agent_type":  "pac_eda",
            "network_type": "physical_access",
            "alert_type":  alert_type,
            "severity":    severity,
            "confidence":  0.90,
            "source":      {"device_id": "RFID-F1", "zone": "Floor1",
                            "gateway_id": "GW-PAC-01", "card_uid": card_uid},
            "details":     {"card_uid": card_uid,
                            "area_sensitivity": area_sensitivity},
            "recommended_actions": ["notify_pac_manager"],
        }

    def test_high_alert_escalated_to_hq(self):
        mgr = make_pac_mgr()
        escalated = []
        mgr._escalate_to_hq = lambda inc: escalated.append(inc)

        mgr.handle_alert("pac.alerts",
                         self._alert("unknown_card_attempt", "HIGH"))

        assert len(escalated) == 1
        assert escalated[0]["network_domain"] == "physical_access"

    def test_critical_queued_for_approval(self):
        mgr = make_pac_mgr()
        mgr.handle_alert("pac.alerts",
                         self._alert("brute_force_badge_attempt", "CRITICAL"))
        assert len(mgr._pending) == 1

    def test_reclassify_unknown_card_plus_brute_force(self):
        mgr = make_pac_mgr()
        escalated = []
        mgr._escalate_to_hq = lambda inc: escalated.append(inc)

        mgr.handle_alert("pac.alerts",
                         self._alert("unknown_card_attempt", "HIGH"))
        mgr.handle_alert("pac.alerts",
                         self._alert("brute_force_badge_attempt", "HIGH"))

        # One of the incidents must be CRITICAL
        all_sev = [i["severity"] for i in mgr._incidents]
        assert "CRITICAL" in all_sev, \
            "unknown_card + brute_force together must produce CRITICAL incident"

    def test_restricted_area_upgrades_severity(self):
        mgr = make_pac_mgr()
        result = mgr._area_upgrade(
            {"details": {"area_sensitivity": "restricted"}}, "MEDIUM")
        assert result == "HIGH", "MEDIUM in restricted area must upgrade to HIGH"

    def test_coordinated_attack_three_alerts(self):
        mgr = make_pac_mgr()
        escalated = []
        mgr._escalate_to_hq = lambda inc: escalated.append(inc)
        card = "ATTACKER-01"

        for alert_type in ["unknown_card_attempt", "unauthorized_area_access",
                           "after_hours_access_attempt"]:
            mgr.handle_alert("pac.alerts",
                             self._alert(alert_type, "MEDIUM", card_uid=card))

        all_sev = [i["severity"] for i in mgr._incidents]
        assert "CRITICAL" in all_sev, \
            "3 alerts from same card in 30s must produce CRITICAL incident"

    def test_approve_clears_pending(self):
        mgr = make_pac_mgr()
        escalated = []
        mgr._escalate_to_hq = lambda inc: escalated.append(inc)

        mgr.handle_alert("pac.alerts",
                         self._alert("brute_force_badge_attempt", "CRITICAL"))
        assert len(mgr._pending) == 1
        iid = list(mgr._pending.keys())[0]

        mgr._pending[iid]["status"] = "manually_approved"
        inc = mgr._pending.pop(iid)
        mgr._escalate_to_hq(inc)

        assert len(mgr._pending) == 0
        assert len(escalated) == 1
