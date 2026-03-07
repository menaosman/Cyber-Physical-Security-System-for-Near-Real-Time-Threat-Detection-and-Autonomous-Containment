"""
managers/pac_local_manager/main.py
Phase 2 — PAC Local Manager

Consumes: pac.alerts  (from pac_eda_agent + credential_anomaly_agent)
Publishes: pac.incidents → hq.incidents

Reclassification rules (IEC 62443-2-1):
  - unknown_card HIGH + brute_force_badge within 120s → CRITICAL
  - unauthorized_area + impossible_travel same card within 60s → CRITICAL
  - 3+ alerts same card within 30s → CRITICAL (coordinated attack)

Operator approval: 60s window for CRITICAL, auto-escalate on timeout.
Area-sensitivity boost: restricted area alerts auto-upgrade by one level.

FastAPI:
  GET  /health  /alerts  /incidents  /devices  /pending
  POST /approve/{id}  /dismiss/{id}  /lock_door/{door_id}

Standards: NIST SP 800-61, IEC 62443-2-1, NIST CSF 2.0 RESPOND
"""
from __future__ import annotations

import logging, os, sys, threading, time, uuid
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Dict, List
from pathlib import Path

import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
from common.kafka_client import KafkaConsumerClient, KafkaProducerClient, Topics
from common.models import SeverityLevel

logging.basicConfig(level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s")
logger = logging.getLogger("pac_local_manager")

MANAGER_ID   = os.getenv("MANAGER_ID",          "pac-local-manager-01")
BOOTSTRAP    = os.getenv("KAFKA_BOOTSTRAP",      "localhost:9092")
HEALTH_PORT  = int(os.getenv("HEALTH_PORT",     "8011"))
APPROVAL_WIN = int(os.getenv("APPROVAL_WINDOW_SEC",    "60"))
CORR_WIN     = int(os.getenv("CORRELATION_WINDOW_SEC", "120"))
HB_TIMEOUT   = int(os.getenv("HEARTBEAT_TIMEOUT_SEC",  "30"))

# Restricted areas get automatic severity upgrade
RESTRICTED_AREAS = {"restricted", "server_room", "admin"}
SEVERITY_ORDER   = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
SEVERITY_UP      = {v: k for k, v in SEVERITY_ORDER.items()}   # int → name


class PACLocalManager:
    def __init__(self):
        logger.info(f"🚀 PAC Local Manager {MANAGER_ID}")
        self._alerts:    deque = deque(maxlen=300)
        self._incidents: List[dict] = []
        self._pending:   Dict[str, dict] = {}
        self._last_seen: Dict[str, float] = {}    # card_uid → last event ts

        # Per card-uid rolling alert history for correlation
        self._card_alerts: Dict[str, deque] = defaultdict(lambda: deque(maxlen=20))
        # Per alert_type rolling history for cross-type correlation
        self._type_alerts: Dict[str, deque] = defaultdict(lambda: deque(maxlen=20))

        self._producer = KafkaProducerClient(BOOTSTRAP)
        self._consumer = KafkaConsumerClient(MANAGER_ID, [Topics.PAC_ALERTS], BOOTSTRAP)
        self._stats = {"received": 0, "incidents": 0, "escalated": 0,
                       "auto_escalated": 0, "dismissed": 0, "locked_doors": 0}
        self._locked_doors: Dict[str, str] = {}  # door_id → reason
        self._app = self._build_app()
        logger.info("✅ PAC Local Manager ready")

    # ── Alert handler ─────────────────────────────────────────────────────────
    def handle_alert(self, topic: str, payload: dict):
        self._stats["received"] += 1
        card_uid   = (payload.get("source") or {}).get("card_uid", "unknown")
        alert_type = payload.get("alert_type", "")
        severity   = payload.get("severity", "LOW")
        ts         = time.time()

        self._last_seen[card_uid] = ts
        self._alerts.append({**payload, "received_at": datetime.now(timezone.utc).isoformat()})
        self._card_alerts[card_uid].append({"ts": ts, "type": alert_type, "sev": severity})
        self._type_alerts[alert_type].append({"ts": ts, "card": card_uid, "sev": severity})

        logger.info(f"📥 [{severity}] {alert_type} card={card_uid}")

        # Apply area-sensitivity upgrade
        severity = self._area_upgrade(payload, severity)

        # Apply correlation reclassification
        severity = self._reclassify(card_uid, alert_type, severity, ts)

        if SEVERITY_ORDER.get(severity, 0) >= SEVERITY_ORDER["HIGH"]:
            incident = self._create_incident(payload, severity, card_uid)
            self._handle_escalation(incident)

    # ── Reclassification rules ────────────────────────────────────────────────
    def _area_upgrade(self, payload: dict, severity: str) -> str:
        details = payload.get("details", {})
        area    = details.get("area_sensitivity", "")
        if area in RESTRICTED_AREAS and severity != "CRITICAL":
            idx = SEVERITY_ORDER.get(severity, 0)
            upgraded = SEVERITY_UP.get(min(idx + 1, 3), severity)
            if upgraded != severity:
                logger.info(f"⬆️  Area upgrade [{severity}] → [{upgraded}] (restricted area)")
            return upgraded
        return severity

    def _reclassify(self, card_uid: str, alert_type: str,
                    severity: str, now: float) -> str:
        cutoff = now - CORR_WIN

        def recent_type(atype, min_sev="LOW"):
            return any(
                a["ts"] >= cutoff
                and SEVERITY_ORDER.get(a["sev"], 0) >= SEVERITY_ORDER.get(min_sev, 0)
                for a in self._type_alerts.get(atype, [])
            )

        def card_alert_count(min_sev="MEDIUM", window=30):
            return sum(
                1 for a in self._card_alerts.get(card_uid, [])
                if (now - a["ts"]) <= window
                and SEVERITY_ORDER.get(a["sev"], 0) >= SEVERITY_ORDER.get(min_sev, 0)
            )

        # Rule 1: unknown_card + brute_force within CORR_WIN → CRITICAL
        if alert_type == "unknown_card_attempt" and recent_type("brute_force_badge_attempt","HIGH"):
            logger.warning("🔴 Rule 1: unknown_card + brute_force → CRITICAL")
            return "CRITICAL"
        if alert_type == "brute_force_badge_attempt" and recent_type("unknown_card_attempt","HIGH"):
            logger.warning("🔴 Rule 1 (inv): brute_force + unknown_card → CRITICAL")
            return "CRITICAL"

        # Rule 2: unauthorized_area + impossible_travel same card → CRITICAL
        if alert_type == "unauthorized_area_access" and recent_type("impossible_travel_detected","HIGH"):
            logger.warning("🔴 Rule 2: unauthorized_area + impossible_travel → CRITICAL")
            return "CRITICAL"
        if alert_type == "impossible_travel_detected" and recent_type("unauthorized_area_access","MEDIUM"):
            logger.warning("🔴 Rule 2 (inv): impossible_travel + unauthorized → CRITICAL")
            return "CRITICAL"

        # Rule 3: ≥3 alerts same card in 30s → CRITICAL (coordinated)
        if card_alert_count(min_sev="MEDIUM", window=30) >= 3:
            logger.warning(f"🔴 Rule 3: ≥3 alerts card={card_uid} in 30s → CRITICAL")
            return "CRITICAL"

        return severity

    # ── Incident management ───────────────────────────────────────────────────
    def _create_incident(self, payload: dict, severity: str, card_uid: str) -> dict:
        inc = {
            "incident_id":      f"INC-PAC-{uuid.uuid4().hex[:8].upper()}",
            "created_at":       datetime.now(timezone.utc).isoformat(),
            "manager_id":       MANAGER_ID,
            "severity":         severity,
            "network_domain":   "physical_access",
            "trigger_alert_id": payload.get("alert_id"),
            "card_uid":         card_uid,
            "alert_type":       payload.get("alert_type", ""),
            "details":          payload.get("details", {}),
            "status":           "pending_approval" if severity == "CRITICAL" else "auto_escalated",
            "recommended_actions": payload.get("recommended_actions", []),
        }
        self._incidents.append(inc)
        self._stats["incidents"] += 1
        logger.warning(f"📋 Incident {inc['incident_id']} [{severity}] card={card_uid}")
        return inc

    def _handle_escalation(self, inc: dict):
        if inc["severity"] == "CRITICAL":
            self._pending[inc["incident_id"]] = {**inc, "deadline": time.time() + APPROVAL_WIN}
            logger.warning(f"⏳ {inc['incident_id']} queued — auto-escalates in {APPROVAL_WIN}s")
            threading.Thread(target=self._approval_timeout,
                             args=(inc["incident_id"],), daemon=True).start()
        else:
            self._escalate_to_hq(inc)

    def _approval_timeout(self, iid: str):
        time.sleep(APPROVAL_WIN)
        if iid in self._pending:
            inc = self._pending.pop(iid)
            inc["status"] = "auto_escalated_after_timeout"
            logger.warning(f"⏰ Auto-escalating {iid}")
            self._escalate_to_hq(inc)
            self._stats["auto_escalated"] += 1

    def _escalate_to_hq(self, inc: dict):
        inc["status"]       = "escalated_to_hq"
        inc["escalated_at"] = datetime.now(timezone.utc).isoformat()
        self._producer.publish(Topics.HQ_INCIDENTS, inc, key=inc["incident_id"])
        self._stats["escalated"] += 1
        logger.warning(f"🚀 → HQ: {inc['incident_id']} [{inc['severity']}]")

    # ── FastAPI ───────────────────────────────────────────────────────────────
    def _build_app(self) -> FastAPI:
        app = FastAPI(title="PAC Local Manager")

        @app.get("/health")
        def health():
            return JSONResponse({"manager_id": MANAGER_ID, "status": "running",
                                  "timestamp": datetime.now(timezone.utc).isoformat(),
                                  "stats": self._stats,
                                  "locked_doors": self._locked_doors})

        @app.get("/alerts")
        def alerts(limit: int = 50):
            return JSONResponse(list(self._alerts)[-limit:])

        @app.get("/incidents")
        def incidents():
            return JSONResponse(self._incidents)

        @app.get("/pending")
        def pending():
            return JSONResponse(list(self._pending.values()))

        @app.get("/devices")
        def devices():
            now = time.time()
            return JSONResponse({c: {"last_seen_ago_sec": round(now - ts, 1)}
                                  for c, ts in self._last_seen.items()})

        @app.post("/approve/{iid}")
        def approve(iid: str):
            if iid not in self._pending:
                raise HTTPException(404, "Not found or already processed")
            inc = self._pending.pop(iid)
            inc["status"] = "manually_approved"
            self._escalate_to_hq(inc)
            return JSONResponse({"approved": True, "incident_id": iid})

        @app.post("/dismiss/{iid}")
        def dismiss(iid: str):
            if iid not in self._pending:
                raise HTTPException(404, "Not found")
            self._pending[iid]["status"] = "dismissed"
            del self._pending[iid]
            self._stats["dismissed"] += 1
            return JSONResponse({"dismissed": True, "incident_id": iid})

        @app.post("/lock_door/{door_id}")
        def lock_door(door_id: str, reason: str = "manual_lock"):
            self._locked_doors[door_id] = reason
            self._stats["locked_doors"] += 1
            logger.warning(f"🔒 Door locked: {door_id} reason={reason}")
            return JSONResponse({"locked": True, "door_id": door_id, "reason": reason})

        return app

    def start(self):
        threading.Thread(target=self._consumer.poll_loop,
                         args=(self.handle_alert,),
                         daemon=True, name="pac-mgr-consumer").start()
        logger.info(f"▶️  PAC Local Manager — API :{HEALTH_PORT}")
        uvicorn.run(self._app, host="0.0.0.0", port=HEALTH_PORT, log_level="warning")

    def stop(self):
        self._consumer.stop()
        self._producer.close()


if __name__ == "__main__":
    m = PACLocalManager()
    try:
        m.start()
    except KeyboardInterrupt:
        m.stop()
