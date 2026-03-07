"""
agents/physical_access/pac_eda_agent/main.py
Phase 2 — Physical Access Control Event-Driven Agent (PAC-EDA)

Consumes:  pac.events  (RFID access events from pi-physical / pac_simulator)
Publishes: pac.alerts

Detects:
  - Unauthorized area access     (LDAP: valid card, wrong floor)
  - Unknown card                 (LDAP: card UID not found)        → HIGH
  - Tailgating                   (same card twice within 5s)       → HIGH
  - After-hours access           (valid card outside permitted hours)
  - Brute-force badge attempts   (≥5 denied events in 60s window)  → CRITICAL
  - Badge cloning                (same UID, two different readers simultaneously)

Health: GET /health  (port 8002)

Standards: NIST SP 800-116, IEC 62443 Zone/Conduit, MITRE ATT&CK T0861
"""
from __future__ import annotations

import logging, os, sys, threading, time, uuid
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Dict, List, Optional
from pathlib import Path

import uvicorn
from fastapi import FastAPI
from fastapi.responses import JSONResponse

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
from common.kafka_client import KafkaConsumerClient, KafkaProducerClient, Topics
from common.models import Alert, SeverityLevel

logging.basicConfig(level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s")
logger = logging.getLogger("pac_eda_agent")

AGENT_ID     = os.getenv("AGENT_ID",         "pac-eda-agent-01")
BOOTSTRAP    = os.getenv("KAFKA_BOOTSTRAP",   "localhost:9092")
HEALTH_PORT  = int(os.getenv("HEALTH_PORT",  "8002"))

TAILGATE_WINDOW_SEC   = int(os.getenv("TAILGATE_WINDOW_SEC",    "5"))
BRUTE_FORCE_WINDOW    = int(os.getenv("BRUTE_FORCE_WINDOW_SEC", "60"))
BRUTE_FORCE_THRESHOLD = int(os.getenv("BRUTE_FORCE_THRESHOLD",  "5"))

MITRE_ACCESS = "T0861"  # Spoof Reporting Message / Unauthorized access

# Known protected areas and their sensitivity levels
AREA_SENSITIVITY = {
    1: "standard",    # Academic floors — student accessible
    2: "elevated",    # Labs / faculty only
    3: "restricted",  # Server rooms, admin
}


class PACEdaAgent:
    def __init__(self):
        logger.info(f"🚀 PAC-EDA Agent {AGENT_ID}")
        # card_uid → deque of recent event timestamps (for tailgating / brute-force)
        self._card_events:    Dict[str, deque] = defaultdict(lambda: deque(maxlen=20))
        # card_uid → deque of recent DENIED events (brute-force detection)
        self._denied_events:  Dict[str, deque] = defaultdict(lambda: deque(maxlen=20))
        # card_uid → {reader_id: last_ts}  for badge cloning detection
        self._reader_map:     Dict[str, Dict[str, float]] = defaultdict(dict)

        self._producer = KafkaProducerClient(BOOTSTRAP)
        self._consumer = KafkaConsumerClient(AGENT_ID, [Topics.PAC_EVENTS], BOOTSTRAP)
        self._stats = {"processed": 0, "alerts": 0,
                       "unknown_card": 0, "unauthorized": 0,
                       "tailgating": 0, "after_hours": 0,
                       "brute_force": 0, "badge_clone": 0}
        self._recent_alerts: List[dict] = []
        self._app = self._build_app()
        logger.info("✅ PAC-EDA Agent ready")

    # ── Main event handler ────────────────────────────────────────────────────
    def handle_event(self, topic: str, payload: dict):
        self._stats["processed"] += 1
        card_uid  = payload.get("card_uid", "UNKNOWN")
        access    = payload.get("access", "denied")
        reason    = payload.get("reason", "")
        floor     = payload.get("floor", 1)
        hour      = payload.get("hour", datetime.now(timezone.utc).hour)
        did       = payload.get("device_id", "unknown")
        ts        = time.time()

        logger.info(f"📡 [{access.upper():7s}] card={card_uid} floor={floor} reason={reason}")

        self._card_events[card_uid].append(ts)
        if access == "denied":
            self._denied_events[card_uid].append(ts)

        # Update reader map for clone detection
        self._reader_map[card_uid][did] = ts

        alerts = []

        # ── Unknown card ──────────────────────────────────────────────────────
        if reason == "unknown_card":
            alerts.append(self._make_alert(
                payload, "unknown_card_attempt", SeverityLevel.HIGH, 0.95,
                {"card_uid": card_uid, "floor": floor,
                 "mitre": MITRE_ACCESS, "ldap_result": "NOT_FOUND"},
                ["deny_access", "notify_pac_manager", "flag_card_uid"],
            ))
            self._stats["unknown_card"] += 1

        # ── Unauthorized area (valid card, wrong floor) ───────────────────────
        elif reason == "unauthorized_area":
            sensitivity = AREA_SENSITIVITY.get(floor, "standard")
            sev = SeverityLevel.HIGH if sensitivity == "restricted" else SeverityLevel.MEDIUM
            alerts.append(self._make_alert(
                payload, "unauthorized_area_access", sev, 0.90,
                {"card_uid": card_uid, "floor": floor,
                 "area_sensitivity": sensitivity,
                 "user_name": payload.get("user_name", ""),
                 "user_role": payload.get("user_role", ""),
                 "mitre": MITRE_ACCESS},
                ["deny_access", "log_attempt", "notify_pac_manager"],
            ))
            self._stats["unauthorized"] += 1

        # ── After-hours access ────────────────────────────────────────────────
        elif reason == "after_hours" or payload.get("forced_hour", hour) > 20:
            actual_hour = payload.get("forced_hour", hour)
            alerts.append(self._make_alert(
                payload, "after_hours_access_attempt", SeverityLevel.MEDIUM, 0.88,
                {"card_uid": card_uid, "floor": floor,
                 "hour": actual_hour, "user_name": payload.get("user_name", ""),
                 "user_role": payload.get("user_role", ""),
                 "mitre": MITRE_ACCESS},
                ["deny_access", "notify_security_desk"],
            ))
            self._stats["after_hours"] += 1

        # ── Tailgating: same card twice in TAILGATE_WINDOW_SEC ────────────────
        tailgate = self._detect_tailgating(card_uid, ts)
        if tailgate:
            alerts.append(self._make_alert(
                payload, "tailgating_detected", SeverityLevel.HIGH, 0.82,
                {"card_uid": card_uid, "floor": floor,
                 "gap_seconds": round(tailgate, 2),
                 "tailgate_window": TAILGATE_WINDOW_SEC,
                 "mitre": MITRE_ACCESS},
                ["notify_pac_manager", "flag_for_review", "enable_camera_review"],
            ))
            self._stats["tailgating"] += 1

        # ── Brute-force badge (≥5 denied in 60s) ─────────────────────────────
        if self._detect_brute_force(card_uid, ts):
            alerts.append(self._make_alert(
                payload, "brute_force_badge_attempt", SeverityLevel.CRITICAL, 0.97,
                {"card_uid": card_uid, "floor": floor,
                 "denied_in_window": BRUTE_FORCE_THRESHOLD,
                 "window_sec": BRUTE_FORCE_WINDOW,
                 "mitre": MITRE_ACCESS},
                ["lock_door", "alert_security", "notify_pac_manager",
                 "notify_hq_immediately"],
            ))
            self._stats["brute_force"] += 1
            # Clear to prevent re-alerting on same burst
            self._denied_events[card_uid].clear()

        # ── Badge cloning: same UID on two different readers within 3s ────────
        clone = self._detect_badge_clone(card_uid, did, ts)
        if clone:
            alerts.append(self._make_alert(
                payload, "badge_clone_suspected", SeverityLevel.CRITICAL, 0.85,
                {"card_uid": card_uid,
                 "reader_1": clone["r1"], "reader_2": clone["r2"],
                 "gap_seconds": round(clone["gap"], 2),
                 "mitre": MITRE_ACCESS},
                ["revoke_card_uid", "notify_pac_manager", "notify_hq_immediately"],
            ))
            self._stats["badge_clone"] += 1

        for alert in alerts:
            self._producer.publish(Topics.PAC_ALERTS, alert, key=card_uid)
            self._recent_alerts.append(alert)
            if len(self._recent_alerts) > 100:
                self._recent_alerts.pop(0)
            self._stats["alerts"] += 1
            logger.warning(
                f"🚨 [{alert['severity']}] {alert['alert_type']} card={card_uid}")

    # ── Detection helpers ─────────────────────────────────────────────────────
    def _detect_tailgating(self, card_uid: str, now: float) -> Optional[float]:
        events = list(self._card_events[card_uid])
        if len(events) < 2:
            return None
        gap = now - events[-2]
        if gap <= TAILGATE_WINDOW_SEC:
            return gap
        return None

    def _detect_brute_force(self, card_uid: str, now: float) -> bool:
        cutoff = now - BRUTE_FORCE_WINDOW
        recent = [t for t in self._denied_events[card_uid] if t >= cutoff]
        return len(recent) >= BRUTE_FORCE_THRESHOLD

    def _detect_badge_clone(self, card_uid: str, reader_id: str,
                             now: float) -> Optional[dict]:
        for other_reader, other_ts in self._reader_map[card_uid].items():
            if other_reader != reader_id and (now - other_ts) <= 3.0:
                return {"r1": other_reader, "r2": reader_id,
                        "gap": now - other_ts}
        return None

    def _make_alert(self, event: dict, alert_type: str, severity: SeverityLevel,
                    confidence: float, details: dict,
                    actions: List[str]) -> dict:
        return {
            "alert_id":    str(uuid.uuid4()),
            "agent_id":    AGENT_ID,
            "agent_type":  "pac_eda",
            "network_type": "physical_access",
            "alert_type":  alert_type,
            "severity":    severity.value,
            "confidence":  confidence,
            "timestamp":   datetime.now(timezone.utc).isoformat(),
            "source": {
                "device_id":  event.get("device_id", ""),
                "zone":       event.get("zone", ""),
                "gateway_id": event.get("gateway_id", ""),
                "card_uid":   event.get("card_uid", ""),
            },
            "details":              details,
            "recommended_actions":  actions,
        }

    # ── FastAPI ───────────────────────────────────────────────────────────────
    def _build_app(self) -> FastAPI:
        app = FastAPI(title="PAC-EDA Agent")

        @app.get("/health")
        def health():
            return JSONResponse({
                "agent_id":  AGENT_ID, "status": "running",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "stats":     self._stats,
            })

        @app.get("/alerts")
        def alerts(limit: int = 50):
            return JSONResponse(self._recent_alerts[-limit:])

        return app

    def start(self):
        threading.Thread(target=self._consumer.poll_loop,
                         args=(self.handle_event,),
                         daemon=True, name="pac-eda-consumer").start()
        logger.info(f"▶️  PAC-EDA Agent — health :{HEALTH_PORT}/health")
        uvicorn.run(self._app, host="0.0.0.0", port=HEALTH_PORT, log_level="warning")

    def stop(self):
        self._consumer.stop()
        self._producer.close()


if __name__ == "__main__":
    a = PACEdaAgent()
    try:
        a.start()
    except KeyboardInterrupt:
        a.stop()
