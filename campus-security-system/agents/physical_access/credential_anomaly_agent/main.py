"""
agents/physical_access/credential_anomaly_agent/main.py
Phase 2 — Credential Anomaly Agent

Consumes:  pac.events  (all RFID events)
Publishes: pac.alerts

Detects:
  - Impossible travel: same card at two physically distant locations
    within too short a time (e.g., Floor 1 → Floor 3 in 2 seconds)
  - Credential sharing: same card used by two different people
    simultaneously (detected by overlapping active sessions)
  - Off-schedule patterns: statistical baseline per card,
    flag access at unusual times for that specific user

Health: GET /health  (port 8003)

Standards: NIST SP 800-116, MITRE ATT&CK T0859 (Valid Accounts)
"""
from __future__ import annotations

import logging, os, sys, threading, time, uuid
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
from pathlib import Path

import numpy as np
import uvicorn
from fastapi import FastAPI
from fastapi.responses import JSONResponse

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
from common.kafka_client import KafkaConsumerClient, KafkaProducerClient, Topics
from common.models import SeverityLevel

logging.basicConfig(level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s")
logger = logging.getLogger("credential_anomaly_agent")

AGENT_ID    = os.getenv("AGENT_ID",          "cred-anomaly-agent-01")
BOOTSTRAP   = os.getenv("KAFKA_BOOTSTRAP",    "localhost:9092")
HEALTH_PORT = int(os.getenv("HEALTH_PORT",   "8003"))

# Minimum travel time (seconds) to move between floors
# Based on real campus: stairs take ~30s per floor
FLOOR_TRAVEL_TIME: Dict[Tuple[int, int], float] = {
    (1, 2): 30.0, (2, 1): 30.0,
    (1, 3): 60.0, (3, 1): 60.0,
    (2, 3): 30.0, (3, 2): 30.0,
}
SAME_FLOOR_TRAVEL = 5.0   # minimum seconds between doors on same floor

MITRE_VALID_ACCOUNTS = "T0859"
BASELINE_WINDOW = 20     # readings per card to build hour-of-day baseline
OFF_SCHEDULE_Z   = 3.0   # modified Z-score threshold for off-schedule detection


class CredentialAnomalyAgent:
    def __init__(self):
        logger.info(f"🚀 Credential Anomaly Agent {AGENT_ID}")
        # card_uid → {"floor": int, "reader": str, "ts": float}
        self._last_seen:      Dict[str, dict] = {}
        # card_uid → deque of access hours (for baseline)
        self._hour_baseline:  Dict[str, deque] = defaultdict(lambda: deque(maxlen=50))
        # Active sessions: card_uid → set of reader_ids seen in last 60s
        self._active_readers: Dict[str, Dict[str, float]] = defaultdict(dict)

        self._producer = KafkaProducerClient(BOOTSTRAP)
        self._consumer = KafkaConsumerClient(AGENT_ID, [Topics.PAC_EVENTS], BOOTSTRAP)
        self._stats = {"processed": 0, "alerts": 0,
                       "impossible_travel": 0, "credential_sharing": 0,
                       "off_schedule": 0}
        self._recent_alerts: List[dict] = []
        self._app = self._build_app()
        logger.info("✅ Credential Anomaly Agent ready")

    # ── Main handler ──────────────────────────────────────────────────────────
    def handle_event(self, topic: str, payload: dict):
        self._stats["processed"] += 1
        card_uid = payload.get("card_uid", "UNKNOWN")
        floor    = int(payload.get("floor", 1))
        reader   = payload.get("device_id", "unknown")
        hour     = int(payload.get("hour", datetime.now(timezone.utc).hour))
        ts       = time.time()

        # Only analyse GRANTED events for travel/sharing (denied = no movement)
        if payload.get("access") == "granted":
            self._hour_baseline[card_uid].append(hour)
            self._active_readers[card_uid][reader] = ts

            alerts = []

            # ── Impossible travel ─────────────────────────────────────────────
            it = self._detect_impossible_travel(card_uid, floor, reader, ts)
            if it:
                alerts.append(self._build_alert(
                    payload, "impossible_travel_detected",
                    SeverityLevel.CRITICAL, 0.94,
                    {"card_uid": card_uid,
                     "from_floor": it["from_floor"],
                     "to_floor":   floor,
                     "elapsed_sec": round(it["elapsed"], 2),
                     "min_required_sec": it["min_required"],
                     "from_reader": it["from_reader"],
                     "to_reader":   reader,
                     "mitre": MITRE_VALID_ACCOUNTS},
                    ["revoke_session", "notify_pac_manager",
                     "flag_card_for_investigation"],
                ))
                self._stats["impossible_travel"] += 1

            # ── Credential sharing: card active on 2+ readers simultaneously ──
            cs = self._detect_credential_sharing(card_uid, reader, ts)
            if cs:
                alerts.append(self._build_alert(
                    payload, "credential_sharing_suspected",
                    SeverityLevel.HIGH, 0.80,
                    {"card_uid": card_uid,
                     "reader_a": cs["r1"], "reader_b": cs["r2"],
                     "gap_sec": round(cs["gap"], 2),
                     "mitre": MITRE_VALID_ACCOUNTS},
                    ["revoke_session", "notify_pac_manager"],
                ))
                self._stats["credential_sharing"] += 1

            # ── Off-schedule pattern ──────────────────────────────────────────
            os_alert = self._detect_off_schedule(card_uid, hour)
            if os_alert:
                alerts.append(self._build_alert(
                    payload, "off_schedule_access_pattern",
                    SeverityLevel.LOW, 0.65,
                    {"card_uid":        card_uid,
                     "current_hour":    hour,
                     "baseline_median": round(os_alert["median"], 1),
                     "baseline_mad":    round(os_alert["mad"], 2),
                     "z_score":         round(os_alert["z"], 2),
                     "mitre":           MITRE_VALID_ACCOUNTS},
                    ["log_for_review"],
                ))
                self._stats["off_schedule"] += 1

            for alert in alerts:
                self._producer.publish(Topics.PAC_ALERTS, alert, key=card_uid)
                self._recent_alerts.append(alert)
                if len(self._recent_alerts) > 100:
                    self._recent_alerts.pop(0)
                self._stats["alerts"] += 1
                logger.warning(
                    f"🚨 [{alert['severity']}] {alert['alert_type']} card={card_uid}")

            # Update last seen AFTER checks
            self._last_seen[card_uid] = {"floor": floor, "reader": reader, "ts": ts}

    # ── Detection helpers ─────────────────────────────────────────────────────
    def _detect_impossible_travel(self, card_uid: str, to_floor: int,
                                   to_reader: str, now: float) -> Optional[dict]:
        prev = self._last_seen.get(card_uid)
        if not prev:
            return None
        from_floor = prev["floor"]
        elapsed    = now - prev["ts"]
        if from_floor == to_floor:
            min_t = SAME_FLOOR_TRAVEL
        else:
            key   = (min(from_floor, to_floor), max(from_floor, to_floor))
            min_t = FLOOR_TRAVEL_TIME.get(key, 30.0)
        if elapsed < min_t and to_reader != prev["reader"]:
            return {"from_floor": from_floor, "elapsed": elapsed,
                    "min_required": min_t, "from_reader": prev["reader"]}
        return None

    def _detect_credential_sharing(self, card_uid: str, reader: str,
                                    now: float) -> Optional[dict]:
        active = self._active_readers[card_uid]
        # Clean up stale sessions (> 60s)
        stale = [r for r, t in active.items() if now - t > 60]
        for r in stale:
            del active[r]
        # Check if card is simultaneously active on another reader
        for other_reader, other_ts in list(active.items()):
            if other_reader != reader and (now - other_ts) < 30.0:
                return {"r1": other_reader, "r2": reader,
                        "gap": now - other_ts}
        return None

    def _detect_off_schedule(self, card_uid: str, hour: int) -> Optional[dict]:
        baseline = list(self._hour_baseline[card_uid])
        if len(baseline) < BASELINE_WINDOW:
            return None
        arr    = np.array(baseline[:-1])   # exclude current reading
        median = float(np.median(arr))
        mad    = float(np.median(np.abs(arr - median)))
        if mad < 0.5:
            return None   # not enough hour-of-day variance to flag
        z = abs(0.6745 * (hour - median) / mad)
        if z > OFF_SCHEDULE_Z:
            return {"median": median, "mad": mad, "z": z}
        return None

    def _build_alert(self, event: dict, alert_type: str, severity: SeverityLevel,
                      confidence: float, details: dict, actions: List[str]) -> dict:
        return {
            "alert_id":    str(uuid.uuid4()),
            "agent_id":    AGENT_ID,
            "agent_type":  "credential_anomaly",
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
            "details":             details,
            "recommended_actions": actions,
        }

    # ── FastAPI ───────────────────────────────────────────────────────────────
    def _build_app(self) -> FastAPI:
        app = FastAPI(title="Credential Anomaly Agent")

        @app.get("/health")
        def health():
            return JSONResponse({
                "agent_id":  AGENT_ID, "status": "running",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "stats":     self._stats,
                "cards_tracked": len(self._last_seen),
            })

        @app.get("/alerts")
        def alerts(limit: int = 50):
            return JSONResponse(self._recent_alerts[-limit:])

        return app

    def start(self):
        threading.Thread(target=self._consumer.poll_loop,
                         args=(self.handle_event,),
                         daemon=True, name="cred-anomaly-consumer").start()
        logger.info(f"▶️  Credential Anomaly Agent — health :{HEALTH_PORT}/health")
        uvicorn.run(self._app, host="0.0.0.0", port=HEALTH_PORT, log_level="warning")

    def stop(self):
        self._consumer.stop()
        self._producer.close()


if __name__ == "__main__":
    a = CredentialAnomalyAgent()
    try:
        a.start()
    except KeyboardInterrupt:
        a.stop()
