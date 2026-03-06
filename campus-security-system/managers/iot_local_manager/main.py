"""
IoT Local Manager — managers/iot_local_manager/main.py
Phase 1 / Week 3 deliverable

Consumes alerts from iot.alerts (gateway_agent + behavioral_agent outputs),
re-classifies with multi-sensor context, manages device heartbeats,
and escalates confirmed incidents to hq.incidents.

Also exposes FastAPI endpoints:
  GET  /health           — liveness check
  GET  /alerts           — recent alert list
  GET  /incidents        — escalated incidents
  GET  /devices          — device heartbeat status
  POST /approve/{id}     — manual operator approval (60s window)

Standards:
  - NIST SP 800-61 — Incident detection and analysis
  - IEC 62443-2-1 — Security management for IACS
  - NIST CSF 2.0 DETECT / RESPOND
"""

from __future__ import annotations

import logging
import os
import sys
import threading
import time
import uuid
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Dict, List, Optional

import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.kafka_client import KafkaConsumerClient, KafkaProducerClient, Topics
from common.models import Alert, SeverityLevel

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger("iot_local_manager")

MANAGER_ID    = os.getenv("MANAGER_ID",      "iot-local-manager-01")
BOOTSTRAP     = os.getenv("KAFKA_BOOTSTRAP", "localhost:9092")
HEALTH_PORT   = int(os.getenv("HEALTH_PORT", "8010"))

# Heartbeat: if no message from a device for > this many seconds → dropout alert
HEARTBEAT_TIMEOUT_SEC = int(os.getenv("HEARTBEAT_TIMEOUT_SEC", "20"))

# Operator approval window for CRITICAL escalations
APPROVAL_WINDOW_SEC = int(os.getenv("APPROVAL_WINDOW_SEC", "60"))

# Correlation window: events within this window get grouped into one incident
CORRELATION_WINDOW_SEC = int(os.getenv("CORRELATION_WINDOW_SEC", "30"))


class IoTLocalManager:

    def __init__(self):
        logger.info(f"🚀 Starting IoT Local Manager {MANAGER_ID}")

        # Alert storage (last 200)
        self._alerts: deque = deque(maxlen=200)

        # Incidents waiting for operator approval: {incident_id: incident_dict}
        self._pending_approval: Dict[str, dict] = {}

        # Confirmed/escalated incidents
        self._incidents: List[dict] = []

        # Device heartbeat tracking: device_id -> last_seen timestamp
        self._last_seen: Dict[str, float] = {}

        # Recent alert buffer per sensor_type for correlation
        self._recent_alerts: Dict[str, deque] = defaultdict(lambda: deque(maxlen=10))

        # Kafka
        self._producer = KafkaProducerClient(BOOTSTRAP)
        self._consumer = KafkaConsumerClient(
            group_id=MANAGER_ID,
            topics=[Topics.IOT_ALERTS],
            bootstrap_servers=BOOTSTRAP,
        )

        self._stats = {
            "alerts_received": 0,
            "incidents_created": 0,
            "escalated_to_hq": 0,
            "device_dropouts_detected": 0,
        }

        self._app = self._build_api()
        logger.info("✅ IoT Local Manager initialized")

    # ─── Alert processing ─────────────────────────────────────────────────────

    def handle_alert(self, topic: str, payload: dict):
        """Main handler for incoming IoT alerts."""
        self._stats["alerts_received"] += 1

        # Update device heartbeat
        device_id = payload.get("source", {}).get("device_id") or payload.get("device_id", "unknown")
        self._last_seen[device_id] = time.time()

        # Store alert
        alert_entry = {
            **payload,
            "received_at": datetime.now(timezone.utc).isoformat(),
            "manager_id": MANAGER_ID,
        }
        self._alerts.append(alert_entry)

        severity = payload.get("severity", "LOW")
        alert_type = payload.get("alert_type", "")
        sensor_type = payload.get("source", {}).get("sensor_type", "unknown")

        logger.info(f"📥 Alert received: [{severity}] {alert_type} device={device_id}")

        # Track in correlation window
        self._recent_alerts[sensor_type].append({
            "ts": time.time(),
            "severity": severity,
            "alert_id": payload.get("alert_id"),
            "payload": payload,
        })

        # Reclassify with context
        reclassified_severity = self._reclassify(payload, sensor_type, severity)

        # Take action based on reclassified severity
        if reclassified_severity in ("HIGH", "CRITICAL"):
            incident = self._create_incident(payload, reclassified_severity)
            self._handle_escalation(incident)

    def _reclassify(self, payload: dict, sensor_type: str, original_severity: str) -> str:
        """
        Context-aware reclassification.
        Rules (IEC 62443-2-1 aligned):
          1. If temp HIGH + gas MEDIUM within 30s → upgrade both to CRITICAL (fire risk)
          2. If motion + gas HIGH within 30s → CRITICAL (intruder + hazard)
          3. Single gas/temp HIGH without corroboration → keep HIGH
          4. MEDIUM without prior HIGH context → keep MEDIUM
        """
        now = time.time()
        cutoff = now - CORRELATION_WINDOW_SEC

        def recent_of_type(stype: str, min_severity: str) -> bool:
            sev_order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
            min_val = sev_order.get(min_severity, 0)
            for a in self._recent_alerts.get(stype, []):
                if a["ts"] >= cutoff and sev_order.get(a["severity"], 0) >= min_val:
                    return True
            return False

        # Rule 1: Temperature spike + recent gas anomaly → fire risk → CRITICAL
        if sensor_type == "temperature" and original_severity in ("HIGH", "CRITICAL"):
            if recent_of_type("gas", "MEDIUM"):
                logger.warning("🔥 Reclassify: temp HIGH + gas MEDIUM → CRITICAL (fire risk)")
                return "CRITICAL"

        # Rule 2: Gas anomaly + recent temperature HIGH → CRITICAL
        if sensor_type == "gas" and original_severity in ("HIGH", "CRITICAL"):
            if recent_of_type("temperature", "HIGH"):
                logger.warning("🔥 Reclassify: gas HIGH + temp HIGH → CRITICAL")
                return "CRITICAL"

        # Rule 3: Motion + gas HIGH → CRITICAL
        if sensor_type == "motion" and original_severity in ("HIGH", "CRITICAL"):
            if recent_of_type("gas", "HIGH"):
                logger.warning("⚠️  Reclassify: motion HIGH + gas HIGH → CRITICAL")
                return "CRITICAL"

        return original_severity

    def _create_incident(self, payload: dict, severity: str) -> dict:
        incident = {
            "incident_id": f"INC-IOT-{uuid.uuid4().hex[:8].upper()}",
            "created_at":  datetime.now(timezone.utc).isoformat(),
            "manager_id":  MANAGER_ID,
            "severity":    severity,
            "network_domain": "iot",
            "trigger_alert_id": payload.get("alert_id"),
            "device_id":   payload.get("source", {}).get("device_id", "unknown"),
            "alert_type":  payload.get("alert_type", ""),
            "details":     payload.get("details", {}),
            "status":      "pending_approval" if severity == "CRITICAL" else "auto_escalated",
            "recommended_actions": payload.get("recommended_actions", []),
        }
        self._incidents.append(incident)
        self._stats["incidents_created"] += 1
        logger.warning(f"📋 Incident created: {incident['incident_id']} [{severity}]")
        return incident

    def _handle_escalation(self, incident: dict):
        """Escalate to HQ or queue for operator approval."""
        severity = incident["severity"]

        if severity == "CRITICAL":
            # Queue for 60s operator approval window
            self._pending_approval[incident["incident_id"]] = {
                **incident,
                "approval_deadline": time.time() + APPROVAL_WINDOW_SEC,
            }
            logger.warning(
                f"⏳ CRITICAL incident {incident['incident_id']} queued for approval "
                f"(auto-escalates in {APPROVAL_WINDOW_SEC}s)"
            )
            # Start approval timeout thread
            threading.Thread(
                target=self._approval_timeout,
                args=(incident["incident_id"],),
                daemon=True,
            ).start()
        else:
            # HIGH → auto-escalate to HQ
            self._escalate_to_hq(incident)

    def _approval_timeout(self, incident_id: str):
        """Auto-escalate CRITICAL incident if not manually approved within window."""
        time.sleep(APPROVAL_WINDOW_SEC)
        if incident_id in self._pending_approval:
            incident = self._pending_approval.pop(incident_id)
            incident["status"] = "auto_escalated_after_timeout"
            logger.warning(f"⏰ Auto-escalating {incident_id} after {APPROVAL_WINDOW_SEC}s timeout")
            self._escalate_to_hq(incident)

    def _escalate_to_hq(self, incident: dict):
        """Publish incident to hq.incidents topic."""
        incident["status"] = "escalated_to_hq"
        incident["escalated_at"] = datetime.now(timezone.utc).isoformat()
        self._producer.publish(
            topic=Topics.HQ_INCIDENTS,
            payload=incident,
            key=incident["incident_id"],
        )
        self._stats["escalated_to_hq"] += 1
        logger.warning(f"🚀 Escalated to HQ: {incident['incident_id']} [{incident['severity']}]")

    # ─── Heartbeat watchdog ───────────────────────────────────────────────────

    def _heartbeat_watchdog(self):
        """
        Background thread. Checks every 5s if any device has gone silent.
        Publishes device_dropout alert to iot.alerts if timeout exceeded.
        """
        logger.info(f"💓 Heartbeat watchdog started (timeout={HEARTBEAT_TIMEOUT_SEC}s)")
        while True:
            time.sleep(5)
            now = time.time()
            for device_id, last in list(self._last_seen.items()):
                if now - last > HEARTBEAT_TIMEOUT_SEC:
                    self._stats["device_dropouts_detected"] += 1
                    dropout_alert = {
                        "alert_id":    f"DROPOUT-{uuid.uuid4().hex[:8].upper()}",
                        "agent_id":    MANAGER_ID,
                        "agent_type":  "iot_local_manager",
                        "network_type": "iot",
                        "alert_type":  "sensor_dropout",
                        "severity":    "HIGH",
                        "confidence":  1.0,
                        "source":      {"device_id": device_id},
                        "details": {
                            "last_seen_ago_sec": round(now - last, 1),
                            "timeout_threshold": HEARTBEAT_TIMEOUT_SEC,
                            "mitre_technique":   "T0829",  # Loss of View (ICS)
                        },
                        "recommended_actions": [
                            "check_pi_iot_hardware",
                            "verify_mqtt_connectivity",
                            "escalate_if_unresolved_after_60s",
                        ],
                    }
                    # Publish dropout as an alert so it flows through the pipeline
                    self._producer.publish(
                        topic=Topics.IOT_ALERTS,
                        payload=dropout_alert,
                        key=device_id,
                    )
                    logger.warning(
                        f"💀 DEVICE DROPOUT: {device_id} "
                        f"(silent for {round(now-last,1)}s)"
                    )
                    # Remove from tracking so we don't spam alerts
                    del self._last_seen[device_id]

    # ─── FastAPI endpoints ────────────────────────────────────────────────────

    def _build_api(self) -> FastAPI:
        app = FastAPI(title="IoT Local Manager API")

        @app.get("/health")
        def health():
            return JSONResponse({
                "manager_id": MANAGER_ID,
                "status":     "running",
                "timestamp":  datetime.now(timezone.utc).isoformat(),
                "stats":      self._stats,
            })

        @app.get("/alerts")
        def get_alerts(limit: int = 50):
            return JSONResponse(list(self._alerts)[-limit:])

        @app.get("/incidents")
        def get_incidents():
            return JSONResponse(self._incidents)

        @app.get("/devices")
        def get_devices():
            now = time.time()
            return JSONResponse({
                d: {"last_seen_ago_sec": round(now - ts, 1), "status": "online"}
                for d, ts in self._last_seen.items()
            })

        @app.get("/pending")
        def get_pending():
            return JSONResponse(list(self._pending_approval.values()))

        @app.post("/approve/{incident_id}")
        def approve(incident_id: str):
            if incident_id not in self._pending_approval:
                raise HTTPException(status_code=404, detail="Incident not found or already processed")
            incident = self._pending_approval.pop(incident_id)
            incident["status"] = "manually_approved"
            self._escalate_to_hq(incident)
            return JSONResponse({"approved": True, "incident_id": incident_id})

        @app.post("/dismiss/{incident_id}")
        def dismiss(incident_id: str):
            if incident_id not in self._pending_approval:
                raise HTTPException(status_code=404, detail="Incident not found or already processed")
            self._pending_approval[incident_id]["status"] = "dismissed_by_operator"
            del self._pending_approval[incident_id]
            return JSONResponse({"dismissed": True, "incident_id": incident_id})

        return app

    # ─── Lifecycle ────────────────────────────────────────────────────────────

    def start(self):
        # Heartbeat watchdog thread
        threading.Thread(
            target=self._heartbeat_watchdog,
            daemon=True,
            name="heartbeat-watchdog",
        ).start()

        # Kafka consumer thread
        threading.Thread(
            target=self._consumer.poll_loop,
            args=(self.handle_alert,),
            daemon=True,
            name="iot-consumer",
        ).start()

        logger.info(f"▶️  IoT Local Manager running — API on :{HEALTH_PORT}")
        uvicorn.run(self._app, host="0.0.0.0", port=HEALTH_PORT, log_level="warning")

    def stop(self):
        logger.info("🛑 Stopping IoT Local Manager")
        self._consumer.stop()
        self._producer.close()


if __name__ == "__main__":
    manager = IoTLocalManager()
    try:
        manager.start()
    except KeyboardInterrupt:
        manager.stop()
