"""
managers/data_local_manager/main.py
Phase 3 Week 7 — Data Network Local Manager

Consumes: data.alerts (from NDR + EDR agents)
Reclassification rules (cross-agent correlation):
  - ransomware + credential_dump on same host within 5 min → CRITICAL
  - port_scan + brute_force from same src_ip within 2 min → CRITICAL
  - lateral_movement + privilege_escalation within 10 min → CRITICAL (APT)
  - any CRITICAL from EDR on server subnet (10.0.60.x) → immediate HQ escalation
  - data_exfiltration always → CRITICAL
60s operator approval for CRITICAL. Escalates to hq.incidents.

FastAPI:
  GET  /health  /alerts  /incidents  /pending
  POST /approve/{id}  /dismiss/{id}  /isolate/{host_id}

Standards: NIST SP 800-61, NIST SP 800-53 IR-4, NIST CSF 2.0 RESPOND
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

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from common.kafka_client import KafkaConsumerClient, KafkaProducerClient, Topics
from common.models import SeverityLevel

logging.basicConfig(level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s")
logger = logging.getLogger("data_local_manager")

MANAGER_ID   = os.getenv("MANAGER_ID",           "data-local-manager-01")
BOOTSTRAP    = os.getenv("KAFKA_BOOTSTRAP",       "localhost:9092")
HEALTH_PORT  = int(os.getenv("HEALTH_PORT",      "8012"))
APPROVAL_WIN = int(os.getenv("APPROVAL_WINDOW_SEC","60"))
SHORT_CORR   = int(os.getenv("SHORT_CORR_SEC",   "120"))   # 2 min — fast attack chains
LONG_CORR    = int(os.getenv("LONG_CORR_SEC",    "600"))   # 10 min — APT chains

SERVER_SUBNET = os.getenv("SERVER_SUBNET", "10.0.60.")


class DataLocalManager:
    def __init__(self):
        logger.info(f"🚀 Data Local Manager {MANAGER_ID}")
        self._alerts:    deque = deque(maxlen=500)
        self._incidents: List[dict] = []
        self._pending:   Dict[str, dict] = {}
        self._isolated_hosts: Dict[str, str] = {}   # host → reason
        self._stats = {
            "received": 0, "incidents": 0,
            "escalated": 0, "isolated_hosts": 0,
        }
        # Recent alert tracking for correlation
        # key: "{alert_type}::{host_or_ip}" → deque of {ts, severity}
        self._recent: Dict[str, deque] = defaultdict(lambda: deque(maxlen=20))

        self._producer = KafkaProducerClient(BOOTSTRAP)
        self._consumer = KafkaConsumerClient(MANAGER_ID, [Topics.DATA_ALERTS], BOOTSTRAP)
        self._app = self._build_app()
        logger.info("✅ Data Local Manager ready")

    # ── Alert handler ─────────────────────────────────────────────────────────
    def handle_alert(self, topic: str, payload: dict):
        self._stats["received"] += 1
        alert_type = payload.get("alert_type", "")
        severity   = payload.get("severity", "LOW")
        source     = payload.get("source", {})
        host_id    = source.get("host_id", source.get("src_ip", ""))
        ts         = time.time()

        self._alerts.append({**payload, "received_at": datetime.now(timezone.utc).isoformat()})

        # Index by alert_type + host/ip for correlation lookups
        self._recent[f"{alert_type}::{host_id}"].append({"ts": ts, "severity": severity})

        logger.info(f"📥 [{severity}] {alert_type} host={host_id}")

        new_severity = self._reclassify(payload, alert_type, severity, host_id, ts)

        if new_severity in ("HIGH", "CRITICAL"):
            inc = self._create_incident(payload, new_severity, alert_type, host_id)
            self._handle_escalation(inc)

    def _reclassify(self, payload, alert_type, severity, host_id, ts) -> str:
        short_cutoff = ts - SHORT_CORR
        long_cutoff  = ts - LONG_CORR

        def recent(atype, host, since):
            return [a for a in self._recent.get(f"{atype}::{host}", [])
                    if a["ts"] >= since]

        # Rule 1: data_exfiltration is always CRITICAL
        if alert_type == "data_exfiltration":
            return "CRITICAL"

        # Rule 2: ransomware + credential_dump on same host (5 min window)
        if alert_type == "ransomware_behavior":
            if recent("credential_dump", host_id, ts - 300):
                logger.warning(f"🔴 Reclassify: ransomware + cred_dump on {host_id} → CRITICAL (double threat)")
                return "CRITICAL"

        if alert_type == "credential_dump":
            if recent("ransomware_behavior", host_id, ts - 300):
                logger.warning(f"🔴 Reclassify: cred_dump + ransomware on {host_id} → CRITICAL")
                return "CRITICAL"

        # Rule 3: port_scan + brute_force from same src_ip (2 min)
        if alert_type == "port_scan":
            if (recent("brute_force_ssh", host_id, short_cutoff) or
                    recent("brute_force_http", host_id, short_cutoff)):
                logger.warning(f"🔴 Reclassify: port_scan + brute_force from {host_id} → CRITICAL")
                return "CRITICAL"

        if alert_type in ("brute_force_ssh", "brute_force_http"):
            if recent("port_scan", host_id, short_cutoff):
                logger.warning(f"🔴 Reclassify: brute_force after port_scan from {host_id} → CRITICAL")
                return "CRITICAL"

        # Rule 4: lateral_movement + privilege_escalation (APT pattern, 10 min)
        if alert_type == "lateral_movement":
            if recent("privilege_escalation", host_id, long_cutoff):
                logger.warning(f"🔴 Reclassify: lateral_movement + privesc from {host_id} → CRITICAL (APT)")
                return "CRITICAL"

        if alert_type == "privilege_escalation":
            if recent("lateral_movement", host_id, long_cutoff):
                logger.warning(f"🔴 Reclassify: privesc + lateral_movement from {host_id} → CRITICAL (APT)")
                return "CRITICAL"

        # Rule 5: Any EDR CRITICAL on server subnet → immediate
        if severity == "CRITICAL" and host_id.startswith(SERVER_SUBNET):
            logger.warning(f"🔴 CRITICAL on server subnet {host_id} → immediate HQ escalation")
            return "CRITICAL"

        return severity

    def _create_incident(self, payload, severity, alert_type, host_id) -> dict:
        inc = {
            "incident_id":    f"INC-DATA-{uuid.uuid4().hex[:8].upper()}",
            "created_at":     datetime.now(timezone.utc).isoformat(),
            "manager_id":     MANAGER_ID,
            "severity":       severity,
            "network_domain": "data_network",
            "alert_type":     alert_type,
            "host_id":        host_id,
            "trigger_alert_id": payload.get("alert_id"),
            "details":        payload.get("details", {}),
            "status":         "pending_approval" if severity == "CRITICAL" else "auto_escalated",
            "recommended_actions": payload.get("recommended_actions", []),
            "agent_type":     payload.get("agent_type", ""),
        }
        self._incidents.append(inc)
        self._stats["incidents"] += 1
        logger.warning(f"📋 Incident {inc['incident_id']} [{severity}] {alert_type}")
        return inc

    def _handle_escalation(self, inc: dict):
        if inc["severity"] == "CRITICAL":
            self._pending[inc["incident_id"]] = {**inc, "deadline": time.time() + APPROVAL_WIN}
            logger.warning(f"⏳ {inc['incident_id']} — {APPROVAL_WIN}s approval window")
            threading.Thread(target=self._approval_timeout,
                             args=(inc["incident_id"],), daemon=True).start()
        else:
            self._escalate(inc)

    def _approval_timeout(self, iid: str):
        time.sleep(APPROVAL_WIN)
        if iid in self._pending:
            inc = self._pending.pop(iid)
            inc["status"] = "auto_escalated_after_timeout"
            logger.warning(f"⏰ Auto-escalating {iid}")
            self._escalate(inc)

    def _escalate(self, inc: dict):
        inc["status"]       = "escalated_to_hq"
        inc["escalated_at"] = datetime.now(timezone.utc).isoformat()
        self._producer.publish(Topics.HQ_INCIDENTS, inc, key=inc["incident_id"])
        self._stats["escalated"] += 1
        logger.warning(f"🚀 → HQ: {inc['incident_id']} [{inc['severity']}]")

    # ── FastAPI ───────────────────────────────────────────────────────────────
    def _build_app(self) -> FastAPI:
        app = FastAPI(title="Data Local Manager")

        @app.get("/health")
        def health():
            return JSONResponse({"manager_id": MANAGER_ID, "status": "running",
                                  "timestamp": datetime.now(timezone.utc).isoformat(),
                                  "stats": self._stats,
                                  "isolated_hosts": self._isolated_hosts})

        @app.get("/alerts")
        def alerts(limit: int = 50):
            return JSONResponse(list(self._alerts)[-limit:])

        @app.get("/incidents")
        def incidents():
            return JSONResponse(self._incidents)

        @app.get("/pending")
        def pending():
            return JSONResponse(list(self._pending.values()))

        @app.post("/approve/{iid}")
        def approve(iid: str):
            if iid not in self._pending:
                raise HTTPException(404, "Not found")
            inc = self._pending.pop(iid)
            inc["status"] = "manually_approved"
            self._escalate(inc)
            return JSONResponse({"approved": True, "incident_id": iid})

        @app.post("/dismiss/{iid}")
        def dismiss(iid: str):
            if iid not in self._pending:
                raise HTTPException(404, "Not found")
            self._pending[iid]["status"] = "dismissed"
            del self._pending[iid]
            return JSONResponse({"dismissed": True, "incident_id": iid})

        @app.post("/isolate/{host_id}")
        def isolate(host_id: str, reason: str = "manual_operator_action"):
            self._isolated_hosts[host_id] = reason
            self._stats["isolated_hosts"] += 1
            self._producer.publish(Topics.SOAR_COMMANDS, {
                "command_id": str(uuid.uuid4()), "issued_by": MANAGER_ID,
                "command": "isolate_host", "target": host_id,
                "reason": reason, "timestamp": datetime.now(timezone.utc).isoformat(),
            }, key=host_id)
            logger.warning(f"🔒 Host isolated: {host_id} — {reason}")
            return JSONResponse({"isolated": True, "host_id": host_id})

        return app

    def start(self):
        threading.Thread(target=self._consumer.poll_loop,
                         args=(self.handle_alert,),
                         daemon=True, name="data-mgr-consumer").start()
        logger.info(f"▶️  Data Local Manager — API :{HEALTH_PORT}")
        uvicorn.run(self._app, host="0.0.0.0", port=HEALTH_PORT, log_level="warning")

    def stop(self):
        self._consumer.stop()
        self._producer.close()


if __name__ == "__main__":
    m = DataLocalManager()
    try:
        m.start()
    except KeyboardInterrupt:
        m.stop()
