"""
managers/central_manager/main.py
Phase 4 Week 10 — Central Manager (System Dashboard + Control)

Aggregates system-wide status from all agents and local managers.
Tracks all active incidents across all three domains.
Provides the investor-demo API endpoints.

FastAPI endpoints:
  GET  /status               — full system health (all agents + managers)
  GET  /incidents            — all active incidents across all domains
  GET  /incidents/{domain}   — incidents filtered by domain
  GET  /correlations         — HQ-level correlated incidents
  GET  /commands             — recent SOAR commands issued
  POST /approve/{incident_id} — operator approval forwarded to correct manager
  POST /dismiss/{incident_id} — operator dismissal

Consumes: hq.incidents, hq.correlated, soar.commands, agents.heartbeats
Health:   GET /health (port 8020)

Standards: NIST SP 800-61 Rev2, NIST CSF 2.0 GOVERN/RESPOND
"""
from __future__ import annotations
import logging, os, sys, threading, time, uuid
from collections import deque
from datetime import datetime, timezone
from typing import Dict, List
from pathlib import Path

import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from common.kafka_client import KafkaConsumerClient, KafkaProducerClient, Topics

logging.basicConfig(level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s")
logger = logging.getLogger("central_manager")

MANAGER_ID  = os.getenv("MANAGER_ID",        "central-manager-01")
BOOTSTRAP   = os.getenv("KAFKA_BOOTSTRAP",   "localhost:9092")
HEALTH_PORT = int(os.getenv("HEALTH_PORT",  "8020"))
HB_TIMEOUT  = int(os.getenv("HB_TIMEOUT_SEC","30"))

# Expected agents — used to compute system health percentage
EXPECTED_AGENTS = [
    "gateway-agent-01", "behavioral-agent-01", "iot-local-manager-01",
    "pac-eda-agent-01", "credential-anomaly-agent-01", "pac-local-manager-01",
    "ndr-agent-01", "edr-agent-01", "data-local-manager-01",
    "analytical-agent-01", "orchestrator-agent-01",
]


class CentralManager:
    def __init__(self):
        logger.info(f"🚀 Central Manager {MANAGER_ID}")

        # Incident tracking per domain
        self._incidents: Dict[str, List[dict]] = {
            "iot": [], "physical_access": [], "data_network": [],
        }
        self._correlations: List[dict] = []
        self._commands: deque = deque(maxlen=200)
        self._all_incidents: deque = deque(maxlen=1000)

        # Agent heartbeat tracking
        self._heartbeats: Dict[str, float] = {}
        self._agent_status: Dict[str, dict] = {}

        self._stats = {
            "total_incidents": 0, "total_correlations": 0,
            "total_commands": 0, "agents_healthy": 0,
        }
        self._producer = KafkaProducerClient(BOOTSTRAP)
        self._consumer = KafkaConsumerClient(
            MANAGER_ID,
            [Topics.HQ_INCIDENTS, Topics.HQ_CORRELATED,
             Topics.SOAR_COMMANDS, Topics.HEARTBEATS],
            BOOTSTRAP,
        )
        self._app = self._build_app()
        logger.info("✅ Central Manager ready")

    # ── Message handler ───────────────────────────────────────────────────────
    def handle_message(self, topic: str, payload: dict):
        if topic == Topics.HQ_INCIDENTS:
            self._handle_incident(payload)
        elif topic == Topics.HQ_CORRELATED:
            self._handle_correlation(payload)
        elif topic == Topics.SOAR_COMMANDS:
            self._commands.append({**payload,
                "received_at": datetime.now(timezone.utc).isoformat()})
            self._stats["total_commands"] += 1
        elif topic == Topics.HEARTBEATS:
            self._handle_heartbeat(payload)

    def _handle_incident(self, payload: dict):
        domain = payload.get("network_domain", "unknown")
        payload["_received_at"] = datetime.now(timezone.utc).isoformat()
        self._all_incidents.append(payload)
        if domain in self._incidents:
            self._incidents[domain].append(payload)
        self._stats["total_incidents"] += 1
        logger.info(f"📥 Incident [{domain}] [{payload.get('severity','')}] "
                    f"{payload.get('incident_id','')}")

    def _handle_correlation(self, payload: dict):
        self._correlations.append(payload)
        self._stats["total_correlations"] += 1
        logger.warning(f"🧠 Correlation [{payload.get('severity','')}] "
                       f"[{payload.get('correlation_type','')}]")

    def _handle_heartbeat(self, payload: dict):
        agent_id = payload.get("agent_id","")
        if agent_id:
            self._heartbeats[agent_id] = time.time()
            self._agent_status[agent_id] = {
                "agent_id":   agent_id,
                "last_seen":  datetime.now(timezone.utc).isoformat(),
                "status":     payload.get("status","running"),
                "stats":      payload.get("stats",{}),
            }

    # ── System status ─────────────────────────────────────────────────────────
    def _compute_status(self) -> dict:
        now = time.time()
        agent_health = {}
        healthy_count = 0
        for agent_id in EXPECTED_AGENTS:
            last = self._heartbeats.get(agent_id, 0)
            is_healthy = (now - last) < HB_TIMEOUT
            if is_healthy:
                healthy_count += 1
            agent_health[agent_id] = {
                "healthy":   is_healthy,
                "last_seen_ago_sec": round(now - last, 1) if last else None,
            }
        self._stats["agents_healthy"] = healthy_count
        health_pct = round(healthy_count / len(EXPECTED_AGENTS) * 100, 1)

        active_incidents = [i for i in self._all_incidents
                            if i.get("status") not in ("dismissed","resolved")]
        critical_count = sum(1 for i in active_incidents if i.get("severity")=="CRITICAL")
        high_count     = sum(1 for i in active_incidents if i.get("severity")=="HIGH")

        # Overall system threat level
        if critical_count >= 2 or len(self._correlations) >= 1:
            threat_level = "CRITICAL"
        elif critical_count >= 1 or high_count >= 3:
            threat_level = "HIGH"
        elif high_count >= 1:
            threat_level = "MEDIUM"
        else:
            threat_level = "LOW"

        return {
            "system_id":         MANAGER_ID,
            "timestamp":         datetime.now(timezone.utc).isoformat(),
            "threat_level":      threat_level,
            "health_percentage": health_pct,
            "agents_healthy":    healthy_count,
            "agents_total":      len(EXPECTED_AGENTS),
            "agent_health":      agent_health,
            "incidents": {
                "total":    len(active_incidents),
                "critical": critical_count,
                "high":     high_count,
                "by_domain": {d: len(incs) for d, incs in self._incidents.items()},
            },
            "correlations_active": len(self._correlations),
            "commands_issued":     self._stats["total_commands"],
        }

    # ── FastAPI ───────────────────────────────────────────────────────────────
    def _build_app(self) -> FastAPI:
        app = FastAPI(title="MASS Central Manager",
                      description="Predictive Cyber-Physical Security — Campus MASS System")
        app.add_middleware(CORSMiddleware, allow_origins=["*"],
                           allow_methods=["*"], allow_headers=["*"])

        @app.get("/health")
        def health():
            return JSONResponse({"manager_id": MANAGER_ID, "status": "running",
                                  "timestamp": datetime.now(timezone.utc).isoformat()})

        @app.get("/status")
        def status():
            return JSONResponse(self._compute_status())

        @app.get("/incidents")
        def incidents(limit: int = 100):
            items = list(self._all_incidents)[-limit:]
            return JSONResponse({"count": len(items), "incidents": items})

        @app.get("/incidents/{domain}")
        def incidents_by_domain(domain: str, limit: int = 50):
            if domain not in self._incidents:
                raise HTTPException(400, f"Unknown domain: {domain}")
            items = self._incidents[domain][-limit:]
            return JSONResponse({"domain": domain, "count": len(items),
                                  "incidents": items})

        @app.get("/correlations")
        def correlations(limit: int = 20):
            return JSONResponse({"count": len(self._correlations),
                                  "correlations": self._correlations[-limit:]})

        @app.get("/commands")
        def commands(limit: int = 50):
            return JSONResponse(list(self._commands)[-limit:])

        @app.post("/approve/{incident_id}")
        def approve(incident_id: str):
            # Forward approval command to appropriate local manager via Kafka
            self._producer.publish(Topics.SOAR_COMMANDS, {
                "command_id":   str(uuid.uuid4()),
                "action":       "approve_incident",
                "incident_id":  incident_id,
                "approved_by":  "central_manager_operator",
                "approved_at":  datetime.now(timezone.utc).isoformat(),
            }, key=incident_id)
            return JSONResponse({"approved": True, "incident_id": incident_id})

        @app.post("/dismiss/{incident_id}")
        def dismiss(incident_id: str):
            self._producer.publish(Topics.SOAR_COMMANDS, {
                "command_id":   str(uuid.uuid4()),
                "action":       "dismiss_incident",
                "incident_id":  incident_id,
                "dismissed_by": "central_manager_operator",
                "dismissed_at": datetime.now(timezone.utc).isoformat(),
            }, key=incident_id)
            return JSONResponse({"dismissed": True, "incident_id": incident_id})

        return app

    def start(self):
        threading.Thread(target=self._consumer.poll_loop,
                         args=(self.handle_message,),
                         daemon=True, name="central-consumer").start()
        logger.info(f"▶️  Central Manager — API :{HEALTH_PORT}")
        uvicorn.run(self._app, host="0.0.0.0", port=HEALTH_PORT, log_level="warning")

    def stop(self):
        self._consumer.stop()
        self._producer.close()


if __name__ == "__main__":
    m = CentralManager()
    try:
        m.start()
    except KeyboardInterrupt:
        m.stop()
