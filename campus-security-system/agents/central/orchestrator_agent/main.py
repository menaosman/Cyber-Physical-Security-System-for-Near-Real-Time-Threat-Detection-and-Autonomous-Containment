"""
agents/hq/orchestrator_agent/main.py
Phase 4 Week 9 — Orchestrator Agent (SOAR Engine)

Consumes correlated incidents from hq.correlated.
Selects and executes YAML playbooks based on threat type + severity.
Issues SOAR commands to soar.commands and tracks responses.

Built-in playbooks (3 required for demo):
  1. ransomware_response     — isolate host, kill processes, snapshot, notify
  2. intrusion_response      — block IP, rotate creds, full packet capture
  3. iot_compromise_response — isolate IoT VLAN, restart sensors, alert team

Publishes:  soar.commands, soar.responses
Health:     GET /health  /playbooks  /executions (port 8007)

Standards: NIST SP 800-61 Rev2 Section 3.3, IEC 62443-3-3
"""
from __future__ import annotations
import logging, os, sys, threading, time, uuid
from collections import deque
from datetime import datetime, timezone
from typing import Dict, List
from pathlib import Path

import uvicorn
from fastapi import FastAPI
from fastapi.responses import JSONResponse

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
from common.kafka_client import KafkaConsumerClient, KafkaProducerClient, Topics

logging.basicConfig(level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s")
logger = logging.getLogger("orchestrator_agent")

AGENT_ID    = os.getenv("AGENT_ID",        "orchestrator-agent-01")
BOOTSTRAP   = os.getenv("KAFKA_BOOTSTRAP", "localhost:9092")
HEALTH_PORT = int(os.getenv("HEALTH_PORT", "8007"))


# ── Playbook definitions (inline YAML-equivalent) ─────────────────────────────
PLAYBOOKS: Dict[str, dict] = {
    "ransomware_response": {
        "name":        "Ransomware Response",
        "triggers":    ["ransomware_behavior", "coordinated_attack"],
        "min_severity":"HIGH",
        "steps": [
            {"step": 1, "action": "isolate_host",
             "description": "Network-isolate the affected endpoint immediately",
             "target_field": "host_id", "auto": True},
            {"step": 2, "action": "kill_suspicious_processes",
             "description": "Terminate all non-whitelisted processes on host",
             "target_field": "host_id", "auto": True},
            {"step": 3, "action": "take_forensic_snapshot",
             "description": "Capture memory + disk image before any cleanup",
             "target_field": "host_id", "auto": True},
            {"step": 4, "action": "notify_incident_response_team",
             "description": "Page on-call IR team with full incident context",
             "auto": True},
            {"step": 5, "action": "block_c2_ips",
             "description": "Block all external IPs seen in the correlated incident",
             "auto": True},
            {"step": 6, "action": "restore_from_backup",
             "description": "Restore affected files from last clean backup",
             "auto": False, "requires_approval": True},
        ]
    },
    "intrusion_response": {
        "name":        "Active Intrusion Response",
        "triggers":    ["coordinated_attack","campus_wide_threat",
                        "physical_cyber_combo","insider_threat"],
        "min_severity":"HIGH",
        "steps": [
            {"step": 1, "action": "block_attacker_ip",
             "description": "Add attacker IP to campus firewall blocklist",
             "target_field": "src_ip", "auto": True},
            {"step": 2, "action": "capture_full_traffic",
             "description": "Enable full packet capture on affected segments",
             "auto": True},
            {"step": 3, "action": "rotate_compromised_credentials",
             "description": "Force password reset for all potentially compromised accounts",
             "auto": False, "requires_approval": True},
            {"step": 4, "action": "enable_enhanced_logging",
             "description": "Increase log verbosity on all campus systems",
             "auto": True},
            {"step": 5, "action": "notify_management_and_legal",
             "description": "Brief CISO, legal team, and management",
             "auto": True},
        ]
    },
    "iot_compromise_response": {
        "name":        "IoT Compromise Response",
        "triggers":    ["iot_cyber_bridge", "coordinated_attack"],
        "min_severity":"HIGH",
        "steps": [
            {"step": 1, "action": "isolate_iot_vlan",
             "description": "Block all inter-VLAN traffic from IoT segment (VLAN 20-23)",
             "auto": True},
            {"step": 2, "action": "restart_compromised_sensors",
             "description": "Send restart command to pi-iot and pi-physical",
             "auto": True},
            {"step": 3, "action": "verify_sensor_integrity",
             "description": "Check sensor firmware hashes against known-good baseline",
             "auto": True},
            {"step": 4, "action": "notify_facilities_team",
             "description": "Alert facilities management about potential physical sensor tampering",
             "auto": True},
            {"step": 5, "action": "rotate_mqtt_credentials",
             "description": "Regenerate MQTT client certificates for all IoT devices",
             "auto": False, "requires_approval": True},
        ]
    },
    "access_control_lockdown": {
        "name":        "Access Control Lockdown",
        "triggers":    ["physical_cyber_combo","insider_threat","campus_wide_threat"],
        "min_severity":"CRITICAL",
        "steps": [
            {"step": 1, "action": "lock_all_restricted_doors",
             "description": "Issue lock command to all server room and HQ doors",
             "auto": True},
            {"step": 2, "action": "suspend_flagged_rfid_cards",
             "description": "Disable access for all cards flagged in past 30 min",
             "auto": True},
            {"step": 3, "action": "activate_security_cameras",
             "description": "Switch all campus cameras to real-time recording mode",
             "auto": True},
            {"step": 4, "action": "notify_physical_security_team",
             "description": "Alert on-site security personnel",
             "auto": True},
        ]
    },
}


class OrchestratorAgent:
    def __init__(self):
        logger.info(f"🚀 Starting Orchestrator Agent {AGENT_ID}")
        self._executions: List[dict] = []
        self._pending_approvals: Dict[str, dict] = {}
        self._stats = {
            "correlations_received": 0, "playbooks_executed": 0,
            "commands_issued": 0, "approvals_pending": 0,
        }
        self._producer = KafkaProducerClient(BOOTSTRAP)
        self._consumer = KafkaConsumerClient(
            AGENT_ID, [Topics.HQ_CORRELATED, Topics.SOAR_RESPONSES], BOOTSTRAP)
        self._app = self._build_app()
        logger.info(f"✅ Orchestrator ready — {len(PLAYBOOKS)} playbooks loaded")

    # ── Main handler ──────────────────────────────────────────────────────────
    def handle_message(self, topic: str, payload: dict):
        if topic == Topics.HQ_CORRELATED:
            self._handle_correlation(payload)
        elif topic == Topics.SOAR_RESPONSES:
            self._handle_response(payload)

    def _handle_correlation(self, payload: dict):
        self._stats["correlations_received"] += 1
        corr_type = payload.get("correlation_type","")
        severity  = payload.get("severity","LOW")
        corr_id   = payload.get("correlation_id","")

        logger.info(f"📥 Correlation [{severity}] [{corr_type}] id={corr_id}")

        # Select matching playbooks
        matched = self._select_playbooks(corr_type, severity)
        if not matched:
            logger.info(f"  No playbook matched for [{corr_type}]")
            return

        for playbook_name in matched:
            self._execute_playbook(playbook_name, payload)

    def _select_playbooks(self, corr_type: str, severity: str) -> List[str]:
        order = {"LOW":0,"MEDIUM":1,"HIGH":2,"CRITICAL":3}
        sev_level = order.get(severity, 0)
        matched = []
        for name, pb in PLAYBOOKS.items():
            if corr_type in pb["triggers"]:
                if sev_level >= order.get(pb["min_severity"], 0):
                    matched.append(name)
        return matched

    def _execute_playbook(self, playbook_name: str, correlation: dict):
        pb = PLAYBOOKS[playbook_name]
        execution_id = f"EXEC-{uuid.uuid4().hex[:8].upper()}"
        corr_id = correlation.get("correlation_id","")
        logger.warning(f"▶️  Executing playbook '{pb['name']}' "
                       f"exec={execution_id} for corr={corr_id}")

        commands_issued = []
        approval_steps  = []

        for step in pb["steps"]:
            cmd_id = f"CMD-{uuid.uuid4().hex[:8].upper()}"
            cmd = {
                "command_id":    cmd_id,
                "execution_id":  execution_id,
                "playbook":      playbook_name,
                "step":          step["step"],
                "action":        step["action"],
                "description":   step["description"],
                "target":        correlation.get("details",{}).get(
                                     step.get("target_field",""), "campus"),
                "correlation_id":corr_id,
                "issued_by":     AGENT_ID,
                "issued_at":     datetime.now(timezone.utc).isoformat(),
                "auto":          step.get("auto", True),
                "requires_approval": step.get("requires_approval", False),
            }
            if step.get("requires_approval"):
                approval_steps.append(cmd)
                self._pending_approvals[cmd_id] = cmd
                self._stats["approvals_pending"] += 1
                logger.info(f"  ⏸  Step {step['step']}: {step['action']} — AWAITING APPROVAL")
            else:
                self._producer.publish(Topics.SOAR_COMMANDS, cmd, key=cmd_id)
                commands_issued.append(cmd_id)
                self._stats["commands_issued"] += 1
                logger.info(f"  ✅ Step {step['step']}: {step['action']} → SOAR")

        execution = {
            "execution_id":  execution_id,
            "playbook":      playbook_name,
            "playbook_name": pb["name"],
            "correlation_id":corr_id,
            "started_at":    datetime.now(timezone.utc).isoformat(),
            "status":        "running",
            "commands_issued":    commands_issued,
            "pending_approvals":  [s["command_id"] for s in approval_steps],
            "total_steps":        len(pb["steps"]),
        }
        self._executions.append(execution)
        self._stats["playbooks_executed"] += 1

    def _handle_response(self, payload: dict):
        cmd_id = payload.get("command_id","")
        status = payload.get("status","")
        logger.info(f"📨 SOAR response: cmd={cmd_id} status={status}")
        # Update execution status if needed
        for exc in self._executions:
            if cmd_id in exc.get("commands_issued",[]):
                logger.info(f"  ✅ Command {cmd_id} completed: {status}")

    # ── FastAPI ───────────────────────────────────────────────────────────────
    def _build_app(self) -> FastAPI:
        app = FastAPI(title="Orchestrator Agent")

        @app.get("/health")
        def health():
            return JSONResponse({"agent_id": AGENT_ID, "status": "running",
                                  "timestamp": datetime.now(timezone.utc).isoformat(),
                                  "stats": self._stats})

        @app.get("/playbooks")
        def playbooks():
            return JSONResponse({name: {
                "name": pb["name"], "triggers": pb["triggers"],
                "steps": len(pb["steps"]), "min_severity": pb["min_severity"]}
                for name, pb in PLAYBOOKS.items()})

        @app.get("/executions")
        def executions(limit: int = 20):
            return JSONResponse(self._executions[-limit:])

        @app.get("/pending")
        def pending():
            return JSONResponse(list(self._pending_approvals.values()))

        @app.post("/approve/{cmd_id}")
        def approve(cmd_id: str):
            if cmd_id not in self._pending_approvals:
                from fastapi import HTTPException
                raise HTTPException(404, "Command not found")
            cmd = self._pending_approvals.pop(cmd_id)
            cmd["approved_at"] = datetime.now(timezone.utc).isoformat()
            self._producer.publish(Topics.SOAR_COMMANDS, cmd, key=cmd_id)
            self._stats["commands_issued"] += 1
            self._stats["approvals_pending"] -= 1
            return JSONResponse({"approved": True, "command_id": cmd_id})

        return app

    def start(self):
        threading.Thread(target=self._consumer.poll_loop,
                         args=(self.handle_message,),
                         daemon=True, name="orch-consumer").start()
        logger.info(f"▶️  Orchestrator Agent running — health :{HEALTH_PORT}/health")
        uvicorn.run(self._app, host="0.0.0.0", port=HEALTH_PORT, log_level="warning")

    def stop(self):
        self._consumer.stop()
        self._producer.close()


if __name__ == "__main__":
    a = OrchestratorAgent()
    try:
        a.start()
    except KeyboardInterrupt:
        a.stop()
