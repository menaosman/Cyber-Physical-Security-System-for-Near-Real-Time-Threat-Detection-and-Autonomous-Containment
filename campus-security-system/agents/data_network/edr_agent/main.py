"""
agents/data_network/edr_agent/main.py
Phase 3 Week 6 — Endpoint Detection & Response Agent (EDR)

Detects endpoint-level attacks from process/file/auth event records:
  1. ransomware_behavior   — mass file renames/encrypts in short window (T1486)
  2. privilege_escalation  — process spawned with root/SYSTEM from non-root parent (T1548)
  3. credential_dump       — access to /etc/shadow, LSASS, SAM registry (T1003)
  4. persistence_mechanism — cron/registry/startup modifications (T1053, T1547)
  5. suspicious_process    — known malicious process names / unusual parent-child (T1059)
  6. yara_match            — payload matches embedded YARA-style signature rules (T1027)

Consumes: data.telemetry (endpoint events from EDR sensors / simulator)
Publishes: data.alerts
Health:    GET /health (port 8005)

Standards: NIST SP 800-61 Rev2, MITRE ATT&CK for Enterprise
"""
from __future__ import annotations
import logging, os, re, sys, threading, time, uuid
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Dict, List
from pathlib import Path

import uvicorn
from fastapi import FastAPI
from fastapi.responses import JSONResponse

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
from common.kafka_client import KafkaConsumerClient, KafkaProducerClient, Topics
from common.models import Alert, SeverityLevel

logging.basicConfig(level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s")
logger = logging.getLogger("edr_agent")

AGENT_ID    = os.getenv("AGENT_ID",        "edr-agent-01")
BOOTSTRAP   = os.getenv("KAFKA_BOOTSTRAP", "localhost:9092")
HEALTH_PORT = int(os.getenv("HEALTH_PORT", "8005"))

RANSOMWARE_FILE_THRESHOLD = int(os.getenv("RANSOMWARE_FILE_THRESHOLD", "20"))
RANSOMWARE_WINDOW         = int(os.getenv("RANSOMWARE_WINDOW_SEC",     "30"))

MITRE = {
    "ransomware_behavior":   "T1486",
    "privilege_escalation":  "T1548",
    "credential_dump":       "T1003",
    "persistence_mechanism": "T1053",
    "suspicious_process":    "T1059",
    "yara_match":            "T1027",
}

# ── Signature rules ───────────────────────────────────────────────────────────

# Known credential dump targets
CREDENTIAL_PATHS = {
    "/etc/shadow", "/etc/passwd", "/proc/*/mem",
    "c:\\windows\\system32\\lsass.exe",
    "sam", "security", "system",   # registry hives
    "/var/lib/sss/db", "ntds.dit",
}

# Ransomware-associated file extensions
RANSOM_EXTENSIONS = {
    ".locked", ".encrypted", ".enc", ".crypted", ".crypt",
    ".crypto", ".cerber", ".locky", ".zepto", ".thor",
    ".aaa", ".abc", ".xyz", ".zzz", ".micro",
}

# Suspicious process names
SUSPICIOUS_PROCESSES = {
    "mimikatz", "procdump", "wce", "fgdump", "pwdump",
    "meterpreter", "cobalt", "empire", "netcat", "nc.exe",
    "psexec", "wmic", "cscript", "wscript",
    "powershell -enc", "cmd /c echo",
}

# Persistence indicators
PERSISTENCE_PATHS = {
    "/etc/cron", "/var/spool/cron", "/etc/init.d", "/etc/rc.local",
    "~/.bashrc", "~/.profile", "/etc/profile.d",
    "hkcu\\software\\microsoft\\windows\\currentversion\\run",
    "hklm\\software\\microsoft\\windows\\currentversion\\run",
    "startup",
}

# Inline YARA-style patterns (regex on payload strings)
YARA_RULES: List[Dict] = [
    {"name": "powershell_encoded",
     "pattern": re.compile(r"powershell.*-e(nc|ncodedcommand)\s+[A-Za-z0-9+/=]{20,}", re.I),
     "severity": SeverityLevel.HIGH,  "mitre": "T1059.001"},
    {"name": "base64_shellcode",
     "pattern": re.compile(r"(?:eval|exec|system)\s*\(\s*base64_decode", re.I),
     "severity": SeverityLevel.HIGH,  "mitre": "T1027"},
    {"name": "reverse_shell",
     "pattern": re.compile(r"bash\s+-i\s+>&?\s*/dev/tcp/", re.I),
     "severity": SeverityLevel.CRITICAL, "mitre": "T1059.004"},
    {"name": "wget_curl_pipe",
     "pattern": re.compile(r"(?:wget|curl).*\|\s*(?:bash|sh|python)", re.I),
     "severity": SeverityLevel.HIGH,  "mitre": "T1105"},
    {"name": "shadow_read",
     "pattern": re.compile(r"cat\s+/etc/shadow|/etc/shadow\s*>", re.I),
     "severity": SeverityLevel.CRITICAL, "mitre": "T1003.008"},
]


class EdrAgent:
    def __init__(self):
        logger.info(f"🚀 Starting EDR Agent {AGENT_ID}")
        # File modification tracking per host for ransomware detection
        self._file_mods: Dict[str, deque] = defaultdict(lambda: deque(maxlen=500))
        # Process tree tracking per host
        self._proc_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        # Alert dedup
        self._last_alert: Dict[str, float] = {}

        self._producer = KafkaProducerClient(BOOTSTRAP)
        self._consumer = KafkaConsumerClient(AGENT_ID, ["data.telemetry"], BOOTSTRAP)
        self._recent_alerts: deque = deque(maxlen=200)
        self._stats = {
            "events_processed": 0, "alerts_sent": 0,
            **{k: 0 for k in MITRE}
        }
        self._app = self._build_app()
        logger.info("✅ EDR Agent ready")

    # ── Main handler ──────────────────────────────────────────────────────────
    def handle_event(self, topic: str, payload: dict):
        self._stats["events_processed"] += 1
        event_type = payload.get("event_type", "").lower()
        host_id    = payload.get("host_id", payload.get("src_ip", "unknown"))
        ts         = time.time()

        if event_type == "file_op":
            self._check_ransomware(host_id, payload, ts)
            self._check_credential_dump(host_id, payload, ts)
            self._check_persistence(host_id, payload, ts)

        elif event_type == "process":
            self._check_suspicious_process(host_id, payload, ts)
            self._check_privilege_escalation(host_id, payload, ts)
            self._check_yara(host_id, payload, ts)

        elif event_type == "auth":
            self._check_credential_dump(host_id, payload, ts)

        # Always run YARA on command line strings
        elif event_type in ("command", "script"):
            self._check_yara(host_id, payload, ts)

    # ── Detection 1: Ransomware ───────────────────────────────────────────────
    def _check_ransomware(self, host_id, payload, ts):
        file_path = payload.get("file_path", "").lower()
        op        = payload.get("operation", "").lower()

        is_ransom_ext = any(file_path.endswith(ext) for ext in RANSOM_EXTENSIONS)
        is_bulk_write = op in ("write", "rename", "create", "encrypt")
        if not (is_ransom_ext or is_bulk_write):
            return

        buf = self._file_mods[host_id]
        buf.append({"ts": ts, "path": file_path, "op": op, "ransom": is_ransom_ext})
        cutoff = ts - RANSOMWARE_WINDOW
        recent = [e for e in buf if e["ts"] >= cutoff]
        ransom_files = [e for e in recent if e["ransom"]]
        bulk_count   = len(recent)

        if len(ransom_files) >= 3 or bulk_count >= RANSOMWARE_FILE_THRESHOLD:
            if self._dedup(f"ransomware:{host_id}", ts, cooldown=60):
                sev = SeverityLevel.CRITICAL if ransom_files else SeverityLevel.HIGH
                self._alert(payload, "ransomware_behavior", sev, 0.92,
                    {"host_id": host_id,
                     "ransomware_extension_files": len(ransom_files),
                     "bulk_file_ops": bulk_count, "window_sec": RANSOMWARE_WINDOW,
                     "sample_files": [e["path"] for e in ransom_files[:5]]},
                    ["isolate_host", "kill_suspicious_processes",
                     "take_snapshot", "escalate_to_hq_immediately"])
                self._stats["ransomware_behavior"] += 1

    # ── Detection 2: Privilege escalation ─────────────────────────────────────
    def _check_privilege_escalation(self, host_id, payload, ts):
        username     = payload.get("username", "").lower()
        parent_user  = payload.get("parent_username", "").lower()
        proc_name    = payload.get("process_name", "").lower()

        # Spawned as root/system from non-privileged parent
        is_root = username in ("root", "system", "administrator", "nt authority\\system")
        parent_nonpriv = parent_user not in ("root", "system", "administrator", "")

        if is_root and parent_nonpriv:
            if self._dedup(f"privesc:{host_id}:{proc_name}", ts, cooldown=30):
                self._alert(payload, "privilege_escalation", SeverityLevel.HIGH, 0.90,
                    {"host_id": host_id, "process": proc_name,
                     "elevated_user": username, "parent_user": parent_user},
                    ["kill_process", "revoke_token", "notify_data_local_manager"])
                self._stats["privilege_escalation"] += 1

    # ── Detection 3: Credential dump ──────────────────────────────────────────
    def _check_credential_dump(self, host_id, payload, ts):
        path = payload.get("file_path", payload.get("target", "")).lower()
        proc = payload.get("process_name", "").lower()

        path_hit = any(cred in path for cred in CREDENTIAL_PATHS)
        proc_hit = any(c in proc for c in ("lsass", "procdump", "mimikatz", "wce"))

        if path_hit or proc_hit:
            if self._dedup(f"cred_dump:{host_id}", ts, cooldown=60):
                self._alert(payload, "credential_dump", SeverityLevel.CRITICAL, 0.95,
                    {"host_id": host_id, "target": path or proc,
                     "detail": "Credential store accessed by suspicious process"},
                    ["isolate_host", "rotate_all_credentials",
                     "escalate_to_hq_immediately"])
                self._stats["credential_dump"] += 1

    # ── Detection 4: Persistence mechanism ───────────────────────────────────
    def _check_persistence(self, host_id, payload, ts):
        path = payload.get("file_path", "").lower()
        op   = payload.get("operation", "").lower()
        if op not in ("write", "create", "modify"):
            return
        if any(p in path for p in PERSISTENCE_PATHS):
            if self._dedup(f"persist:{host_id}:{path}", ts, cooldown=120):
                self._alert(payload, "persistence_mechanism", SeverityLevel.MEDIUM, 0.82,
                    {"host_id": host_id, "path": path, "operation": op,
                     "detail": "Startup/persistence path modified"},
                    ["review_file", "check_full_process_tree"])
                self._stats["persistence_mechanism"] += 1

    # ── Detection 5: Suspicious process ──────────────────────────────────────
    def _check_suspicious_process(self, host_id, payload, ts):
        proc_name = payload.get("process_name", "").lower()
        cmd_line  = payload.get("command_line", "").lower()
        full_str  = f"{proc_name} {cmd_line}"

        hit = next((p for p in SUSPICIOUS_PROCESSES if p in full_str), None)
        if hit:
            if self._dedup(f"susp_proc:{host_id}:{hit}", ts, cooldown=60):
                self._alert(payload, "suspicious_process", SeverityLevel.HIGH, 0.88,
                    {"host_id": host_id, "process": proc_name,
                     "command_line": cmd_line[:200], "matched_indicator": hit},
                    ["kill_process", "quarantine_binary", "notify_data_local_manager"])
                self._stats["suspicious_process"] += 1

    # ── Detection 6: YARA-style matching ─────────────────────────────────────
    def _check_yara(self, host_id, payload, ts):
        scan_str = " ".join([
            payload.get("command_line", ""),
            payload.get("script_content", ""),
            payload.get("process_name", ""),
            payload.get("file_content_excerpt", ""),
        ])
        for rule in YARA_RULES:
            if rule["pattern"].search(scan_str):
                key = f"yara:{host_id}:{rule['name']}"
                if self._dedup(key, ts, cooldown=60):
                    self._alert(payload, "yara_match", rule["severity"], 0.91,
                        {"host_id": host_id, "yara_rule": rule["name"],
                         "mitre_technique": rule["mitre"],
                         "matched_string": scan_str[:150]},
                        ["quarantine_process", "notify_data_local_manager"])
                    self._stats["yara_match"] += 1

    # ── Helpers ───────────────────────────────────────────────────────────────
    def _dedup(self, key: str, ts: float, cooldown: float = 30.0) -> bool:
        if ts - self._last_alert.get(key, 0) < cooldown:
            return False
        self._last_alert[key] = ts
        return True

    def _alert(self, raw, attack_type, severity, confidence, details, actions):
        mitre = details.pop("mitre_technique", MITRE.get(attack_type, ""))
        alert = Alert(
            alert_id=str(uuid.uuid4()),
            agent_id=AGENT_ID, agent_type="edr",
            network_type="data_network",
            alert_type=attack_type, severity=severity, confidence=confidence,
            source={"host_id":  raw.get("host_id", raw.get("src_ip","")),
                    "process":  raw.get("process_name",""),
                    "username": raw.get("username",""),
                    "sensor":   raw.get("sensor","edr_endpoint")},
            details={**details, "mitre_technique": mitre},
            recommended_actions=actions,
        )
        d = alert.model_dump(mode="json")
        self._producer.publish(Topics.DATA_ALERTS, d,
                               key=raw.get("host_id", raw.get("src_ip","unknown")))
        self._recent_alerts.append(d)
        self._stats["alerts_sent"] += 1
        logger.warning(f"🚨 EDR [{severity.value}] [{attack_type}] host={raw.get('host_id','')}")

    # ── FastAPI ───────────────────────────────────────────────────────────────
    def _build_app(self) -> FastAPI:
        app = FastAPI(title="EDR Agent")

        @app.get("/health")
        def health():
            return JSONResponse({"agent_id": AGENT_ID, "status": "running",
                                  "timestamp": datetime.now(timezone.utc).isoformat(),
                                  "stats": self._stats})

        @app.get("/alerts")
        def alerts(limit: int = 50):
            return JSONResponse(list(self._recent_alerts)[-limit:])

        return app

    def start(self):
        threading.Thread(target=self._consumer.poll_loop,
                         args=(self.handle_event,),
                         daemon=True, name="edr-consumer").start()
        logger.info(f"▶️  EDR Agent running — health :{HEALTH_PORT}/health")
        uvicorn.run(self._app, host="0.0.0.0", port=HEALTH_PORT, log_level="warning")

    def stop(self):
        self._consumer.stop()
        self._producer.close()


if __name__ == "__main__":
    a = EdrAgent()
    try:
        a.start()
    except KeyboardInterrupt:
        a.stop()
