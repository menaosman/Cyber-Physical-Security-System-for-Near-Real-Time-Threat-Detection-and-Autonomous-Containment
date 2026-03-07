"""
agents/data_network/ndr_agent/main.py
Phase 3 Week 6 — Network Detection & Response Agent (NDR)

Detects network-layer attacks by consuming raw flow/event records
published to Kafka by Zeek/Suricata (or the data_network_simulator).

Detection rules (signature + statistical):
  1. port_scan         — >20 unique dst_ports from same src_ip in 60s (T1046)
  2. brute_force_ssh   — >10 failed SSH connections from same src_ip in 60s (T1110)
  3. brute_force_http  — >15 failed HTTP 401/403 from same src_ip in 60s (T1110)
  4. data_exfiltration — single flow > 50 MB to external IP (T1048)
  5. lateral_movement  — src_ip crosses 3+ internal VLANs in 120s (T1021)
  6. c2_beacon         — periodic small flows to same external IP, >5 in 5 min (T1071)
  7. unauthorized_vlan — traffic between VLANs that should be isolated (T1599)

Consumes: data.telemetry (flow records from Zeek/Suricata/simulator)
Publishes: data.alerts
Health:    GET /health (port 8004)

Standards: NIST SP 800-94, NIST SP 800-61 Rev2
           MITRE ATT&CK T1046, T1048, T1110, T1021, T1071, T1599
"""
from __future__ import annotations
import logging, os, sys, threading, time, uuid
from collections import defaultdict, deque
from datetime import datetime, timezone
from ipaddress import ip_address, ip_network
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
logger = logging.getLogger("ndr_agent")

AGENT_ID    = os.getenv("AGENT_ID",        "ndr-agent-01")
BOOTSTRAP   = os.getenv("KAFKA_BOOTSTRAP", "localhost:9092")
HEALTH_PORT = int(os.getenv("HEALTH_PORT", "8004"))

# Thresholds (all tunable via env vars)
PORT_SCAN_THRESHOLD      = int(os.getenv("PORT_SCAN_THRESHOLD",      "20"))
PORT_SCAN_WINDOW         = int(os.getenv("PORT_SCAN_WINDOW_SEC",     "60"))
BRUTE_SSH_THRESHOLD      = int(os.getenv("BRUTE_SSH_THRESHOLD",      "10"))
BRUTE_HTTP_THRESHOLD     = int(os.getenv("BRUTE_HTTP_THRESHOLD",     "15"))
BRUTE_WINDOW             = int(os.getenv("BRUTE_WINDOW_SEC",         "60"))
EXFIL_THRESHOLD_MB       = float(os.getenv("EXFIL_THRESHOLD_MB",     "50.0"))
LATERAL_VLAN_THRESHOLD   = int(os.getenv("LATERAL_VLAN_THRESHOLD",   "3"))
LATERAL_WINDOW           = int(os.getenv("LATERAL_WINDOW_SEC",      "120"))
C2_BEACON_THRESHOLD      = int(os.getenv("C2_BEACON_THRESHOLD",      "5"))
C2_BEACON_WINDOW         = int(os.getenv("C2_BEACON_WINDOW_SEC",    "300"))

# Campus internal network ranges (VLANs 10-70)
INTERNAL_NETWORKS = [
    ip_network("10.0.10.0/24"),  # VLAN 10 — Academic Data
    ip_network("10.0.11.0/24"),  # VLAN 11
    ip_network("10.0.12.0/24"),  # VLAN 12
    ip_network("10.0.15.0/24"),  # VLAN 15
    ip_network("10.0.20.0/24"),  # VLAN 20 — IoT
    ip_network("10.0.30.0/24"),  # VLAN 30 — Physical Access
    ip_network("10.0.50.0/24"),  # VLAN 50 — DMZ
    ip_network("10.0.60.0/24"),  # VLAN 60 — Internal Servers
    ip_network("10.0.70.0/24"),  # VLAN 70 — Visitors
]

# VLAN isolation rules: these pairs should NEVER communicate
ISOLATED_VLAN_PAIRS = {
    ("10.0.20.0/24", "10.0.60.0/24"),   # IoT → Servers
    ("10.0.70.0/24", "10.0.60.0/24"),   # Visitors → Servers
    ("10.0.20.0/24", "10.0.15.0/24"),   # IoT → HQ Data
    ("10.0.30.0/24", "10.0.60.0/24"),   # Physical Access → Servers
}

MITRE = {
    "port_scan":          "T1046",
    "brute_force_ssh":    "T1110",
    "brute_force_http":   "T1110",
    "data_exfiltration":  "T1048",
    "lateral_movement":   "T1021",
    "c2_beacon":          "T1071",
    "unauthorized_vlan":  "T1599",
}


def _is_internal(ip_str: str) -> bool:
    try:
        ip = ip_address(ip_str)
        return any(ip in net for net in INTERNAL_NETWORKS)
    except ValueError:
        return False


def _vlan_subnet(ip_str: str) -> Optional[str]:
    try:
        ip = ip_address(ip_str)
        for net in INTERNAL_NETWORKS:
            if ip in net:
                return str(net)
    except ValueError:
        pass
    return None


class NdrAgent:
    def __init__(self):
        logger.info(f"🚀 Starting NDR Agent {AGENT_ID}")

        # State per src_ip — sliding window buffers
        self._port_scans:   Dict[str, deque] = defaultdict(lambda: deque(maxlen=500))
        self._ssh_fails:    Dict[str, deque] = defaultdict(lambda: deque(maxlen=200))
        self._http_fails:   Dict[str, deque] = defaultdict(lambda: deque(maxlen=200))
        self._vlan_hops:    Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        self._c2_beacons:   Dict[str, deque] = defaultdict(lambda: deque(maxlen=50))

        # Alert dedup: don't fire same alert type for same src more than once/30s
        self._last_alert:   Dict[str, float] = {}

        self._producer  = KafkaProducerClient(BOOTSTRAP)
        self._consumer  = KafkaConsumerClient(
            AGENT_ID, ["data.telemetry"], BOOTSTRAP)
        self._recent_alerts: deque = deque(maxlen=200)
        self._stats = {
            "flows_processed": 0, "alerts_sent": 0,
            **{k: 0 for k in MITRE}
        }
        self._app = self._build_app()
        logger.info("✅ NDR Agent ready")

    # ── Main handler ──────────────────────────────────────────────────────────
    def handle_flow(self, topic: str, payload: dict):
        self._stats["flows_processed"] += 1
        src_ip   = payload.get("src_ip", "")
        dst_ip   = payload.get("dst_ip", "")
        dst_port = int(payload.get("dst_port", 0))
        proto    = payload.get("proto", "").lower()
        status   = payload.get("status", "")
        bytes_out= float(payload.get("bytes_out", 0))
        ts       = time.time()

        self._check_port_scan(src_ip, dst_ip, dst_port, ts, payload)
        self._check_brute_force(src_ip, dst_port, proto, status, ts, payload)
        self._check_exfiltration(src_ip, dst_ip, bytes_out, ts, payload)
        self._check_lateral_movement(src_ip, dst_ip, ts, payload)
        self._check_c2_beacon(src_ip, dst_ip, bytes_out, ts, payload)
        self._check_unauthorized_vlan(src_ip, dst_ip, ts, payload)

    # ── Detection 1: Port scan ────────────────────────────────────────────────
    def _check_port_scan(self, src_ip, dst_ip, dst_port, ts, payload):
        if not src_ip or not dst_port:
            return
        buf = self._port_scans[src_ip]
        buf.append({"ts": ts, "dst_port": dst_port, "dst_ip": dst_ip})
        cutoff = ts - PORT_SCAN_WINDOW
        recent = [e for e in buf if e["ts"] >= cutoff]
        unique_ports = len({e["dst_port"] for e in recent})
        if unique_ports >= PORT_SCAN_THRESHOLD:
            if self._dedup(f"port_scan:{src_ip}", ts, cooldown=30):
                self._alert(payload, "port_scan", SeverityLevel.HIGH, 0.93,
                    {"src_ip": src_ip, "unique_ports_scanned": unique_ports,
                     "window_sec": PORT_SCAN_WINDOW, "threshold": PORT_SCAN_THRESHOLD,
                     "sample_ports": sorted({e["dst_port"] for e in recent})[:10]},
                    ["block_src_ip", "notify_data_local_manager"])
                self._stats["port_scan"] += 1

    # ── Detection 2: Brute force SSH / HTTP ───────────────────────────────────
    def _check_brute_force(self, src_ip, dst_port, proto, status, ts, payload):
        if not src_ip:
            return
        cutoff = ts - BRUTE_WINDOW
        # SSH: port 22, connection refused/reset
        if dst_port == 22 and status in ("reset", "refused", "failed", "S0", "REJ"):
            buf = self._ssh_fails[src_ip]
            buf.append({"ts": ts})
            count = sum(1 for e in buf if e["ts"] >= cutoff)
            if count >= BRUTE_SSH_THRESHOLD:
                if self._dedup(f"brute_ssh:{src_ip}", ts, cooldown=30):
                    self._alert(payload, "brute_force_ssh", SeverityLevel.HIGH, 0.95,
                        {"src_ip": src_ip, "failed_attempts": count,
                         "window_sec": BRUTE_WINDOW, "service": "SSH"},
                        ["block_src_ip", "rotate_ssh_keys", "notify_data_local_manager"])
                    self._stats["brute_force_ssh"] += 1
        # HTTP: port 80/443, status 401/403
        if dst_port in (80, 443, 8080, 8443) and str(status) in ("401","403"):
            buf = self._http_fails[src_ip]
            buf.append({"ts": ts})
            count = sum(1 for e in buf if e["ts"] >= cutoff)
            if count >= BRUTE_HTTP_THRESHOLD:
                if self._dedup(f"brute_http:{src_ip}", ts, cooldown=30):
                    self._alert(payload, "brute_force_http", SeverityLevel.HIGH, 0.92,
                        {"src_ip": src_ip, "failed_attempts": count,
                         "window_sec": BRUTE_WINDOW, "service": "HTTP"},
                        ["block_src_ip", "enable_rate_limiting"])
                    self._stats["brute_force_http"] += 1

    # ── Detection 3: Data exfiltration ────────────────────────────────────────
    def _check_exfiltration(self, src_ip, dst_ip, bytes_out, ts, payload):
        if not src_ip or not dst_ip:
            return
        mb_out = bytes_out / (1024 * 1024)
        # Only flag internal→external large transfers
        if mb_out >= EXFIL_THRESHOLD_MB and _is_internal(src_ip) and not _is_internal(dst_ip):
            if self._dedup(f"exfil:{src_ip}:{dst_ip}", ts, cooldown=60):
                self._alert(payload, "data_exfiltration", SeverityLevel.CRITICAL, 0.88,
                    {"src_ip": src_ip, "dst_ip": dst_ip,
                     "bytes_out": int(bytes_out), "mb_out": round(mb_out, 2),
                     "threshold_mb": EXFIL_THRESHOLD_MB,
                     "direction": "internal_to_external"},
                    ["block_connection", "capture_full_packet",
                     "escalate_to_hq_immediately", "notify_data_local_manager"])
                self._stats["data_exfiltration"] += 1

    # ── Detection 4: Lateral movement ─────────────────────────────────────────
    def _check_lateral_movement(self, src_ip, dst_ip, ts, payload):
        if not src_ip or not dst_ip:
            return
        if not _is_internal(src_ip) or not _is_internal(dst_ip):
            return
        dst_vlan = _vlan_subnet(dst_ip)
        if not dst_vlan:
            return
        buf = self._vlan_hops[src_ip]
        buf.append({"ts": ts, "dst_vlan": dst_vlan})
        cutoff = ts - LATERAL_WINDOW
        recent_vlans = {e["dst_vlan"] for e in buf if e["ts"] >= cutoff}
        if len(recent_vlans) >= LATERAL_VLAN_THRESHOLD:
            if self._dedup(f"lateral:{src_ip}", ts, cooldown=60):
                self._alert(payload, "lateral_movement", SeverityLevel.HIGH, 0.85,
                    {"src_ip": src_ip, "vlans_accessed": list(recent_vlans),
                     "vlan_count": len(recent_vlans), "window_sec": LATERAL_WINDOW},
                    ["isolate_host", "notify_data_local_manager", "escalate_to_hq"])
                self._stats["lateral_movement"] += 1

    # ── Detection 5: C2 beaconing ─────────────────────────────────────────────
    def _check_c2_beacon(self, src_ip, dst_ip, bytes_out, ts, payload):
        if not src_ip or not dst_ip:
            return
        # Small flows (<10KB) from internal to external at regular intervals
        if not _is_internal(src_ip) or _is_internal(dst_ip):
            return
        if bytes_out > 10240:  # ignore large flows
            return
        key = f"{src_ip}→{dst_ip}"
        buf = self._c2_beacons[key]
        buf.append({"ts": ts})
        cutoff = ts - C2_BEACON_WINDOW
        count = sum(1 for e in buf if e["ts"] >= cutoff)
        if count >= C2_BEACON_THRESHOLD:
            if self._dedup(f"c2:{key}", ts, cooldown=120):
                self._alert(payload, "c2_beacon", SeverityLevel.HIGH, 0.80,
                    {"src_ip": src_ip, "dst_ip": dst_ip,
                     "beacon_count": count, "window_sec": C2_BEACON_WINDOW,
                     "avg_bytes": round(bytes_out, 0)},
                    ["block_dst_ip", "capture_full_packet", "notify_data_local_manager"])
                self._stats["c2_beacon"] += 1

    # ── Detection 6: Unauthorized VLAN crossing ───────────────────────────────
    def _check_unauthorized_vlan(self, src_ip, dst_ip, ts, payload):
        src_vlan = _vlan_subnet(src_ip)
        dst_vlan = _vlan_subnet(dst_ip)
        if not src_vlan or not dst_vlan or src_vlan == dst_vlan:
            return
        pair = (src_vlan, dst_vlan)
        if pair in ISOLATED_VLAN_PAIRS or (pair[1], pair[0]) in ISOLATED_VLAN_PAIRS:
            if self._dedup(f"vlan:{src_ip}:{dst_ip}", ts, cooldown=60):
                self._alert(payload, "unauthorized_vlan", SeverityLevel.HIGH, 0.97,
                    {"src_ip": src_ip, "src_vlan": src_vlan,
                     "dst_ip": dst_ip, "dst_vlan": dst_vlan,
                     "rule": "isolated_vlan_pair_violation"},
                    ["block_traffic", "log_full_flow", "notify_data_local_manager"])
                self._stats["unauthorized_vlan"] += 1

    # ── Helpers ───────────────────────────────────────────────────────────────
    def _dedup(self, key: str, ts: float, cooldown: float = 30.0) -> bool:
        if ts - self._last_alert.get(key, 0) < cooldown:
            return False
        self._last_alert[key] = ts
        return True

    def _alert(self, raw, attack_type, severity, confidence, details, actions):
        alert = Alert(
            alert_id=str(uuid.uuid4()),
            agent_id=AGENT_ID, agent_type="ndr",
            network_type="data_network",
            alert_type=attack_type, severity=severity, confidence=confidence,
            source={"src_ip":  raw.get("src_ip",""),
                    "dst_ip":  raw.get("dst_ip",""),
                    "dst_port":raw.get("dst_port",""),
                    "proto":   raw.get("proto",""),
                    "sensor":  raw.get("sensor","zeek")},
            details={**details, "mitre_technique": MITRE.get(attack_type,"")},
            recommended_actions=actions,
        )
        d = alert.model_dump(mode="json")
        self._producer.publish(Topics.DATA_ALERTS, d, key=raw.get("src_ip","unknown"))
        self._recent_alerts.append(d)
        self._stats["alerts_sent"] += 1
        logger.warning(f"🚨 NDR [{severity.value}] [{attack_type}] "
                       f"src={raw.get('src_ip','')} dst={raw.get('dst_ip','')}")

    # ── FastAPI ───────────────────────────────────────────────────────────────
    def _build_app(self) -> FastAPI:
        app = FastAPI(title="NDR Agent")

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
                         args=(self.handle_flow,),
                         daemon=True, name="ndr-consumer").start()
        logger.info(f"▶️  NDR Agent running — health :{HEALTH_PORT}/health")
        uvicorn.run(self._app, host="0.0.0.0", port=HEALTH_PORT, log_level="warning")

    def stop(self):
        self._consumer.stop()
        self._producer.close()


if __name__ == "__main__":
    a = NdrAgent()
    try:
        a.start()
    except KeyboardInterrupt:
        a.stop()
