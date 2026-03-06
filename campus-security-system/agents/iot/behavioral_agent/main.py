"""
agents/iot/behavioral_agent/main.py
Phase 1 Week 2 — Two-layer IoT anomaly detection.

Layer 1 — Statistical (immediate):
  • Static threshold breach  (temp ≥ 40°C, gas ≥ 400 ppm)
  • Z-score > 3σ from rolling baseline

Layer 2 — ML (subtle drift):
  • Isolation Forest on rolling z-score features
  • Trains after MIN_TRAIN_SAMPLES baseline readings

Consumes: iot.telemetry
Publishes: iot.alerts
Health:    GET /health  (port 8001)

Standards: NIST SP 800-82, NIST SP 800-61, MITRE ATT&CK for ICS
"""
from __future__ import annotations

import logging
import os
import sys
import threading
import time
import uuid
from collections import deque
from datetime import datetime, timezone
from typing import Dict, Optional, Tuple
from pathlib import Path

import numpy as np
import uvicorn
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from sklearn.ensemble import IsolationForest

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
from common.kafka_client import KafkaConsumerClient, KafkaProducerClient, Topics
from common.models import Alert, SeverityLevel

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger("behavioral_agent")

AGENT_ID          = os.getenv("AGENT_ID",                "behavioral-agent-01")
BOOTSTRAP         = os.getenv("KAFKA_BOOTSTRAP",          "localhost:9092")
HEALTH_PORT       = int(os.getenv("HEALTH_PORT",          "8001"))
IF_CONTAMINATION  = float(os.getenv("IF_CONTAMINATION",  "0.05"))
IF_N_ESTIMATORS   = int(os.getenv("IF_N_ESTIMATORS",     "100"))
MIN_TRAIN_SAMPLES = int(os.getenv("MIN_TRAIN_SAMPLES",   "50"))
ZSCORE_THRESHOLD  = float(os.getenv("ZSCORE_THRESHOLD",  "3.0"))
IF_SCORE_THRESHOLD= float(os.getenv("IF_SCORE_THRESHOLD","-0.05"))
WINDOW_SIZE       = 50

# MITRE ATT&CK for ICS
MITRE = {"temperature": "T0830", "gas": "T0830", "motion": "T0829"}

# Static safety thresholds per sensor type (Layer 1a)
# These catch obvious physical breaches immediately, before ML training
STATIC_THRESHOLDS = {
    "temperature": {"high": 40.0,  "low":  -5.0},   # °C
    "gas":         {"high": 400.0},                   # ppm
    "motion":      {},
}


class SensorWindow:
    """Rolling statistics window — baseline is frozen after training."""

    def __init__(self, maxlen: int = WINDOW_SIZE):
        self._buf: deque = deque(maxlen=maxlen)
        self._baseline_mean: Optional[float] = None
        self._baseline_std:  Optional[float] = None

    def push(self, value: float):
        self._buf.append(value)

    def freeze_baseline(self):
        """Call once after training to lock in the normal baseline stats."""
        arr = np.array(list(self._buf))
        self._baseline_mean = float(arr.mean())
        self._baseline_std  = float(arr.std()) if arr.std() > 1e-9 else 1e-6
        logger.info(f"  Baseline frozen: mean={self._baseline_mean:.3f} "
                    f"std={self._baseline_std:.4f}")

    def zscore(self, value: float) -> float:
        """Z-score vs frozen baseline. Large = anomalous."""
        if self._baseline_mean is None:
            return 0.0
        return (value - self._baseline_mean) / self._baseline_std

    def ready(self, n: int = 20) -> bool:
        return len(self._buf) >= n

    def stats(self) -> dict:
        if not self._buf:
            return {"mean": 0.0, "std": 0.0, "max": 0.0, "min": 0.0, "last": 0.0}
        a = np.array(list(self._buf))
        return {"mean": float(a.mean()), "std": float(a.std()),
                "max": float(a.max()),  "min": float(a.min()), "last": float(a[-1])}


class BehavioralAgent:
    """
    Two-layer IoT behavioral analysis agent.

    Layer 1 (statistical) — fires immediately on obvious anomalies.
    Layer 2 (ML) — Isolation Forest on z-score features for subtle drift.
    Both layers publish to iot.alerts with full evidence payload.
    """

    def __init__(self):
        logger.info(f"🚀 Starting Behavioral Agent {AGENT_ID}")

        self._windows: Dict[str, SensorWindow] = {
            k: SensorWindow() for k in ["temperature", "gas", "motion"]
        }
        # Isolation Forest (Layer 2)
        self._models:    Dict[str, Optional[IsolationForest]] = {k: None for k in self._windows}
        self._train_buf: Dict[str, list] = {k: [] for k in self._windows}
        self._trained:   Dict[str, bool]  = {k: False for k in self._windows}

        self._producer = KafkaProducerClient(BOOTSTRAP)
        self._consumer = KafkaConsumerClient(
            AGENT_ID, [Topics.IOT_TELEMETRY, Topics.IOT_ALERTS], BOOTSTRAP
        )
        self._stats = {"processed": 0, "l1_anomalies": 0, "l2_anomalies": 0, "trained": 0}
        self._app = self._build_app()
        logger.info("✅ Behavioral Agent ready")

    # ── Layer 1: Statistical detection ───────────────────────────────────────

    def _layer1_check(self, stype: str, value: float) -> Tuple[bool, str, float]:
        """
        Two sub-checks:
          1a. Static threshold breach (immediate, no warmup needed)
          1b. Z-score > ZSCORE_THRESHOLD vs frozen baseline (needs warmup)
        Returns (is_anomaly, reason, confidence)
        """
        # 1a — Static threshold
        st = STATIC_THRESHOLDS.get(stype, {})
        if "high" in st and value >= st["high"]:
            return True, f"static_high_threshold({value:.1f}>={st['high']})", 0.98
        if "low" in st and value <= st["low"]:
            return True, f"static_low_threshold({value:.1f}<={st['low']})", 0.98

        # 1b — Z-score (only once baseline is frozen)
        win = self._windows[stype]
        if win._baseline_mean is not None:
            z = abs(win.zscore(value))
            if z > ZSCORE_THRESHOLD:
                conf = min(0.97, 0.75 + z * 0.01)
                return True, f"zscore_anomaly(z={z:.1f}>{ZSCORE_THRESHOLD})", conf

        return False, "normal", 0.0

    # ── Layer 2: Isolation Forest ─────────────────────────────────────────────

    def _make_feature(self, stype: str, value: float) -> Optional[np.ndarray]:
        """Feature = [z_score, abs_z, raw_value] using frozen baseline."""
        win = self._windows[stype]
        if win._baseline_mean is None:
            return None
        z = win.zscore(value)
        return np.array([[z, abs(z), value]])

    def _train(self, stype: str):
        data = self._train_buf[stype]
        if len(data) < MIN_TRAIN_SAMPLES:
            return
        X = np.array(data[-MIN_TRAIN_SAMPLES:])
        m = IsolationForest(
            n_estimators=IF_N_ESTIMATORS,
            contamination=IF_CONTAMINATION,
            random_state=42, n_jobs=-1,
        )
        m.fit(X)
        self._models[stype]  = m
        self._trained[stype] = True
        self._stats["trained"] += 1
        logger.info(f"🧠 IF trained [{stype}] on {len(data)} samples")

    def _layer2_check(self, stype: str, value: float) -> Tuple[bool, float]:
        """Returns (is_anomaly, score). Only runs if model is trained."""
        fv = self._make_feature(stype, value)
        m  = self._models.get(stype)
        if fv is None or m is None:
            return False, 0.0
        score = float(m.decision_function(fv)[0])
        return score <= IF_SCORE_THRESHOLD, score

    # ── Main message handler ──────────────────────────────────────────────────

    def handle_message(self, topic: str, payload: dict):
        self._stats["processed"] += 1
        stype = payload.get("device_type", "").lower()
        if stype not in self._windows:
            return
        try:
            value = float(payload.get("value", 0.0))
            did   = payload.get("device_id", "unknown")
        except (TypeError, ValueError):
            return

        win = self._windows[stype]

        # ── Layer 1: check BEFORE pushing (catches first spike immediately) ──
        l1_anomaly, l1_reason, l1_conf = self._layer1_check(stype, value)
        if l1_anomaly:
            self._stats["l1_anomalies"] += 1
            self._publish(payload, stype, value, l1_reason, l1_conf, "layer1_statistical", did)
            # Still push to window for baseline tracking (spikes are real data)
            win.push(value)
            return

        # Push normal reading into window
        win.push(value)

        # ── Accumulate training data until MIN_TRAIN_SAMPLES ─────────────────
        if not self._trained[stype]:
            fv = self._make_feature(stype, value)
            # Before baseline is frozen, use raw value as single feature
            if win._baseline_mean is None:
                if win.ready(MIN_TRAIN_SAMPLES):
                    win.freeze_baseline()
                    # Rebuild training features with frozen baseline
                    for v in list(win._buf):
                        z = win.zscore(v)
                        self._train_buf[stype].append([z, abs(z), v])
                    self._train(stype)
            elif fv is not None:
                self._train_buf[stype].append(fv[0].tolist())
                if len(self._train_buf[stype]) >= MIN_TRAIN_SAMPLES:
                    self._train(stype)
            return

        # ── Layer 2: Isolation Forest on z-score features ────────────────────
        l2_anomaly, l2_score = self._layer2_check(stype, value)
        if l2_anomaly:
            self._stats["l2_anomalies"] += 1
            conf = min(0.90, 0.65 + abs(l2_score) * 2)
            self._publish(payload, stype, value,
                          f"if_anomaly(score={l2_score:.4f})", conf,
                          "layer2_isolation_forest", did)
        else:
            logger.debug(f"✅ NORMAL [{stype}] val={value}")

    def _publish(self, raw, stype, value, reason, confidence, method, did):
        """Build and publish an anomaly alert to iot.alerts."""
        if confidence >= 0.95:
            sev = SeverityLevel.CRITICAL
        elif confidence >= 0.88:
            sev = SeverityLevel.HIGH
        else:
            sev = SeverityLevel.MEDIUM

        alert = Alert(
            alert_id=str(uuid.uuid4()),
            agent_id=AGENT_ID,
            agent_type="behavioral_analysis",
            network_type="iot",
            alert_type=f"{stype}_behavioral_anomaly",
            severity=sev,
            confidence=round(confidence, 4),
            source={
                "device_id":   did,
                "zone":        raw.get("zone", ""),
                "gateway_id":  raw.get("gateway_id", ""),
                "sensor_type": stype,
            },
            details={
                "current_value":     value,
                "unit":              raw.get("unit", ""),
                "detection_method":  method,
                "detection_reason":  reason,
                "zscore_threshold":  ZSCORE_THRESHOLD,
                "static_thresholds": STATIC_THRESHOLDS.get(stype, {}),
                "mitre_technique":   MITRE.get(stype, "T0000"),
            },
            recommended_actions=[
                "notify_local_iot_manager",
                "cross_reference_physical_access_events",
            ],
        )
        self._producer.publish(Topics.IOT_ALERTS, alert.model_dump(mode="json"), key=did)
        logger.warning(
            f"🚨 [{sev.value}] [{stype}] val={value} method={method} "
            f"reason={reason} conf={confidence:.2f}"
        )

    # ── FastAPI health endpoint ───────────────────────────────────────────────

    def _build_app(self) -> FastAPI:
        app = FastAPI(title="Behavioral Agent")

        @app.get("/health")
        def health():
            return JSONResponse({
                "agent_id":    AGENT_ID,
                "status":      "running",
                "timestamp":   datetime.now(timezone.utc).isoformat(),
                "stats":       self._stats,
                "models_ready": self._trained,
                "baselines":   {k: {"mean": w._baseline_mean, "std": w._baseline_std}
                                for k, w in self._windows.items()},
            })
        return app

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def start(self):
        threading.Thread(
            target=self._consumer.poll_loop,
            args=(self.handle_message,),
            daemon=True, name="behavioral-consumer",
        ).start()
        logger.info(f"▶️  Behavioral Agent — health :{HEALTH_PORT}/health")
        uvicorn.run(self._app, host="0.0.0.0", port=HEALTH_PORT, log_level="warning")

    def stop(self):
        self._consumer.stop()
        self._producer.close()


if __name__ == "__main__":
    a = BehavioralAgent()
    try:
        a.start()
    except KeyboardInterrupt:
        a.stop()
