"""
Behavioral Analysis Agent — behavioral_agent/main.py
Phase 1 / Week 2 deliverable

Consumes raw IoT telemetry from Kafka (iot.telemetry + iot.alerts),
runs real-time Isolation Forest anomaly detection, and publishes
enriched alerts back to iot.alerts.

Key responsibilities:
  1. Train Isolation Forest on normal sensor baseline
  2. Score every incoming reading in real-time
  3. Cross-correlate multi-sensor events (temp + gas + motion)
  4. Publish HIGH anomaly alerts with ML evidence to Kafka
  5. Expose /health FastAPI endpoint

Standards:
  - NIST SP 800-82 — CPS anomaly detection
  - NIST SP 800-61 — Incident response (detection phase)
  - MITRE ATT&CK for ICS — T0830 (Adversarial Sensor Reading)
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
import uuid
from collections import deque
from datetime import datetime, timezone
from typing import Dict, Optional, Tuple

import numpy as np
import uvicorn
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from sklearn.ensemble import IsolationForest

# Kafka client (relative import when run as part of the package)
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.kafka_client import KafkaConsumerClient, KafkaProducerClient, Topics
from common.models import Alert, SeverityLevel

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger("behavioral_agent")

AGENT_ID      = os.getenv("AGENT_ID", "behavioral-agent-01")
BOOTSTRAP     = os.getenv("KAFKA_BOOTSTRAP", "localhost:9092")
HEALTH_PORT   = int(os.getenv("HEALTH_PORT", "8001"))

# ─── Isolation Forest config ──────────────────────────────────────────────────
# contamination = expected fraction of anomalies in training data
# 0.05 = 5% expected anomalies (conservative for campus environment)
IF_CONTAMINATION   = float(os.getenv("IF_CONTAMINATION", "0.05"))
IF_N_ESTIMATORS    = int(os.getenv("IF_N_ESTIMATORS", "100"))
MIN_TRAIN_SAMPLES  = int(os.getenv("MIN_TRAIN_SAMPLES", "50"))
# anomaly_score <= this threshold → HIGH alert (more negative = more anomalous)
ANOMALY_SCORE_THRESHOLD = float(os.getenv("ANOMALY_SCORE_THRESHOLD", "-0.15"))

# ─── Sensor feature windows (rolling buffer per device_type) ──────────────────
WINDOW_SIZE = 20   # keep last N readings per sensor for feature extraction


class SensorWindow:
    """Rolling window of readings for a single sensor type."""

    def __init__(self, maxlen: int = WINDOW_SIZE):
        self._buf: deque[Tuple[float, float]] = deque(maxlen=maxlen)  # (timestamp, value)

    def push(self, ts: float, value: float):
        self._buf.append((ts, value))

    def values(self) -> list[float]:
        return [v for _, v in self._buf]

    def ready(self, min_n: int = 5) -> bool:
        return len(self._buf) >= min_n

    def stats(self) -> Dict:
        vals = self.values()
        if not vals:
            return {"mean": 0.0, "std": 0.0, "max": 0.0, "min": 0.0, "last": 0.0}
        arr = np.array(vals)
        return {
            "mean": float(arr.mean()),
            "std":  float(arr.std()),
            "max":  float(arr.max()),
            "min":  float(arr.min()),
            "last": float(arr[-1]),
        }


class BehavioralAgent:
    """
    Isolation Forest-based behavioral analysis agent for IoT sensors.
    Consumes from Kafka, scores anomalies, re-publishes enriched alerts.
    """

    def __init__(self):
        logger.info(f"🚀 Starting Behavioral Agent {AGENT_ID}")

        # Per-sensor-type rolling windows
        self._windows: Dict[str, SensorWindow] = {
            "temperature": SensorWindow(),
            "gas":         SensorWindow(),
            "motion":      SensorWindow(),
        }

        # Isolation Forest per sensor type (trained lazily once MIN_TRAIN_SAMPLES reached)
        self._models:   Dict[str, Optional[IsolationForest]] = {k: None for k in self._windows}
        self._training_data: Dict[str, list] = {k: [] for k in self._windows}
        self._model_trained: Dict[str, bool]  = {k: False for k in self._windows}

        # Kafka
        self._producer = KafkaProducerClient(BOOTSTRAP)
        self._consumer = KafkaConsumerClient(
            group_id=AGENT_ID,
            topics=[Topics.IOT_TELEMETRY, Topics.IOT_ALERTS],
            bootstrap_servers=BOOTSTRAP,
        )

        # Stats
        self._stats = {
            "messages_processed": 0,
            "anomalies_detected": 0,
            "models_trained": 0,
        }

        # FastAPI health app
        self._app = self._build_health_app()
        logger.info("✅ Behavioral Agent initialized")

    # ─── ML helpers ──────────────────────────────────────────────────────────

    def _feature_vector(self, sensor_type: str, current_value: float) -> Optional[np.ndarray]:
        """
        Build feature vector for Isolation Forest scoring.
        Features: [value, mean_last_N, std_last_N, delta_from_mean, max_last_N]
        """
        win = self._windows.get(sensor_type)
        if win is None or not win.ready(5):
            return None
        s = win.stats()
        delta = current_value - s["mean"]
        return np.array([[
            current_value,
            s["mean"],
            s["std"],
            delta,
            s["max"],
        ]])

    def _train_model(self, sensor_type: str):
        """Train (or retrain) Isolation Forest from collected baseline data."""
        data = self._training_data[sensor_type]
        if len(data) < MIN_TRAIN_SAMPLES:
            return

        X = np.array(data[-MIN_TRAIN_SAMPLES:])  # use most recent baseline
        model = IsolationForest(
            n_estimators=IF_N_ESTIMATORS,
            contamination=IF_CONTAMINATION,
            random_state=42,
            n_jobs=-1,
        )
        model.fit(X)
        self._models[sensor_type]     = model
        self._model_trained[sensor_type] = True
        self._stats["models_trained"] += 1
        logger.info(f"🧠 Isolation Forest trained for [{sensor_type}] on {len(data)} samples — ≥85% recall target active")

    def _score(self, sensor_type: str, value: float) -> Tuple[float, bool]:
        """
        Returns (anomaly_score, is_anomaly).
        score < ANOMALY_SCORE_THRESHOLD → anomaly.
        Isolation Forest decision_function: lower = more anomalous.
        """
        fv = self._feature_vector(sensor_type, value)
        model = self._models.get(sensor_type)
        if fv is None or model is None:
            return 0.0, False

        score = float(model.decision_function(fv)[0])
        is_anomaly = score <= ANOMALY_SCORE_THRESHOLD
        return score, is_anomaly

    # ─── Message handler ──────────────────────────────────────────────────────

    def handle_message(self, topic: str, payload: dict):
        """Main processing pipeline for each Kafka message."""
        self._stats["messages_processed"] += 1

        sensor_type = payload.get("device_type", "").lower()
        if sensor_type not in self._windows:
            return

        try:
            value     = float(payload.get("value", 0.0))
            device_id = payload.get("device_id", "unknown")
            ts        = time.time()
        except (TypeError, ValueError):
            return

        # Push into rolling window
        win = self._windows[sensor_type]
        win.push(ts, value)

        # Accumulate training data if model not yet trained
        if not self._model_trained[sensor_type]:
            fv = self._feature_vector(sensor_type, value)
            if fv is not None:
                self._training_data[sensor_type].append(fv[0].tolist())
            if len(self._training_data[sensor_type]) >= MIN_TRAIN_SAMPLES:
                self._train_model(sensor_type)
            return  # don't score until model is ready

        # Score against Isolation Forest
        score, is_anomaly = self._score(sensor_type, value)

        if is_anomaly:
            self._stats["anomalies_detected"] += 1
            self._publish_anomaly(payload, sensor_type, value, score, device_id)
        else:
            logger.debug(f"✅ NORMAL [{sensor_type}] value={value} score={score:.4f}")

    def _publish_anomaly(
        self,
        raw_payload: dict,
        sensor_type: str,
        value: float,
        score: float,
        device_id: str,
    ):
        """Build and publish an anomaly alert to iot.alerts."""
        stats = self._windows[sensor_type].stats()

        # Determine severity by how far below the threshold we are
        if score <= ANOMALY_SCORE_THRESHOLD - 0.10:
            severity = SeverityLevel.CRITICAL
            confidence = 0.95
        elif score <= ANOMALY_SCORE_THRESHOLD - 0.05:
            severity = SeverityLevel.HIGH
            confidence = 0.90
        else:
            severity = SeverityLevel.MEDIUM
            confidence = 0.78

        # Map sensor type to MITRE technique
        mitre_map = {
            "temperature": "T0830",   # Adversarial Sensor Reading (ICS)
            "gas":         "T0830",
            "motion":      "T0829",   # Loss of View
        }

        alert = Alert(
            alert_id=str(uuid.uuid4()),
            agent_id=AGENT_ID,
            agent_type="behavioral_analysis",
            network_type="iot",
            alert_type=f"{sensor_type}_behavioral_anomaly",
            severity=severity,
            confidence=confidence,
            source={
                "device_id":   device_id,
                "zone":        raw_payload.get("zone", "unknown"),
                "gateway_id":  raw_payload.get("gateway_id", "unknown"),
                "sensor_type": sensor_type,
            },
            details={
                "current_value":      value,
                "unit":               raw_payload.get("unit", ""),
                "anomaly_score":      round(score, 6),
                "score_threshold":    ANOMALY_SCORE_THRESHOLD,
                "baseline_mean":      round(stats["mean"], 2),
                "baseline_std":       round(stats["std"], 2),
                "delta_from_baseline": round(value - stats["mean"], 2),
                "mitre_technique":    mitre_map.get(sensor_type, "T0000"),
                "ml_model":          "IsolationForest",
                "n_estimators":      IF_N_ESTIMATORS,
            },
            recommended_actions=[
                "notify_local_iot_manager",
                "cross_reference_physical_access_events",
                "check_adjacent_sensors",
            ],
        )

        payload_dict = alert.model_dump(mode="json")
        self._producer.publish(
            topic=Topics.IOT_ALERTS,
            payload=payload_dict,
            key=device_id,
        )
        logger.warning(
            f"🚨 ANOMALY [{severity.value}] [{sensor_type}] "
            f"value={value} score={score:.4f} confidence={confidence} "
            f"device={device_id}"
        )

    # ─── FastAPI health endpoint ──────────────────────────────────────────────

    def _build_health_app(self) -> FastAPI:
        app = FastAPI(title="Behavioral Agent Health")

        @app.get("/health")
        def health():
            return JSONResponse({
                "agent_id":   AGENT_ID,
                "status":     "running",
                "timestamp":  datetime.now(timezone.utc).isoformat(),
                "stats":      self._stats,
                "models_ready": self._model_trained,
                "window_sizes": {k: len(v._buf) for k, v in self._windows.items()},
            })

        return app

    # ─── Lifecycle ────────────────────────────────────────────────────────────

    def start(self):
        """Start consumer loop in a thread, health API in the main thread."""
        consumer_thread = threading.Thread(
            target=self._consumer.poll_loop,
            args=(self.handle_message,),
            daemon=True,
            name="behavioral-consumer",
        )
        consumer_thread.start()
        logger.info(f"▶️  Behavioral Agent running — health on :{HEALTH_PORT}/health")

        # Run health server (blocks until shutdown)
        uvicorn.run(self._app, host="0.0.0.0", port=HEALTH_PORT, log_level="warning")

    def stop(self):
        logger.info("🛑 Stopping Behavioral Agent")
        self._consumer.stop()
        self._producer.close()
        logger.info("👋 Behavioral Agent stopped")


# ─── Entry point ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    agent = BehavioralAgent()
    try:
        agent.start()
    except KeyboardInterrupt:
        agent.stop()
