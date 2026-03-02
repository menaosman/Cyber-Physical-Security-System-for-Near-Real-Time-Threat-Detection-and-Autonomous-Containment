from __future__ import annotations

import json
import uuid
from typing import Dict, Optional
from confluent_kafka import Producer

from common.models import Alert, SensorReading, SeverityLevel


class AlertCommunicator:
    def __init__(self, config: Dict, agent_id: str):
        self.agent_id = agent_id

        kafka_cfg = config.get("kafka", {})
        self.kafka_enabled: bool = bool(kafka_cfg.get("enabled", False))
        self.bootstrap: str = kafka_cfg.get("bootstrap_servers", "localhost:9092")

        topics = kafka_cfg.get("topics", {})
        self.topic_high = topics.get("high", "alerts-high")
        self.topic_medium = topics.get("medium", "alerts-medium")
        self.topic_low = topics.get("low", "telemetry-normal")

        self.producer: Optional[Producer] = None
        if self.kafka_enabled:
            self.producer = Producer({"bootstrap.servers": self.bootstrap})

    def _pick_topic(self, severity: SeverityLevel) -> str:
        if severity == SeverityLevel.HIGH:
            return self.topic_high
        if severity == SeverityLevel.MEDIUM:
            return self.topic_medium
        return self.topic_low

    def send_alert(self, reading: SensorReading, severity: SeverityLevel, confidence: float, details: Dict):
        alert = Alert(
            alert_id=str(uuid.uuid4()),
            agent_id=self.agent_id,
            agent_type="iot_gateway",
            network_type="iot",
            alert_type=f"{reading.device_type}_anomaly",
            severity=severity,
            confidence=confidence,
            source={
                "device_id": reading.device_id,
                "zone": reading.zone,
                "gateway_id": reading.gateway_id
            },
            details=details,
            recommended_actions=["notify_security"] if severity != SeverityLevel.LOW else [],
        )

        payload = alert.model_dump(mode="json")
        topic = self._pick_topic(severity)

        if self.kafka_enabled and self.producer:
            self.producer.produce(topic, json.dumps(payload).encode("utf-8"))
            self.producer.flush()
            print(f"🚨 Kafka Sent: severity={severity.value} topic={topic}")
        else:
            print(f"ALERT (Kafka disabled) >> {payload}")

        return alert

    def send_telemetry(self, reading: SensorReading, severity: SeverityLevel, extra: Dict):
        """Send LOW telemetry events to telemetry-normal."""
        event = {
            "device_id": reading.device_id,
            "device_type": reading.device_type,
            "zone": reading.zone,
            "value": reading.value,
            "unit": reading.unit,
            "gateway_id": reading.gateway_id,
            "seq": reading.seq,
            "timestamp": reading.timestamp.isoformat(),
            "severity": severity.value,
            **extra
        }
        if self.kafka_enabled and self.producer:
            self.producer.produce(self.topic_low, json.dumps(event).encode("utf-8"))
            self.producer.flush()
            print(f"✅ Kafka Telemetry Sent topic={self.topic_low}")
        else:
            print(f"TELEMETRY (Kafka disabled) >> {event}")
