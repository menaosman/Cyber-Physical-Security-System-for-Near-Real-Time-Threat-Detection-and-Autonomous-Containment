"""
MASS Kafka Client
Reusable Kafka producer and consumer for all agents and managers.

Standards:
  - NIST SP 800-53 AU-9 (Protection of Audit Information)
  - All messages are JSON-serialized and keyed by device_id or agent_id
    so Kafka guarantees ordering per device within a partition.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Callable, Dict, List, Optional

from confluent_kafka import Consumer, KafkaError, KafkaException, Producer
from confluent_kafka.admin import AdminClient, NewTopic

logger = logging.getLogger(__name__)


# ─── Topic Registry ───────────────────────────────────────────────────────────
# Single source of truth for all Kafka topic names used across the system.
# Agents MUST import these constants — never hardcode topic strings.
class Topics:
    # IoT domain
    IOT_TELEMETRY       = "iot.telemetry"        # raw sensor readings (LOW)
    IOT_ALERTS          = "iot.alerts"            # gateway + behavioral alerts
    IOT_INCIDENTS       = "iot.incidents"         # IoT local manager escalations

    # Physical Access domain
    PAC_EVENTS          = "pac.events"            # all door/RFID events log
    PAC_ALERTS          = "pac.alerts"            # PAC-EDA + credential alerts
    PAC_INCIDENTS       = "pac.incidents"         # PAC local manager escalations

    # Data Network domain
    DATA_ALERTS         = "data.alerts"           # NDR + EDR alerts
    DATA_INCIDENTS      = "data.incidents"        # Data local manager escalations

    # HQ / cross-domain
    HQ_INCIDENTS        = "hq.incidents"          # all local managers → HQ
    HQ_CORRELATED       = "hq.correlated"         # analytical agent output
    SOAR_COMMANDS       = "soar.commands"         # orchestrator → responsive agents
    SOAR_RESPONSES      = "soar.responses"        # responsive agents → orchestrator

    # Heartbeats
    HEARTBEATS          = "agents.heartbeats"     # all agent health pulses

    ALL = [
        IOT_TELEMETRY, IOT_ALERTS, IOT_INCIDENTS,
        PAC_EVENTS, PAC_ALERTS, PAC_INCIDENTS,
        DATA_ALERTS, DATA_INCIDENTS,
        HQ_INCIDENTS, HQ_CORRELATED,
        SOAR_COMMANDS, SOAR_RESPONSES,
        HEARTBEATS,
    ]


# ─── Producer ─────────────────────────────────────────────────────────────────
class KafkaProducerClient:
    """
    Thread-safe Kafka producer.
    All agents use this to publish events/alerts.
    """

    def __init__(self, bootstrap_servers: str = "localhost:9092"):
        self.bootstrap_servers = bootstrap_servers
        self._producer = Producer({
            "bootstrap.servers": bootstrap_servers,
            "acks": "all",                  # strongest durability guarantee
            "retries": 5,
            "retry.backoff.ms": 300,
            "compression.type": "lz4",
            "linger.ms": 5,                 # small batch window for throughput
        })
        logger.info(f"✅ KafkaProducer ready → {bootstrap_servers}")

    def publish(self, topic: str, payload: dict, key: Optional[str] = None) -> bool:
        """
        Publish a dict payload to a Kafka topic.
        key: optional partition key (use device_id or agent_id for ordering).
        Returns True on success.
        """
        try:
            encoded_key = key.encode("utf-8") if key else None
            encoded_val = json.dumps(payload, default=str).encode("utf-8")
            self._producer.produce(
                topic,
                value=encoded_val,
                key=encoded_key,
                on_delivery=self._delivery_report,
            )
            self._producer.poll(0)   # non-blocking trigger of delivery callbacks
            return True
        except KafkaException as e:
            logger.error(f"❌ Kafka produce error topic={topic}: {e}")
            return False

    def flush(self, timeout: float = 5.0):
        """Flush all pending messages. Call before shutdown."""
        remaining = self._producer.flush(timeout)
        if remaining > 0:
            logger.warning(f"⚠️  {remaining} messages NOT delivered after flush")

    def close(self):
        self.flush()
        logger.info("👋 KafkaProducer closed")

    @staticmethod
    def _delivery_report(err, msg):
        if err:
            logger.error(f"❌ Delivery failed topic={msg.topic()} err={err}")
        else:
            logger.debug(f"✅ Delivered topic={msg.topic()} partition={msg.partition()} offset={msg.offset()}")


# ─── Consumer ─────────────────────────────────────────────────────────────────
class KafkaConsumerClient:
    """
    Kafka consumer for agents/managers that need to react to events.
    Runs a blocking poll loop — call start() in a thread or async task.
    """

    def __init__(
        self,
        group_id: str,
        topics: List[str],
        bootstrap_servers: str = "localhost:9092",
        auto_offset_reset: str = "latest",
    ):
        self.group_id = group_id
        self.topics = topics
        self._running = False

        self._consumer = Consumer({
            "bootstrap.servers": bootstrap_servers,
            "group.id": group_id,
            "auto.offset.reset": auto_offset_reset,
            "enable.auto.commit": True,
            "auto.commit.interval.ms": 1000,
            "session.timeout.ms": 30000,
            "heartbeat.interval.ms": 10000,
        })
        self._consumer.subscribe(topics)
        logger.info(f"✅ KafkaConsumer group={group_id} topics={topics}")

    def poll_loop(self, handler: Callable[[str, dict], None], poll_timeout: float = 1.0):
        """
        Blocking poll loop. Call handler(topic, payload) for each message.
        Run this in a dedicated thread.
        """
        self._running = True
        logger.info(f"▶️  Consumer poll loop started — group={self.group_id}")

        while self._running:
            msg = self._consumer.poll(poll_timeout)
            if msg is None:
                continue
            if msg.error():
                if msg.error().code() == KafkaError._PARTITION_EOF:
                    continue
                logger.error(f"❌ Consumer error: {msg.error()}")
                continue
            try:
                payload = json.loads(msg.value().decode("utf-8"))
                handler(msg.topic(), payload)
            except Exception as e:
                logger.error(f"❌ Handler error topic={msg.topic()}: {e}")

        logger.info("⏹️  Consumer poll loop stopped")

    def stop(self):
        self._running = False
        self._consumer.close()
        logger.info("👋 KafkaConsumer closed")


# ─── Topic Provisioner ────────────────────────────────────────────────────────
def ensure_topics(
    bootstrap_servers: str = "localhost:9092",
    topics: Optional[List[str]] = None,
    num_partitions: int = 3,
    replication_factor: int = 1,
    retries: int = 10,
    retry_delay: float = 3.0,
):
    """
    Idempotently create all required Kafka topics.
    Call this once at startup (e.g. from docker-compose init script or
    the first agent/manager that boots).
    Retries because Kafka may not be ready immediately after container start.
    """
    if topics is None:
        topics = Topics.ALL

    admin = None
    for attempt in range(1, retries + 1):
        try:
            admin = AdminClient({"bootstrap.servers": bootstrap_servers})
            # Quick connectivity check
            admin.list_topics(timeout=5)
            break
        except Exception as e:
            logger.warning(f"⏳ Kafka not ready (attempt {attempt}/{retries}): {e}")
            time.sleep(retry_delay)
    else:
        raise RuntimeError(f"❌ Cannot connect to Kafka at {bootstrap_servers} after {retries} attempts")

    existing = set(admin.list_topics(timeout=10).topics.keys())
    to_create = [
        NewTopic(t, num_partitions=num_partitions, replication_factor=replication_factor)
        for t in topics if t not in existing
    ]

    if not to_create:
        logger.info(f"✅ All {len(topics)} Kafka topics already exist")
        return

    results = admin.create_topics(to_create)
    for topic, future in results.items():
        try:
            future.result()
            logger.info(f"✅ Created topic: {topic}")
        except Exception as e:
            if "already exists" in str(e).lower():
                logger.debug(f"Topic already exists: {topic}")
            else:
                logger.error(f"❌ Failed to create topic {topic}: {e}")
