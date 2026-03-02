import json
import logging
import ssl
from typing import Callable, Optional

import paho.mqtt.client as mqtt

logger = logging.getLogger(__name__)


class SecureMQTTClient:
    def __init__(
        self,
        client_id: str,
        broker_host: str,
        broker_port: int = 8883,
        ca_cert: str | None = None,
        client_cert: str | None = None,
        client_key: str | None = None,
    ):
        self.client_id = client_id
        self.broker_host = broker_host
        self.broker_port = broker_port

        self.client = mqtt.Client(client_id=client_id, protocol=mqtt.MQTTv311)

        if ca_cert and client_cert and client_key:
            self.client.tls_set(
                ca_certs=ca_cert,
                certfile=client_cert,
                keyfile=client_key,
                cert_reqs=ssl.CERT_REQUIRED,
                tls_version=ssl.PROTOCOL_TLSv1_2,
            )

        self.client.on_connect = self._on_connect
        self.client.on_disconnect = self._on_disconnect
        self.client.on_message = self._on_message

        self._cb: Optional[Callable[[str, dict], None]] = None
        self.connected = False

    def set_message_callback(self, cb: Callable[[str, dict], None]):
        self._cb = cb

    def connect(self):
        self.client.connect(self.broker_host, self.broker_port, keepalive=60)
        self.client.loop_start()
        logger.info("🔄 Connecting to MQTT...")

    def disconnect(self):
        self.client.loop_stop()
        self.client.disconnect()
        logger.info("👋 MQTT disconnected")

    def subscribe(self, topic: str, qos: int = 1):
        self.client.subscribe(topic, qos=qos)
        logger.info(f"📥 Subscribed: {topic}")

    def publish(self, topic: str, payload: dict, qos: int = 1):
        msg = json.dumps(payload, default=str)
        res = self.client.publish(topic, msg, qos=qos)
        return res.rc == mqtt.MQTT_ERR_SUCCESS

    def _on_connect(self, client, userdata, flags, rc):
        if rc == 0:
            self.connected = True
            logger.info(f"✅ Connected to {self.broker_host}:{self.broker_port}")
        else:
            logger.error(f"❌ MQTT connect failed rc={rc}")

    def _on_disconnect(self, client, userdata, rc):
        self.connected = False
        if rc != 0:
            logger.warning(f"⚠️ Unexpected disconnect rc={rc}")

    def _on_message(self, client, userdata, msg):
        try:
            payload = json.loads(msg.payload.decode("utf-8"))
            if self._cb:
                self._cb(msg.topic, payload)
        except Exception as e:
            logger.error(f"❌ Message parse error: {e}")
