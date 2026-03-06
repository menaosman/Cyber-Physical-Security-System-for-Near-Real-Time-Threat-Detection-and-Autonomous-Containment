"""
IoT Sensor Simulator — iot_simulator.py
Phase 1 / Week 1 deliverable

Simulates ALL real sensors wired to pi-iot:
  • DHT22  — temperature + humidity  (GPIO 14)
  • MQ-2   — gas / smoke             (GPIO 15)
  • PIR    — motion / occupancy      (GPIO 18)

Modes:
  normal          — realistic baseline readings (LOW severity)
  temperature_spike  — DHT22 reads 55 °C (attack scenario 1)
  gas_anomaly        — MQ-2 reads high gas/smoke (attack scenario 2)
  sensor_dropout     — stops sending heartbeat (attack scenario 3)
  combined           — temperature spike + unauthorized access (attack scenario 4)

Usage:
  python iot_simulator.py --mode normal
  python iot_simulator.py --mode temperature_spike
  python iot_simulator.py --mode gas_anomaly
  python iot_simulator.py --mode sensor_dropout
  python iot_simulator.py --mode combined
  python iot_simulator.py --mode all      # run all scenarios sequentially

Standards:
  • NIST SP 800-82 — IoT/OT continuous monitoring
  • Messages conform to SensorReading model in common/models.py
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# Add project root
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from common.mqtt_client import SecureMQTTClient

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger("iot_simulator")


# ─── MQTT topic structure (matches campus topology) ───────────────────────────
# sensors/{building}/{floor}/{sensor_type}
# Maps to VLAN 20 (Academic IoT), subnet 192.168.20.x
TOPICS = {
    "temperature": "sensors/academic/floor1/temperature",
    "gas":         "sensors/academic/floor1/gas",
    "motion":      "sensors/academic/floor1/motion",
}

# Device IDs matching the whitelist in gateway_agent/config.yaml
DEVICE_IDS = {
    "temperature": "DHT22-ACADEMIC-F1-LABA-01",
    "gas":         "MQ2-ACADEMIC-F1-LABA-01",
    "motion":      "PIR-ACADEMIC-F1-LABA-01",
}

GATEWAY_ID = "GW-ACADEMIC-F1-01"
ZONE       = "Academic/Floor1/LabA"


class IoTSimulator:
    """
    Simulates pi-iot sensor data over MQTT.
    Each scenario maps to one of the 4 attack modes from iot_anomaly_sim.py
    """

    def __init__(
        self,
        broker_host: str = "localhost",
        broker_port: int = 8883,
        ca_cert: str = "config/certificates/ca.crt",
        client_cert: str = "config/certificates/gateway-agent.crt",
        client_key: str = "config/certificates/gateway-agent.key",
    ):
        self._seq: dict[str, int] = {}
        self._running = True

        self.mqtt = SecureMQTTClient(
            client_id="iot-simulator",
            broker_host=broker_host,
            broker_port=broker_port,
            ca_cert=ca_cert,
            client_cert=client_cert,
            client_key=client_key,
        )
        self.mqtt.connect()
        time.sleep(1.5)
        logger.info("✅ IoT Simulator connected to MQTT broker")

    # ─── Core publish helper ──────────────────────────────────────────────────
    def _seq_next(self, device_id: str) -> int:
        self._seq[device_id] = self._seq.get(device_id, 0) + 1
        return self._seq[device_id]

    def publish(
        self,
        sensor_type: str,
        value: float,
        unit: str,
        extra: Optional[dict] = None,
    ):
        device_id = DEVICE_IDS[sensor_type]
        topic     = TOPICS[sensor_type]
        payload   = {
            "device_id":  device_id,
            "device_type": sensor_type,
            "zone":        ZONE,
            "value":       value,
            "unit":        unit,
            "gateway_id":  GATEWAY_ID,
            "seq":         self._seq_next(device_id),
            "timestamp":   datetime.now(timezone.utc).isoformat(),
        }
        if extra:
            payload.update(extra)

        ok = self.mqtt.publish(topic, payload, qos=1)
        status = "✅" if ok else "❌"
        logger.info(f"{status} [{sensor_type.upper()}] {value} {unit}  seq={payload['seq']}")
        return ok

    # ─── Scenario 1: Normal baseline readings (LOW) ───────────────────────────
    def scenario_normal(self, duration_sec: int = 30, interval: float = 2.0):
        """
        Realistic normal readings from all 3 sensors.
        Gate test: gateway_agent must classify ALL as LOW.
        """
        logger.info("=" * 55)
        logger.info("📊 SCENARIO: normal — baseline readings")
        logger.info("=" * 55)

        import random
        end = time.time() + duration_sec
        while time.time() < end and self._running:
            self.publish("temperature", round(random.uniform(20.0, 28.0), 1), "celsius")
            self.publish("gas",         round(random.uniform(80.0, 180.0), 1), "ppm")
            self.publish("motion",      float(random.choice([0, 0, 0, 1])),    "bool",
                         {"motion_detected": bool(random.choice([0, 0, 0, 1]))})
            time.sleep(interval)

        logger.info("✅ Normal scenario complete")

    # ─── Scenario 2: Temperature spike (Attack 1) ─────────────────────────────
    def scenario_temperature_spike(self, sustained_sec: int = 20, interval: float = 2.0):
        """
        Injects 55 °C reading (simulating lighter held near DHT22).
        Expected: gateway_agent → HIGH alert → IoT local manager notified.

        Maps to: iot_anomaly_sim.py temperature_spike attack
        MITRE: T1499 (resource exhaustion via sensor flooding)
        """
        logger.info("=" * 55)
        logger.info("🌡️  SCENARIO: temperature_spike — inject 55°C readings")
        logger.info("=" * 55)

        import random

        # 3 normal readings first
        for _ in range(3):
            self.publish("temperature", round(random.uniform(21.0, 24.0), 1), "celsius")
            time.sleep(interval)

        logger.info("🔥 SPIKE START — injecting high temperature readings")
        end = time.time() + sustained_sec
        while time.time() < end and self._running:
            # Realistic variation around 55°C like a real lighter
            spike_val = round(55.0 + random.uniform(-1.5, 2.5), 1)
            self.publish("temperature", spike_val, "celsius",
                         extra={"anomaly_injected": True, "scenario": "temperature_spike"})
            time.sleep(interval)

        logger.info("❄️  Spike ended — returning to normal")
        for _ in range(3):
            self.publish("temperature", round(random.uniform(21.0, 24.0), 1), "celsius")
            time.sleep(interval)

        logger.info("✅ Temperature spike scenario complete")

    # ─── Scenario 3: Gas / smoke anomaly (Attack 2) ───────────────────────────
    def scenario_gas_anomaly(self, sustained_sec: int = 20, interval: float = 2.0):
        """
        Injects high MQ-2 gas reading (simulating smoke / gas leak).
        Expected: CRITICAL fire/smoke alert → escalated immediately.

        Maps to: iot_anomaly_sim.py gas_anomaly attack
        MITRE: T1499
        """
        logger.info("=" * 55)
        logger.info("💨 SCENARIO: gas_anomaly — inject high gas/smoke readings")
        logger.info("=" * 55)

        import random

        # 3 normal readings first
        for _ in range(3):
            self.publish("gas", round(random.uniform(90.0, 160.0), 1), "ppm")
            time.sleep(interval)

        logger.info("🚨 GAS ANOMALY START — injecting high ppm readings")
        end = time.time() + sustained_sec
        while time.time() < end and self._running:
            # Above 450 ppm threshold → HIGH; critical at 600+
            gas_val = round(random.uniform(480.0, 620.0), 1)
            self.publish("gas", gas_val, "ppm",
                         extra={"anomaly_injected": True, "scenario": "gas_anomaly",
                                "fire_risk": gas_val > 550})
            time.sleep(interval)

        logger.info("✅ Gas anomaly scenario complete")

    # ─── Scenario 4: Sensor dropout (Attack 3) ───────────────────────────────
    def scenario_sensor_dropout(self, normal_sec: int = 10, dropout_sec: int = 15):
        """
        Simulates pi-iot script being killed / sensor going offline.
        Sends normal readings, then STOPS for dropout_sec.
        Expected: IoT manager detects missing heartbeat → device failure alert.

        Maps to: iot_anomaly_sim.py sensor_dropout attack
        """
        logger.info("=" * 55)
        logger.info("💀 SCENARIO: sensor_dropout — simulate dead sensor")
        logger.info("=" * 55)

        import random
        # Normal readings
        end = time.time() + normal_sec
        while time.time() < end and self._running:
            self.publish("temperature", round(random.uniform(21.0, 24.0), 1), "celsius")
            self.publish("gas",         round(random.uniform(90.0, 160.0), 1), "ppm")
            time.sleep(2.0)

        logger.info(f"⚡ DROPOUT — stopping all sensor messages for {dropout_sec}s")
        time.sleep(dropout_sec)   # <-- complete silence, no MQTT messages

        logger.info("🔄 Sensor back online — resuming normal readings")
        for _ in range(5):
            self.publish("temperature", round(random.uniform(21.0, 24.0), 1), "celsius")
            self.publish("gas",         round(random.uniform(90.0, 160.0), 1), "ppm")
            time.sleep(2.0)

        logger.info("✅ Sensor dropout scenario complete")

    # ─── Scenario 5: Combined attack (Attack 4) ──────────────────────────────
    def scenario_combined(self):
        """
        Temperature spike + gas anomaly simultaneously.
        Expected: HQ manager correlates both events into one coordinated incident.

        Maps to: iot_anomaly_sim.py combined attack
        Also fires the PIR to add motion context to the incident.
        """
        logger.info("=" * 55)
        logger.info("⚡ SCENARIO: combined — simultaneous temperature + gas")
        logger.info("=" * 55)

        import random, threading

        stop_flag = {"stop": False}

        def spike_temp():
            while not stop_flag["stop"]:
                v = round(55.0 + random.uniform(-1.0, 2.0), 1)
                self.publish("temperature", v, "celsius",
                             extra={"anomaly_injected": True, "scenario": "combined"})
                time.sleep(2.0)

        def spike_gas():
            while not stop_flag["stop"]:
                v = round(random.uniform(490.0, 610.0), 1)
                self.publish("gas", v, "ppm",
                             extra={"anomaly_injected": True, "scenario": "combined"})
                time.sleep(2.1)  # slightly offset so messages don't collide

        def spike_motion():
            for _ in range(5):
                self.publish("motion", 1.0, "bool",
                             extra={"motion_detected": True, "scenario": "combined"})
                time.sleep(3.0)

        logger.info("🔥💨 Launching simultaneous temperature + gas + motion attack")
        t1 = threading.Thread(target=spike_temp,   daemon=True)
        t2 = threading.Thread(target=spike_gas,    daemon=True)
        t3 = threading.Thread(target=spike_motion, daemon=True)
        t1.start(); t2.start(); t3.start()

        time.sleep(25)  # run combined attack for 25 seconds
        stop_flag["stop"] = True
        t1.join(timeout=3); t2.join(timeout=3); t3.join(timeout=3)

        logger.info("✅ Combined scenario complete")

    # ─── Run all scenarios sequentially ──────────────────────────────────────
    def run_all(self):
        logger.info("🎬 Running ALL IoT attack scenarios sequentially")
        try:
            self.scenario_normal(duration_sec=20)
            time.sleep(3)
            self.scenario_temperature_spike(sustained_sec=20)
            time.sleep(3)
            self.scenario_gas_anomaly(sustained_sec=20)
            time.sleep(3)
            self.scenario_sensor_dropout(normal_sec=10, dropout_sec=15)
            time.sleep(3)
            self.scenario_combined()
        except KeyboardInterrupt:
            logger.info("⏸️  Simulation interrupted by user")
        finally:
            self.stop()

    def stop(self):
        self._running = False
        self.mqtt.disconnect()
        logger.info("👋 IoT Simulator stopped")


# ─── CLI entry point ──────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="MASS IoT Sensor Simulator")
    parser.add_argument(
        "--mode",
        choices=["normal", "temperature_spike", "gas_anomaly",
                 "sensor_dropout", "combined", "all"],
        default="normal",
        help="Simulation scenario to run",
    )
    parser.add_argument("--broker", default="localhost", help="MQTT broker host")
    parser.add_argument("--port",   type=int, default=8883, help="MQTT broker port")
    parser.add_argument("--ca",     default="config/certificates/ca.crt")
    parser.add_argument("--cert",   default="config/certificates/gateway-agent.crt")
    parser.add_argument("--key",    default="config/certificates/gateway-agent.key")
    args = parser.parse_args()

    sim = IoTSimulator(
        broker_host=args.broker,
        broker_port=args.port,
        ca_cert=args.ca,
        client_cert=args.cert,
        client_key=args.key,
    )

    try:
        if args.mode == "normal":
            sim.scenario_normal()
        elif args.mode == "temperature_spike":
            sim.scenario_temperature_spike()
        elif args.mode == "gas_anomaly":
            sim.scenario_gas_anomaly()
        elif args.mode == "sensor_dropout":
            sim.scenario_sensor_dropout()
        elif args.mode == "combined":
            sim.scenario_combined()
        elif args.mode == "all":
            sim.run_all()
    finally:
        sim.stop()


if __name__ == "__main__":
    main()
