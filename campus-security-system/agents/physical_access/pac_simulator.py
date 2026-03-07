"""
agents/physical_access/pac_simulator.py
Physical Access Control Simulator — 4 attack modes
Simulates pi-physical (RFID RC522 + relay) events over MQTT.

Modes: normal | unauthorized_card | unknown_card | tailgating | after_hours | all
Usage: python pac_simulator.py --mode unknown_card
"""
from __future__ import annotations
import argparse, logging, random, sys, time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from common.mqtt_client import SecureMQTTClient

logging.basicConfig(level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s")
logger = logging.getLogger("pac_simulator")

TOPIC_ACCESS = "access/academic/floor{floor}/door{door}"
GATEWAY_ID   = "GW-PAC-ACADEMIC-F1-01"

# Simulated LDAP user database
LDAP_USERS = {
    "A1B2C3D4": {"name": "Alice Student",  "role": "student",
                 "floors": [1],     "hours": (8, 20)},
    "E5F6G7H8": {"name": "Bob Faculty",    "role": "faculty",
                 "floors": [1,2,3], "hours": (0, 24)},
    "I9J0K1L2": {"name": "Carol IT Staff", "role": "it_staff",
                 "floors": [1,2,3], "hours": (0, 24)},
    "M3N4O5P6": {"name": "Dave Lab Asst",  "role": "lab_asst",
                 "floors": [1],     "hours": (9, 18)},
}
UNAUTHORIZED_CARD = "A1B2C3D4"  # student card — floor 2 not in permissions
UNKNOWN_CARD      = "DEADBEEF"  # not in LDAP at all


class PACSimulator:
    def __init__(self, broker="localhost", port=8883,
                 ca="config/certificates/ca.crt",
                 cert="config/certificates/gateway-agent.crt",
                 key="config/certificates/gateway-agent.key"):
        self._seq = 0
        self.mqtt = SecureMQTTClient("pac-simulator", broker, port, ca, cert, key)
        self.mqtt.connect()
        time.sleep(1.5)
        logger.info("✅ PAC Simulator connected")

    def _send(self, floor, door, card_uid, override_hour=None, extra=None):
        self._seq += 1
        now  = datetime.now(timezone.utc)
        hour = override_hour if override_hour is not None else now.hour
        user = LDAP_USERS.get(card_uid)

        if user is None:
            ldap_result, access, reason = "NOT_FOUND", "denied", "unknown_card"
        elif floor not in user["floors"]:
            ldap_result, access, reason = "UNAUTHORIZED", "denied", "unauthorized_area"
        elif not (user["hours"][0] <= hour < user["hours"][1]):
            ldap_result, access, reason = "TIME_RESTRICTED", "denied", "after_hours"
        else:
            ldap_result, access, reason = "AUTHORIZED", "granted", "normal"

        payload = {
            "device_id":   f"RFID-ACADEMIC-F{floor}-DOOR{door}-01",
            "device_type": "rfid_reader",
            "zone":        f"Academic/Floor{floor}/Door{door}",
            "card_uid":    card_uid,
            "floor":       floor,
            "door_id":     f"door_acad_f{floor}_d{door}",
            "gateway_id":  GATEWAY_ID,
            "seq":         self._seq,
            "timestamp":   now.isoformat(),
            "ldap_result": ldap_result,
            "access":      access,
            "reason":      reason,
            "hour":        hour,
        }
        if user:
            payload["user_name"] = user["name"]
            payload["user_role"] = user["role"]
        if extra:
            payload.update(extra)

        topic = TOPIC_ACCESS.format(floor=floor, door=door)
        self.mqtt.publish(topic, payload, qos=1)
        icon = "✅" if access == "granted" else "🚫"
        logger.info(f"{icon} [{reason.upper():20s}] card={card_uid} floor={floor} → {access}")

    # ── Normal ────────────────────────────────────────────────────────────────
    def scenario_normal(self, count=10, interval=3.0):
        logger.info("📊 SCENARIO: normal")
        cards = [c for c in LDAP_USERS]
        for _ in range(count):
            card  = random.choice(cards)
            floor = random.choice(LDAP_USERS[card]["floors"])
            self._send(floor, 1, card)
            time.sleep(interval)
        logger.info("✅ Normal done")

    # ── Attack 1: Unauthorized card (exists but wrong floor) ──────────────────
    def scenario_unauthorized_card(self, count=5, interval=2.0):
        logger.info("🚫 SCENARIO: unauthorized_card — student card on floor 2")
        for i in range(count):
            self._send(2, 1, UNAUTHORIZED_CARD,
                       extra={"attack_scenario": "unauthorized_card", "attempt": i+1})
            time.sleep(interval)
        logger.info("✅ Unauthorized card done")

    # ── Attack 2: Unknown card (not in LDAP) ──────────────────────────────────
    def scenario_unknown_card(self, count=5, interval=2.0):
        logger.info("⚠️  SCENARIO: unknown_card — card not in LDAP")
        for i in range(count):
            self._send(1, 1, UNKNOWN_CARD,
                       extra={"attack_scenario": "unknown_card", "attempt": i+1})
            time.sleep(interval)
        logger.info("✅ Unknown card done")

    # ── Attack 3: Tailgating (same card twice < 5s) ───────────────────────────
    def scenario_tailgating(self, count=4, interval=4.0):
        logger.info("🚶 SCENARIO: tailgating — double scan < 5s")
        for i in range(count):
            self._send(1, 1, "E5F6G7H8",
                       extra={"attack_scenario": "tailgating", "scan": 1})
            time.sleep(1.5)   # only 1.5s between scans → triggers tailgating rule
            self._send(1, 1, "E5F6G7H8",
                       extra={"attack_scenario": "tailgating", "scan": 2})
            time.sleep(interval)
        logger.info("✅ Tailgating done")

    # ── Attack 4: After-hours (valid card, wrong time) ────────────────────────
    def scenario_after_hours(self, count=5, interval=2.0):
        logger.info("🌙 SCENARIO: after_hours — lab assistant at 23:00")
        for i in range(count):
            self._send(1, 1, "M3N4O5P6", override_hour=23,
                       extra={"attack_scenario": "after_hours", "attempt": i+1})
            time.sleep(interval)
        logger.info("✅ After-hours done")

    def run_all(self):
        try:
            for fn in [self.scenario_normal, self.scenario_unauthorized_card,
                       self.scenario_unknown_card, self.scenario_tailgating,
                       self.scenario_after_hours]:
                fn()
                time.sleep(3)
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()

    def stop(self):
        self.mqtt.disconnect()
        logger.info("👋 PAC Simulator stopped")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--mode", choices=["normal","unauthorized_card","unknown_card",
                   "tailgating","after_hours","all"], default="normal")
    p.add_argument("--broker", default="localhost")
    p.add_argument("--port",   type=int, default=8883)
    p.add_argument("--ca",     default="config/certificates/ca.crt")
    p.add_argument("--cert",   default="config/certificates/gateway-agent.crt")
    p.add_argument("--key",    default="config/certificates/gateway-agent.key")
    args = p.parse_args()
    sim = PACSimulator(args.broker, args.port, args.ca, args.cert, args.key)
    try:
        if args.mode == "all":
            sim.run_all()
        else:
            getattr(sim, f"scenario_{args.mode}")()
    finally:
        sim.stop()

if __name__ == "__main__":
    main()
