import sys
from pathlib import Path

# Add project root to the Python path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

import time
import random
from datetime import datetime
from common.mqtt_client import SecureMQTTClient

TOPIC = "sensors/academic/floor1/laba"

def main():
    client = SecureMQTTClient(
        client_id="sim",
        broker_host="localhost",
        broker_port=8883,
        ca_cert="config/certificates/ca.crt",
        client_cert="config/certificates/gateway-agent.crt",
        client_key="config/certificates/gateway-agent.key",
    )
    client.connect()
    time.sleep(1)

    seq = 0
    while True:
        seq += 1
        value = random.choice([120, 150, 320, 360, 520, 540])  # mix
        msg = {
            "device_id": "GAS-ACADEMIC-F1-LABA-01",
            "device_type": "gas",
            "zone": "Academic/Floor1/LabA",
            "value": float(value),
            "unit": "ppm",
            "gateway_id": "GW-TEST-01",
            "seq": seq,
            "timestamp": datetime.utcnow().isoformat()
        }
        client.publish(TOPIC, msg, qos=1)
        print("sent", value, "seq", seq)
        time.sleep(2)

if __name__ == "__main__":
    main()
