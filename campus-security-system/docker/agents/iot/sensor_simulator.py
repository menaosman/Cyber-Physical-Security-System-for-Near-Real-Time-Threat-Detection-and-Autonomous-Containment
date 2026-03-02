"""
IoT Sensor Simulator
Simulates gas, temperature, and smoke sensors sending data via MQTT
"""
import json
import time
import random
import sys
from pathlib import Path
from datetime import datetime

# Add project root
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from common.mqtt_client import SecureMQTTClient


class SensorSimulator:
    """Simulates multiple IoT sensors"""
    
    def __init__(self):
        self.sequence_numbers = {}
        
        # Connect to MQTT broker
        self.mqtt_client = SecureMQTTClient(
            client_id="sensor-simulator",
            broker_host="localhost",
            broker_port=8883,
            ca_cert="config/certificates/ca.crt",
            client_cert="config/certificates/gateway-agent.crt",
            client_key="config/certificates/gateway-agent.key"
        )
        
        self.mqtt_client.connect()
        time.sleep(2)  # Wait for connection
        
        print("✅ Sensor Simulator connected to MQTT broker")
    
    def get_seq(self, device_id):
        """Get and increment sequence number"""
        if device_id not in self.sequence_numbers:
            self.sequence_numbers[device_id] = 0
        self.sequence_numbers[device_id] += 1
        return self.sequence_numbers[device_id]
    
    def send_reading(self, device_id, device_type, zone, value, unit):
        """Send sensor reading"""
        message = {
            "device_id": device_id,
            "device_type": device_type,
            "zone": zone,
            "value": value,
            "unit": unit,
            "gateway_id": "GW-ACADEMIC-F1-01",
            "seq": self.get_seq(device_id),
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
        
        topic = f"sensors/academic/floor1/{zone.split('/')[-1].lower()}"
        
        self.mqtt_client.publish(topic, message)
        
        severity = "LOW"
        if device_type == "gas":
            if value >= 450:
                severity = "HIGH 🚨"
            elif value >= 300:
                severity = "MEDIUM ⚠️"
        
        print(f"📤 {device_id}: {value} {unit} [{severity}]")
    
    def run_scenario_normal(self):
        """Scenario 1: Normal readings (LOW)"""
        print("\n" + "="*60)
        print("📊 SCENARIO 1: Normal Readings (LOW)")
        print("="*60)
        
        for i in range(5):
            # Gas sensor - normal
            self.send_reading(
                "GAS-ACADEMIC-F1-LABA-01",
                "gas",
                "Academic/Floor1/LabA",
                random.randint(80, 150),
                "ppm"
            )
            time.sleep(2)
    
    def run_scenario_medium(self):
        """Scenario 2: Warning readings (MEDIUM)"""
        print("\n" + "="*60)
        print("⚠️  SCENARIO 2: Warning Readings (MEDIUM)")
        print("="*60)
        
        for i in range(5):
            # Gas sensor - medium level
            self.send_reading(
                "GAS-ACADEMIC-F1-LABA-01",
                "gas",
                "Academic/Floor1/LabA",
                random.randint(320, 380),
                "ppm"
            )
            time.sleep(2)
    
    def run_scenario_high_sustained(self):
        """Scenario 3: Critical sustained HIGH"""
        print("\n" + "="*60)
        print("🚨 SCENARIO 3: HIGH Sustained (CRITICAL!)")
        print("="*60)
        
        print("⏱️  Sending HIGH readings for 20 seconds...")
        
        for i in range(10):  # 10 readings × 2 seconds = 20 seconds
            self.send_reading(
                "GAS-ACADEMIC-F1-LABA-01",
                "gas",
                "Academic/Floor1/LabA",
                random.randint(480, 550),
                "ppm"
            )
            time.sleep(2)
    
    def run_scenario_spike(self):
        """Scenario 4: Transient spike (should downgrade to MEDIUM)"""
        print("\n" + "="*60)
        print("📈 SCENARIO 4: Transient Spike (should become MEDIUM)")
        print("="*60)
        
        # Normal
        self.send_reading(
            "GAS-ACADEMIC-F1-LABA-01",
            "gas",
            "Academic/Floor1/LabA",
            150,
            "ppm"
        )
        time.sleep(2)
        
        # Sudden spike
        print("💥 SPIKE!")
        self.send_reading(
            "GAS-ACADEMIC-F1-LABA-01",
            "gas",
            "Academic/Floor1/LabA",
            520,
            "ppm"
        )
        time.sleep(2)
        
        # Back to normal
        print("↓ Back to normal")
        self.send_reading(
            "GAS-ACADEMIC-F1-LABA-01",
            "gas",
            "Academic/Floor1/LabA",
            160,
            "ppm"
        )
        time.sleep(2)
    
    def run_all_scenarios(self):
        """Run all test scenarios"""
        print("\n🎬 Starting IoT Sensor Simulation")
        print("="*60)
        
        try:
            self.run_scenario_normal()
            time.sleep(3)
            
            self.run_scenario_medium()
            time.sleep(3)
            
            self.run_scenario_spike()
            time.sleep(3)
            
            self.run_scenario_high_sustained()
            
            print("\n" + "="*60)
            print("✅ All scenarios completed!")
            print("="*60)
            
        except KeyboardInterrupt:
            print("\n⏸️  Simulation stopped by user")
        finally:
            self.mqtt_client.disconnect()


if __name__ == "__main__":
    simulator = SensorSimulator()
    simulator.run_all_scenarios()
EOF
