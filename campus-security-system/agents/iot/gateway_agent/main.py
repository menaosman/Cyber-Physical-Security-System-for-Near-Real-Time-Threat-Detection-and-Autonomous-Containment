"""
IoT Gateway Agent - Main Entry Point

This agent:
1. Receives sensor data via MQTT
2. Validates data integrity
3. Classifies risk level
4. Sends alerts to Local Manager via Kafka
"""
import os
import sys
import logging
import yaml
import signal
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(project_root))

from common.mqtt_client import SecureMQTTClient
from validator import SensorValidator
from classifier import RiskClassifier
from communicator import AlertCommunicator
from common.models import SeverityLevel

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('gateway_agent.log')
    ]
)
logger = logging.getLogger(__name__)


class GatewayAgent:
    """
    Main Gateway Agent class
    Coordinates validation, classification, and communication
    """
    
    def __init__(self, config_path: str):
        logger.info("🚀 Starting Gateway Agent...")
        
        # Load configuration
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
        
        self.agent_id = self.config['gateway']['id']
        logger.info(f"📍 Agent ID: {self.agent_id}")
        logger.info(f"📍 Location: {self.config['gateway']['location']}")
        
        # Initialize components
        self.validator = SensorValidator(self.config)
        self.classifier = RiskClassifier(self.config)
        self.communicator = AlertCommunicator(self.config, self.agent_id)
        
        # Initialize MQTT client
        mqtt_config = self.config['mqtt']
        tls_config = mqtt_config['tls']
        
        self.mqtt_client = SecureMQTTClient(
            client_id=self.agent_id,
            broker_host=mqtt_config['broker'],
            broker_port=mqtt_config['port'],
            ca_cert=tls_config['ca_cert'],
            client_cert=tls_config['client_cert'],
            client_key=tls_config['client_key']
        )
        
        self.mqtt_client.set_message_callback(self.handle_sensor_message)
        
        # Statistics
        self.stats = {
            'messages_received': 0,
            'messages_valid': 0,
            'messages_invalid': 0,
            'alerts_sent': 0,
            'device_counters': {}  # To count messages per device
        }
        
        logger.info("✅ Gateway Agent initialized successfully")
    
    def handle_sensor_message(self, topic: str, payload: dict):
        """
        Handle incoming sensor message
        This is the main processing pipeline
        """
        self.stats['messages_received'] += 1
        
        logger.debug(f"📨 Received message from topic: {topic}")
        
        # STEP 1: Validate
        is_valid, reason, sensor_reading = self.validator.validate(payload)
        
        if not is_valid:
            self.stats['messages_invalid'] += 1
            logger.warning(
                f"⚠️  Invalid message rejected. Reason: {reason}, "
                f"Device: {payload.get('device_id', 'UNKNOWN')}"
            )
            
            # TODO: Send security alert for certain violations
            if reason in ['unauthorized_device', 'sequence_anomaly']:
                # This could indicate an attack
                pass
            
            return
        
        self.stats['messages_valid'] += 1
        
        # STEP 2: Update device counters
        self.update_device_counter(sensor_reading.device_id)
        
        # STEP 3: Classify Risk
        severity, confidence, details = self.classifier.classify(sensor_reading)
        
        logger.info(
            f"📊 Classification: {sensor_reading.device_id} → "
            f"{severity.value} (confidence: {confidence:.2f})"
        )
        
        # STEP 4: Take Action Based on Severity
        if severity in [SeverityLevel.HIGH, SeverityLevel.CRITICAL]:
            # Send alert immediately
            success = self.communicator.send_alert(
                sensor_reading, severity, confidence, details
            )
            
            if success:
                self.stats['alerts_sent'] += 1
                logger.warning(
                    f"🚨 HIGH/CRITICAL alert sent! "
                    f"Device: {sensor_reading.device_id}, "
                    f"Value: {sensor_reading.value} {sensor_reading.unit}"
                )
            
        elif severity == SeverityLevel.MEDIUM:
            # Send alert
            success = self.communicator.send_alert(
                sensor_reading, severity, confidence, details
            )
            
            if success:
                self.stats['alerts_sent'] += 1
                logger.info(
                    f"⚠️  MEDIUM alert sent. "
                    f"Device: {sensor_reading.device_id}"
                )
        
        else:
            # LOW - just log for telemetry
            self.communicator.send_event_log(sensor_reading, severity)
        
        # Print statistics every 10 messages
        if self.stats['messages_received'] % 10 == 0:
            self.print_statistics()
    
    def update_device_counter(self, device_id: str):
        """
        Update message counter for each device
        """
        if device_id not in self.stats['device_counters']:
            self.stats['device_counters'][device_id] = 0
        self.stats['device_counters'][device_id] += 1
    
    def start(self):
        """Start the agent"""
        logger.info("▶️  Starting Gateway Agent...")
        
        # Connect to MQTT broker
        self.mqtt_client.connect()
        
        # Subscribe to sensor topics
        subscribe_topic = self.config['mqtt']['topics']['subscribe']
        self.mqtt_client.subscribe(subscribe_topic)
        
        logger.info(f"✅ Gateway Agent is running and listening to: {subscribe_topic}")
        logger.info("Press Ctrl+C to stop")
        
        # Keep running
        try:
            while True:
                pass  # MQTT client runs in background thread
        except KeyboardInterrupt:
            logger.info("⏸️  Received shutdown signal...")
            self.stop()
    
    def stop(self):
        """Stop the agent"""
        logger.info("🛑 Stopping Gateway Agent...")
        
        # Print final statistics
        self.print_statistics()
        
        # Cleanup
        self.mqtt_client.disconnect()
        self.communicator.close()
        
        logger.info("👋 Gateway Agent stopped gracefully")
    
    def print_statistics(self):
        """Print agent statistics"""
        logger.info(
            f"📊 Statistics: "
            f"Received={self.stats['messages_received']}, "
            f"Valid={self.stats['messages_valid']}, "
            f"Invalid={self.stats['messages_invalid']}, "
            f"Alerts={self.stats['alerts_sent']}, "
            f"Device Counters={self.stats['device_counters']}"
        )


def main():
    """Main entry point"""
    config_path = os.path.join(
        os.path.dirname(__file__),
        'config.yaml'
    )
    
    agent = GatewayAgent(config_path)
    
    # Handle graceful shutdown
    def signal_handler(sig, frame):
        logger.info("Signal received, shutting down...")
        agent.stop()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    agent.start()


if __name__ == "__main__":
    main()
