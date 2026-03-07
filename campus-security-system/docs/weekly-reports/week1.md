# Week 1 Report — Foundation Setup
**Project:** Predictive Cyber-Physical Security System (MASS)  
**Branch:** phase/1-iot  
**Date:** Week 1 of 11  
**Student:** Mena Osman

---

## What Was Built

Set up the entire project infrastructure from scratch. Created the GitHub repository and branch structure (`phase/1-iot`). Designed and committed the docker-compose file with 7 services: Zookeeper, Kafka, Mosquitto MQTT broker (TLS on port 8883), MongoDB, InfluxDB, PostgreSQL, and Grafana. All services start healthy with a single `docker-compose up`.

Designed the full Kafka topic architecture — 13 topics covering all three network domains (IoT, Physical Access, Data Network) plus HQ-level topics for correlation, SOAR commands, and agent heartbeats. Built `common/kafka_client.py` with a single `Topics` class as the source of truth for all topic names, plus producer (acks=all, lz4 compression) and consumer clients.

Built the IoT simulator (`iot_simulator.py`) covering all 3 physical sensors: DHT22 temperature, MQ-2 gas, PIR motion. Supports 5 modes: normal, temperature_spike, gas_anomaly, sensor_dropout, combined. Publishes to correct MQTT topics using the real sensor IDs that match the Raspberry Pi hardware.

Defined the shared Pydantic data models (`common/models.py`): `SensorReading`, `Alert`, and `SeverityLevel` enum used by all agents.

## Tests Passing
- Docker: all 7 services healthy ✅
- IoT simulator: all 3 sensors publish correctly ✅

## Problems Encountered
- MQTT TLS certificate generation required careful configuration of Subject Alternative Names for hostname matching. Resolved by updating the `generate_certs.sh` script.
- Kafka topic auto-creation was unreliable on first boot; added a retry loop in `ensure_topics()`.

## Next Week Plan
Build the Gateway Agent (DPI, allowlist, rate limiter, fingerprinting) and start the Behavioral Analysis Agent with Isolation Forest.
