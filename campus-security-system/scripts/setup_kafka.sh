#!/bin/bash
# Run once after docker compose up to create all Kafka topics
KAFKA="localhost:9092"
TOPICS=(
  "iot.telemetry" "iot.alerts" "iot.incidents"
  "pac.events" "pac.alerts" "pac.incidents"
  "data.alerts" "data.incidents"
  "hq.incidents" "hq.correlated"
  "soar.commands" "soar.responses"
  "agents.heartbeats"
)
for t in "${TOPICS[@]}"; do
  docker exec campus-kafka \
    kafka-topics --create --if-not-exists \
    --bootstrap-server "$KAFKA" \
    --replication-factor 1 --partitions 3 \
    --topic "$t"
  echo "✅ $t"
done
echo "All topics ready"
