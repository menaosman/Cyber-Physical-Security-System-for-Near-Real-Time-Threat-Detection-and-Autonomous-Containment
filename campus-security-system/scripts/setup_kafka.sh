#!/bin/bash
set -e

echo "🐳 Starting Kafka (KRaft mode) via Docker Compose..."
cd docker

# Create a minimal compose if not present
if [ ! -f docker-compose.yml ]; then
  echo "docker/docker-compose.yml not found. Please create it first."
  exit 1
fi

docker compose up -d
docker compose ps
