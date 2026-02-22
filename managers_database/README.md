# Manager's Database

This folder contains the database layer for the Network Manager (Manager's Database).
It is organized by:
- core: shared tables across all networks
- iot_network: IoT-specific tables
- data_network: Data network-specific tables
- physical_network: Physical access-specific tables
- integrations: Kafka topics + DB contract
- docs: database design + ERD
- docker: local Postgres for demo/testing

## Quick Start (Docker)
1) cd managers_database/docker
2) docker compose up -d
3) Database will be available on localhost:5432
   - DB: cpss_db
   - User: cpss_user
   - Password: cpss_pass

## Apply schema
The docker/init.sql creates schemas and core/network tables.
