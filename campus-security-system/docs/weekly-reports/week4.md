# Week 4 Report — PAC Simulator + PAC-EDA Agent
**Project:** Predictive Cyber-Physical Security System (MASS)  
**Branch:** phase/2-pac  
**Date:** Week 4 of 11  
**Student:** Mena Osman

---

## What Was Built

Built the **PAC Simulator** (`pac_simulator.py`) that generates realistic RFID door access events for 4 simulated users: a student (floor 1 only), a faculty member (all floors), an IT staff member, and a lab assistant (floor 1 only, 9am–6pm). Supports 5 attack modes: normal, unauthorized_card, unknown_card, tailgating, after_hours. Publishes events to MQTT topic `access/academic/floor{N}/door{N}`.

Built the **PAC-EDA Agent** (Physical Access Control — Event Detection Agent). Consumes every door access event and detects:
- **Unknown card** (card UID not found in LDAP directory) → HIGH alert, MITRE T1078
- **Unauthorized area** (valid card, wrong floor/zone) → MEDIUM alert
- **Tailgating** (same door swiped twice within 5 seconds — one person holding door for another) → MEDIUM alert
- **After-hours access** (valid card, outside permitted hours for that user type) → MEDIUM alert

Dual Kafka output: all events → `pac.events` (for the Credential Anomaly Agent to analyze patterns), confirmed attacks → `pac.alerts` (for PAC Local Manager). FastAPI `/health` and `/alerts` on port 8002.

## Tests Passing
- 6/6 PAC-EDA tests passing ✅
- Unknown card → HIGH alert in <10s ✅
- Tailgating detected with 1.5s inter-swipe window ✅
- Normal access generates no alert ✅

## Problems Encountered
- Tailgating detection needed to track per-door state separately from per-card state. Implemented a `_door_last_access` dict with 5-second windows per door ID.

## Next Week Plan
Build Credential Anomaly Agent and PAC Local Manager, pass Phase 2 gate, merge PR.
