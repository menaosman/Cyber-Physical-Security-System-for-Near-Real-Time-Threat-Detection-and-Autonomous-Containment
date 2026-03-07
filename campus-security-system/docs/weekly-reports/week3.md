# Week 3 Report — IoT Local Manager + Phase 1 Gate
**Project:** Predictive Cyber-Physical Security System (MASS)  
**Branch:** phase/1-iot → merged to main  
**Date:** Week 3 of 11  
**Student:** Mena Osman

---

## What Was Built

Completed the **IoT Local Manager** — the decision-maker for the IoT domain. It consumes alerts from both the Gateway Agent and Behavioral Agent via Kafka, applies cross-sensor context reclassification within a 30-second correlation window:
- HIGH temperature + MEDIUM gas → CRITICAL (fire risk)
- HIGH gas + HIGH temperature → CRITICAL
- HIGH motion + HIGH gas → CRITICAL (intruder + hazard)

Added a **heartbeat watchdog**: if any registered sensor is silent for more than 20 seconds, the manager fires a device dropout alert (MITRE T0829 — Loss of View). This covers the scenario where an attacker physically disconnects a sensor to blind the system.

Implemented the **60-second operator approval window** for CRITICAL incidents. The manager holds the incident in a pending queue, starts a background timer, and auto-escalates to `hq.incidents` if no human approves or dismisses within the window. Operators can approve via `POST /approve/{id}`.

FastAPI endpoints: GET /health, /alerts, /incidents, /devices, /pending; POST /approve/{id}, /dismiss/{id}.

## Tests Passing (Phase 1 Gate)
- 18/18 tests passing ✅
- Full chain: iot_simulator → Gateway → Behavioral → IoT Local Manager ✅
- Reclassification: temp HIGH + gas MEDIUM → CRITICAL ✅
- Heartbeat dropout detection ✅

## GitHub Actions
- PR phase/1-iot → main merged ✅
- Tag: v0.1.0-phase1 ✅

## Problems Encountered
- Method naming mismatch between test expectations and implementation (`handle_alert` vs `handle`, `_recent_alerts` vs `_recent`). Fixed by aligning implementation to test contracts first.

## Next Week Plan
Build PAC-EDA Agent and PAC simulator for Phase 2 (Physical Access).
