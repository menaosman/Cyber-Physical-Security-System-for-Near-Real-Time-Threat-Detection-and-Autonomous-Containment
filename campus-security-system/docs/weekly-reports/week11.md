# Week 11 Report — Demo Polish + Final Release
**Project:** Predictive Cyber-Physical Security System (MASS)  
**Branch:** phase/5-demo → merged to main  
**Date:** Week 11 of 11  
**Student:** Mena Osman

---

## What Was Built This Week

**Grafana Dashboard** — 8 panels covering the full system:
1. Header banner with live status indicator
2. System threat level (colour-coded LOW/MEDIUM/HIGH/CRITICAL stat panel)
3. Active CRITICAL incidents count with threshold colouring
4. Agent health gauge (9 agents across 4 layers)
5. Alert rate over time — time series for IoT, PAC, Data, HQ (all domains)
6. Incidents by severity — donut chart (CRITICAL/HIGH/MEDIUM/LOW)
7. MITRE ATT&CK techniques detected — time series (T1046, T1110, T1486, T1003, T1048, T1078)
8. Latest HQ correlations — live table
9. SOAR playbook executions — live table with status colouring
10. Learning Agent model F1 scores — time series for all 3 models

**Full system test** (`tests/full_system_test.py`) — automated integration test that runs all 3 simulators simultaneously and verifies events arrive on the correct Kafka topics within timing targets: IoT <5s, PAC <10s, Data <10s, HQ correlation <30s.

**DEMO_SCRIPT.md** (`docs/DEMO_SCRIPT.md`) — exact commands and narration script for the 15–18 minute presentation. Includes fallback plan if live demo fails.

**week11.md** — this report.

## Final Test Count
- 76/76 unit + integration tests passing across all 5 test files
- Full system test: all 3 simulators publish simultaneously, all events received ✅
- Full attack scenario: 20 steps, 76 events, 23 seconds, zero errors ✅

## Final System Summary
| Component | Count | Status |
|---|---|---|
| Agents | 9 | ✅ All built and tested |
| Local Managers | 3 | ✅ All built and tested |
| Central Manager | 1 | ✅ Built and tested |
| Test files | 5 | ✅ 76/76 passing |
| Kafka topics | 13 | ✅ Configured |
| SOAR playbooks | 4 | ✅ Implemented |
| MITRE techniques mapped | 14 | ✅ Documented |
| Weekly reports | 11 | ✅ Committed |
| Grafana panels | 8 | ✅ Dashboard JSON ready |

## GitHub Actions
- PR phase/5-demo → main merged ✅
- Tag: v1.0.0 — final release ✅

## Rehearsals Completed
- Rehearsal 1: 17 minutes — adjusted pacing for Phase C narration
- Rehearsal 2: 16 minutes — clean run
- Rehearsal 3: 15 minutes — clean run, backup recording saved
