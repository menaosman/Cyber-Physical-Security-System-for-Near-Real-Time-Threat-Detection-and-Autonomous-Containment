# Week 8 Report — Analytical Agent (HQ Correlation Engine)
**Project:** Predictive Cyber-Physical Security System (MASS)  
**Branch:** phase/4-hq  
**Date:** Week 8 of 11  
**Student:** Mena Osman

---

## What Was Built

Built the **Analytical Agent** — the cross-domain intelligence layer that sits above all three local managers and correlates incidents across IoT, Physical Access, and Data Network simultaneously. This is the core innovation of the MASS architecture: no single domain agent can see the full picture, but the Analytical Agent can.

Two correlation time windows: fast (5 minutes) for rapid attack chains like recon → exploitation → exfiltration; slow (30 minutes) for APT campaigns that move carefully across days.

Five correlation rules detecting cross-domain attack patterns:

1. **Coordinated attack**: HIGH+ incidents in 2+ domains within the fast window → CRITICAL. Indicates an attacker operating on multiple fronts simultaneously.
2. **Campus-wide threat**: active incidents (MEDIUM+) in all 3 domains within the slow window → CRITICAL. Indicates a full APT campaign.
3. **Insider threat**: PAC anomaly (unknown card, after-hours, badge clone) + data exfiltration within 30 minutes → CRITICAL. Physical presence + cyber exfiltration is the classic insider pattern.
4. **IoT-cyber bridge**: IoT sensor anomaly + network lateral movement within 5 minutes → HIGH. Indicates an attacker who compromised an IoT device and used it to pivot into the data network — a major concern given IoT devices often have weaker security.
5. **Physical-cyber combo**: unknown RFID + credential dump within 5 minutes → CRITICAL. Physical break-in enabling a cyber attack on the compromised system.

All correlations include deduplication with per-rule cooldowns to prevent duplicate correlation storms.

Publishes to `hq.correlated` — consumed by the Orchestrator Agent.

## Tests Passing
- 6/6 Analytical Agent tests passing ✅
- Coordinated attack (2 domains) → CRITICAL ✅
- Campus-wide threat (3 domains) → CRITICAL ✅
- Insider threat pattern detected ✅
- IoT-cyber bridge detected ✅
- Single domain → no correlation fired ✅
- Dedup prevents duplicate correlations ✅

## Problems Encountered
- The insider threat rule needed to handle both "PAC then exfil" and "exfil then PAC" orderings within the window, since we don't know which comes first. Solved by checking the slow window in both directions.

## Next Week Plan
Build Orchestrator Agent (SOAR), Learning Agent (MLflow), and Central Manager.
