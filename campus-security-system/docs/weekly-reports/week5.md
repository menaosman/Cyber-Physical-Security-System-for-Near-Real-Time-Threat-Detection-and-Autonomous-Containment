# Week 5 Report — Credential Anomaly Agent + PAC Local Manager + Phase 2 Gate
**Project:** Predictive Cyber-Physical Security System (MASS)  
**Branch:** phase/2-pac → merged to main  
**Date:** Week 5 of 11  
**Student:** Mena Osman

---

## What Was Built

Built the **Credential Anomaly Agent** — detects attacks that only become visible when analyzing patterns across multiple events over time. Four detection rules:

1. **Impossible travel**: same card UID appears at two different buildings in under 60 seconds. Physically impossible, indicates credential sharing or cloning. → HIGH (confidence 0.93)
2. **Credential sharing**: same card+door combination 3+ times within 30 seconds. → MEDIUM (confidence 0.75)
3. **Brute force access**: 5+ different unknown cards attempting the same door within 60 seconds — systematic attack on an access point. → HIGH (confidence 0.95, MITRE T1110.001)
4. **Badge cloning**: same card UID appears at two different physical doors within 10 seconds — impossible without a cloned card. → CRITICAL (confidence 0.90)

Built the **PAC Local Manager** — area-sensitivity reclassification: any incident near HQ, server room, data center, or administrative zone automatically upgrades to CRITICAL regardless of original severity. Three or more unauthorized attempts at the same door → CRITICAL + lockdown command sent to `soar.commands`. Same 60-second operator approval window as IoT Local Manager.

## Tests Passing (Phase 2 Gate)
- 15/15 tests passing ✅
- Impossible travel detected across buildings ✅
- Badge clone → CRITICAL ✅
- Restricted area upgrade working ✅
- 60-second approval window with auto-escalation ✅

## GitHub Actions
- PR phase/2-pac → main merged ✅
- Tag: v0.2.0-phase2 ✅

## Problems Encountered
- Badge clone detection required separating "same card, different door" from "same card, same door" (which is just tailgating). Implemented using a composite key of card_uid+door_id in the tracking buffer.

## Next Week Plan
Build NDR Agent and data network simulator for Phase 3.
