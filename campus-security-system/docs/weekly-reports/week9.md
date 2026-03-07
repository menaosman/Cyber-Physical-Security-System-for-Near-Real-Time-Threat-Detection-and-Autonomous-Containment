# Week 9 Report — Orchestrator Agent + Learning Agent + Central Manager
**Project:** Predictive Cyber-Physical Security System (MASS)  
**Branch:** phase/4-hq  
**Date:** Week 9 of 11  
**Student:** Mena Osman

---

## What Was Built

Built the **Orchestrator Agent** (SOAR Engine) — receives correlated incidents from the Analytical Agent and automatically selects and executes the appropriate response playbook. 4 playbooks implemented:

1. **Ransomware Response**: isolate_host → kill_suspicious_processes → take_forensic_snapshot → notify_ir_team → block_c2_ips → [APPROVAL REQUIRED: restore_from_backup]
2. **Active Intrusion Response**: block_attacker_ip → capture_full_traffic → [APPROVAL REQUIRED: rotate_compromised_credentials] → enable_enhanced_logging → notify_management_and_legal
3. **IoT Compromise Response**: isolate_iot_vlan → restart_compromised_sensors → verify_sensor_integrity → notify_facilities_team → [APPROVAL REQUIRED: rotate_mqtt_credentials]
4. **Access Control Lockdown**: lock_all_restricted_doors → suspend_flagged_rfid_cards → activate_security_cameras → notify_physical_security_team

Auto steps fire immediately to `soar.commands`. Steps marked `requires_approval: True` are held in a pending queue accessible via `GET /pending` and released via `POST /approve/{cmd_id}`. This satisfies the human-in-the-loop requirement for destructive actions.

Built the **Learning Agent** — adaptive retraining pipeline. Consumes confirmed incidents and dismissed incidents (false positives) from Kafka, builds a labeled training dataset, and triggers model retraining. Auto-retrains after every 50 confirmed incidents and on a 24-hour schedule. Computes threshold recommendations when false positive rates are high (e.g., if SSH brute force has ≥2 false positives, recommend raising threshold from 10 to 15). Publishes threshold updates to `soar.commands` so agents can hot-update without restart. MLflow-compatible run logging at every retrain cycle.

Built the **Central Manager** — the single `/status` endpoint showing: live threat level (LOW/MEDIUM/HIGH/CRITICAL), agent heartbeat health percentage, incident counts by domain, and active correlations. The investor demo dashboard.

## Tests Passing
- 7/7 Orchestrator tests passing ✅
- 7/7 Learning Agent tests passing ✅
- 5/5 Central Manager tests passing ✅
- Approval-required steps held in pending queue ✅
- LOW severity correctly skips HIGH min_severity playbooks ✅

## Problems Encountered
- Playbook trigger matching needed to handle the case where one correlation type maps to multiple playbooks (e.g., coordinated_attack triggers both intrusion_response and iot_compromise_response). Implemented as a list of matched playbook names, all executed sequentially.

## Next Week Plan
Full system integration test with all 9 agents simultaneously, Grafana dashboards, README.
