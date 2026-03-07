# MASS — Demo Script
## Exact Commands + Timing for Final Presentation (15–18 minutes)

---

## Before You Start (5 minutes before presenter arrives)

```bash
# 1. Start all infrastructure
cd campus-security-system
docker-compose -f docker/docker-compose.yml up -d

# 2. Wait for all services (30 seconds)
sleep 30

# 3. Activate virtual environment
source venv/bin/activate

# 4. Verify all 76 tests pass — show this first
pytest tests/ -v --tb=short
```

Open these 4 browser tabs before the demo:
- **Tab 1:** Grafana → http://localhost:3000 (login: admin / admin)
- **Tab 2:** Central Manager → http://localhost:8020/status
- **Tab 3:** Analytical Agent → http://localhost:8006/correlations
- **Tab 4:** Orchestrator → http://localhost:8007/executions

---

## Presentation Flow

### Slide 1 — The Problem (2 minutes)

> "A university campus has three separate security systems that never talk to each other.
> One watches the IoT sensors — temperature, gas, motion.
> One watches the access control doors — who swipes their card and when.
> One watches the computer network — traffic, processes, file operations.
>
> A smart attacker exploits this gap. They tailgate through a door, compromise an IoT
> sensor, pivot onto the data network, steal passwords, and copy 80MB of files — and
> not one system sees the full attack. Each system only sees one piece."

Point at the three separate boxes in the architecture diagram.

> "Our system — MASS — connects all three. It doesn't just detect threats in isolation.
> It correlates them across domains and responds automatically."

---

### Slide 2 — Architecture (2 minutes)

> "We have 9 specialized agents organized in 4 layers.
>
> Layer 1: IoT — 3 agents watching sensors on the Raspberry Pi nodes.
> Layer 2: Physical Access — 3 agents watching every RFID door swipe.
> Layer 3: Data Network — 2 agents watching network flows and endpoint behavior.
> Layer 4: HQ Intelligence — 4 agents that see everything simultaneously.
>
> All agents communicate over Apache Kafka — a distributed event streaming platform
> that guarantees no message is ever lost, even if an agent restarts.
>
> The whole system is containerized in Docker — one command starts everything."

---

### Slide 3 — Show the Tests (1 minute)

Run in terminal:
```bash
pytest tests/ --tb=short -q
```

> "76 tests. All passing. Every phase has a gate test — the PR cannot merge
> to main until 100% pass. This is enforced by our branching strategy."

Expected output:
```
76 passed in 13.93s
```

---

### Slide 4 — Live Attack Demo (8 minutes) ← THE MAIN EVENT

Open the terminal and run:
```bash
python scripts/full_attack_scenario.py --demo-mode
```

**Narrate each phase as the steps print:**

**When Phase A prints (steps 1–5):**
> "An unknown RFID card just tried the server room door. It's not in the university
> LDAP directory at all — that's immediately flagged as HIGH severity by the PAC-EDA
> agent. Then it tries 4 more times. The Credential Anomaly Agent sees 5 unknown
> cards at the same door in under 60 seconds — that's a brute force pattern against
> our access control system."

**When Phase B prints (steps 6–10):**
> "Now the IoT layer. Temperature in Lab A just jumped to 55°C. Our Behavioral
> Analysis Agent has a frozen baseline of 22°C for this sensor — a Modified Z-score
> calculation gives a score of 110 against a threshold of 8. That's not a gradual
> change — that's a spike. The gas sensor then reads 520ppm, followed by 3 sustained
> readings above 490ppm. The IoT Local Manager sees both sensors at the same time
> and reclassifies to CRITICAL — fire risk."

**When Phase C prints (steps 11–20):**
> "Now the data network. The same external IP that's been suspicious just scanned 22
> different ports in one second — that's reconnaissance. 2 steps later, 12 failed
> SSH attempts from the same IP — that's brute force. Our Data Local Manager sees
> both events from the same IP within 2 minutes and upgrades to CRITICAL automatically.
>
> Then lateral movement — a workstation connecting to 4 different VLANs in 4 seconds.
> That's an attacker who got in and is now exploring every part of the network.
>
> Ransomware: 25 files renamed to .locked in 1 second on the server.
> Credential dump: mimikatz running to steal passwords from memory.
> And finally — 80 megabytes leaving the campus network to an unknown external IP.
> That's data exfiltration. Always CRITICAL. No thresholds needed."

**After the demo script finishes — switch to Tab 2:**
```
http://localhost:8020/status
```
> "The Central Manager now shows threat level: CRITICAL. Let me show you what
> the Analytical Agent correlated."

**Switch to Tab 3:**
```
http://localhost:8006/correlations
```
> "Four cross-domain correlations fired. The most important one is
> 'physical_cyber_combo' — it connected the unknown RFID card from Phase A
> with the credential dump from Phase C. No individual agent could see that.
> Only the Analytical Agent, watching all three domains simultaneously, could
> make that connection."

**Switch to Tab 4:**
```
http://localhost:8007/executions
```
> "The Orchestrator Agent automatically ran 3 playbooks. For the ransomware
> it already isolated the affected server, killed the suspicious process, and
> took a forensic memory snapshot. The only step it didn't run automatically
> is 'restore from backup' — that's a destructive action that requires human
> approval. Everything else: fully automated, in under 15 seconds."

---

### Slide 5 — Standards and Learning Agent (1 minute)

> "Every detection rule maps to a published standard. MITRE ATT&CK for the
> specific technique number. NIST SP 800-61 for incident response structure.
> IEC 62443 for IoT security zones.
>
> And the system gets smarter. The Learning Agent builds a labeled dataset
> from every confirmed incident and every dismissed false positive. After 50
> confirmed incidents it retrains the detection models and pushes updated
> thresholds to the agents without restarting them. The system improves while
> it runs."

---

### Slide 6 — Close (30 seconds)

> "76 tests. 9 agents. 4 layers. 3 network domains. One system.
> Built over 10 weeks by one student.
> Thank you."

---

## If Something Goes Wrong

| Problem | Fix |
|---|---|
| Kafka not available | `docker-compose -f docker/docker-compose.yml up -d kafka` then wait 20s |
| Demo script error | Run `pytest tests/ -q` first — if green, re-run demo |
| Grafana not loading | http://localhost:3000 login admin/admin, import `docker/grafana/mass_dashboard.json` |
| Port already in use | `docker-compose down` then `docker-compose up -d` |

## Backup

If live demo fails completely, show the pre-recorded terminal output saved at:
`docs/demo_recording.txt`

---

*Target runtime: 15–18 minutes. Practice 3 times before the real presentation.*
