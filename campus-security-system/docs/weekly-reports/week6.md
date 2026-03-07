# Week 6 Report — NDR Agent
**Project:** Predictive Cyber-Physical Security System (MASS)  
**Branch:** phase/3-data  
**Date:** Week 6 of 11  
**Student:** Mena Osman

---

## What Was Built

Built the **NDR Agent** (Network Detection & Response) — analyzes network flow records produced by Zeek/Suricata or the data network simulator. Detects 6 network-layer attack types:

1. **Port scan** (MITRE T1046): >20 unique destination ports from same source IP within 60 seconds. Uses a per-src_ip sliding window buffer. Threshold configurable via env var.
2. **SSH brute force** (T1110): >10 failed SSH connections (status=REJ/reset) from same IP within 60 seconds.
3. **HTTP brute force** (T1110): >15 HTTP 401/403 responses from same IP within 60 seconds.
4. **Data exfiltration** (T1048): single flow >50MB from internal IP to external IP. Always CRITICAL.
5. **Lateral movement** (T1021): source IP connects to 3+ different internal VLANs within 120 seconds. Detects cross-VLAN traversal that indicates an attacker moving through the network.
6. **C2 beaconing** (T1071): 5+ small flows (<10KB each) from internal to same external IP within 5 minutes — periodic check-in pattern of command-and-control malware.
7. **Unauthorized VLAN crossing** (T1599): traffic between VLANs that are explicitly isolated in campus policy (e.g., IoT VLAN 20 → Server VLAN 60).

All detections include alert deduplication (30-second cooldown per src_ip per attack type) to prevent alert flooding.

Built the **Data Network Simulator** with 6 attack modes matching the 6 NDR detection rules.

## Tests Passing
- 5/5 NDR agent tests passing ✅
- Port scan: 25 flows → HIGH alert ✅
- Exfiltration: 80MB flow → CRITICAL immediately ✅
- Unauthorized VLAN: IoT→Server → HIGH alert ✅
- Normal traffic: 5 flows to same port → no alert ✅

## Problems Encountered
- Lateral movement detection needed to track VLANs crossed by source IP, not destination IPs. Implemented using a per-src_ip deque that records the VLAN subnet of each destination.

## Next Week Plan
Build EDR Agent, Data Local Manager, pass Phase 3 gate, add Grafana panels, merge PR.
