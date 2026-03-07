# Week 7 Report — EDR Agent + Data Local Manager + Phase 3 Gate
**Project:** Predictive Cyber-Physical Security System (MASS)  
**Branch:** phase/3-data → merged to main  
**Date:** Week 7 of 11  
**Student:** Mena Osman

---

## What Was Built

Built the **EDR Agent** (Endpoint Detection & Response) — analyzes process and file system events from campus endpoint sensors. Detects 6 endpoint attack types:

1. **Ransomware behavior** (T1486): mass file rename/encrypt operations with suspicious extensions (.locked, .encrypted, .cerber, etc.) — >20 file ops in 30 seconds → CRITICAL.
2. **Credential dump** (T1003): access to `/etc/shadow`, LSASS process, SAM registry hives, or `ntds.dit` — always CRITICAL (confidence 0.95).
3. **Privilege escalation** (T1548): process spawned running as root/SYSTEM when the parent process ran as a non-privileged user → HIGH.
4. **Persistence mechanism** (T1053): write/modify operations on cron directories, init.d, RC scripts, or Windows Run registry keys → MEDIUM.
5. **Suspicious process** (T1059): process name or command line matches known attacker tools: mimikatz, procdump, netcat, meterpreter, cobalt strike, psexec → HIGH.
6. **YARA-style matching** (T1027): command line or script content matches 5 inline signature rules: PowerShell encoded commands, base64 shellcode eval, reverse shell bash syntax, wget/curl pipe to shell, shadow file read — CRITICAL for reverse shell.

Built the **Data Local Manager** with cross-agent correlation rules. Most important: ransomware + credential dump on same host within 5 minutes → CRITICAL (double threat indicating sophisticated attacker); port scan + brute force from same IP within 2 minutes → CRITICAL (recon-to-exploitation chain); lateral movement + privilege escalation within 10 minutes → CRITICAL (APT pattern). Also adds a `/isolate/{host_id}` endpoint that sends an isolation command to SOAR.

## Tests Passing (Phase 3 Gate)
- 17/17 tests + 1 Kafka integration test passing ✅
- YARA reverse shell → CRITICAL ✅
- Ransomware + credential dump correlation → CRITICAL ✅
- Port scan + brute force chain → CRITICAL ✅

## GitHub Actions
- PR phase/3-data → main merged ✅
- Tag: v0.3.0-phase3 ✅

## Problems Encountered
- YARA pattern for PowerShell encoded commands needed to handle both `-enc` and `-encodedcommand` flags with variable spacing. Used regex with `re.I` flag.

## Next Week Plan
Build Analytical Agent for HQ cross-domain correlation.
