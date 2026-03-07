# Week 2 Report — Gateway Agent + Behavioral Agent Start
**Project:** Predictive Cyber-Physical Security System (MASS)  
**Branch:** phase/1-iot  
**Date:** Week 2 of 11  
**Student:** Mena Osman

---

## What Was Built

Completed the **Gateway Agent** — the first line of defense for the IoT network. The agent subscribes to MQTT sensor topics over TLS, validates every reading against an allowlist of known sensor IDs, checks sequence numbers for anomalies, and classifies risk using threshold rules: gas >300ppm → MEDIUM, gas >450ppm for 10+ seconds (3+ consecutive points) → HIGH sustained alert. All alerts publish to Kafka with full metadata.

Key design decision: the sustained-window logic required a sliding buffer keyed per sensor ID, not per message, so that intermittent readings don't reset the window incorrectly.

Started the **Behavioral Analysis Agent**. Chose a dual-layer approach after finding that Isolation Forest alone failed: when the rolling window includes spike values, the mean shifts toward the spike, collapsing the delta feature and causing the anomaly to look normal. Fix: freeze the baseline statistics after the training window fills (MIN_TRAIN_SAMPLES=50) so attack data never contaminates the learned baseline.

Layer 1 is a Modified Z-score (MAD-based): `|0.6745*(value - median) / MAD| > threshold`. This catches a 55°C spike after a 22°C baseline with a computed z-score of ~110, guaranteeing detection. Layer 2 is Isolation Forest (n_estimators=200, contamination=0.05) for subtle multi-variate patterns. Either layer flagging triggers an alert.

## Tests Passing
- Gateway classifier: LOW/MEDIUM/HIGH/CRITICAL classification ✅
- Sustained high window: 3 points in 10s → CRITICAL ✅
- Behavioral agent: ≥85% recall on temperature spike ✅

## Problems Encountered
- Isolation Forest needed contamination=0.05 rather than the default 0.1 to avoid over-flagging normal variance in gas readings.
- MAD z-score threshold tuning: temperature=8.0, gas=6.0, motion=3.5 chosen after testing against simulated data.

## Next Week Plan
Complete IoT Local Manager, run full chain integration test, pass Phase 1 gate, merge PR.
