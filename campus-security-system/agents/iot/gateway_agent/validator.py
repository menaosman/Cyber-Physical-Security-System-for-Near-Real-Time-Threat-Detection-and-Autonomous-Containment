from __future__ import annotations
from typing import Dict, Tuple, Optional
from common.models import SensorReading

class SensorValidator:
    def __init__(self, config: Dict):
        self.whitelist = set(config.get("sensors", {}).get("whitelist", []))
        self.last_seq = {}  # device_id -> last seq

    def validate(self, payload: Dict) -> Tuple[bool, Optional[str], Optional[SensorReading]]:
        try:
            reading = SensorReading(**payload)
        except Exception as e:
            return False, f"schema_invalid: {e}", None

        if self.whitelist and reading.device_id not in self.whitelist:
            return False, "unauthorized_device", reading

        last = self.last_seq.get(reading.device_id)
        if last is not None and reading.seq <= last:
            return False, "sequence_anomaly", reading

        self.last_seq[reading.device_id] = reading.seq
        return True, None, reading
