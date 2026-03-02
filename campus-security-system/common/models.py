from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class SeverityLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class SensorReading(BaseModel):
    device_id: str
    device_type: str
    zone: str
    value: float
    unit: str
    gateway_id: str
    seq: int
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class Alert(BaseModel):
    alert_id: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    agent_id: str
    agent_type: str
    network_type: str  # "iot", "physical_access", "data"
    alert_type: str
    severity: SeverityLevel
    confidence: float = Field(..., ge=0.0, le=1.0)

    source: Dict[str, Any] = Field(default_factory=dict)
    details: Dict[str, Any] = Field(default_factory=dict)
    recommended_actions: List[str] = Field(default_factory=list)
    evidence: Optional[Dict[str, Any]] = None
