from __future__ import annotations
from enum import Enum
from datetime import datetime, timezone
from typing import Optional
from pydantic import BaseModel, Field

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class IncidentStatus(str, Enum):
    OPEN = "open"
    TRIAGING = "triaging"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"

class AlertSource(BaseModel):
    service: str
    environment: str
    region: Optional[str] = None

class IncidentCreate(BaseModel):
    title: str
    description: str = ""
    fingerprint: str = Field(..., description="Dedup key from rules engine")
    source: AlertSource
    raw_alert: dict = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)

class IncidentRead(BaseModel):
    id: str
    title: str
    description: str
    fingerprint: str
    source: AlertSource
    raw_alert: dict
    tags: list[str]
    severity: Severity
    labels: dict[str, str] = Field(default_factory=dict)
    status: IncidentStatus
    correlation_count: int = 1
    assigned_team: Optional[str] = None
    created_at: datetime
    updated_at: datetime

class IncidentTriageUpdate(BaseModel):
    severity: Optional[Severity] = None
    status: Optional[IncidentStatus] = None
    assigned_team: Optional[str] = None
    labels: Optional[dict[str, str]] = None
    tags: Optional[list[str]] = None