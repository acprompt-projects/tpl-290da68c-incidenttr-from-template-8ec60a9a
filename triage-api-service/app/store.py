from datetime import datetime, timezone
from typing import Optional
from app.models import (
    IncidentCreate, IncidentRead, IncidentTriageUpdate,
    Severity, IncidentStatus
)

_incidents: dict[str, IncidentRead] = {}
_fingerprint_index: dict[str, str] = {}
_counter = 0

def _next_id() -> str:
    global _counter
    _counter += 1
    return f"INC-{_counter:06d}"

def find_duplicate(fingerprint: str) -> Optional[IncidentRead]:
    incident_id = _fingerprint_index.get(fingerprint)
    if incident_id:
        return _incidents.get(incident_id)
    return None

def correlate(existing_id: str, payload: IncidentCreate) -> IncidentRead:
    existing = _incidents[existing_id]
    now = datetime.now(timezone.utc)
    updated = existing.model_copy(update={
        "correlation_count": existing.correlation_count + 1,
        "updated_at": now,
    })
    _incidents[existing_id] = updated
    return updated

def create(payload: IncidentCreate, severity: Severity, labels: dict[str, str]) -> IncidentRead:
    incident_id = _next_id()
    now = datetime.now(timezone.utc)
    incident = IncidentRead(
        id=incident_id,
        title=payload.title,
        description=payload.description,
        fingerprint=payload.fingerprint,
        source=payload.source,
        raw_alert=payload.raw_alert,
        tags=payload.tags,
        severity=severity,
        labels=labels,
        status=IncidentStatus.OPEN,
        correlation_count=1,
        created_at=now,
        updated_at=now,
    )
    _incidents[incident_id] = incident
    _fingerprint_index[payload.fingerprint] = incident_id
    return incident

def get(incident_id: str) -> Optional[IncidentRead]:
    return _incidents.get(incident_id)

def update_triage(incident_id: str, update: IncidentTriageUpdate) -> IncidentRead:
    existing = _incidents[incident_id]
    now = datetime.now(timezone.utc)
    patch = {"updated_at": now}
    if update.severity is not None:
        patch["severity"] = update.severity
    if update.status is not None:
        patch["status"] = update.status
    if update.assigned_team is not None:
        patch["assigned_team"] = update.assigned_team
    if update.labels is not None:
        patch["labels"] = {**existing.labels, **update.labels}
    if update.tags is not None:
        patch["tags"] = list(set(existing.tags + update.tags))
    updated = existing.model_copy(update=patch)
    _incidents[incident_id] = updated
    return updated