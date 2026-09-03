from fastapi import FastAPI, HTTPException
from contextlib import asynccontextmanager
from app.models import (
    IncidentCreate, IncidentRead, IncidentTriageUpdate,
    Severity, IncidentStatus
)
from app.store import store
from app.classifier import classify_incident
from app.notifier import dispatch_notifications

@asynccontextmanager
async def lifespan(app: FastAPI):
    yield

app = FastAPI(title="Incident Triage Service", version="1.0.0", lifespan=lifespan)

@app.post("/incidents", response_model=IncidentRead, status_code=201)
async def create_incident(payload: IncidentCreate):
    dedup = store.find_duplicate(payload.fingerprint)
    if dedup:
        correlated = store.correlate(dedup.id, payload)
        return correlated
    severity, labels = classify_incident(payload)
    incident = store.create(payload, severity, labels)
    dispatch_notifications(incident)
    return incident

@app.get("/incidents/{incident_id}", response_model=IncidentRead)
async def get_incident(incident_id: str):
    incident = store.get(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident

@app.patch("/incidents/{incident_id}/triage", response_model=IncidentRead)
async def update_triage(incident_id: str, update: IncidentTriageUpdate):
    incident = store.get(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    updated = store.update_triage(incident_id, update)
    if update.status in (IncidentStatus.ACKNOWLEDGED, IncidentStatus.RESOLVED):
        dispatch_notifications(updated)
    return updated