from app.models import IncidentCreate, Severity

_KEYWORD_MAP: dict[Severity, list[str]] = {
    Severity.CRITICAL: ["outage", "down", "data_loss", "breach"],
    Severity.HIGH: ["degradation", "error_rate", "timeout", "failover"],
    Severity.MEDIUM: ["warning", "retry", "slow", "latency"],
    Severity.LOW: ["info", "notice", "flap"],
}

_TEAM_MAP: dict[str, str] = {
    "payments": "finops",
    "auth": "identity",
    "infra": "sre",
    "database": "data-eng",
}

def classify_incident(payload: IncidentCreate) -> tuple[Severity, dict[str, str]]:
    text = (payload.title + " " + payload.description).lower()
    severity = Severity.INFO
    for sev, keywords in _KEYWORD_MAP.items():
        if any(kw in text for kw in keywords):
            severity = sev
            break
    labels: dict[str, str] = {}
    for service_key, team in _TEAM_MAP.items():
        if service_key in payload.source.service.lower():
            labels["assigned_team"] = team
            break
    if "prod" in payload.source.environment.lower():
        labels["env_tier"] = "production"
    elif "staging" in payload.source.environment.lower():
        labels["env_tier"] = "staging"
    return severity, labels