import os, logging, json
from app.models import IncidentRead

logger = logging.getLogger(__name__)

SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")
PAGERDUTY_ROUTING_KEY = os.getenv("PAGERDUTY_ROUTING_KEY", "")

def _post(url: str, payload: dict) -> None:
    try:
        import urllib.request
        req = urllib.request.Request(
            url, data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            logger.info("Notification sent to %s – status %s", url, resp.status)
    except Exception as exc:
        logger.warning("Notification failed for %s: %s", url, exc)

def dispatch_notifications(incident: IncidentRead) -> None:
    if SLACK_WEBHOOK_URL:
        _post(SLACK_WEBHOOK_URL, {
            "text": f"[{incident.severity.value.upper()}] {incident.title} – {incident.id} ({incident.status.value})"
        })
    if PAGERDUTY_ROUTING_KEY and incident.severity in (
        IncidentRead.__fields__["severity"].type_.CRITICAL,
        IncidentRead.__fields__["severity"].type_.HIGH,
    ):
        _post("https://events.pagerduty.com/v2/enqueue", {
            "routing_key": PAGERDUTY_ROUTING_KEY,
            "event_action": "trigger",
            "payload": {
                "summary": incident.title,
                "severity": incident.severity.value,
                "source": incident.source.service,
                "group": incident.source.environment,
            },
        })