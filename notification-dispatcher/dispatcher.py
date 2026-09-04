import time
import hashlib
import logging
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional
from collections import defaultdict

import httpx

logger = logging.getLogger(__name__)


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Channel(str, Enum):
    SLACK = "slack"
    PAGERDUTY = "pagerduty"
    EMAIL = "email"


@dataclass
class Incident:
    id: str
    title: str
    severity: Severity
    category: str
    description: str = ""
    metadata: dict = field(default_factory=dict)


@dataclass
class RoutingRule:
    channels: list[Channel]
    min_severity: Severity
    categories: list[str] = field(default_factory=list)

    _SEVERITY_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]

    def matches(self, incident: Incident) -> bool:
        sev_idx = self._SEVERITY_ORDER.index(self.min_severity)
        inc_idx = self._SEVERITY_ORDER.index(incident.severity)
        if inc_idx < sev_idx:
            return False
        if self.categories and incident.category not in self.categories:
            return False
        return True


DEFAULT_ROUTING_RULES: list[RoutingRule] = [
    RoutingRule(channels=[Channel.SLACK, Channel.PAGERDUTY, Channel.EMAIL], min_severity=Severity.CRITICAL),
    RoutingRule(channels=[Channel.SLACK, Channel.PAGERDUTY], min_severity=Severity.HIGH),
    RoutingRule(channels=[Channel.SLACK, Channel.EMAIL], min_severity=Severity.MEDIUM, categories=["security", "infra"]),
    RoutingRule(channels=[Channel.SLACK], min_severity=Severity.MEDIUM),
    RoutingRule(channels=[Channel.SLACK], min_severity=Severity.LOW),
]


class RateLimiter:
    def __init__(self, max_per_minute: int = 30, max_per_hour: int = 200):
        self.max_per_minute = max_per_minute
        self.max_per_hour = max_per_hour
        self._minute_buckets: dict[str, list[float]] = defaultdict(list)
        self._hour_buckets: dict[str, list[float]] = defaultdict(list)

    def _prune(self, bucket: list[float], window: float) -> list[float]:
        cutoff = time.time() - window
        return [t for t in bucket if t > cutoff]

    def is_allowed(self, key: str) -> bool:
        now = time.time()
        self._minute_buckets[key] = self._prune(self._minute_buckets[key], 60)
        self._hour_buckets[key] = self._prune(self._hour_buckets[key], 3600)
        if len(self._minute_buckets[key]) >= self.max_per_minute:
            return False
        if len(self._hour_buckets[key]) >= self.max_per_hour:
            return False
        self._minute_buckets[key].append(now)
        self._hour_buckets[key].append(now)
        return True


class SlackDispatcher:
    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url
        self._client = httpx.AsyncClient(timeout=10.0)

    async def send(self, incident: Incident) -> bool:
        severity_colors = {"critical": "#ff0000", "high": "#ff6600", "medium": "#ffcc00", "low": "#36a64f", "info": "#4393c3"}
        payload = {
            "attachments": [{
                "color": severity_colors.get(incident.severity.value, "#cccccc"),
                "title": f"[{incident.severity.value.upper()}] {incident.title}",
                "text": incident.description,
                "fields": [
                    {"title": "Incident ID", "value": incident.id, "short": True},
                    {"title": "Category", "value": incident.category, "short": True},
                ],
                "footer": "Incident Triage Service",
            }]
        }
        try:
            resp = await self._client.post(self.webhook_url, json=payload)
            resp.raise_for_status()
            logger.info("Slack notification sent for incident %s", incident.id)
            return True
        except httpx.HTTPError as exc:
            logger.error("Slack dispatch failed for %s: %s", incident.id, exc)
            return False

    async def close(self):
        await self._client.aclose()


class PagerDutyDispatcher:
    def __init__(self, routing_key: str, api_url: str = "https://events.pagerduty.com/v2/enqueue"):
        self.routing_key = routing_key
        self.api_url = api_url
        self._client = httpx.AsyncClient(timeout=10.0)

    async def send(self, incident: Incident) -> bool:
        severity_map = {"critical": "critical", "high": "critical", "medium": "warning", "low": "info", "info": "info"}
        payload = {
            "routing_key": self.routing_key,
            "event_action": "trigger",
            "payload": {
                "summary": incident.title,
                "severity": severity_map.get(incident.severity.value, "info"),
                "source": incident.metadata.get("source", "incident-triage"),
                "component": incident.category,
                "group": incident.id,
                "custom_details": {"description": incident.description},
            },
        }
        try:
            resp = await self._client.post(self.api_url, json=payload)
            resp.raise_for_status()
            logger.info("PagerDuty notification sent for incident %s", incident.id)
            return True
        except httpx.HTTPError as exc:
            logger.error("PagerDuty dispatch failed for %s: %s", incident.id, exc)
            return False

    async def close(self):
        await self._client.aclose()


class EmailDispatcher:
    def __init__(self, smtp_host: str, smtp_port: int, sender: str, recipients: list[str]):
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.sender = sender
        self.recipients = recipients

    async def send(self, incident: Incident) -> bool:
        import smtplib
        from email.mime.text import MIMEText

        msg = MIMEText(f"Incident: {incident.title}\n\nSeverity: {incident.severity.value}\nCategory: {incident.category}\n\n{incident.description}")
        msg["Subject"] = f"[{incident.severity.value.upper()}] {incident.title} — {incident.id}"
        msg["From"] = self.sender
        msg["To"] = ", ".join(self.recipients)
        try:
            with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=10) as srv:
                srv.send_message(msg)
            logger.info("Email notification sent for incident %s", incident.id)
            return True
        except Exception as exc:
            logger.error("Email dispatch failed for %s: %s", incident.id, exc)
            return False

    async def close(self):
        pass


class NotificationDispatcher:
    def __init__(
        self,
        slack: Optional[SlackDispatcher] = None,
        pagerduty: Optional[PagerDutyDispatcher] = None,
        email: Optional[EmailDispatcher] = None,
        routing_rules: Optional[list[RoutingRule]] = None,
        rate_limiter: Optional[RateLimiter] = None,
    ):
        self.slack = slack
        self.pagerduty = pagerduty
        self.email = email
        self.routing_rules = routing_rules or DEFAULT_ROUTING_RULES
        self.rate_limiter = rate_limiter or RateLimiter()
        self._channel_map: dict[Channel, Optional[object]] = {
            Channel.SLACK: self.slack,
            Channel.PAGERDUTY: self.pagerduty,
            Channel.EMAIL: self.email,
        }

    def resolve_channels(self, incident: Incident) -> list[Channel]:
        channels: set[Channel] = set()
        for rule in self.routing_rules:
            if rule.matches(incident):
                channels.update(rule.channels)
        return sorted(channels, key=lambda c: c.value)

    async def dispatch(self, incident: Incident) -> dict[str, bool]:
        rate_key = hashlib.sha256(f"{incident.id}:{incident.severity.value}".encode()).hexdigest()[:16]
        if not self.rate_limiter.is_allowed(rate_key):
            logger.warning("Rate limit exceeded for incident %s", incident.id)
            return {"rate_limited": False}

        channels = self.resolve_channels(incident)
        results: dict[str, bool] = {}
        for channel in channels:
            handler = self._channel_map.get(channel)
            if handler is None:
                logger.warning("No handler configured for channel %s", channel.value)
                results[channel.value] = False
                continue
            try:
                ok = await handler.send(incident)
                results[channel.value] = ok
            except Exception as exc:
                logger.error("Unhandled error on %s for %s: %s", channel.value, incident.id, exc)
                results[channel.value] = False
        return results

    async def close(self):
        for handler in self._channel_map.values():
            if handler is not None:
                await handler.close()