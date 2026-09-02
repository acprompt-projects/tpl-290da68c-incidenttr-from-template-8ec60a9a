===
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class Severity(Enum):
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"


class Category(Enum):
    INFRA = "infra"
    APP = "app"
    SECURITY = "security"
    NETWORK = "network"


@dataclass
class TriageLabel:
    severity: Severity
    category: Category
    confidence: float
    matched_rules: list[str] = field(default_factory=list)
    suppress: bool = False


@dataclass
class ClassificationRule:
    name: str
    severity: Severity
    category: Category
    confidence: float
    suppress: bool = False
    keywords: list[str] = field(default_factory=list)
    source_match: Optional[str] = None
    metric_threshold: Optional[dict[str, Any]] = None


DEFAULT_RULES: list[ClassificationRule] = [
    ClassificationRule("infra_node_down", Severity.P1, Category.INFRA, 0.95,
                       keywords=["node down", "host unreachable", "server offline"],
                       source_match="prometheus",
                       metric_threshold={"cpu_percent": (95, None), "disk_percent": (98, None)}),
    ClassificationRule("infra_disk_critical", Severity.P1, Category.INFRA, 0.92,
                       keywords=["disk full", "no space left"],
                       metric_threshold={"disk_percent": (98, None)}),
    ClassificationRule("infra_high_cpu", Severity.P2, Category.INFRA, 0.85,
                       keywords=["high cpu", "cpu spike"],
                       metric_threshold={"cpu_percent": (85, 95)}),
    ClassificationRule("infra_disk_warning", Severity.P2, Category.INFRA, 0.82,
                       keywords=["disk usage high"],
                       metric_threshold={"disk_percent": (85, 98)}),
    ClassificationRule("infra_rolling_restart", Severity.P3, Category.INFRA, 0.70,
                       keywords=["rolling restart", "node maintenance"]),
    ClassificationRule("app_5xx_spike", Severity.P1, Category.APP, 0.93,
                       keywords=["5xx spike", "error rate critical", "circuit breaker open"],
                       metric_threshold={"error_rate_percent": (50, None)}),
    ClassificationRule("app_error_rate_high", Severity.P2, Category.APP, 0.85,
                       keywords=["error rate high", "increased failures"],
                       metric_threshold={"error_rate_percent": (10, 50)}),
    ClassificationRule("app_deployment_failed", Severity.P2, Category.APP, 0.88,
                       keywords=["deployment failed", "rollback triggered", "deploy error"]),
    ClassificationRule("app_latency", Severity.P3, Category.APP, 0.75,
                       keywords=["latency high", "slow response", "timeout"],
                       metric_threshold={"latency_ms": (2000, None)}),
    ClassificationRule("app_healthcheck_flap", Severity.P4, Category.APP, 0.60,
                       keywords=["healthcheck flapping"]),
    ClassificationRule("security_breach", Severity.P1, Category.SECURITY, 0.97,
                       keywords=["unauthorized access", "data breach", "credential leak", "ransomware"]),
    ClassificationRule("security_intrusion", Severity.P1, Category.SECURITY, 0.94,
                       keywords=["intrusion detected", "malware", "exploit attempted"],
                       source_match="ids"),
    ClassificationRule("security_vuln", Severity.P2, Category.SECURITY, 0.80,
                       keywords=["vulnerability detected", "cve-", "outdated certificate"]),
    ClassificationRule("security_auth_spike", Severity.P2, Category.SECURITY, 0.78,
                       keywords=["auth failure spike", "brute force"],
                       metric_threshold={"auth_fail_count": (100, None)}),
    ClassificationRule("security_cert_expiry", Severity.P3, Category.SECURITY, 0.72,
                       keywords=["certificate expiring"]),
    ClassificationRule("network_outage", Severity.P1, Category.NETWORK, 0.95,
                       keywords=["network down", "connectivity lost", "bgp down", "full outage"]),
    ClassificationRule("network_packet_loss", Severity.P2, Category.NETWORK, 0.82,
                       keywords=["packet loss", "high latency network"],
                       metric_threshold={"packet_loss_percent": (5, None)}),
    ClassificationRule("network_dns", Severity.P2, Category.NETWORK, 0.80,
                       keywords=["dns failure", "dns timeout"]),
    ClassificationRule("network_flapping", Severity.P3, Category.NETWORK, 0.70,
                       keywords=["link flapping", "route flap"]),
    ClassificationRule("suppress_noise", Severity.P4, Category.APP, 0.50,
                       suppress=True,
                       keywords=["test alert", "sandbox", "maintenance window"]),
]


def _text_match(keywords: list[str], text: str) -> bool:
    text_lower = text.lower()
    return any(kw in text_lower for kw in keywords)


def _metric_match(threshold: Optional[dict[str, Any]], metrics: dict[str, float]) -> bool:
    if threshold is None:
        return False
    for metric_name, bounds in threshold.items():
        value = metrics.get(metric_name)
        if value is None:
            continue
        low, high = bounds
        if low is not None and value >= low:
            if high is None or value < high:
                return True
    return False


def _source_match(expected: Optional[str], source: str) -> bool:
    if expected is None:
        return True
    return source.lower() == expected.lower()


class IncidentClassifier:
    def __init__(self, rules: Optional[list[ClassificationRule]] = None):
        self.rules = rules if rules is not None else list(DEFAULT_RULES)

    def classify(self, incident: dict[str, Any]) -> TriageLabel:
        title = incident.get("title", "")
        body = incident.get("body", "")
        source = incident.get("source", "")
        metrics: dict[str, float] = incident.get("metrics", {}) or {}
        combined_text = f"{title} {body}"

        candidates: list[TriageLabel] = []

        for rule in self.rules:
            score = 0.0
            matched: list[str] = []

            kw_hit = _text_match(rule.keywords, combined_text)
            metric_hit = _metric_match(rule.metric_threshold, metrics)
            src_hit = _source_match(rule.source_match, source)

            if rule.keywords and kw_hit:
                score += 0.5
                matched.append("keywords")
            if rule.metric_threshold and metric_hit:
                score += 0.35
                matched.append("metrics")
            if rule.source_match and src_hit:
                score += 0.15
                matched.append("source")

            if not rule.keywords and not rule.metric_threshold and not rule.source_match:
                continue
            if score == 0:
                continue

            confidence = min(rule.confidence * score / 0.5, 1.0) if score < 0.5 else rule.confidence
            candidates.append(TriageLabel(
                severity=rule.severity,
                category=rule.category,
                confidence=round(confidence, 3),
                matched_rules=[rule.name],
                suppress=rule.suppress,
            ))

        if not candidates:
            return TriageLabel(
                severity=Severity.P4,
                category=Category.APP,
                confidence=0.3,
                matched_rules=["default_fallback"],
            )

        candidates.sort(key=lambda c: (c.suppress, -_severity_rank(c.severity), -c.confidence))
        best = candidates[0]
        for c in candidates[1:]:
            if c.severity == best.severity and c.category == best.category and not c.suppress:
                best.matched_rules.extend(c.matched_rules)
                best.confidence = min(round((best.confidence + c.confidence) / 2, 3), 1.0)
        return best


def _severity_rank(s: Severity) -> int:
    return {Severity.P1: 4, Severity.P2: 3, Severity.P3: 2, Severity.P4: 1}[s]


def classify_incident(incident: dict[str, Any], rules: Optional[list[ClassificationRule]] = None) -> dict:
    classifier = IncidentClassifier(rules)
    label = classifier.classify(incident)
    return {
        "severity": label.severity.value,
        "category": label.category.value,
        "confidence": label.confidence,
        "matched_rules": label.matched_rules,
        "suppress": label.suppress,
    }