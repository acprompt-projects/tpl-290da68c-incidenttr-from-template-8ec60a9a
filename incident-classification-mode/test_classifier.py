===
import pytest
from classifier import (
    IncidentClassifier, ClassificationRule, Severity, Category,
    TriageLabel, classify_incident, DEFAULT_RULES,
)


def test_infra_node_down_severity_p1():
    incident = {"title": "node down in us-east-1", "body": "", "source": "prometheus", "metrics": {}}
    result = classify_incident(incident)
    assert result["severity"] == "P1"
    assert result["category"] == "infra"
    assert not result["suppress"]


def test_infra_cpu_metric_threshold():
    incident = {"title": "alert", "body": "cpu high", "source": "prometheus",
                "metrics": {"cpu_percent": 90}}
    result = classify_incident(incident)
    assert result["severity"] == "P2"
    assert result["category"] == "infra"


def test_app_5xx_spike():
    incident = {"title": "5xx spike detected", "body": "error rate critical", "source": "grafana",
                "metrics": {"error_rate_percent": 60}}
    result = classify_incident(incident)
    assert result["severity"] == "P1"
    assert result["category"] == "app"


def test_security_breach():
    incident = {"title": "unauthorized access detected", "body": "credential leak", "source": "ids"}
    result = classify_incident(incident)
    assert result["severity"] == "P1"
    assert result["category"] == "security"


def test_network_outage():
    incident = {"title": "network down", "body": "bgp down detected", "source": "nagios"}
    result = classify_incident(incident)
    assert result["severity"] == "P1"
    assert result["category"] == "network"


def test_suppress_noise():
    incident = {"title": "test alert from sandbox", "body": "", "source": "ci"}
    result = classify_incident(incident)
    assert result["suppress"] is True


def test_fallback_when_no_match():
    incident = {"title": "something weird", "body": "no keywords match", "source": "custom",
                "metrics": {}}
    result = classify_incident(incident)
    assert result["severity"] == "P4"
    assert result["category"] == "app"
    assert result["matched_rules"] == ["default_fallback"]


def test_custom_rule_overrides():
    custom = [ClassificationRule("custom_rule", Severity.P1, Category.SECURITY, 0.99,
                                  keywords=["xyz-trigger"])]
    incident = {"title": "xyz-trigger fired", "body": "", "source": "custom", "metrics": {}}
    result = classify_incident(incident, rules=custom)
    assert result["severity"] == "P1"
    assert result["category"] == "security"
    assert result["matched_rules"] == ["custom_rule"]


def test_metric_threshold_with_bounds():
    incident = {"title": "alert", "body": "", "source": "prometheus",
                "metrics": {"cpu_percent": 92}}
    result = classify_incident(incident)
    assert result["severity"] == "P2"


def test_source_match_filters():
    incident = {"title": "node down", "body": "", "source": "grafana", "metrics": {}}
    result = classify_incident(incident)
    assert result["severity"] == "P1"
    assert result["category"] == "infra"


def test_classifier_returns_triage_label():
    classifier = IncidentClassifier()
    label = classifier.classify({"title": "dns failure", "body": "", "source": "", "metrics": {}})
    assert isinstance(label, TriageLabel)
    assert label.severity == Severity.P2
    assert label.category == Category.NETWORK