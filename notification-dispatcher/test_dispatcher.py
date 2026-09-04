import asyncio
from unittest.mock import AsyncMock, patch

from dispatcher import (
    NotificationDispatcher, Incident, Severity, Channel,
    RoutingRule, RateLimiter, SlackDispatcher, PagerDutyDispatcher, EmailDispatcher,
)


def _incident(severity: Severity = Severity.HIGH, category: str = "infra") -> Incident:
    return Incident(id="inc-001", title="DB replica lag", severity=severity, category=category, description="Replication lag > 60s")


def test_routing_rules():
    inc_crit_sec = _incident(Severity.CRITICAL, "security")
    inc_high_inf = _incident(Severity.HIGH, "infra")
    inc_med_app = _incident(Severity.MEDIUM, "application")
    inc_low = _incident(Severity.LOW, "misc")

    disp = NotificationDispatcher()
    assert Channel.PAGERDUTY in disp.resolve_channels(inc_crit_sec)
    assert Channel.EMAIL in disp.resolve_channels(inc_crit_sec)
    assert Channel.PAGERDUTY in disp.resolve_channels(inc_high_inf)
    assert Channel.SLACK in disp.resolve_channels(inc_med_app)
    assert Channel.PAGERDUTY not in disp.resolve_channels(inc_med_app)
    assert Channel.SLACK in disp.resolve_channels(inc_low)


def test_custom_routing():
    rules = [RoutingRule(channels=[Channel.EMAIL], min_severity=Severity.MEDIUM, categories=["security"])]
    disp = NotificationDispatcher(routing_rules=rules)
    inc = _incident(Severity.HIGH, "security")
    assert disp.resolve_channels(inc) == [Channel.EMAIL]
    inc2 = _incident(Severity.HIGH, "infra")
    assert disp.resolve_channels(inc2) == []


def test_rate_limiter():
    rl = RateLimiter(max_per_minute=3, max_per_hour=100)
    assert rl.is_allowed("key")
    assert rl.is_allowed("key")
    assert rl.is_allowed("key")
    assert not rl.is_allowed("key")
    assert rl.is_allowed("other_key")


def test_dispatch_routes_to_correct_channels():
    slack_mock = AsyncMock(spec=SlackDispatcher, webhook_url="http://x")
    slack_mock.send = AsyncMock(return_value=True)
    slack_mock.close = AsyncMock()
    pd_mock = AsyncMock(spec=PagerDutyDispatcher, routing_key="rk", api_url="http://x")
    pd_mock.send = AsyncMock(return_value=True)
    pd_mock.close = AsyncMock()
    disp = NotificationDispatcher(slack=slack_mock, pagerduty=pd_mock)
    inc = _incident(Severity.HIGH, "infra")
    result = asyncio.get_event_loop().run_until_complete(disp.dispatch(inc))
    assert result.get("slack") is True
    assert result.get("pagerduty") is True
    assert "email" not in result


def test_dispatch_rate_limited():
    disp = NotificationDispatcher(rate_limiter=RateLimiter(max_per_minute=0, max_per_hour=0))
    inc = _incident()
    result = asyncio.get_event_loop().run_until_complete(disp.dispatch(inc))
    assert result == {"rate_limited": False}


if __name__ == "__main__":
    test_routing_rules()
    test_custom_routing()
    test_rate_limiter()
    test_dispatch_routes_to_correct_channels()
    test_dispatch_rate_limited()
    print("All tests passed!")