# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""AWS Health provider-incident lane tests (Wave 5 #16) — fake API responses,
no live calls. Pins: normalization (arn identity, category→severity), the
checkpoint discipline (advance over anything seen; never regress), and the
honest support-plan denial (structured status, never silence)."""
from __future__ import annotations

import datetime as dt
import time

import aws_health
import cloud_events
import source_status

T0 = dt.datetime(2026, 7, 18, 12, 0, tzinfo=dt.timezone.utc)

EVENT = {
    "arn": "arn:aws:health:us-west-2::event/EC2/AWS_EC2_OPERATIONAL_ISSUE/abc",
    "service": "EC2",
    "eventTypeCode": "AWS_EC2_OPERATIONAL_ISSUE",
    "eventTypeCategory": "issue",
    "region": "us-west-2",
    "statusCode": "open",
    "startTime": T0,
    "lastUpdatedTime": T0,
}


class _Producer:
    def __init__(self):
        self.sent = []

    def send(self, topic, rec):
        self.sent.append((topic, rec))

    def flush(self, timeout=None):
        pass


class _Health:
    def __init__(self, events, error=None):
        self.events = events
        self.error = error
        self.calls = 0

    def describe_events(self, **kw):
        self.calls += 1
        if self.error is not None:
            raise self.error
        return {"events": self.events}


def _client_error(code: str) -> Exception:
    exc = Exception(f"An error occurred ({code}) when calling DescribeEvents")
    exc.response = {"Error": {"Code": code},
                    "ResponseMetadata": {"HTTPStatusCode": 400}}
    return exc


# ── normalization ────────────────────────────────────────────────────────────

def test_normalize_event_shape_and_severity():
    rec = aws_health.normalize_event(EVENT, "t1", "123")
    assert rec["kind"] == "provider_event"
    assert rec["tenant_id"] == "t1"
    assert rec["provider"] == "aws"
    assert rec["resource_id"] == EVENT["arn"]
    assert rec["region"] == "us-west-2"
    assert rec["severity"] == "high"  # an active issue is high
    assert rec["attrs"]["service"] == "EC2"
    assert rec["attrs"]["category"] == "issue"
    assert rec["attrs"]["status"] == "open"
    assert "OPERATIONAL ISSUE" in rec["attrs"]["summary"]


def test_normalize_scheduled_change_warns_and_notification_informs():
    sched = dict(EVENT, eventTypeCategory="scheduledChange")
    note = dict(EVENT, eventTypeCategory="accountNotification")
    assert aws_health.normalize_event(sched, "t", "1")["severity"] == "warn"
    assert aws_health.normalize_event(note, "t", "1")["severity"] == "info"


def test_normalize_event_without_identity_is_dropped_not_guessed():
    assert aws_health.normalize_event({"service": "EC2"}, "t", "1") is None
    assert aws_health.normalize_event({"arn": "a"}, "t", "1") is None


def test_provider_event_builder_rejects_blank_identity():
    try:
        cloud_events.provider_event(
            provider="aws", tenant="t", event_arn="", region="r",
            service="EC2", category="issue", status="open", summary="s",
            ts="2026-07-18T12:00:00Z")
        raise AssertionError("expected ValueError")
    except ValueError:
        pass


# ── poll: emission + checkpoint discipline ───────────────────────────────────

def test_poll_emits_and_advances_checkpoint_on_events():
    p = _Producer()
    st = {}
    n = aws_health.poll(_Health([EVENT]), p, "t1", "123", st,
                        now=T0.timestamp() + 600)
    assert n == 1
    topic, rec = p.sent[0]
    assert topic == "netops.cloud"
    assert rec["kind"] == "provider_event"
    assert st["health_ts"] == T0.timestamp()  # anchored on the newest SEEN


def test_poll_empty_window_advances_to_lagged_now_never_regresses():
    p = _Producer()
    now = time.time()
    st = {"health_ts": now - 3600}
    aws_health.poll(_Health([]), p, "t1", "123", st, now=now)
    assert st["health_ts"] > now - 3600  # empty window still advances
    assert st["health_ts"] <= now  # but never into the future
    # never regresses
    st2 = {"health_ts": now + 100}
    aws_health.poll(_Health([]), p, "t1", "123", st2, now=now)
    assert st2["health_ts"] == now + 100


# ── run: honest structured status ────────────────────────────────────────────

def test_run_basic_support_plan_reports_requires_support_plan():
    source_status.reset()
    p = _Producer()
    n = aws_health.run(_Health([], error=_client_error("SubscriptionRequiredException")),
                       p, "t1", "123", {})
    assert n == 0
    key = ("t1", "aws", "123", aws_health.HEALTH_REGION, "provider_health")
    rec = source_status._active[key]
    assert rec["status"] == "misconfigured"
    assert "requires a Business or Enterprise support plan" in rec["detail"]
    source_status.reset()


def test_run_iam_denial_classifies_and_success_clears():
    source_status.reset()
    p = _Producer()
    denied = _client_error("AccessDeniedException")
    denied.response["ResponseMetadata"]["HTTPStatusCode"] = 403
    aws_health.run(_Health([], error=denied), p, "t1", "123", {})
    key = ("t1", "aws", "123", aws_health.HEALTH_REGION, "provider_health")
    assert source_status._active[key]["status"] == "permission_denied"
    aws_health.run(_Health([EVENT]), p, "t1", "123", {})
    assert key not in source_status._active
    source_status.reset()


def test_run_never_raises_on_transient_error():
    source_status.reset()
    p = _Producer()
    n = aws_health.run(_Health([], error=RuntimeError("socket timeout")),
                       p, "t1", "123", {})
    assert n == 0  # logged, isolated, no structured status (not ours to claim)
    assert source_status._active == {}
    source_status.reset()
