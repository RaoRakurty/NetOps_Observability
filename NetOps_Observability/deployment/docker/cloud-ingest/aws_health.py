# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""AWS Health provider incident/maintenance lane (Wave 5 #16).

The provider's OWN declaration that something is wrong (or scheduled) on its
side — the missing input whenever "is it us or is it AWS?" is the question.
DescribeEvents is free of charge, but the AWS Health API itself is only
AVAILABLE to accounts with a Business/Enterprise support plan: a Basic-support
account gets SubscriptionRequiredException. That is a structural fact, not a
transient error — it becomes an explicit source-status record
("requires AWS support plan …"), never a silent absence.

Checkpointed on lastUpdatedTime (the trail_state rule: advance over anything
SEEN; an empty window advances to the lagged now; never regress) so an event
UPDATE (open → closed) is re-read and re-emitted — the same event arn keys the
same downstream signal, and the latest observation wins on the read side
(/api/cloud/provider-events).

Emissions: normalized kind=provider_event records (cloud_events.provider_event)
onto netops.cloud — the EXISTING event pipeline; no new topic, no new consumer.
"""
from __future__ import annotations

import datetime as dt
import json
import time

import cloud_events
import source_status
import trail_state

# The AWS Health API is a global service homed in us-east-1.
HEALTH_REGION = "us-east-1"
SOURCE_TYPE = "provider_health"
# Bounded read: pages per cycle × 100 events/page.
PAGE_CAP = 10
# First run looks back this far (provider incidents age fast; a week covers
# the operationally-relevant tail without an unbounded backfill).
BACKFILL_S = 7 * 24 * 3600.0

SUPPORT_PLAN_DETAIL = ("provider incidents not available: the AWS Health API "
                      "requires a Business or Enterprise support plan "
                      "(SubscriptionRequiredException)")


def _log(msg: str, **kw) -> None:
    print(json.dumps({"ts": time.time(), "service": "cloud-ingest",
                      "component": "aws-health", "msg": msg, **kw}), flush=True)


def _is_subscription_required(exc: BaseException) -> bool:
    resp = getattr(exc, "response", None)
    if isinstance(resp, dict):
        code = str((resp.get("Error") or {}).get("Code") or "")
        return code == "SubscriptionRequiredException"
    return "SubscriptionRequiredException" in str(exc)


def _iso(ts) -> str:
    if hasattr(ts, "astimezone"):
        return (ts.astimezone(dt.timezone.utc).replace(microsecond=0)
                .isoformat().replace("+00:00", "Z"))
    return str(ts or "")


def normalize_event(ev: dict, tenant: str, account: str) -> dict | None:
    """One AWS Health event → a normalized provider_event record, or None when
    the event carries no identity (never guessed)."""
    arn = str(ev.get("arn") or "")
    service = str(ev.get("service") or "")
    if not arn or not service:
        return None
    category = str(ev.get("eventTypeCategory") or "")
    status = str(ev.get("statusCode") or "")
    code = str(ev.get("eventTypeCode") or "")
    # The DESCRIBE-level summary is the event type code, humanized — event
    # detail text needs DescribeEventDetails (a second call per event); the
    # code alone already answers "what kind of incident, where".
    summary = code.replace("_", " ").strip()
    ts = _iso(ev.get("lastUpdatedTime") or ev.get("startTime"))
    if not ts:
        return None
    return cloud_events.provider_event(
        provider="aws", tenant=tenant, event_arn=arn,
        region=str(ev.get("region") or "global"),
        service=service, category=category, status=status,
        summary=summary, ts=ts, account=account,
        attrs={"event_type_code": code,
               "start_time": _iso(ev.get("startTime")),
               "end_time": _iso(ev.get("endTime"))})


def poll(health, producer, tenant: str, account: str, st: dict,
         now: float | None = None) -> int:
    """One AWS Health poll: events updated since the checkpoint → normalized
    provider_event records on netops.cloud. Returns records emitted. Raises
    provider errors to the caller (run() classifies them)."""
    now = time.time() if now is None else now
    start = float(st.get("health_ts", now - BACKFILL_S))
    start_dt = dt.datetime.fromtimestamp(start + 0.001, dt.timezone.utc)
    newest = start
    sent = 0
    token = None
    events: list[dict] = []
    for _ in range(PAGE_CAP):
        kw = {"filter": {"lastUpdatedTimes": [{"from": start_dt}]},
              "maxResults": 100}
        if token:
            kw["nextToken"] = token
        resp = health.describe_events(**kw)
        events.extend(resp.get("events", []))
        token = resp.get("nextToken")
        if not token:
            break
    else:
        _log("health page ceiling hit — window truncated", pages=PAGE_CAP)
    for ev in events:
        upd = ev.get("lastUpdatedTime") or ev.get("startTime")
        if hasattr(upd, "timestamp"):
            newest = max(newest, upd.timestamp())
        rec = normalize_event(ev, tenant, account)
        if rec is None:
            continue
        producer.send("netops.cloud", rec)
        sent += 1
    if sent:
        producer.flush(10)
    # Health events are UPDATED in place; the delivery-lag guard keeps a quiet
    # window from skipping a just-updated event (the trail_state rule).
    st["health_ts"] = trail_state.advance_checkpoint(
        start, newest, bool(events), now)
    return sent


def run(health, producer, tenant: str, account: str, st: dict, *,
        region: str = HEALTH_REGION, connector_id: str = "") -> int:
    """The lane wrapper: poll + honest structured status.

    * Basic support plan → explicit "requires AWS support plan" record
      (misconfigured — the operator must change the plan, retrying won't).
    * IAM denial / misconfiguration → classified source-status record.
    * success → clears the record.
    Never raises — a health-lane hiccup must not touch the sibling lanes.
    """
    try:
        n = poll(health, producer, tenant, account, st)
    except Exception as exc:  # noqa: BLE001 — lane isolation
        if _is_subscription_required(exc):
            source_status.note_status(
                "aws", SOURCE_TYPE, "misconfigured", SUPPORT_PLAN_DETAIL,
                tenant=tenant, account=account, region=region,
                connector_id=connector_id)
            _log("aws health requires support plan", account=account)
            return 0
        status = source_status.note("aws", SOURCE_TYPE, exc, tenant=tenant,
                                    account=account, region=region,
                                    connector_id=connector_id)
        _log("aws health lane error", classified=status or "",
             error=str(exc)[:200])
        return 0
    source_status.clear("aws", SOURCE_TYPE, tenant=tenant,
                        account=account, region=region)
    return n
