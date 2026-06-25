"""Tests for the cloud log parsers — #81 P3B.

Proves AWS ALB access logs + VPC flow logs parse into the canonical netops.cloud
contract, that ONLY signal-worthy records (ELB-side 5xx, flow REJECT) become
signals, and that the emitted dicts round-trip through the ingestion lane
(cloud_signal_from_event) into valid cloud Signals — so P3B output plugs straight
into the engine.
"""

from __future__ import annotations

from datetime import datetime, timezone

from cloud_log_parsers import (
    alb_lb_signal,
    cloud_log_event,
    parse_alb_access_log,
    parse_vpc_flow_log,
    vpc_flow_signal,
)
from cloud_producers import cloud_signal_from_event
from signals import EntityType, ModalityClass, Source

TS = datetime(2026, 6, 25, 12, 0, 0, tzinfo=timezone.utc)

# A real-shape ALB access-log line (5xx variant) — 29 documented fields.
ALB_5XX = (
    'http 2026-06-25T22:00:00.000000Z app/billing-alb/0a1b2c3d '
    '203.0.113.10:54321 10.0.1.20:443 0.001 0.002 0.000 502 502 412 900 '
    '"GET https://billing.example.com:443/pay HTTP/1.1" "curl/8.0" '
    'ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 '
    'arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/billing-tg/abc123 '
    '"Root=1-abc" "billing.example.com" "-" 0 2026-06-25T21:59:59.000000Z '
    '"forward" "-" "-" "10.0.1.20:443" "502" "-" "-"'
)
ALB_200 = ALB_5XX.replace(" 502 502 ", " 200 200 ")

VPC_REJECT = "2 123456789012 eni-0abc123 203.0.113.55 10.0.1.20 44321 443 6 8 480 1719352800 1719352830 REJECT OK"
VPC_ACCEPT = VPC_REJECT.replace("REJECT", "ACCEPT")
VPC_NODATA = "2 123456789012 eni-0abc123 - - - - - - - 1719352800 1719352830 - NODATA"


# ── ALB ──────────────────────────────────────────────────────────────────────

def test_alb_parse_extracts_fields_and_arn():
    r = parse_alb_access_log(ALB_5XX)
    assert r is not None
    assert r["elb"] == "app/billing-alb/0a1b2c3d"
    assert r["elb_status_code"] == "502"
    assert r["domain_name"] == "billing.example.com"
    assert r["region"] == "us-east-1" and r["account"] == "123456789012"


def test_alb_5xx_becomes_cloud_lb_signal_and_round_trips():
    ev = alb_lb_signal(parse_alb_access_log(ALB_5XX))
    assert ev is not None
    assert ev["kind"] == "cloud_lb_log" and ev["resource_id"] == "app/billing-alb/0a1b2c3d"
    assert ev["account"] == "123456789012" and ev["region"] == "us-east-1"
    assert ev["attrs"]["domain"] == "billing.example.com"
    # round-trips through the ingestion lane into a valid cloud Signal
    sig = cloud_signal_from_event(ev, "acme", TS)
    assert sig.source is Source.CLOUD and sig.kind == "cloud_lb_log"
    assert sig.modality_class is ModalityClass.PASSIVE_FLOW
    assert sig.entity_type is EntityType.CLOUD_RESOURCE and sig.entity_id == "app/billing-alb/0a1b2c3d"


def test_alb_non_5xx_is_not_a_signal():
    assert alb_lb_signal(parse_alb_access_log(ALB_200)) is None


def test_alb_malformed_returns_none():
    assert parse_alb_access_log("") is None
    assert parse_alb_access_log("not a real alb line") is None
    assert alb_lb_signal(None) is None


# ── VPC flow logs ────────────────────────────────────────────────────────────

def test_vpc_parse_maps_by_name():
    r = parse_vpc_flow_log(VPC_REJECT)
    assert r is not None
    assert r["interface-id"] == "eni-0abc123" and r["action"] == "REJECT"
    assert r["dstport"] == "443" and r["account-id"] == "123456789012"


def test_vpc_reject_becomes_cloud_flow_signal_and_round_trips():
    ev = vpc_flow_signal(parse_vpc_flow_log(VPC_REJECT))
    assert ev is not None
    assert ev["kind"] == "cloud_flow_log" and ev["resource_id"] == "eni-0abc123"
    assert ev["attrs"]["protocol"] == "tcp" and ev["attrs"]["dstport"] == "443"
    sig = cloud_signal_from_event(ev, "acme", TS)
    assert sig.source is Source.CLOUD and sig.kind == "cloud_flow_log"
    assert sig.entity_type is EntityType.CLOUD_RESOURCE and sig.entity_id == "eni-0abc123"


def test_vpc_accept_and_nodata_are_not_signals():
    assert vpc_flow_signal(parse_vpc_flow_log(VPC_ACCEPT)) is None  # ACCEPT = volume, not fault
    assert parse_vpc_flow_log(VPC_NODATA) is None                   # NODATA carries no 5-tuple


def test_vpc_custom_field_layout_maps_by_name():
    fields = ("action", "interface-id", "account-id", "srcaddr", "dstaddr", "dstport", "protocol", "bytes", "log-status")
    line = "REJECT eni-9 999999999999 1.1.1.1 2.2.2.2 22 6 64 OK"
    ev = vpc_flow_signal(parse_vpc_flow_log(line, fields))
    assert ev is not None and ev["resource_id"] == "eni-9" and ev["account"] == "999999999999"
    assert ev["attrs"]["dstport"] == "22"


def test_vpc_wrong_field_count_returns_none():
    assert parse_vpc_flow_log("2 123456789012 eni-0abc123 REJECT") is None


# ── runtime dispatch (the file tailer's per-line router) ─────────────────────

def test_cloud_log_event_dispatch_by_extension():
    assert cloud_log_event("billing.alb", ALB_5XX)["kind"] == "cloud_lb_log"
    assert cloud_log_event("prod.vpc", VPC_REJECT)["kind"] == "cloud_flow_log"
    assert cloud_log_event("billing.alb", ALB_200) is None    # non-5xx → no signal
    assert cloud_log_event("notes.txt", ALB_5XX) is None       # unknown extension ignored
