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
    dns_error_rollup,
    parse_alb_access_log,
    parse_aws_waf_log,
    parse_r53_dns_log,
    parse_vpc_flow_log,
    vpc_accept_rollup,
    vpc_flow_signal,
    waf_block_rollup,
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


# ── ACCEPT volume rollup + event time + provider stamp (audit P1-6/P1-7/P0-7) ─

def test_vpc_reject_carries_event_time_and_provider():
    ev = vpc_flow_signal(parse_vpc_flow_log(VPC_REJECT))
    assert ev["ts"] == "2024-06-25T22:00:30Z"      # the record's own 'end' epoch
    assert ev["attrs"]["provider"] == "aws"        # parse fact, facets the matrix


def test_alb_signal_carries_provider():
    assert alb_lb_signal(parse_alb_access_log(ALB_5XX))["attrs"]["provider"] == "aws"


def test_vpc_accept_rollup_aggregates_per_eni():
    recs = [parse_vpc_flow_log(VPC_ACCEPT) for _ in range(3)]
    recs.append(parse_vpc_flow_log(VPC_ACCEPT.replace("eni-0abc123", "eni-0other1")))
    recs.append(parse_vpc_flow_log(VPC_REJECT))  # REJECT never enters the volume lane
    out = vpc_accept_rollup(recs)
    assert [e["resource_id"] for e in out] == ["eni-0abc123", "eni-0other1"]
    first = out[0]
    assert first["kind"] == "cloud_flow_volume" and first["severity"] == "info"
    assert first["value"] == 3 * 480.0 and first["attrs"]["flows"] == "3"
    assert first["ts"] == "2024-06-25T22:00:30Z"
    assert first["attrs"]["provider"] == "aws"
    sig = cloud_signal_from_event(first, "acme", TS)
    assert sig.kind == "cloud_flow_volume" and sig.entity_id == "eni-0abc123"


def test_vpc_accept_rollup_empty_batch_is_empty():
    assert vpc_accept_rollup([]) == []


# ── WAF + DNS lanes (log-fidelity program) ────────────────────────────────────

WAF_BLOCK = ('{"timestamp":1719352800000,"formatVersion":1,"webaclId":'
             '"arn:aws:wafv2:us-west-2:123456789012:regional/webacl/correlix/abc",'
             '"action":"BLOCK","terminatingRuleId":"rate-limit-api",'
             '"httpRequest":{"clientIp":"203.0.113.9","uri":"/api/pay","httpMethod":"POST",'
             '"headers":[{"name":"Host","value":"billing.example.com"}]}}')
WAF_ALLOW = WAF_BLOCK.replace('"action":"BLOCK"', '"action":"ALLOW"')

DNS_NX = ('{"version":"1.1","account_id":"123456789012","region":"us-west-2",'
          '"vpc_id":"vpc-01","query_timestamp":"2026-06-25T22:00:30Z",'
          '"query_name":"db.internal.example.com.","query_type":"A","query_class":"IN",'
          '"rcode":"NXDOMAIN","answers":[],"srcaddr":"10.60.10.10","srcport":"53511"}')
DNS_OK = DNS_NX.replace('"rcode":"NXDOMAIN"', '"rcode":"NOERROR"')


def test_waf_block_rollup_aggregates_per_rule():
    recs = [parse_aws_waf_log(WAF_BLOCK) for _ in range(4)]
    recs.append(parse_aws_waf_log(WAF_ALLOW))  # ALLOW is volume, never a signal
    out = waf_block_rollup(recs)
    assert len(out) == 1
    ev = out[0]
    assert ev["kind"] == "cloud_waf_log" and ev["value"] == 4.0
    assert ev["attrs"]["rule"] == "rate-limit-api"
    assert ev["attrs"]["provider"] == "aws"
    assert ev["attrs"]["host"] == "billing.example.com"
    assert ev["ts"] == "2024-06-25T22:00:00Z"
    sig = cloud_signal_from_event(ev, "acme", TS)
    assert sig.kind == "cloud_waf_log" and sig.entity_id.endswith("/webacl/correlix/abc")


def test_dns_error_rollup_aggregates_per_name_and_rcode():
    recs = [parse_r53_dns_log(DNS_NX) for _ in range(3)]
    recs.append(parse_r53_dns_log(DNS_OK))  # NOERROR is volume, never a signal
    out = dns_error_rollup(recs)
    assert len(out) == 1
    ev = out[0]
    assert ev["kind"] == "cloud_dns_log" and ev["value"] == 3.0
    assert ev["resource_id"] == "db.internal.example.com"  # trailing dot stripped
    assert ev["attrs"]["rcode"] == "NXDOMAIN"
    sig = cloud_signal_from_event(ev, "acme", TS)
    assert sig.kind == "cloud_dns_log"
    assert str(sig.entity_type).endswith("SERVICE")  # the NAME is the entity
    assert sig.entity_id == "db.internal.example.com"


def test_waf_dns_malformed_lines_return_none():
    assert parse_aws_waf_log("not json") is None
    assert parse_aws_waf_log('{"no":"waf fields"}') is None
    assert parse_r53_dns_log("garbage") is None
    assert dns_error_rollup([]) == []
    assert waf_block_rollup([]) == []
