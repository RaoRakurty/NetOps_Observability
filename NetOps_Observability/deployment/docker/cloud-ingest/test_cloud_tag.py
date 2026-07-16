"""Unit tests for cloud_tag — the ingest-side family/provider/resource tagging
that makes raw cloud logs searchable as `cloud_family:… cloud_provider:…`.

Pure module (no boto3/kafka), so these run standalone. They pin: the family is
taken from the lane file extension, the provider from its prefix (never guessed
from content), resource_id is extracted from the right place per family, the
tenant is REQUIRED (never an untagged/cross-tenant bucket — §3a), and an
unrecognized lane/line degrades to None (honest drop, never a fabricated tag)."""
import json

import cloud_tag

ALB_LINE = (
    'http 2026-07-15T00:00:00.000000Z app/billing-alb/0a1b2c3d4e5f6a7b '
    '10.0.0.9:52111 10.0.1.20:8080 0.001 0.010 0.000 502 502 34 136 '
    '"GET http://billing.example.com:80/health HTTP/1.1" "curl/8" - - '
    'arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/billing-tg/abc '
    '"Root=1-x" "billing.example.com" "-" 0 2026-07-15T00:00:00.000000Z "forward" "-" "-" '
    '"10.0.1.20:8080" "502" "-" "-"'
)
VPC_LINE = "2 123456789012 eni-0abc12345 10.0.0.5 10.0.1.9 44321 22 6 6 360 1620000000 1620000060 REJECT OK"
WAF_LINE = json.dumps({
    "webaclId": "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/edge-acl/abc",
    "action": "BLOCK", "terminatingRuleId": "rate-limit",
    "httpRequest": {"uri": "/login", "clientIp": "203.0.113.7"},
})
DNS_LINE = json.dumps({"query_name": "api.example.com.", "rcode": "SERVFAIL", "srcaddr": "10.0.0.5"})


def test_family_and_provider_from_lane_name():
    assert cloud_tag.family_for("aws-vpc-flow.vpc") == "flow"
    assert cloud_tag.family_for("aws-alb-access.alb") == "lb"
    assert cloud_tag.family_for("aws-waf.waf") == "waf"
    assert cloud_tag.family_for("aws-r53-resolver.dns") == "dns"
    assert cloud_tag.family_for("mystery.txt") == ""
    assert cloud_tag.provider_for("aws-waf.waf") == "aws"
    assert cloud_tag.provider_for("gcp-lb.waf") == "gcp"
    assert cloud_tag.provider_for("weird.waf") == ""  # unknown prefix, never guessed


def test_resource_id_per_family():
    assert cloud_tag.resource_id_for("flow", VPC_LINE) == "eni-0abc12345"
    assert cloud_tag.resource_id_for("lb", ALB_LINE) == "app/billing-alb/0a1b2c3d4e5f6a7b"
    assert "edge-acl" in cloud_tag.resource_id_for("waf", WAF_LINE)
    assert cloud_tag.resource_id_for("dns", DNS_LINE) == "api.example.com"  # trailing dot stripped
    # A header/garbage flow line yields no resource id (not a fabricated one).
    assert cloud_tag.resource_id_for("flow", "version account-id interface-id") == ""


def test_cloud_log_doc_is_fully_tagged():
    doc = cloud_tag.cloud_log_doc("aws-waf.waf", WAF_LINE, "acme",
                                  account="123456789012", region="us-east-1",
                                  timestamp="2026-07-15T00:00:00Z")
    assert doc["tenant_id"] == "acme"
    assert doc["cloud_family"] == "waf"
    assert doc["cloud_provider"] == "aws"
    assert "edge-acl" in doc["resource_id"]
    assert doc["message"] == WAF_LINE
    assert doc["timestamp"] == "2026-07-15T00:00:00Z"
    assert doc["source_type"] == "cloud"


def test_tenant_is_required_no_untagged_bucket():
    # §3a: cloud logs are tenant-scoped. An empty tenant must NOT produce a doc
    # (which would land in an untagged/cross-tenant bucket) — it drops instead.
    assert cloud_tag.cloud_log_doc("aws-waf.waf", WAF_LINE, "") is None


def test_unrecognized_lane_and_blank_drop():
    assert cloud_tag.cloud_log_doc("mystery.txt", "hello", "acme") is None
    assert cloud_tag.cloud_log_doc("aws-waf.waf", "   ", "acme") is None


def test_event_ts_per_family():
    # Log-time standard: the searchable timestamp is the record's OWN event
    # time, parsed from where each family's format carries it — RFC 3339 UTC.
    assert cloud_tag.event_ts_for("lb", ALB_LINE) == "2026-07-15T00:00:00.000Z"
    # VPC flow v2 fields 10/11 are start/end epoch seconds → start is used.
    assert cloud_tag.event_ts_for("flow", VPC_LINE) == "2021-05-03T00:00:00.000Z"
    waf = json.dumps({"webaclId": "acl", "timestamp": 1752537600000})  # epoch ms
    assert cloud_tag.event_ts_for("waf", waf) == "2025-07-15T00:00:00.000Z"
    dns = json.dumps({"query_name": "x.example.com.",
                      "query_timestamp": "2026-07-15T00:00:05Z"})
    assert cloud_tag.event_ts_for("dns", dns) == "2026-07-15T00:00:05.000Z"


def test_event_ts_never_guesses():
    # Zone-less / absent / garbage provider stamps → "" (never a silent zone
    # assumption, never an exception).
    assert cloud_tag.event_ts_for("dns", json.dumps({"query_timestamp": "2026-07-15 00:00:05"})) == ""
    assert cloud_tag.event_ts_for("waf", json.dumps({"timestamp": "not-a-number"})) == ""
    assert cloud_tag.event_ts_for("waf", json.dumps({"timestamp": 42})) == ""  # not a sane epoch
    assert cloud_tag.event_ts_for("lb", "") == ""
    assert cloud_tag.event_ts_for("flow", "version account eni") == ""
    assert cloud_tag.event_ts_for("host", "anything") == ""


def test_cloud_log_doc_prefers_event_time_and_keeps_ingest_time():
    ingest = "2026-07-15T00:07:00Z"  # S3 delivery lag: doc lands ~7 min later
    doc = cloud_tag.cloud_log_doc("aws-alb-access.alb", ALB_LINE, "acme",
                                  timestamp=ingest)
    assert doc["timestamp"] == "2026-07-15T00:00:00.000Z"  # event time wins
    assert doc["ingested_at"] == ingest                     # skew observable
    # A line with no parseable event time falls back to the ingest stamp.
    doc2 = cloud_tag.cloud_log_doc("aws-waf.waf", WAF_LINE, "acme", timestamp=ingest)
    assert doc2["timestamp"] == ingest
    assert doc2["ingested_at"] == ingest


def test_change_log_doc():
    doc = cloud_tag.change_log_doc("acme", resource_id="sg-123",
                                   event_name="AuthorizeSecurityGroupIngress",
                                   actor="arn:aws:iam::1:user/deployer")
    assert doc["cloud_family"] == "change"
    assert doc["resource_id"] == "sg-123"
    assert "deployer" in doc["message"]
    # No tenant → no doc.
    assert cloud_tag.change_log_doc("", resource_id="sg-1", event_name="X") is None
