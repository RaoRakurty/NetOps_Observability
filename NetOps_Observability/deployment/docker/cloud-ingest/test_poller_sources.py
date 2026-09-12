# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Unit tests for the multi-source S3 log config (poller.extra_s3_sources).

Prod-grade log ingestion must support real AWS layouts: WAF logs in a
dedicated aws-waf-logs-* bucket, flow/ALB in their own buckets, possibly across
accounts. These tests pin the parse contract for S3_LOG_SOURCES and prove a
malformed override can never take the poller down (it degrades to no-op)."""
import json

import poller


def _run(raw: str) -> list:
    """Drive extra_s3_sources() with a given raw S3_LOG_SOURCES value."""
    poller.S3_LOG_SOURCES_RAW = raw
    poller._extra_s3_sources_cache = None  # reset memo
    return poller.extra_s3_sources()


def test_empty_is_no_op():
    assert _run("") == []
    assert _run("   ") == []


def test_valid_multi_lane_source():
    src = [{"name": "edge", "flow_bucket": "fb",
            "alb_bucket": "ab", "waf_bucket": "aws-waf-logs-x"}]
    out = _run(json.dumps(src))
    assert len(out) == 1
    assert out[0]["_name"] == "edge"
    assert out[0]["waf_bucket"] == "aws-waf-logs-x"
    assert out[0].get("dns_bucket") is None  # omitted lane stays off


def test_autoname_and_skip_bucketless():
    # 1st gets an auto name; 2nd names nothing that's a bucket -> dropped.
    src = [{"flow_bucket": "fb"}, {"name": "no-buckets"}]
    out = _run(json.dumps(src))
    assert len(out) == 1
    assert out[0]["_name"] == "src1"


def test_malformed_json_ignored():
    assert _run("{not valid json") == []


def test_non_list_ignored():
    assert _run(json.dumps({"flow_bucket": "fb"})) == []


def test_memoized():
    poller.S3_LOG_SOURCES_RAW = json.dumps([{"flow_bucket": "fb"}])
    poller._extra_s3_sources_cache = None
    first = poller.extra_s3_sources()
    # change the raw value; memo must return the SAME parsed list
    poller.S3_LOG_SOURCES_RAW = ""
    assert poller.extra_s3_sources() is first
