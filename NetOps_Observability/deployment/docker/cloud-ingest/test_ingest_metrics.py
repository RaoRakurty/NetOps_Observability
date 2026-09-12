# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Per-exchange self-metrics for the poller (Wave 4 #13 slice 4).

Pins: outcome classification from BrokerError statuses, bounded-label counter
rendering in Prometheus text format, the /metrics endpoint end-to-end on an
ephemeral port, and the never-raise / never-take-a-lane-down contract.
"""
import urllib.error
import urllib.request

import ingest_metrics
from broker_client import BrokerError


def setup_function(_fn):
    ingest_metrics.reset()


def _broker_error(status: int) -> BrokerError:
    exc = BrokerError("exchange failed")
    exc.status = status
    return exc


def test_classify_error_maps_status_to_outcome():
    assert ingest_metrics.classify_error(_broker_error(401)) == ingest_metrics.OUTCOME_AUTH_FAIL
    assert ingest_metrics.classify_error(_broker_error(403)) == ingest_metrics.OUTCOME_AUTH_FAIL
    assert ingest_metrics.classify_error(_broker_error(429)) == ingest_metrics.OUTCOME_THROTTLED
    assert ingest_metrics.classify_error(_broker_error(500)) == ingest_metrics.OUTCOME_API_ERROR
    assert ingest_metrics.classify_error(_broker_error(0)) == ingest_metrics.OUTCOME_API_ERROR
    # No status attribute at all (non-broker failure) → api_error, never a raise.
    assert ingest_metrics.classify_error(RuntimeError("boom")) == ingest_metrics.OUTCOME_API_ERROR


def test_record_and_render_counters():
    ingest_metrics.record_exchange("aws", ingest_metrics.OUTCOME_SUCCESS, 0.25)
    ingest_metrics.record_exchange("aws", ingest_metrics.OUTCOME_SUCCESS, 0.75)
    ingest_metrics.record_exchange("azure", ingest_metrics.OUTCOME_AUTH_FAIL, 0.1)
    ingest_metrics.record_exchange("", ingest_metrics.OUTCOME_API_ERROR)  # no latency
    out = ingest_metrics.render()
    assert 'netops_cloud_ingest_exchange_total{provider="aws",outcome="auth_success"} 2' in out
    assert 'netops_cloud_ingest_exchange_total{provider="azure",outcome="auth_fail"} 1' in out
    # Empty provider is bounded to "unknown", never an empty label value.
    assert 'netops_cloud_ingest_exchange_total{provider="unknown",outcome="api_error"} 1' in out
    assert 'netops_cloud_ingest_exchange_latency_seconds_sum{provider="aws"} 1.000000' in out
    assert 'netops_cloud_ingest_exchange_latency_seconds_count{provider="aws"} 2' in out
    # The API-error record carried no latency — no latency series for "unknown".
    assert 'latency_seconds_count{provider="unknown"}' not in out


def test_metrics_endpoint_serves_and_404s():
    srv = ingest_metrics.serve(port=0)  # ephemeral
    assert srv is not None
    try:
        port = srv.server_address[1]
        ingest_metrics.record_exchange("gcp", ingest_metrics.OUTCOME_THROTTLED, 0.05)
        body = urllib.request.urlopen(f"http://127.0.0.1:{port}/metrics").read().decode()
        assert 'provider="gcp",outcome="throttled"' in body
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/other")
            raise AssertionError("non-/metrics path must 404")
        except urllib.error.HTTPError as exc:
            assert exc.code == 404
    finally:
        srv.shutdown()


def test_serve_disabled_and_bad_port_return_none(monkeypatch):
    monkeypatch.setenv(ingest_metrics.PORT_ENV, "off")
    assert ingest_metrics.serve() is None
    monkeypatch.setenv(ingest_metrics.PORT_ENV, "not-a-port")
    assert ingest_metrics.serve() is None
