"""Per-tenant ingestion tests (Wave 1 #2): the poller's connector cycle.

Pins the contracts that make multi-tenant polling safe:
  - ambient fallback: no broker config ⇒ connector mode OFF, nothing called;
  - failure isolation: one connector failing never affects the others;
  - bounded cycle: connector count cap + wall-clock budget are honored;
  - tenant sourcing: everything a lane stamps comes from the SERVER-provided
    connector row (tenant/id), never from local env;
  - credentials hygiene: broker errors never carry the API key or a token.
"""
import json
import os

import broker_client
import poller


# ── broker_client ─────────────────────────────────────────────────────────────

def test_not_configured_without_url_or_key(monkeypatch):
    monkeypatch.setattr(broker_client, "API_URL", "")
    monkeypatch.setattr(broker_client, "KEY_FILE", "")
    monkeypatch.delenv("BROKER_API_KEY", raising=False)
    assert not broker_client.configured()
    monkeypatch.setattr(broker_client, "API_URL", "http://api:8080")
    assert not broker_client.configured()  # url alone is not enough
    monkeypatch.setenv("BROKER_API_KEY", "ntk_test")
    assert broker_client.configured()


class _FakeResp:
    def __init__(self, status, body=None):
        self.status_code = status
        self._body = body if body is not None else {}

    def json(self):
        return self._body


def test_request_retries_5xx_with_backoff_then_succeeds(monkeypatch):
    monkeypatch.setattr(broker_client, "API_URL", "http://api:8080")
    monkeypatch.setenv("BROKER_API_KEY", "ntk_test")
    monkeypatch.setattr(broker_client, "KEY_FILE", "")
    calls = []
    sleeps = []

    def fake_request(method, url, **kw):
        calls.append((method, url))
        return _FakeResp(500) if len(calls) < 3 else _FakeResp(200, {"connectors": [{"id": "ccn_1"}]})

    monkeypatch.setattr(broker_client.requests, "request", fake_request)
    monkeypatch.setattr(broker_client.time, "sleep", sleeps.append)
    out = broker_client.list_connectors()
    assert out == [{"id": "ccn_1"}]
    assert len(calls) == 3          # two 5xx retries, then success
    assert len(sleeps) == 2         # backoff between attempts
    assert all(s > 0 for s in sleeps)


def test_request_4xx_is_terminal_and_sanitized(monkeypatch):
    monkeypatch.setattr(broker_client, "API_URL", "http://api:8080")
    monkeypatch.setenv("BROKER_API_KEY", "ntk_SUPER_SECRET")
    monkeypatch.setattr(broker_client, "KEY_FILE", "")
    calls = []
    monkeypatch.setattr(broker_client.requests, "request",
                        lambda m, u, **kw: (calls.append(1), _FakeResp(403, {"token": "leak"}))[1])
    try:
        broker_client.credentials("ccn_x")
        raise AssertionError("4xx must raise")
    except broker_client.BrokerError as exc:
        msg = str(exc)
        assert "403" in msg
        # NO credential material in errors — the key, a token, or a body.
        assert "ntk_SUPER_SECRET" not in msg
        assert "leak" not in msg
    assert len(calls) == 1          # 4xx is terminal: exactly one attempt


# ── connector cycle ───────────────────────────────────────────────────────────

def test_ambient_fallback_no_broker_configured(monkeypatch):
    """No broker config ⇒ connector mode is off; the loop's guard is
    broker_client.configured(), so nothing connector-related runs."""
    monkeypatch.setattr(broker_client, "API_URL", "")
    monkeypatch.setattr(broker_client, "KEY_FILE", "")
    monkeypatch.delenv("BROKER_API_KEY", raising=False)
    assert not broker_client.configured()


def test_connector_failure_isolated(monkeypatch):
    """Connector 1's credential fetch blows up; connector 2 still polls."""
    conns = [
        {"id": "ccn_bad", "tenant": "t_a", "provider": "aws", "scopes": []},
        {"id": "ccn_good", "tenant": "t_b", "provider": "aws", "scopes": []},
    ]
    monkeypatch.setattr(poller.broker_client, "list_connectors", lambda: conns)

    def creds(cid):
        if cid == "ccn_bad":
            raise broker_client.BrokerError("POST .../credentials -> 502")
        return {"aws_access_key_id": "AKIA", "aws_secret_access_key": "s", "aws_session_token": "t"}

    monkeypatch.setattr(poller.broker_client, "credentials", creds)
    polled = []
    monkeypatch.setitem(poller.CONNECTOR_LANES, "aws",
                        lambda conn, creds, producer, cst: polled.append(conn["id"]) or {"resources": 1})
    st = {}
    counts = poller.connector_cycle(producer=None, st=st)
    assert polled == ["ccn_good"]
    assert counts == {"connectors": 1, "failed": 1, "skipped": 0}


def test_connector_lane_exception_isolated(monkeypatch):
    """A lane raising mid-poll counts as failed and does not stop the pass."""
    conns = [
        {"id": "ccn_1", "tenant": "t_a", "provider": "aws", "scopes": []},
        {"id": "ccn_2", "tenant": "t_b", "provider": "aws", "scopes": []},
    ]
    monkeypatch.setattr(poller.broker_client, "list_connectors", lambda: conns)
    monkeypatch.setattr(poller.broker_client, "credentials", lambda cid: {})
    seen = []

    def lane(conn, creds, producer, cst):
        seen.append(conn["id"])
        if conn["id"] == "ccn_1":
            raise RuntimeError("provider exploded")
        return {"resources": 2}

    monkeypatch.setitem(poller.CONNECTOR_LANES, "aws", lane)
    counts = poller.connector_cycle(producer=None, st={})
    assert seen == ["ccn_1", "ccn_2"]
    assert counts["connectors"] == 1 and counts["failed"] == 1


def test_unknown_provider_and_missing_tenant_skipped(monkeypatch):
    conns = [
        {"id": "ccn_1", "tenant": "t_a", "provider": "oraclecloud", "scopes": []},
        {"id": "ccn_2", "tenant": "", "provider": "aws", "scopes": []},
    ]
    monkeypatch.setattr(poller.broker_client, "list_connectors", lambda: conns)
    called = []
    monkeypatch.setattr(poller.broker_client, "credentials",
                        lambda cid: called.append(cid) or {})
    counts = poller.connector_cycle(producer=None, st={})
    assert called == []             # no credential is ever fetched for a skip
    assert counts == {"connectors": 0, "failed": 0, "skipped": 2}


def test_cycle_is_bounded_by_cap(monkeypatch):
    conns = [{"id": f"ccn_{i}", "tenant": "t", "provider": "aws", "scopes": []}
             for i in range(poller.CONNECTOR_MAX_PER_CYCLE + 10)]
    monkeypatch.setattr(poller.broker_client, "list_connectors", lambda: conns)
    monkeypatch.setattr(poller.broker_client, "credentials", lambda cid: {})
    n = []
    monkeypatch.setitem(poller.CONNECTOR_LANES, "aws",
                        lambda conn, creds, producer, cst: n.append(1) or {})
    counts = poller.connector_cycle(producer=None, st={})
    assert counts["connectors"] == poller.CONNECTOR_MAX_PER_CYCLE
    assert len(n) == poller.CONNECTOR_MAX_PER_CYCLE


def test_broker_outage_returns_empty_cycle(monkeypatch):
    def boom():
        raise broker_client.BrokerError("GET /api/cloud/ingest/connectors -> 503")
    monkeypatch.setattr(poller.broker_client, "list_connectors", boom)
    counts = poller.connector_cycle(producer=None, st={})
    assert counts == {"connectors": 0, "failed": 0, "skipped": 0}


# ── tenant sourcing (server truth, not local env) ─────────────────────────────

def test_aws_lane_tags_with_connector_tenant(monkeypatch):
    """The AWS lane must (a) build its boto3 session from the BROKER credential,
    (b) deliver inventory via the broker (server-side tenant stamp), and
    (c) stamp bus evidence with the CONNECTOR's tenant + id — never CLOUD_TENANT."""
    conn = {"id": "ccn_a", "tenant": "t_customer",
            "provider": "aws", "scopes": [{"type": "account", "ref": "1", "regions": ["eu-west-1"]}]}
    creds = {"aws_access_key_id": "AKIA1", "aws_secret_access_key": "sec", "aws_session_token": "tok"}

    sessions = []

    class FakeSession:
        def __init__(self, **kw):
            sessions.append(kw)

        def client(self, name):
            return f"client:{name}"

    monkeypatch.setattr(poller.boto3, "Session", FakeSession)
    inv = {"provider": "aws", "account_id": "111",
           "collection": {"mode": "live_poller"}, "resources": [{"resource_id": "i-1"}]}
    monkeypatch.setattr(poller.discover, "discover_aws",
                        lambda ec2, session=None, region="": (inv, {"edges": []}))
    delivered = []
    monkeypatch.setattr(poller.broker_client, "put_inventory",
                        lambda cid, doc: delivered.append((cid, doc)) or {})
    trail_calls = []

    def fake_trail(ct, producer, cst, tenant=None, account=None, region=None, connector_id=""):
        trail_calls.append({"tenant": tenant, "account": account,
                            "region": region, "connector_id": connector_id})

    monkeypatch.setattr(poller, "poll_cloudtrail", fake_trail)

    out = poller.poll_connector_aws(conn, creds, producer=object(), cst={})
    assert out == {"resources": 1}
    # session built from the broker credential + the connector's scope region
    assert sessions == [{"aws_access_key_id": "AKIA1", "aws_secret_access_key": "sec",
                         "aws_session_token": "tok", "region_name": "eu-west-1"}]
    # inventory delivered through the broker under the connector id
    assert delivered == [("ccn_a", inv)]
    # bus evidence carries the CONNECTOR's tenant + id (server truth)
    assert trail_calls == [{"tenant": "t_customer", "account": "111",
                            "region": "eu-west-1", "connector_id": "ccn_a"}]


def test_scoped_inventory_doc_swaps_and_restores_scope(monkeypatch, tmp_path):
    """Azure/GCP lanes substitute the connector's subscription/project for the
    duration of the call and ALWAYS restore the ambient value (even on error)."""
    class FakeMod:
        SUBSCRIPTION = "ambient-sub"

        @staticmethod
        def write_inventory(tok, d):
            # the module sees the CONNECTOR's scope while running
            assert FakeMod.SUBSCRIPTION == "conn-sub"
            with open(os.path.join(d, "azure.json"), "w", encoding="utf-8") as f:
                json.dump({"provider": "azure", "resources": []}, f)
            return 0

    doc = poller._scoped_inventory_doc(FakeMod, "SUBSCRIPTION", "conn-sub", "tok", "azure.json")
    assert doc["provider"] == "azure"
    assert FakeMod.SUBSCRIPTION == "ambient-sub"  # restored

    class BoomMod:
        SUBSCRIPTION = "ambient-sub"

        @staticmethod
        def write_inventory(tok, d):
            raise RuntimeError("ARM down")

    try:
        poller._scoped_inventory_doc(BoomMod, "SUBSCRIPTION", "conn-sub", "tok", "azure.json")
        raise AssertionError("must propagate")
    except RuntimeError:
        pass
    assert BoomMod.SUBSCRIPTION == "ambient-sub"  # restored on failure too


def test_per_connector_checkpoints_do_not_mix(monkeypatch):
    """Each connector gets its own state sub-dict (st['connectors'][id]) so
    CloudTrail checkpoints never bleed between tenants or into ambient state."""
    conns = [
        {"id": "ccn_1", "tenant": "t_a", "provider": "aws", "scopes": []},
        {"id": "ccn_2", "tenant": "t_b", "provider": "aws", "scopes": []},
    ]
    monkeypatch.setattr(poller.broker_client, "list_connectors", lambda: conns)
    monkeypatch.setattr(poller.broker_client, "credentials", lambda cid: {})

    def lane(conn, creds, producer, cst):
        cst["trail_ts"] = conn["id"]  # simulate a lane checkpoint write
        return {}

    monkeypatch.setitem(poller.CONNECTOR_LANES, "aws", lane)
    st = {"trail_ts": "ambient"}
    poller.connector_cycle(producer=None, st=st)
    assert st["trail_ts"] == "ambient"                       # ambient untouched
    assert st["connectors"]["ccn_1"]["trail_ts"] == "ccn_1"  # per-connector
    assert st["connectors"]["ccn_2"]["trail_ts"] == "ccn_2"
