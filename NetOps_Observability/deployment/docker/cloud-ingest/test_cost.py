"""Cost-lane tests (Wave 5 #18 slice 1) — fake provider responses, no live calls.

Pins the contracts that make cost ingestion safe and honest:
  * the normalized cost record: exact field set, identical across providers,
    loud ValueError on a blank field (the cloud_events.py discipline);
  * checkpoint discipline (trail_state model for a day-keyed lane): backfill,
    restate overlap, never regress, in-flight day never read;
  * AWS Cost Explorer + Azure Cost Management parsing from realistic fake
    responses (column order discovered, never assumed);
  * bounded emission (record cap honored);
  * GCP honest gap: NO records ever emitted; a structured "not enabled"
    source-status record instead of silent zeros;
  * cycle isolation: one failing lane/connector never kills the pass; a
    permission failure becomes a structured source-status record.

Run: python3 -m pytest test_cost.py
"""
import datetime as dt
import json

import pytest

import cost
import source_status


class _Producer:
    def __init__(self):
        self.sent = []

    def send(self, topic, value):
        self.sent.append((topic, value))

    def flush(self, timeout=None):
        pass


@pytest.fixture(autouse=True)
def _clean_status():
    source_status.reset()
    yield
    source_status.reset()


# ── the record contract ───────────────────────────────────────────────────────

def _one(provider):
    return cost.cost_record(provider=provider, tenant="t", account="acct",
                            service="svc", day="2026-07-17", amount=1.25,
                            currency="USD", ts="2026-07-18T00:00:00Z")


def test_record_exact_field_set_identical_across_providers():
    aws, az, g = _one("aws"), _one("azure"), _one("gcp")
    for rec in (aws, az, g):
        assert set(rec) == set(cost.COST_RECORD_FIELDS)
    assert set(aws) == set(az) == set(g)
    assert aws["kind"] == "cloud_cost"
    assert aws["granularity"] == "daily"


def test_record_collection_path_per_provider():
    assert _one("aws")["collection_path"] == "aws_cost_explorer"
    assert _one("azure")["collection_path"] == "azure_cost_management"


def test_record_negative_amount_is_valid_credit():
    rec = cost.cost_record(provider="aws", tenant="t", account="a", service="s",
                           day="2026-07-17", amount=-3.5, currency="USD",
                           ts="2026-07-18T00:00:00Z")
    assert rec["amount"] == -3.5


def test_record_rejects_blank_fields_and_bad_day():
    base = dict(provider="aws", tenant="t", account="a", service="s",
                day="2026-07-17", amount=1.0, currency="USD",
                ts="2026-07-18T00:00:00Z")
    for bad in ({"tenant": ""}, {"account": " "}, {"service": ""},
                {"currency": ""}, {"day": "07/17/2026"}, {"day": ""}):
        kw = dict(base)
        kw.update(bad)
        with pytest.raises(ValueError):
            cost.cost_record(**kw)
    with pytest.raises(ValueError):
        cost.cost_record(**{**base, "amount": True})  # type: ignore[dict-item]


# ── checkpoint core (pure) ────────────────────────────────────────────────────

def test_poll_window_first_run_backfills(monkeypatch):
    monkeypatch.setattr(cost, "COST_BACKFILL_DAYS", 30)
    win = cost.poll_window("", "2026-07-18")
    assert win == ("2026-06-18", "2026-07-18")  # end EXCLUSIVE: in-flight day never read


def test_poll_window_resumes_with_restate_overlap(monkeypatch):
    monkeypatch.setattr(cost, "COST_RESTATE_DAYS", 3)
    win = cost.poll_window("2026-07-17", "2026-07-18")
    assert win == ("2026-07-15", "2026-07-18")  # 3 trailing days re-read


def test_poll_window_never_regresses_past_backfill_horizon(monkeypatch):
    monkeypatch.setattr(cost, "COST_BACKFILL_DAYS", 5)
    monkeypatch.setattr(cost, "COST_RESTATE_DAYS", 30)
    win = cost.poll_window("2026-07-17", "2026-07-18")
    assert win == ("2026-07-13", "2026-07-18")


def test_advance_day_checkpoint_never_regresses():
    assert cost.advance_day_checkpoint("", "2026-07-18") == "2026-07-17"
    assert cost.advance_day_checkpoint("2026-07-20", "2026-07-18") == "2026-07-20"


# ── AWS lane ──────────────────────────────────────────────────────────────────

class _FakeCE:
    """Two-page Cost Explorer stub with realistic GetCostAndUsage shape."""

    def __init__(self):
        self.calls = []

    def get_cost_and_usage(self, **kw):
        self.calls.append(kw)
        if "NextPageToken" not in kw:
            return {
                "ResultsByTime": [{
                    "TimePeriod": {"Start": "2026-07-16", "End": "2026-07-17"},
                    "Groups": [
                        {"Keys": ["Amazon Elastic Compute Cloud - Compute", "111111111111"],
                         "Metrics": {"UnblendedCost": {"Amount": "12.34", "Unit": "USD"}}},
                        {"Keys": ["Amazon Simple Storage Service", "111111111111"],
                         "Metrics": {"UnblendedCost": {"Amount": "0.56", "Unit": "USD"}}},
                    ],
                }],
                "NextPageToken": "p2",
            }
        return {
            "ResultsByTime": [{
                "TimePeriod": {"Start": "2026-07-17", "End": "2026-07-18"},
                "Groups": [
                    {"Keys": ["AWS Lambda", "222222222222"],
                     "Metrics": {"UnblendedCost": {"Amount": "-1.00", "Unit": "USD"}}},
                ],
            }],
        }


def test_aws_poll_emits_normalized_records_and_checkpoints():
    ce, prod, st = _FakeCE(), _Producer(), {}
    n = cost.poll_aws(ce, prod, "acme", "111111111111", st, today="2026-07-18")
    assert n == 3
    assert len(prod.sent) == 3
    topics = {t for t, _ in prod.sent}
    assert topics == {cost.COST_TOPIC}
    recs = [r for _, r in prod.sent]
    for r in recs:
        assert set(r) == set(cost.COST_RECORD_FIELDS)
        assert r["provider"] == "aws"
        assert r["tenant_id"] == "acme"
    ec2 = recs[0]
    assert ec2["service"] == "Amazon Elastic Compute Cloud - Compute"
    assert ec2["account"] == "111111111111"
    assert ec2["day"] == "2026-07-16"
    assert ec2["amount"] == 12.34
    # linked-account grouping wins over the passed account; credits carried
    assert recs[2]["account"] == "222222222222"
    assert recs[2]["amount"] == -1.0
    # daily granularity + checkpoint = newest COMPLETE day
    assert ce.calls[0]["Granularity"] == "DAILY"
    assert st["cost_day"] == "2026-07-17"


def test_aws_poll_respects_record_cap(monkeypatch):
    monkeypatch.setattr(cost, "COST_MAX_RECORDS", 2)
    prod, st = _Producer(), {}
    n = cost.poll_aws(_FakeCE(), prod, "acme", "1", st, today="2026-07-18")
    assert n == 2
    assert len(prod.sent) == 2


def test_aws_poll_nothing_to_fetch_is_zero_not_a_call(monkeypatch):
    monkeypatch.setattr(cost, "COST_BACKFILL_DAYS", 1)
    monkeypatch.setattr(cost, "COST_RESTATE_DAYS", 1)

    class _NeverCE:
        def get_cost_and_usage(self, **kw):
            raise AssertionError("no window ⇒ no metered CE call")

    st = {"cost_day": "2026-07-17"}
    # restate window still covers yesterday → one call is fine; force emptiness:
    monkeypatch.setattr(cost, "poll_window", lambda last, today: None)
    assert cost.poll_aws(_NeverCE(), _Producer(), "t", "a", st) == 0


# ── Azure lane ────────────────────────────────────────────────────────────────

AZ_RESP = {
    "properties": {
        "columns": [
            {"name": "Cost", "type": "Number"},
            {"name": "UsageDate", "type": "Number"},
            {"name": "ServiceName", "type": "String"},
            {"name": "Currency", "type": "String"},
        ],
        "rows": [
            [4.2, 20260716, "Virtual Machines", "USD"],
            [0.11, 20260717, "Storage", "USD"],
            [1.0, 20260717, None, "USD"],          # null service → unattributed
        ],
    }
}


def test_azure_poll_parses_columns_by_name_and_checkpoints(monkeypatch):
    captured = {}

    def fake_query(tok, sub, start, end_incl):
        captured.update(tok=tok, sub=sub, start=start, end_incl=end_incl)
        return AZ_RESP

    monkeypatch.setattr(cost, "_azure_cost_query", fake_query)
    prod, st = _Producer(), {}
    n = cost.poll_azure("tok", prod, "acme", "sub-1", st, today="2026-07-18")
    assert n == 3
    assert captured["sub"] == "sub-1"
    assert captured["end_incl"] == "2026-07-17"    # inclusive end = newest complete day
    recs = [r for _, r in prod.sent]
    assert recs[0]["provider"] == "azure"
    assert recs[0]["account"] == "sub-1"
    assert recs[0]["day"] == "2026-07-16"
    assert recs[0]["service"] == "Virtual Machines"
    assert recs[2]["service"] == "unattributed"
    assert st["cost_day"] == "2026-07-17"


def test_azure_poll_reordered_columns_still_parse(monkeypatch):
    resp = {"properties": {
        "columns": [{"name": "UsageDate"}, {"name": "Currency"},
                    {"name": "Cost"}, {"name": "ServiceName"}],
        "rows": [[20260717, "EUR", 9.9, "App Service"]],
    }}
    monkeypatch.setattr(cost, "_azure_cost_query", lambda *a: resp)
    prod = _Producer()
    n = cost.poll_azure("tok", prod, "t", "sub", {}, today="2026-07-18")
    assert n == 1
    rec = prod.sent[0][1]
    assert (rec["amount"], rec["currency"], rec["service"]) == (9.9, "EUR", "App Service")


def test_azure_poll_missing_columns_is_loud_zero_not_a_guess(monkeypatch):
    monkeypatch.setattr(cost, "_azure_cost_query",
                        lambda *a: {"properties": {"columns": [{"name": "Nope"}], "rows": [[1]]}})
    assert cost.poll_azure("tok", _Producer(), "t", "sub", {}, today="2026-07-18") == 0


def test_usage_day_forms():
    assert cost._usage_day(20260711) == "2026-07-11"
    assert cost._usage_day("2026-07-11T00:00:00") == "2026-07-11"
    assert cost._usage_day("junk") == ""


# ── GCP honest gap ────────────────────────────────────────────────────────────

def test_gcp_lane_emits_no_records_and_notes_the_gap(monkeypatch):
    class _Resp:
        def read(self):
            return json.dumps({"billingAccountName": "billingAccounts/X",
                               "billingEnabled": True}).encode()

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(cost.urllib.request, "urlopen",
                        lambda req, timeout=0: _Resp())
    out = cost.poll_gcp("tok", "acme", "proj-1")
    assert out["records"] == 0                     # NEVER a fabricated number
    assert out["status"] == "no_spend_api"
    recs = list(source_status._active.values())    # noqa: SLF001 — test hook
    assert len(recs) == 1
    assert recs[0]["source_type"] == "cost"
    assert recs[0]["status"] == "misconfigured"
    assert "BigQuery" in recs[0]["detail"]


def test_note_status_preserves_first_seen():
    source_status.note_status("gcp", "cost", "misconfigured", "d1", tenant="t")
    first = list(source_status._active.values())[0]["since_iso"]  # noqa: SLF001
    source_status.note_status("gcp", "cost", "misconfigured", "d2", tenant="t")
    rec = list(source_status._active.values())[0]  # noqa: SLF001
    assert rec["since_iso"] == first
    assert rec["detail"] == "d2"


# ── cycle isolation ───────────────────────────────────────────────────────────

class _Denied(Exception):
    def __init__(self):
        super().__init__("AccessDenied on ce:GetCostAndUsage")
        self.response = {"Error": {"Code": "AccessDeniedException"},
                         "ResponseMetadata": {"HTTPStatusCode": 403}}


class _Mod:
    """Stub provider module (azure/gcp shape: configured/token/scope attrs)."""

    def __init__(self, ready, tok="tok"):
        self._ready = ready
        self._tok = tok
        self.SUBSCRIPTION = "sub-1"
        self.PROJECT = "proj-1"

    def configured(self):
        return self._ready

    def token(self):
        return self._tok


def test_run_isolates_a_denied_aws_lane_and_still_polls_azure(monkeypatch):
    class _Session:
        def client(self, name, region_name=None):
            class _CE:
                def get_cost_and_usage(self, **kw):
                    raise _Denied()
            return _CE()

    monkeypatch.setattr(cost, "_azure_cost_query", lambda *a: AZ_RESP)
    monkeypatch.setattr(cost.broker_client, "configured", lambda: False)
    prod, st = _Producer(), {}
    counts = cost.run(prod, st, session=_Session(),
                      azure_mod=_Mod(True), gcp_mod=_Mod(False))
    # AWS denial became a structured record; Azure still delivered.
    assert counts["azure"] == 3
    assert counts["aws"] == 0
    recs = {(r["provider"], r["status"])
            for r in source_status._active.values()}  # noqa: SLF001
    assert ("aws", "permission_denied") in recs


def test_run_disabled_lane_is_honestly_disabled(monkeypatch):
    monkeypatch.setattr(cost, "COST_LANES", False)
    assert cost.run(_Producer(), {}) == {"disabled": True}


def test_connector_pass_isolates_failures_and_stamps_connector_tenant(monkeypatch):
    conns = [
        {"id": "ccn_bad", "tenant": "t_a", "provider": "azure",
         "scopes": [{"type": "subscription", "ref": "sub-bad"}]},
        {"id": "ccn_good", "tenant": "t_b", "provider": "azure",
         "scopes": [{"type": "subscription", "ref": "sub-good"}]},
    ]
    monkeypatch.setattr(cost.broker_client, "configured", lambda: True)
    monkeypatch.setattr(cost.broker_client, "list_connectors", lambda: conns)
    monkeypatch.setattr(cost.broker_client, "credentials", lambda cid: {"token": "tk"})

    def fake_query(tok, sub, start, end_incl):
        if sub == "sub-bad":
            import urllib.error
            raise urllib.error.HTTPError("u", 403, "forbidden", None, None)
        return AZ_RESP

    monkeypatch.setattr(cost, "_azure_cost_query", fake_query)
    prod, st = _Producer(), {}
    counts = cost.connector_pass(prod, st)
    assert counts == {"connectors": 1, "failed": 1, "skipped": 0}
    # the good connector's records are owned by ITS tenant (server truth)
    tenants = {r["tenant_id"] for _, r in prod.sent}
    assert tenants == {"t_b"}
    # the denial is a structured record on the BAD connector's tenant
    recs = list(source_status._active.values())  # noqa: SLF001
    assert any(r["tenant"] == "t_a" and r["status"] == "permission_denied"
               and r["source_type"] == "cost" for r in recs)


def test_connector_pass_honors_count_cap(monkeypatch):
    monkeypatch.setattr(cost, "COST_CONNECTOR_MAX", 1)
    conns = [{"id": f"ccn_{i}", "tenant": "t", "provider": "azure",
              "scopes": [{"type": "subscription", "ref": "s"}]} for i in range(3)]
    monkeypatch.setattr(cost.broker_client, "configured", lambda: True)
    monkeypatch.setattr(cost.broker_client, "list_connectors", lambda: conns)
    monkeypatch.setattr(cost.broker_client, "credentials", lambda cid: {"token": "tk"})
    monkeypatch.setattr(cost, "_azure_cost_query", lambda *a: AZ_RESP)
    counts = cost.connector_pass(_Producer(), {})
    assert counts["connectors"] == 1


def test_connector_checkpoints_never_mix(monkeypatch):
    conns = [
        {"id": "ccn_1", "tenant": "t_a", "provider": "azure",
         "scopes": [{"type": "subscription", "ref": "s1"}]},
        {"id": "ccn_2", "tenant": "t_b", "provider": "azure",
         "scopes": [{"type": "subscription", "ref": "s2"}]},
    ]
    monkeypatch.setattr(cost.broker_client, "configured", lambda: True)
    monkeypatch.setattr(cost.broker_client, "list_connectors", lambda: conns)
    monkeypatch.setattr(cost.broker_client, "credentials", lambda cid: {"token": "tk"})
    monkeypatch.setattr(cost, "_azure_cost_query", lambda *a: AZ_RESP)
    st = {}
    cost.connector_pass(_Producer(), st)
    yesterday = (dt.datetime.now(dt.timezone.utc).date()
                 - dt.timedelta(days=1)).isoformat()
    assert st["connectors"]["ccn_1"]["cost_day"] == yesterday
    assert st["connectors"]["ccn_2"]["cost_day"] == yesterday
    assert st["connectors"]["ccn_1"] is not st["connectors"]["ccn_2"]
