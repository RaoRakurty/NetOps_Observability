"""Wave 2 #4 — structured permission_denied/misconfigured emission.

Pins the contracts that turn a poller log line into a renderable product state:
  - classification: 403/401-class provider errors → permission_denied,
    400/404-class → misconfigured, everything else → None (unchanged handling);
  - first-seen preservation: a persisting failure keeps its original since;
  - the connector cycle emits a record ON THE CONNECTOR'S TENANT when a lane
    is denied (fixture-driven, the review's "IAM denied X since Tuesday");
  - the ambient S3 flow lane records a denial instead of crashing the cycle;
  - flush ships the full current set via the broker API and clearing works
    (full-set replace semantics);
  - detail strings never contain the API key or a token.
"""
import urllib.error

import botocore.exceptions
import pytest

import broker_client
import poller
import source_status


@pytest.fixture(autouse=True)
def _clean_state():
    source_status.reset()
    yield
    source_status.reset()


def client_error(code, status, op="ListObjectsV2", msg="explicit deny"):
    return botocore.exceptions.ClientError(
        {"Error": {"Code": code, "Message": msg},
         "ResponseMetadata": {"HTTPStatusCode": status}}, op)


# ── classification ────────────────────────────────────────────────────────────

def test_classify_permission_class():
    assert source_status.classify(client_error("AccessDenied", 403)) == "permission_denied"
    assert source_status.classify(client_error("UnauthorizedOperation", 403)) == "permission_denied"
    # HTTP-status fallback: an unknown code still classifies by its 403.
    assert source_status.classify(client_error("SomeNewDenyCode", 403)) == "permission_denied"
    err = urllib.error.HTTPError("https://management.azure.com/x", 403, "Forbidden", None, None)
    assert source_status.classify(err) == "permission_denied"
    err401 = urllib.error.HTTPError("https://login.microsoftonline.com/t", 401, "Unauthorized", None, None)
    assert source_status.classify(err401) == "permission_denied"


def test_classify_misconfigured_class():
    assert source_status.classify(client_error("NoSuchBucket", 404)) == "misconfigured"
    assert source_status.classify(client_error("ResourceNotFoundException", 400)) == "misconfigured"
    err = urllib.error.HTTPError("https://compute.googleapis.com/x", 404, "Not Found", None, None)
    assert source_status.classify(err) == "misconfigured"


def test_classify_other_errors_are_not_ours():
    assert source_status.classify(ValueError("boom")) is None
    assert source_status.classify(client_error("Throttling", 429)) is None
    err = urllib.error.HTTPError("https://x", 503, "Unavailable", None, None)
    assert source_status.classify(err) is None


# ── note / clear / first-seen ────────────────────────────────────────────────

def test_note_preserves_first_seen_and_clear_drops(monkeypatch):
    exc = client_error("AccessDenied", 403)
    assert source_status.note("aws", "flow_logs", exc, tenant="t_a", account="1") == "permission_denied"
    first = list(source_status._active.values())[0]["since_iso"]
    # The same failure a while later must keep the ORIGINAL since.
    monkeypatch.setattr(source_status.time, "time", lambda: 9999999999.0)
    source_status.note("aws", "flow_logs", exc, tenant="t_a", account="1")
    assert list(source_status._active.values())[0]["since_iso"] == first
    source_status.clear("aws", "flow_logs", tenant="t_a", account="1")
    assert not source_status._active


def test_note_ignores_unclassified():
    assert source_status.note("aws", "flow_logs", ValueError("x")) is None
    assert not source_status._active


# ── flush via the broker API ─────────────────────────────────────────────────

def _configure_broker(monkeypatch, sent):
    monkeypatch.setattr(broker_client, "API_URL", "http://api:8080")
    monkeypatch.setattr(broker_client, "KEY_FILE", "")
    monkeypatch.setenv("BROKER_API_KEY", "ntk_secret_key")
    monkeypatch.setattr(broker_client, "put_source_status",
                        lambda records: sent.append(records) or {"stored": len(records)})


def test_flush_ships_full_set_then_clears(monkeypatch):
    sent = []
    _configure_broker(monkeypatch, sent)
    source_status.note("aws", "flow_logs", client_error("AccessDenied", 403),
                       tenant="t_a", account="1", region="us-west-2")
    assert source_status.flush() is True
    assert len(sent) == 1 and len(sent[0]) == 1
    rec = sent[0][0]
    assert rec["status"] == "permission_denied"
    assert rec["source_type"] == "flow_logs"
    assert rec["tenant"] == "t_a"
    assert rec["since_iso"]
    # No secret material may ever ride along in a record.
    assert "ntk_secret_key" not in str(sent[0])
    # Unchanged set inside the re-report window → no extra call.
    assert source_status.flush() is False
    # Recovery → an EMPTY set is still sent once, clearing the server side.
    source_status.clear("aws", "flow_logs", tenant="t_a", account="1", region="us-west-2")
    assert source_status.flush() is True
    assert sent[-1] == []


def test_flush_survives_broker_failure(monkeypatch):
    monkeypatch.setattr(broker_client, "API_URL", "http://api:8080")
    monkeypatch.setattr(broker_client, "KEY_FILE", "")
    monkeypatch.setenv("BROKER_API_KEY", "ntk_secret_key")

    def boom(records):
        raise broker_client.BrokerError("PUT /api/cloud/ingest/source-status -> 502")

    monkeypatch.setattr(broker_client, "put_source_status", boom)
    source_status.note("aws", "flow_logs", client_error("AccessDenied", 403), tenant="t_a")
    assert source_status.flush() is False  # never raises


def test_flush_off_without_broker(monkeypatch):
    monkeypatch.setattr(broker_client, "API_URL", "")
    monkeypatch.setattr(broker_client, "KEY_FILE", "")
    monkeypatch.delenv("BROKER_API_KEY", raising=False)
    source_status.note("aws", "flow_logs", client_error("AccessDenied", 403))
    assert source_status.flush() is False


# ── fixture-driven: the connector cycle emits on a provider 403 ───────────────

def test_connector_cycle_emits_permission_denied_for_denied_lane(monkeypatch):
    sent = []
    _configure_broker(monkeypatch, sent)
    conns = [
        {"id": "ccn_ok", "tenant": "t_good", "provider": "aws",
         "scopes": [{"type": "account", "ref": "111111111111", "regions": ["us-west-2"]}]},
        {"id": "ccn_denied", "tenant": "t_locked", "provider": "aws",
         "scopes": [{"type": "account", "ref": "222222222222", "regions": ["us-west-2"]}]},
    ]
    monkeypatch.setattr(broker_client, "list_connectors", lambda: conns)
    monkeypatch.setattr(broker_client, "credentials",
                        lambda cid: {"aws_access_key_id": "AKIA", "aws_secret_access_key": "s",
                                     "aws_session_token": "t"})

    def lane(conn, creds, producer, cst):
        if conn["id"] == "ccn_denied":
            raise client_error("AccessDenied", 403, op="DescribeInstances",
                               msg="User is not authorized to perform ec2:DescribeInstances")
        return {"resources": 3}

    monkeypatch.setitem(poller.CONNECTOR_LANES, "aws", lane)
    counts = poller.connector_cycle(None, {})
    assert counts == {"connectors": 1, "failed": 1, "skipped": 0}

    assert source_status.flush() is True
    recs = sent[-1]
    assert len(recs) == 1, recs
    rec = recs[0]
    assert rec["status"] == "permission_denied"
    assert rec["source_type"] == "inventory"
    assert rec["connector_id"] == "ccn_denied"
    assert rec["tenant"] == "t_locked"          # the CONNECTOR's tenant, never env
    assert rec["account_id"] == "222222222222"
    assert "DescribeInstances" in rec["detail"]  # the actual operator question

    # Next cycle the lane recovers → the record clears on flush.
    monkeypatch.setitem(poller.CONNECTOR_LANES, "aws", lambda *a: {"resources": 3})
    poller.connector_cycle(None, {})
    source_status.flush()
    assert sent[-1] == []


# ── fixture-driven: the ambient S3 flow lane records instead of crashing ─────

class _DeniedS3:
    def list_objects_v2(self, **kw):
        raise client_error("AccessDenied", 403, msg="explicit deny on s3:ListBucket")


def test_ambient_s3_flow_lane_records_denial(monkeypatch):
    monkeypatch.setattr(poller, "FLOW_S3_BUCKET", "flow-bucket")
    # Another test may have memoized extra S3 sources — keep this lane primary-only.
    monkeypatch.setattr(poller, "_extra_s3_sources_cache", [])
    # Must NOT raise — the denial becomes a record, the cycle goes on.
    poller.poll_flow_logs_s3(_DeniedS3(), {})
    assert len(source_status._active) == 1
    ((key, rec),) = source_status._active.items()
    assert rec["source_type"] == "flow_logs"
    assert rec["status"] == "permission_denied"
    assert rec["tenant"] == poller.TENANT
    # An unclassified failure still raises into the existing cycle handling.
    class _Broken:
        def list_objects_v2(self, **kw):
            raise RuntimeError("wire fell out")
    with pytest.raises(RuntimeError):
        poller.poll_flow_logs_s3(_Broken(), {})
