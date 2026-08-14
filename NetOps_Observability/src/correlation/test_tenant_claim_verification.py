"""TENANT-HIGH-3/4 — a claimed tenant must be VERIFIED before it is persisted.

THE DEFECT: tenant identity was ASSERTED by the sender and never checked.
Every lane resolved it as

    tenant = str(ev.get("tenant_id") or "") or tenant_for(<device>)

so the trusted device→tenant registry was consulted only for ABSENCE. A
non-empty tenant_id — from anything able to write to the bus, or (worse)
re-derived from the attacker-controlled `devname=` field inside a FortiGate log
BODY — was taken verbatim and written into that tenant's corr_signals.

These tests pin the replacement contract (main.verified_tenant):

  (a) a forged non-empty tenant_id that disagrees with the registry is refused,
      quarantined with its payload, and NOT persisted;
  (b) a legitimate event still flows end to end, unchanged;
  (c) an unresolvable tenant fails closed — never "global", never "__all__",
      never a first match;
  (d) every insert carries the ROW's own tenant scope, and a cross-tenant batch
      has to announce itself and is counted.

Plus the two ingest-tier halves of the same defect, asserted statically against
the shipped Vector configs (VRL cannot be executed here — see the module note
at the bottom).
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
from pathlib import Path
from typing import ClassVar

import pytest

import main

REPO = Path(__file__).resolve().parents[2]


def run(coro):
    return asyncio.run(coro)


class RecordingCH:
    """Fake ClickHouse that records every committed insert."""

    def __init__(self) -> None:
        self.inserts: list[tuple[str, list[dict]]] = []

    async def insert(self, table, rows, dedup_token="") -> bool:
        self.inserts.append((table, list(rows)))
        return True

    def rows_for(self, table: str) -> list[dict]:
        return [r for t, rs in self.inserts if t == table for r in rs]


@pytest.fixture
def registry(tmp_path, monkeypatch):
    """The TRUSTED device→tenant registry: leaf1 → acme, 10.1.1.1 → acme,
    ap-1 → acme, plat1 → "" (the platform's own device)."""
    csv_path = tmp_path / "device_tenant.csv"
    csv_path.write_text(
        "identity,tenant_id\n"
        "leaf1,acme\n"
        "10.1.1.1,acme\n"
        "ap-1,acme\n"
        "plat1,\n"
    )
    monkeypatch.setattr(main, "TENANT_ENRICHMENT_FILE", str(csv_path))
    monkeypatch.setattr(main, "_tenant_map", {})
    monkeypatch.setattr(main, "_tenant_mtime", -1.0)
    return csv_path


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    main.TENANT_REFUSALS.clear()
    main._TENANT_REFUSE_LOG_LAST.clear()
    main.CH_CROSS_TENANT_INSERTS.clear()
    main.CH_INSERT_FAILURES.clear()
    main.QUARANTINE.clear()
    main.SYSLOG_BUCKET.clear()
    monkeypatch.setattr(main, "TENANT_CLAIMS_VERIFIED", 0)
    monkeypatch.setattr(main, "TENANT_CLAIMS_REFUSED", 0)
    monkeypatch.setattr(main, "CORR_SIGNALS_ENABLED", True)
    yield
    main.TENANT_REFUSALS.clear()
    main.CH_CROSS_TENANT_INSERTS.clear()
    main.QUARANTINE.clear()
    main.SYSLOG_BUCKET.clear()


def _syslog(**over) -> dict:
    ev = {
        "hostname": "leaf1",
        "appname": "%BGP-5-ADJCHANGE",
        "severity": "err",
        "message": "neighbor 10.2.2.2 Down BGP Notification sent",
    }
    ev.update(over)
    return ev


def _flow(**over) -> dict:
    ev = {"sampler_address": "10.1.1.1", "bytes": 1000, "in_if": 3}
    ev.update(over)
    return ev


# ── the primitive ────────────────────────────────────────────────────────────


def test_tenant_lookup_separates_unknown_from_platform(registry):
    """`tenant_for` collapses "the registry says platform" and "the registry has
    never heard of this" to the same "global" — which is exactly why it could
    only ever be a fallback and never a check."""
    assert main.tenant_lookup("leaf1") == "acme"
    assert main.tenant_lookup("plat1") == ""       # known, platform-owned
    assert main.tenant_lookup("nosuch") is None    # unknown
    # Back-compat: tenant_for's answers are unchanged.
    assert main.tenant_for("leaf1") == "acme"
    assert main.tenant_for("plat1") == "global"
    assert main.tenant_for("nosuch") == "global"
    assert main.tenant_for("") == "global"


def test_verified_tenant_accepts_a_claim_the_registry_reproduces(registry):
    assert main.verified_tenant("acme", "leaf1", "syslog", registry_anchored=True) == "acme"
    assert main.TENANT_CLAIMS_VERIFIED == 1
    assert main.TENANT_CLAIMS_REFUSED == 0


def test_verified_tenant_refuses_a_claim_the_registry_contradicts(registry):
    with pytest.raises(main.TenantClaimRefused):
        main.verified_tenant("victim", "leaf1", "syslog", registry_anchored=True)
    assert main.TENANT_REFUSALS == {"syslog:claim_mismatch": 1}
    assert main.TENANT_CLAIMS_REFUSED == 1


def test_verified_tenant_refuses_a_claim_on_a_platform_owned_device(registry):
    """The registry saying "" (platform) is an ANSWER, not a gap: a claim of a
    real tenant for a platform device is still a contradiction."""
    with pytest.raises(main.TenantClaimRefused):
        main.verified_tenant("acme", "plat1", "syslog", registry_anchored=True)


def test_unresolvable_identity_fails_closed_on_an_anchored_lane(registry):
    """(c) The registry-anchored lanes get their tenant from this very registry,
    so a claim it cannot reproduce did not come from the pipeline."""
    with pytest.raises(main.TenantClaimRefused):
        main.verified_tenant("acme", "ghost-device", "syslog", registry_anchored=True)
    assert main.TENANT_REFUSALS == {"syslog:identity_unknown": 1}


def test_unattributable_identity_is_quarantined_not_processed_as_global(registry):
    """F-11 (owner decision 2026-08-12, INV-F11-10): no claim + REGISTRY MISS on
    an anchored lane is TENANT_UNATTRIBUTABLE. The old contract processed it as
    the platform tenant — which reaches RCA and the global tenant's
    ticketing/notification destinations. It now joins the durable quarantine,
    the same path a contradicted claim takes. (This test previously pinned the
    old fallback; the F-11 decision superseded it.)"""
    with pytest.raises(main.TenantClaimRefused):
        main.verified_tenant("", "ghost-device", "syslog", registry_anchored=True)
    assert main.TENANT_REFUSALS == {"syslog:identity_unattributable": 1}
    assert main.TENANT_CLAIMS_REFUSED == 1


def test_known_platform_device_still_processes_as_global(registry):
    """The F-11 discriminator is the registry MISS, never tenant=="": a registry
    hit mapping a KNOWN platform device to "" is the platform's own telemetry —
    self-monitoring RCA depends on it and it must keep flowing."""
    got = main.verified_tenant("", "plat1", "syslog", registry_anchored=True)
    assert got == "global"
    assert main.TENANT_CLAIMS_REFUSED == 0


def test_unanchored_lane_lets_an_unknown_identity_through_but_still_catches_a_lie(registry):
    """Cloud/probe/metric identities legitimately live outside the inventory, so
    the registry may only CONTRADICT there — but a contradiction still refuses."""
    assert main.verified_tenant("beta", "some-external-host", "probes") == "beta"
    with pytest.raises(main.TenantClaimRefused):
        main.verified_tenant("beta", "leaf1", "probes")


def test_refusal_is_a_deadletter_so_it_reuses_the_existing_quarantine_path():
    assert issubclass(main.TenantClaimRefused, main.DeadLetter)


# ── (a) forged tenant is refused and NOT persisted ───────────────────────────


def test_forged_syslog_tenant_is_quarantined_and_never_persisted(registry, monkeypatch):
    ch = RecordingCH()
    monkeypatch.setattr(main, "ch", ch)
    before = main.DEADLETTER_COUNT

    run(main.handle_syslog(_syslog(tenant_id="victim-corp")))

    assert ch.inserts == [], "a forged-tenant syslog event reached ClickHouse"
    assert main.TENANT_REFUSALS == {"syslog:claim_mismatch": 1}
    assert main.DEADLETTER_COUNT == before + 1
    rec = main.QUARANTINE[-1]
    assert rec["topic"] == "deadletter:syslog"
    assert "TenantClaimRefused" in rec["error"]
    # The payload is preserved for forensics — the point of quarantining rather
    # than dropping.
    assert json.loads(rec["payload"])["tenant_id"] == "victim-corp"


def test_forged_flow_tenant_is_quarantined_and_never_aggregated(registry, monkeypatch):
    ch = RecordingCH()
    monkeypatch.setattr(main, "ch", ch)
    monkeypatch.setattr(main, "FLOW_CORRELATION_ENABLED", True)
    main._FLOW_AGG.clear()

    run(main.handle_flow(_flow(tenant_id="victim-corp")))

    assert main._FLOW_AGG == {}, "a forged-tenant flow entered the volume aggregator"
    assert main.TENANT_REFUSALS == {"flows:claim_mismatch": 1}
    assert main.QUARANTINE[-1]["topic"] == "deadletter:flows"


def test_forged_flow_tenant_on_an_unknown_exporter_fails_closed(registry, monkeypatch):
    monkeypatch.setattr(main, "ch", RecordingCH())
    monkeypatch.setattr(main, "FLOW_CORRELATION_ENABLED", True)
    main._FLOW_AGG.clear()

    run(main.handle_flow(_flow(sampler_address="203.0.113.9", tenant_id="acme")))

    assert main._FLOW_AGG == {}
    assert main.TENANT_REFUSALS == {"flows:identity_unknown": 1}


def test_forged_trap_tenant_is_refused(registry, monkeypatch):
    monkeypatch.setattr(main, "ch", RecordingCH())
    run(main.handle_snmptrap({"device": "leaf1", "tenant_id": "victim-corp",
                              "trap_name": "linkDown", "host": "10.1.1.1"}))
    assert main.TENANT_REFUSALS == {"snmptrap:claim_mismatch": 1}


def test_forged_metric_tenant_is_refused(registry, monkeypatch):
    monkeypatch.setattr(main, "ch", RecordingCH())
    before = main.METRICS_ACCEPTED
    run(main.handle_metric({"device": "leaf1", "metric": "if_in_errors", "value": 5.0,
                            "signal_family": "interface", "if_name": "Et1",
                            "tenant_id": "victim-corp"}))
    assert main.TENANT_REFUSALS == {"metrics:claim_mismatch": 1}
    assert main.METRICS_ACCEPTED == before, "a forged-tenant metric was accepted"


def test_forged_wireless_session_tenant_is_refused(registry, monkeypatch):
    ch = RecordingCH()
    monkeypatch.setattr(main, "ch", ch)
    run(main.handle_wireless_session({
        "tenant_id": "victim-corp", "session_id": "s1", "client_mac": "aa:bb:cc:dd:ee:ff",
        "bssid": "00:11:22:33:44:55", "observer_id": "ap-1",
    }))
    assert ch.inserts == [], "wireless client PII was written under a forged tenant"
    assert main.TENANT_REFUSALS == {"wireless:claim_mismatch": 1}


def test_dead_letter_file_keeps_the_refused_payload(registry, monkeypatch, tmp_path):
    """The refusal rides the DURABLE quarantine, not just the in-memory ring."""
    dlq = tmp_path / "dlq"
    monkeypatch.setattr(main, "CORR_DLQ_DIR", str(dlq))
    monkeypatch.setattr(main, "ch", RecordingCH())
    run(main.handle_syslog(_syslog(tenant_id="victim-corp")))
    written = (dlq / "corr-deadletter.ndjson").read_text().strip().splitlines()
    assert len(written) == 1
    rec = json.loads(written[0])
    assert rec["topic"] == "deadletter:syslog"
    assert "tenant claim refused" in rec["error"]


# ── F-11 review fix 1: an UNATTRIBUTABLE refusal keeps NO payload ────────────
#
# The router seals the very same registry-MISS event under the quarantine key
# (docs/design/f11-seal-or-quarantine.md D2). If the correlation DLQ kept the
# event BODY — in the /deadletters ring and the durable corr-deadletter.ndjson
# — that would be a second, PLAINTEXT durable copy of what the router just
# encrypted: the exact confidentiality downgrade the owner invariant forbids.
# For this refusal class the record is metadata + identity sha256 only. Every
# OTHER dead-letter class (claim_mismatch, poison payloads, handler crashes)
# keeps its payload for forensics, unchanged — pinned by the tests above.


def test_unattributable_refusal_stores_metadata_and_identity_hash_only(
        registry, monkeypatch, tmp_path):
    dlq = tmp_path / "dlq"
    monkeypatch.setattr(main, "CORR_DLQ_DIR", str(dlq))
    ch = RecordingCH()
    monkeypatch.setattr(main, "ch", ch)
    secret = "user jsmith password=hunter2 tried su on console"
    want_sha = hashlib.sha256(b"ghost-device").hexdigest()

    run(main.handle_syslog(_syslog(hostname="ghost-device", message=secret)))

    assert ch.inserts == []
    assert main.TENANT_REFUSALS == {"syslog:identity_unattributable": 1}

    # The in-memory ring (/deadletters): metadata only.
    rec = main.QUARANTINE[-1]
    assert rec["topic"] == "deadletter:syslog"
    assert rec["lane"] == "syslog"
    assert rec["reason"] == "identity_unattributable"
    assert rec["identity_sha"] == want_sha
    assert rec["ts"]
    assert "payload" not in rec, \
        "the raw event body must never be kept for an unattributable event (F-11)"
    dumped = json.dumps(rec)
    assert secret not in dumped and "hunter2" not in dumped
    assert "ghost-device" not in dumped, \
        "the identity must be kept as a hash, never plaintext (F-11 D2)"

    # The durable NDJSON: same contract.
    lines = (dlq / "corr-deadletter.ndjson").read_text().strip().splitlines()
    assert len(lines) == 1
    assert secret not in lines[0] and "ghost-device" not in lines[0]
    written = json.loads(lines[0])
    assert written["identity_sha"] == want_sha
    assert written["reason"] == "identity_unattributable"
    assert "payload" not in written


def test_unattributable_flow_refusal_keeps_no_payload_either(registry, monkeypatch):
    monkeypatch.setattr(main, "ch", RecordingCH())
    monkeypatch.setattr(main, "FLOW_CORRELATION_ENABLED", True)
    main._FLOW_AGG.clear()

    run(main.handle_flow(_flow(sampler_address="198.51.100.7")))

    assert main._FLOW_AGG == {}
    assert main.TENANT_REFUSALS == {"flows:identity_unattributable": 1}
    rec = main.QUARANTINE[-1]
    assert rec["reason"] == "identity_unattributable"
    assert rec["identity_sha"] == hashlib.sha256(b"198.51.100.7").hexdigest()
    assert "payload" not in rec
    assert "198.51.100.7" not in json.dumps(rec)


# ── F-11 review fix 3: the snmptrap lane is registry-anchored too ────────────
#
# The trap tenant is stamped by the aggregator SOLELY from the device→tenant
# registry (same trust source as syslog/flows), and the router's generated
# quarantine stage seals snmptrap misses. Correlation must agree: a no-claim
# trap from an identity the registry never heard of is TENANT_UNATTRIBUTABLE
# and joins the quarantine — it must NOT process as 'global' into
# corr_signals/RCA/ticketing (INV-F11-10). D1 answers the NAT-ambiguity
# concern: ambiguous identities are deliberate registry misses that must
# quarantine, not process.


def _trap(**over) -> dict:
    ev = {
        "device": "leaf1",
        "host": "10.1.1.1",
        "trap_oid": "1.3.6.1.6.3.1.1.5.3",
        "trap_name": "linkDown",
        "severity": "warning",
        "varbinds": [{"oid": "1.3.6.1.2.1.31.1.1.1.1.7", "value": "Ethernet7"}],
    }
    ev.update(over)
    return ev


def test_unattributable_trap_is_quarantined_not_processed_as_global(registry, monkeypatch):
    ch = RecordingCH()
    monkeypatch.setattr(main, "ch", ch)

    run(main.handle_snmptrap(_trap(device="ghost-sw", host="203.0.113.50")))

    assert ch.inserts == [], \
        "an unattributable trap reached corr_signals — the RCA/ticketing surface (INV-F11-10)"
    assert main.TENANT_REFUSALS == {"snmptrap:identity_unattributable": 1}
    rec = main.QUARANTINE[-1]
    assert rec["topic"] == "deadletter:trap"
    assert rec["reason"] == "identity_unattributable"
    assert "payload" not in rec


def test_trap_from_known_platform_device_still_processes_as_global(registry, monkeypatch):
    """The discriminator is the registry MISS, never tenant=="" — a KNOWN
    platform device's traps keep feeding platform self-monitoring RCA."""
    ch = RecordingCH()
    monkeypatch.setattr(main, "ch", ch)

    run(main.handle_snmptrap(_trap(device="plat1", host="10.9.9.9")))
    run(main.SIGNAL_BATCH.flush())  # drain the batched write path (see CHBatcher)

    rows = ch.rows_for("netops.corr_signals")
    assert rows, "a known platform device's trap stopped producing a signal"
    assert {r["tenant_id"] for r in rows} == {"global"}
    assert main.TENANT_REFUSALS == {}


def test_trap_identity_falls_back_to_source_address_like_the_router(registry, monkeypatch):
    """quarantine.go keys the snmptrap identity on device-falling-back-to-host;
    correlation must key on the SAME identity, or the two tiers disagree about
    what is attributable (router restores an event correlation then refuses)."""
    from entity_resolver import EMPTY_RESOLVER
    ch = RecordingCH()
    monkeypatch.setattr(main, "ch", ch)
    monkeypatch.setattr(main, "cached_entity_resolver_all", lambda: EMPTY_RESOLVER)

    # device unattributed, but the source address IS a registry identity
    # (10.1.1.1 → acme): attributable, so NOT refused. The classifier still
    # emits no signal for a device-less trap — that is the anti-phantom
    # guardrail, not a refusal.
    run(main.handle_snmptrap(_trap(device="")))

    assert main.TENANT_REFUSALS == {}
    assert list(main.QUARANTINE) == []


def test_forged_trap_tenant_on_unknown_device_fails_closed(registry, monkeypatch):
    monkeypatch.setattr(main, "ch", RecordingCH())
    run(main.handle_snmptrap(_trap(device="ghost-sw", host="203.0.113.50",
                                   tenant_id="acme")))
    assert main.TENANT_REFUSALS == {"snmptrap:identity_unknown": 1}


# ── (b) the legitimate event still flows, unchanged ──────────────────────────


def test_legitimate_claim_flows_end_to_end_under_the_registry_tenant(registry, monkeypatch):
    ch = RecordingCH()
    monkeypatch.setattr(main, "ch", ch)

    run(main.handle_syslog(_syslog(tenant_id="acme")))
    run(main.SIGNAL_BATCH.flush())  # drain the batched write path

    rows = ch.rows_for("netops.corr_signals")
    assert rows, "a legitimate syslog event stopped producing a signal"
    assert {r["tenant_id"] for r in rows} == {"acme"}
    assert main.TENANT_CLAIMS_VERIFIED == 1
    assert main.TENANT_REFUSALS == {}
    assert list(main.QUARANTINE) == []


def test_untenanted_event_still_resolves_through_the_registry(registry, monkeypatch):
    """The absence fallback is preserved verbatim — this is the shape Vector
    actually emits today for a device it could enrich."""
    ch = RecordingCH()
    monkeypatch.setattr(main, "ch", ch)

    run(main.handle_syslog(_syslog()))
    run(main.SIGNAL_BATCH.flush())  # drain the batched write path

    rows = ch.rows_for("netops.corr_signals")
    assert rows and {r["tenant_id"] for r in rows} == {"acme"}
    assert main.TENANT_REFUSALS == {}


def test_legitimate_flow_still_aggregates(registry, monkeypatch):
    monkeypatch.setattr(main, "ch", RecordingCH())
    monkeypatch.setattr(main, "FLOW_CORRELATION_ENABLED", True)
    main._FLOW_AGG.clear()

    run(main.handle_flow(_flow(tenant_id="acme")))

    assert ("acme", "10.1.1.1:if3") in main._FLOW_AGG
    assert main.TENANT_REFUSALS == {}
    main._FLOW_AGG.clear()


def test_no_registry_at_all_quarantines_rather_than_processing(monkeypatch, tmp_path):
    """F-11 (superseding the pre-decision contract this test used to pin): with
    a missing/empty CSV, an anchored-lane event's identity is a registry MISS —
    TENANT_UNATTRIBUTABLE. It must NOT be processed as the platform tenant
    (that reaches RCA and the global tenant's ticket/notification
    destinations); it joins the bounded durable quarantine and NO corr_* row
    is written. Quarantine — encrypted at the storage tier, bounded and
    recoverable here — is the safe failure mode for a broken registry mount;
    plaintext-shared processing was the unsafe one. The vector-side miss-rate
    alert (TenantEnrichmentMissRateJumped) is what surfaces the outage."""
    monkeypatch.setattr(main, "TENANT_ENRICHMENT_FILE", str(tmp_path / "absent.csv"))
    monkeypatch.setattr(main, "_tenant_map", {})
    monkeypatch.setattr(main, "_tenant_mtime", -1.0)
    ch = RecordingCH()
    monkeypatch.setattr(main, "ch", ch)

    run(main.handle_syslog(_syslog()))
    assert ch.rows_for("netops.corr_signals") == [], \
        "an unattributable event reached corr_* — the RCA/ticketing surface (INV-F11-10)"
    assert main.TENANT_REFUSALS == {"syslog:identity_unattributable": 1}

    with pytest.raises(main.TenantClaimRefused):
        main.verified_tenant("acme", "leaf1", "syslog", registry_anchored=True)


# ── (d) every insert carries the row's own tenant scope ──────────────────────


def test_insert_scope_is_the_rows_own_tenant():
    assert main.insert_scope([{"tenant_id": "acme", "x": 1}]) == "acme"
    assert main.insert_scope([{"tenant_id": "acme"}, {"tenant_id": "acme"}]) == "acme"
    assert main.insert_scope([{"tenant_id": ""}]) == ""


def test_insert_scope_only_wildcards_for_a_genuinely_cross_tenant_batch():
    assert main.insert_scope([{"tenant_id": "a"}, {"tenant_id": "b"}]) == "__all__"
    assert main.insert_scope([{"no_tenant_column": 1}]) == "__all__"


class _CapturingHTTP:
    def __init__(self) -> None:
        self.params: list[dict] = []

    async def post(self, url, params=None, content=None, auth=None, headers=None):
        self.params.append(dict(params or {}))

        class _R:
            status_code = 200
            headers: ClassVar[dict] = {}
            text = ""

        return _R()


def test_clickhouse_insert_sends_the_rows_tenant_scope():
    ch = main.CH("http://ch:8123", "u", "p")
    http = _CapturingHTTP()
    ch.client = http  # type: ignore[assignment]

    assert run(ch.insert("netops.corr_signals", [{"tenant_id": "acme", "kind": "k"}])) is True
    assert http.params[0]["tenant_scope"] == "acme"
    assert main.CH_CROSS_TENANT_INSERTS == {}


def test_cross_tenant_rollup_insert_announces_itself_and_is_counted():
    """The per-tenant write-amp rollup is the one legitimate cross-tenant
    writer; it must be visible rather than indistinguishable from a leak."""
    ch = main.CH("http://ch:8123", "u", "p")
    http = _CapturingHTTP()
    ch.client = http  # type: ignore[assignment]

    run(ch.insert("netops.corr_tenant_write_amp",
                  [{"tenant_id": "a"}, {"tenant_id": "b"}]))
    assert http.params[0]["tenant_scope"] == "__all__"
    assert main.CH_CROSS_TENANT_INSERTS == {"netops.corr_tenant_write_amp": 1}


def test_insert_still_honours_the_dedup_token_contract():
    """#126 write-integrity: the scope is additive, it must not displace the
    idempotency token or the wire-correctness params."""
    ch = main.CH("http://ch:8123", "u", "p")
    http = _CapturingHTTP()
    ch.client = http  # type: ignore[assignment]

    run(ch.insert("netops.corr_signals", [{"tenant_id": "acme"}], dedup_token="t:0:1:x"))
    p = http.params[0]
    assert p["insert_deduplication_token"] == "t:0:1:x"
    assert p["wait_end_of_query"] == "1"
    assert p["query"].startswith("INSERT INTO netops.corr_signals")


def test_signal_inserts_carry_the_signals_own_scope(registry, monkeypatch):
    """End to end: the scope on the wire equals the verified tenant, not a
    wildcard."""
    scopes: list[str] = []

    class ScopeCH:
        async def insert(self, table, rows, dedup_token=""):
            scopes.append(main.insert_scope(list(rows)))
            return True

    monkeypatch.setattr(main, "ch", ScopeCH())
    run(main.handle_syslog(_syslog(tenant_id="acme")))
    run(main.SIGNAL_BATCH.flush())  # drain the batched write path
    assert scopes and set(scopes) == {"acme"}


# ── observability (§10) ──────────────────────────────────────────────────────


def test_refusals_are_exposed_as_metrics_and_health(registry, monkeypatch):
    monkeypatch.setattr(main, "ch", RecordingCH())
    run(main.handle_syslog(_syslog(tenant_id="victim-corp")))

    h = run(main.health())
    tv = h["tenant_verification"]
    assert tv["claims_refused"] == 1
    assert tv["refusals"]["syslog:claim_mismatch"] == 1

    body = run(main.metrics_exposition()).body.decode()
    assert 'corr_tenant_claims_total{outcome="refused"} 1' in body
    assert 'corr_tenant_claims_refused_total{lane="syslog",reason="claim_mismatch"} 1' in body


# ── the ingest tier: the two halves that live in VRL ─────────────────────────
#
# VRL cannot be executed from this suite (it needs the Vector binary), so these
# assert the shipped CONFIG TEXT. They are structural guards against the exact
# regressions being fixed, not proof that the pipeline behaves — that needs a
# running Vector.


def _vector_src(tier: str, transform: str) -> str:
    import yaml
    path = REPO / "deployment" / "docker" / tier / "vector.yaml"
    cfg = yaml.safe_load(path.read_text())
    return cfg["transforms"][transform]["source"]


def test_fortigate_log_body_can_no_longer_set_tenancy():
    """TENANT-HIGH-3: the second attribution, re-derived from `devname=` INSIDE
    the attacker-controlled log body, is gone."""
    src = _vector_src("vector", "syslog_normalized")
    body = src.split("if vendor == \"fortinet\"", 1)[1]
    # No line in the FortiGate branch may assign .tenant_id.
    offenders = [ln for ln in body.splitlines()
                 if ".tenant_id" in ln and "=" in ln.split("#", 1)[0]
                 and ln.split("#", 1)[0].strip().startswith(".tenant_id")]
    assert offenders == [], f"the FortiGate body still sets tenancy: {offenders}"


def test_syslog_lane_resets_the_inbound_tenant_before_enriching():
    src = _vector_src("vector", "syslog_normalized")
    assert '.tenant_id = ""' in src, \
        "the syslog lane no longer discards the inbound tenant claim"
    assert src.index('.tenant_id = ""') < src.index('find_enrichment_table_records'), \
        "the reset must happen BEFORE the registry lookup, or a claim survives"


def test_flow_lane_treats_the_registry_as_authoritative_not_as_a_fallback():
    """TENANT-HIGH-4: the lookup used to be skipped whenever the record already
    carried a tenant_id, so a self-declared tenant on netops.flows was routed
    into that tenant's index unchecked."""
    src = _vector_src("vector-router", "flows_decoded")
    assert 'if !exists(.tenant_id) { .tenant_id = "" }' not in src, \
        "the inbound tenant claim is preserved again"
    assert 'if sampler != "" && (to_string(.tenant_id) ?? "") == ""' not in src, \
        "the registry lookup is gated on the inbound claim again"
    assert "claimed_tenant = to_string(.tenant_id)" in src, \
        "the inbound claim is no longer captured for comparison"
    assert ".tenant_id = tenant_resolved" in src, \
        "the written tenant is no longer the registry's resolved value"
    assert "claim_rejected" in src, \
        "a rejected tenant claim is not distinguishable from an enrichment miss"


def test_flow_lane_uses_locals_not_a_reread_of_the_assigned_path():
    """VRL guard: `to_string()` on a path VRL knows is a string is INFALLIBLE,
    and a dangling `??` on an infallible call is a COMPILE error — vector then
    exits 78 at boot. Once .tenant_id is unconditionally assigned, every later
    read must go through the local, not through to_string(.tenant_id)."""
    src = _vector_src("vector-router", "flows_decoded")
    after = src.split(".tenant_id = tenant_resolved", 1)[1]
    assert "to_string(.tenant_id)" not in after
    fgt = _vector_src("vector", "syslog_normalized").split('.tenant_id = ""', 1)[1]
    assert "to_string(.tenant_id)" not in fgt


def test_syslog_ng_documents_why_keep_hostname_is_not_an_identity():
    # F-1 split the config: the shared body (options + the TENANT-HIGH-3
    # residual-risk statement) lives in core.conf, included by both variants.
    conf = (REPO / "deployment" / "docker" / "syslog-ng" / "core.conf").read_text()
    assert "keep_hostname(yes)" in conf
    assert "reliable device key" not in conf, \
        "the misleading NAT-survival-means-authenticated claim is back"
    for required in ("UNVERIFIED CLAIM", "RESIDUAL RISK", "RFC5425"):
        assert required in conf, f"syslog-ng.conf no longer documents {required}"


def test_no_new_undeclared_field_is_stamped_by_the_ingest_tier():
    """`dynamic: false` means a field no index template declares is silently
    unsearchable (tests/test_ingest_contract.py owns the full rule). Assert here
    that THIS change introduced no new top-level assignment, since the fix was
    deliberately built out of existing fields."""
    import re

    import yaml
    stamped = set()
    for tier in ("vector", "vector-router"):
        cfg = yaml.safe_load((REPO / "deployment" / "docker" / tier / "vector.yaml").read_text())
        for tr in (cfg.get("transforms") or {}).values():
            stamped |= set(re.findall(r"^\s*\.([a-zA-Z_][a-zA-Z0-9_]*)\s*=",
                                      tr.get("source") or "", re.MULTILINE))
    assert "tenant_identity" not in stamped and "claimed_tenant" not in stamped, \
        "the tenant fix stamped a new top-level field; declare it or use a VRL local"


def test_repo_layout_assumption_holds():
    """Guards the REPO path these config tests resolve from."""
    assert (REPO / "deployment" / "docker" / "vector" / "vector.yaml").is_file()
    assert os.path.isdir(REPO / "src" / "correlation")
