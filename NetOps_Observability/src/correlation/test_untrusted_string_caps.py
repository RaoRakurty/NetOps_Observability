"""Bounds on untrusted intake strings — audit PIPE-MED-11 / FUNC-MED-8.

The intake validated the SHAPE of a record but never its SIZE. Device-,
controller- and attacker-supplied strings flowed uncapped into ClickHouse String
columns, OpenSearch documents and metric labels, where unbounded distinct values
are a cardinality bomb reachable from untrusted input.

Every test asserts the same two-part contract, because a cap that mangles ordinary
data is as much a defect as no cap at all:

    1. a hostile / oversize / high-cardinality input is BOUNDED, and
    2. a NORMAL value passes through completely unchanged.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

import signals as sig_mod
from app_producers import app_identity_from_event
from cloud_log_parsers import dns_error_rollup, waf_block_rollup
from controller_events import controller_event_to_signal
from signals import (
    ATTRS_MAX_BYTES,
    MAX_ID_CHARS,
    MAX_LABEL_CHARS,
    MAX_TEXT_CHARS,
    MAX_TOKENS,
    DeadLetter,
    EntityType,
    ModalityClass,
    Observer,
    ObserverType,
    Severity,
    Signal,
    Source,
    normalize_mac,
)
from wireless_onboarding import assemble_episode, client_identity

T0 = datetime(2026, 7, 27, 12, 0, 0, tzinfo=timezone.utc)
HOSTILE = "A" * 20000


def sig(**kw) -> Signal:
    base = {
        "tenant_id": "t1", "ts": T0, "source": Source.METRIC, "kind": "metric_anomaly",
        "observer": Observer(observer_id="leaf1", observer_type=ObserverType.DEVICE),
        "modality_class": ModalityClass.DEVICE_TELEMETRY,
        "entity_type": EntityType.DEVICE, "entity_id": "leaf1",
        "severity": Severity.WARN, "native_id": "leaf1|cpu|onset|123",
    }
    base.update(kw)
    return Signal(**base)


# ── the model boundary: identity-class fields ────────────────────────────────


def test_identity_fields_are_bounded_at_the_model():
    s = sig(entity_id=HOSTILE, native_id=HOSTILE, kind=HOSTILE,
            site=HOSTILE, metric_name=HOSTILE, path_id=HOSTILE, service_id=HOSTILE)
    assert len(s.entity_id) == MAX_ID_CHARS
    assert len(s.native_id) == MAX_ID_CHARS
    assert len(s.kind) == MAX_ID_CHARS
    assert len(s.site) == MAX_LABEL_CHARS
    assert len(s.metric_name) == MAX_LABEL_CHARS
    assert len(s.path_id) == MAX_LABEL_CHARS
    assert len(s.service_id) == MAX_LABEL_CHARS


def test_a_normal_signal_is_byte_identical_after_the_caps():
    """The cap must be invisible to real traffic — no trimming, no reordering."""
    s = sig(site="dc1-row3", metric_name="if_errors", path_id="p-42",
            service_id="billing", entity_tokens=("leaf1", "Gi0/0/1"))
    assert s.entity_id == "leaf1"
    assert s.native_id == "leaf1|cpu|onset|123"
    assert s.site == "dc1-row3" and s.metric_name == "if_errors"
    assert s.path_id == "p-42" and s.service_id == "billing"
    assert s.entity_tokens == ("leaf1", "Gi0/0/1")


def test_capping_is_idempotent_so_replay_never_drifts():
    once = sig(entity_id=HOSTILE, native_id=HOSTILE)
    twice = sig(entity_id=once.entity_id, native_id=once.native_id)
    assert twice.entity_id == once.entity_id
    assert twice.native_id == once.native_id
    # Same capped native_id ⇒ same deterministic id: the cap is replay-safe.
    assert twice.signal_id == once.signal_id


def test_entity_tokens_are_bounded_in_count_and_in_length():
    s = sig(entity_tokens=tuple(f"device:d{i}" for i in range(500)))
    assert len(s.entity_tokens) == MAX_TOKENS, "token CARDINALITY must be bounded"
    s2 = sig(entity_tokens=("device:" + HOSTILE,))
    assert len(s2.entity_tokens[0]) == MAX_ID_CHARS


def test_observer_block_is_bounded():
    o = Observer(observer_id=HOSTILE, observer_type=ObserverType.CONTROLLER,
                 location=HOSTILE, trust_domain=HOSTILE,
                 collection_path=HOSTILE, clock_quality=HOSTILE)
    for f in ("observer_id", "location", "trust_domain", "collection_path", "clock_quality"):
        assert len(getattr(o, f)) == MAX_LABEL_CHARS, f
    # A normal observer is untouched.
    n = Observer(observer_id="meraki:int-7", observer_type=ObserverType.CONTROLLER,
                 collection_path="via_controller")
    assert n.observer_id == "meraki:int-7" and n.collection_path == "via_controller"


def test_truncation_is_counted_and_never_silent(caplog):
    before = sig_mod.TRUNCATIONS
    with caplog.at_level("WARNING", logger="correlation.signals"):
        sig(entity_id=HOSTILE)
    assert sig_mod.TRUNCATIONS > before, "a bound applied must increment the counter (§10)"
    assert any("entity_id" in r.getMessage() for r in caplog.records), \
        "the bounded field must be NAMED in the log — truncation is never silent"
    # …and a normal signal must not spam the log or the counter.
    quiet = sig_mod.TRUNCATIONS
    sig()
    assert sig_mod.TRUNCATIONS == quiet


# ── FUNC-MED-8: oversize attrs TRUNCATE, they do not dead-letter ─────────────


def test_oversize_attrs_truncate_the_field_not_the_signal():
    """The old behaviour raised DeadLetter, which turned ONE oversize context
    field into two failures: the real event was lost to the engine, and the whole
    unredacted record went to the DLQ. The cap must cost the field, not the event."""
    row = sig(attrs={"message": "x" * 9000, "interface": "Gi0/0/1",
                     "facility": "LINK"}).to_ch_row()
    attrs = json.loads(row["attrs"])
    assert len(row["attrs"].encode()) <= ATTRS_MAX_BYTES
    # The event survived AND the small, useful fields are intact.
    assert attrs["interface"] == "Gi0/0/1"
    assert attrs["facility"] == "LINK"
    # The truncation travels with the row — a reader can see the message was cut.
    assert attrs["attrs_truncated"] == ["message"]
    assert 0 < len(attrs["message"]) < 9000


def test_truncating_attrs_does_not_change_the_signal_id():
    """signal_id derives from source|native_id|ts, so bounding attrs must not
    perturb identity — otherwise replay of a truncated signal would fork."""
    s = sig(attrs={"blob": "y" * 9000})
    assert s.to_ch_row()["signal_id"] == str(s.signal_id) == str(sig().signal_id)


def test_dead_letter_survives_for_a_genuine_producer_bug():
    with pytest.raises(DeadLetter):
        sig(attrs={f"key_{i}": i for i in range(2000)}).to_ch_row()


def test_normal_attrs_are_untouched():
    row = sig(attrs={"facility": "LINK", "mnemonic": "UPDOWN", "severity": 3}).to_ch_row()
    attrs = json.loads(row["attrs"])
    assert "attrs_truncated" not in attrs
    assert attrs["facility"] == "LINK" and attrs["severity"] == 3


# ── MAC / BSSID shape ────────────────────────────────────────────────────────


@pytest.mark.parametrize("raw,want", [
    ("AA:BB:CC:DD:EE:FF", "aa:bb:cc:dd:ee:ff"),
    ("aa-bb-cc-dd-ee-ff", "aa:bb:cc:dd:ee:ff"),
    ("aabb.ccdd.eeff", "aa:bb:cc:dd:ee:ff"),   # Cisco dotted-quad
    ("aabbccddeeff", "aa:bb:cc:dd:ee:ff"),
])
def test_normalize_mac_accepts_every_real_convention(raw, want):
    assert normalize_mac(raw) == want


@pytest.mark.parametrize("raw", [
    "", "not-a-mac", "aa:bb:cc:dd:ee", "zz:bb:cc:dd:ee:ff",
    "aa:bb:cc:dd:ee:ff:00", "A" * 5000, "<script>alert(1)</script>", None, 12345,
])
def test_normalize_mac_is_default_closed(raw):
    """Anything that is not 12 hex nibbles is NOT a MAC. Default-closed: it
    returns "" rather than admitting attacker text into an identity column."""
    assert normalize_mac(raw) == ""


def test_wireless_episode_rejects_a_malformed_mac_and_records_the_rejection():
    ep = assemble_episode(
        "t1", client_mac=HOSTILE, bssid="not-a-bssid", ap_ref=HOSTILE,
        wlan=({"auth_method": "psk", "address_policy": "v4"}),
        observations={"authentication": {"outcome": "failure",
                                         "reason_code": HOSTILE,
                                         "reason_text": HOSTILE,
                                         "evidence_ref": HOSTILE}},
        attempt_start=T0, observer_id=HOSTILE, wlan_ref="w1")
    assert ep.client_mac == "" and ep.bssid == ""
    # Rejected, but NOT silently: the fact is recorded, bounded, in attrs.
    assert ep.attrs["client_mac_invalid"].startswith("A")
    assert len(ep.attrs["client_mac_invalid"]) <= 32
    assert ep.attrs["bssid_invalid"] == "not-a-bssid"
    assert len(ep.ap_ref) == MAX_LABEL_CHARS
    assert len(ep.observer_id) == MAX_LABEL_CHARS
    auth = next(p for p in ep.phases if p.phase == "authentication")
    assert len(auth.reason_code) == MAX_LABEL_CHARS
    assert len(auth.reason_text) == MAX_TEXT_CHARS
    assert len(auth.evidence_ref) == MAX_LABEL_CHARS


def test_wireless_episode_with_a_real_mac_is_unchanged():
    ep = assemble_episode(
        "t1", client_mac="AA:BB:CC:11:22:33", bssid="00:11:22:33:44:55",
        ap_ref="ap-7", wlan={"auth_method": "psk", "address_policy": "v4"},
        observations={"addressing": {"outcome": "failure", "reason_code": "dhcp_nak",
                                     "reason_text": "no offer from relay"}},
        attempt_start=T0, observer_id="wlc-1", wlan_ref="w1")
    assert ep.client_mac == "aa:bb:cc:11:22:33"
    assert ep.bssid == "00:11:22:33:44:55"
    assert ep.attrs == {}
    addr = next(p for p in ep.phases if p.phase == "addressing")
    assert addr.reason_code == "dhcp_nak"
    assert addr.reason_text == "no offer from relay"


def test_stable_mac_identity_rung_requires_a_real_mac():
    """The `stable_mac` rung claims cross-session continuity. A blob that is not a
    MAC must never earn it — it falls to the session-scoped rung, which is the
    honest answer (the ladder under-claims, never over-claims)."""
    _, conf, method = client_identity("t1", HOSTILE, session_seed="s1")
    assert (conf, method) == ("unknown", "randomized_mac")
    # 0x00 first octet: the U/L bit is clear, so this is a burned-in (stable) MAC.
    _, conf, method = client_identity("t1", "00:11:22:33:44:55")
    assert (conf, method) == ("strong", "stable_mac")
    # Same MAC in any convention ⇒ the SAME client id (normalization, not chance).
    a, _, _ = client_identity("t1", "00:11:22:33:44:55")
    b, _, _ = client_identity("t1", "0011.2233.4455")
    assert a == b


# ── cloud logs: the most attacker-proximate intake we have ───────────────────


def test_waf_rollup_bounds_the_attacker_supplied_host_header_and_client():
    recs = [{
        "action": "BLOCK", "webaclId": "arn:aws:wafv2:us-east-1:1:acl/x",
        "terminatingRuleId": "r1", "timestamp": 1781179200000,
        "httpRequest": {
            "uri": "/" + "u" * 5000,
            "clientIp": "9" * 5000,
            "headers": [{"name": "Host", "value": "evil." + "h" * 5000}],
        },
    }]
    out = waf_block_rollup(recs)
    assert len(out) == 1
    a = out[0]["attrs"]
    assert len(a["host"]) == MAX_LABEL_CHARS
    assert len(a["sample_client"]) == MAX_LABEL_CHARS
    assert len(a["sample_uri"]) <= 200


def test_waf_rollup_leaves_a_normal_request_alone():
    recs = [{
        "action": "BLOCK", "webaclId": "acl-1", "terminatingRuleId": "sqli",
        "timestamp": 1781179200000,
        "httpRequest": {"uri": "/api/v1/pay", "clientIp": "203.0.113.9",
                        "headers": [{"name": "Host", "value": "pay.example.com"}]},
    }]
    a = waf_block_rollup(recs)[0]["attrs"]
    assert a["host"] == "pay.example.com"
    assert a["sample_client"] == "203.0.113.9"
    assert a["sample_uri"] == "/api/v1/pay"


def test_dns_rollup_bounds_the_client_supplied_query_name_and_source():
    recs = [{"query_name": "x" * 5000 + ".", "rcode": "NXDOMAIN",
             "srcaddr": "1" * 5000, "vpc_id": "v" * 5000,
             "query_timestamp": "2026-07-27T12:00:00Z", "query_type": "A"}]
    out = dns_error_rollup(recs)
    assert len(out[0]["resource_id"]) == MAX_LABEL_CHARS
    assert len(out[0]["attrs"]["sample_client"]) == MAX_LABEL_CHARS
    assert len(out[0]["attrs"]["vpc"]) == MAX_LABEL_CHARS


# ── controller events ────────────────────────────────────────────────────────


def test_controller_hints_blob_is_bounded_in_keys_and_values():
    s = controller_event_to_signal({
        "tenant_id": "t1", "device_id": "edge-1",
        "normalized_event_type": "controller_bfd_down",
        "source_system": "vmanage", "message": HOSTILE,
        "correlation_hints": {f"k{i}": HOSTILE for i in range(500)},
    }, T0)
    assert s is not None
    hints = s.attrs["correlation_hints"]
    assert len(hints) <= 17, "hint KEY COUNT must be bounded (+1 truncation marker)"
    assert hints["_hints_truncated"] == 500 - 16
    assert all(len(v) <= MAX_LABEL_CHARS for v in hints.values() if isinstance(v, str))
    assert len(s.attrs["message"]) == MAX_TEXT_CHARS
    # And the whole row still fits the attrs bound, without dead-lettering.
    assert len(s.to_ch_row()["attrs"].encode()) <= ATTRS_MAX_BYTES


def test_controller_event_with_normal_hints_is_unchanged():
    s = controller_event_to_signal({
        "tenant_id": "t1", "device_id": "edge-1",
        "normalized_event_type": "controller_bfd_down", "source_system": "vmanage",
        "message": "BFD session to 10.0.0.1 went down",
        "correlation_hints": {"bfd_session": "10.0.0.1", "color": "mpls"},
    }, T0)
    assert s.attrs["correlation_hints"] == {"bfd_session": "10.0.0.1", "color": "mpls"}
    assert s.attrs["message"] == "BFD session to 10.0.0.1 went down"


# ── app-identity wire adapter ────────────────────────────────────────────────


def test_app_identity_wire_event_is_bounded():
    s = app_identity_from_event({
        "tenant_id": "t1", "app": HOSTILE, "provider": HOSTILE,
        "canonical_app_id": HOSTILE, "component": HOSTILE, "dst_ip": HOSTILE,
        "proto": HOSTILE, "flow_id": HOSTILE, "session_id": HOSTILE,
        "sources": [f"src-{i}" for i in range(500)],
        "entity_tokens": [f"host:h{i}" for i in range(500)],
    }, "t1", T0)
    assert len(s.entity_id) <= MAX_ID_CHARS
    assert len(s.attrs["provider"]) == MAX_LABEL_CHARS
    assert len(s.attrs["sources"]) <= 32
    assert len(s.entity_tokens) <= MAX_TOKENS
    assert len(s.to_ch_row()["attrs"].encode()) <= ATTRS_MAX_BYTES


def test_app_identity_normal_event_is_unchanged():
    s = app_identity_from_event({
        "tenant_id": "t1", "app": "salesforce", "provider": "saas",
        "dst_ip": "203.0.113.7", "proto": "tcp",
        "sources": ["dns", "tls_sni"], "entity_tokens": ["host:web-1"],
    }, "t1", T0)
    assert s.entity_id == "salesforce"
    assert s.attrs["provider"] == "saas"
    assert s.attrs["sources"] == ["dns", "tls_sni"]
    assert s.entity_tokens == ("host:web-1",)
