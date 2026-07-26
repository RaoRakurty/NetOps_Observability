"""Onboarding-episode failure classes (#128 Phase 4, report §16/§23) — the
classes the spec demands, not just examples:

  · a PSK WLAN has no RADIUS step — a missing auth observation is never a
    failure of an inapplicable phase
  · skipped ≠ failed: DNS not attempted after DHCP failure is 'skipped'
  · dual-stack v6-only success = DEGRADED (not success, not failed)
  · the signal rule: successes emit NOTHING; failures emit ONE signal at the
    terminal phase's kind (DHCP failure → NETWORK-layer kind, binds to the
    session, tokens name only the AP)
  · randomized MAC → identity 'unknown', session-scoped — never guessed
  · determinism: same observations ⇒ same episode id (replay contract)
"""
from __future__ import annotations

from datetime import datetime, timezone

from layers import CausalLayer, layer_of
from signals import EntityType, Severity
from wireless_onboarding import (
    assemble_episode,
    client_identity,
    episode_signal,
    is_randomized_mac,
)

T0 = datetime(2026, 7, 26, 12, 0, 0, tzinfo=timezone.utc)
WLAN_DOT1X = {"wlan_id": "wlan-corp", "auth_method": "dot1x",
              "security_mode": "wpa2_enterprise", "address_policy": "dual"}
WLAN_OPEN = {"wlan_id": "wlan-guest", "auth_method": "open",
             "security_mode": "open", "address_policy": "v4"}


def _ok(phase_ms=20):
    return {"outcome": "success", "duration_ms": phase_ms}


def _fail(reason=""):
    return {"outcome": "failure", "reason_code": reason}


def full_success_obs():
    return {p: _ok() for p in ("discovery", "authentication", "association",
                               "key_exchange", "addressing", "name_resolution",
                               "first_data")}


def test_success_episode_emits_no_signal():
    ep = assemble_episode("t1", "a8:66:7f:01:02:03", "aa:bb:cc:00:00:01",
                          "ap-abc", WLAN_DOT1X, full_success_obs(), T0, "wlc:int-1")
    assert ep.terminal_outcome == "success"
    assert episode_signal(ep) is None, "successes never enter the engine window"


def test_open_wlan_has_no_key_exchange_and_no_false_failure():
    obs = {p: _ok() for p in ("discovery", "authentication", "association",
                              "addressing", "name_resolution", "first_data")}
    ep = assemble_episode("t1", "a8:66:7f:01:02:03", "aa:bb:cc:00:00:01",
                          "ap-abc", WLAN_OPEN, obs, T0, "wlc:int-1")
    key = next(p for p in ep.phases if p.phase == "key_exchange")
    assert not key.applicable and key.outcome == "skipped"
    assert ep.terminal_outcome == "success", "an inapplicable phase must never fail"


def test_dhcp_failure_skips_dns_and_signals_at_network_layer():
    obs = {"discovery": _ok(), "authentication": _ok(), "association": _ok(),
           "key_exchange": _ok(), "addressing": _fail("no_offer")}
    ep = assemble_episode("t1", "a8:66:7f:01:02:03", "aa:bb:cc:00:00:01",
                          "ap-abc", WLAN_DOT1X, obs, T0, "wlc:int-1")
    assert ep.terminal_phase == "addressing" and ep.terminal_outcome == "failure"
    dns = next(p for p in ep.phases if p.phase == "name_resolution")
    assert dns.outcome == "skipped", "not-attempted DNS is skipped, never failed"

    sig = episode_signal(ep)
    assert sig is not None
    assert sig.kind == "wireless_onboarding_dhcp_failure"
    assert layer_of(sig.kind) is CausalLayer.NETWORK, (
        "a DHCP failure must order at NETWORK so it correlates with the DHCP "
        "server, not the AP")
    assert sig.entity_type is EntityType.WIRELESS_SESSION
    assert sig.severity is Severity.HIGH
    assert sig.entity_tokens == ("ap-abc",), "tokens name ONE AP, nothing wider"


def test_dual_stack_partial_is_degraded_not_success():
    obs = {"discovery": _ok(), "authentication": _ok(), "association": _ok(),
           "key_exchange": _ok(),
           "addressing_v6": {"outcome": "success"},
           "addressing_v4": {"outcome": "failure"},
           "name_resolution": _ok(), "first_data": _ok()}
    ep = assemble_episode("t1", "a8:66:7f:01:02:03", "aa:bb:cc:00:00:01",
                          "ap-abc", WLAN_DOT1X, obs, T0, "wlc:int-1")
    assert ep.terminal_outcome == "degraded", (
        "v6-up/v4-down is DEGRADED — a v4-only monitor would lie 'success'")
    sig = episode_signal(ep)
    assert sig is not None and sig.severity is Severity.WARN
    assert sig.kind == "wireless_onboarding_dhcp_failure"
    assert sig.attrs["terminal_outcome"] == "degraded"


def test_auth_failure_signals_at_link_layer():
    obs = {"discovery": _ok(), "authentication": {"outcome": "timeout",
                                                  "reason_code": "radius_timeout"}}
    ep = assemble_episode("t1", "a8:66:7f:01:02:03", "aa:bb:cc:00:00:01",
                          "ap-abc", WLAN_DOT1X, obs, T0, "wlc:int-1")
    sig = episode_signal(ep)
    assert sig is not None and sig.kind == "wireless_onboarding_auth_failure"
    assert layer_of(sig.kind) is CausalLayer.LINK


def test_identity_ladder():
    # EAP-TLS CN beats everything.
    cid, conf, method = client_identity("t1", "02:00:5e:00:53:01", eap_cn="laptop-42")
    assert conf == "authoritative" and method == "eap_tls_cn"
    # Stable (globally-unique) MAC is strong.
    cid2, conf2, _ = client_identity("t1", "a8:66:7f:01:02:03")
    assert conf2 == "strong"
    # Randomized MAC with nothing better: UNKNOWN, session-scoped — two
    # different sessions get two different identities (no fake continuity).
    a = client_identity("t1", "02:00:5e:00:53:01", session_seed="s1")
    b = client_identity("t1", "02:00:5e:00:53:01", session_seed="s2")
    assert a[1] == "unknown" and b[1] == "unknown" and a[0] != b[0]
    # Malformed fails closed.
    assert is_randomized_mac("garbage") and is_randomized_mac("")


def test_episode_determinism_and_ch_row():
    obs = {"discovery": _ok(), "authentication": _fail("bad_cred")}
    e1 = assemble_episode("t1", "A8:66:7F:01:02:03", "aa:bb:cc:00:00:01",
                          "ap-abc", WLAN_DOT1X, obs, T0, "wlc:int-1")
    e2 = assemble_episode("t1", "A8:66:7F:01:02:03", "aa:bb:cc:00:00:01",
                          "ap-abc", WLAN_DOT1X, obs, T0, "wlc:int-1")
    assert e1.episode_id == e2.episode_id, "same inputs ⇒ same episode id"
    row = e1.to_ch_row()
    assert row["terminal_phase"] == "authentication"
    assert row["tenant_id"] == "t1" and row["attempt_start"] == int(T0.timestamp() * 1000)
    # phases JSON is bounded, sorted, machine-readable.
    import json
    phases = json.loads(row["phases"])
    assert [p["phase"] for p in phases][:2] == ["discovery", "authentication"]
