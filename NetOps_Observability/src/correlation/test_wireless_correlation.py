"""Wireless correlation integration (#128 Phase 3) — the report's engine-side
claims, tested against the REAL engine (never mocks of it):

  · RF = -1 sits below every existing layer and labels as "RF"
  · wireless kinds map to their causal layers (onboarding at the TERMINAL
    phase's layer — a DHCP failure is NETWORK, never "generic wireless")
  · radio → AP containment grounds at rank 1 (authoritative) purely from the
    entity-id structure — no new grounding code
  · the hyphen-prefix rule: an AP entity's device token is 'ap-<id>', never
    the estate-wide literal 'ap' (the #99 weld class)
  · a single controller witness NEVER confirms: two wireless signals through
    the same WLC cap at suspected (the independence gate, report B2)
  · the wireless signature templates load, and the ap-down pair's
    discriminator points both ways
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from catalog import BUILTIN_TEMPLATES, builtin_catalog
from controller_events import controller_event_to_signal
from engine import EngineConfig, build_nodes, resolve_grounding, run_window
from layers import CausalLayer, layer_of, osi_label
from signals import (
    EntityType,
    ModalityClass,
    Observer,
    ObserverType,
    Severity,
    Signal,
    Source,
)

T0 = datetime(2026, 7, 26, 12, 0, 0, tzinfo=timezone.utc)


def _wifi_signal(kind: str, entity_type: EntityType, entity_id: str,
                 ts: datetime = T0, severity: Severity = Severity.HIGH,
                 observer_id: str = "catalyst_9800:int-1") -> Signal:
    return Signal(
        tenant_id="t1", ts=ts, source=Source.CONTROLLER, kind=kind,
        observer=Observer(observer_id=observer_id,
                          observer_type=ObserverType.CONTROLLER,
                          collection_path="via_controller"),
        modality_class=ModalityClass.MANAGEMENT_PLANE,
        entity_type=entity_type, entity_id=entity_id, severity=severity,
        native_id=f"{kind}|{entity_id}|{int(ts.timestamp())}",
    )


# ── layers ───────────────────────────────────────────────────────────────────

def test_rf_layer_is_below_everything():
    assert CausalLayer.RF < CausalLayer.DEVICE < CausalLayer.PHYSICAL
    assert int(CausalLayer.RF) == -1          # Q1: -1, not a renumber
    assert osi_label(CausalLayer.RF) == "RF"
    # Every pre-wireless layer keeps its integer (the replay guarantee).
    assert [int(x) for x in (CausalLayer.DEVICE, CausalLayer.PHYSICAL,
                             CausalLayer.LINK, CausalLayer.NETWORK,
                             CausalLayer.TRANSPORT, CausalLayer.SERVICE,
                             CausalLayer.APPLICATION)] == [0, 1, 2, 3, 4, 5, 6]


def test_wireless_kind_layers():
    assert layer_of("wireless_channel_util_high") is CausalLayer.RF
    assert layer_of("wireless_interference") is CausalLayer.RF
    assert layer_of("wireless_ap_down") is CausalLayer.DEVICE
    assert layer_of("wireless_radio_down") is CausalLayer.PHYSICAL
    assert layer_of("wireless_retry_rate_high") is CausalLayer.LINK
    # Onboarding failures land at the TERMINAL phase's layer (report §16).
    assert layer_of("wireless_onboarding_auth_failure") is CausalLayer.LINK
    assert layer_of("wireless_onboarding_dhcp_failure") is CausalLayer.NETWORK
    assert layer_of("wireless_onboarding_dns_failure") is CausalLayer.SERVICE
    # Member failover deliberately abstains (no fixed causal layer).
    assert layer_of("wireless_wlc_member_failover") is None


# ── controller-event mapping ─────────────────────────────────────────────────

def test_wireless_controller_event_maps_to_wireless_entity():
    ev = {
        "tenant_id": "t1", "normalized_event_type": "wireless_ap_down",
        "source_system": "catalyst_9800", "integration_id": "int-1",
        "device_id": "ap-abc123", "severity": "high",
        "event_time": "2026-07-26T12:00:00Z", "event_id": "e1",
    }
    sig = controller_event_to_signal(ev, T0)
    assert sig is not None
    assert sig.entity_type is EntityType.ACCESS_POINT
    assert sig.entity_id == "ap-abc123"
    assert sig.modality_class is ModalityClass.MANAGEMENT_PLANE
    assert sig.observer.collection_path == "via_controller"

    ev["normalized_event_type"] = "wireless_radio_down"
    ev["device_id"] = "ap-abc123:radio1"
    sig2 = controller_event_to_signal(ev, T0)
    assert sig2 is not None and sig2.entity_type is EntityType.RADIO


# ── grounding ────────────────────────────────────────────────────────────────

def test_radio_grounds_to_ap_rank1_containment():
    sig_ap = _wifi_signal("wireless_ap_down", EntityType.ACCESS_POINT, "ap-abc123")
    sig_radio = _wifi_signal("wireless_radio_down", EntityType.RADIO, "ap-abc123:radio1",
                             ts=T0 + timedelta(seconds=10), severity=Severity.WARN)
    nodes = build_nodes((sig_ap, sig_radio))
    assert len(nodes) == 2
    g = resolve_grounding(nodes[0], nodes[1], seams=())
    assert g is not None, "radio and its AP must ground"
    assert g.rank == 1, f"containment must be rank 1, got {g.rank}"
    assert g.authoritative, "resource-identity grounding must be authoritative"


def test_ap_device_token_is_never_the_bare_prefix():
    """The #99 weld guard: two different APs must never share a device token."""
    a = _wifi_signal("wireless_ap_down", EntityType.ACCESS_POINT, "ap-abc123")
    b = _wifi_signal("wireless_ap_down", EntityType.ACCESS_POINT, "ap-def456")
    na, nb = build_nodes((a, b))
    assert na.device_part() == "ap-abc123"
    assert nb.device_part() == "ap-def456"
    assert na.device_part() != nb.device_part()
    # And two unrelated APs do NOT ground bare (no seam, no adjacency, no
    # shared identity): an edge between them would be the weld bug.
    assert resolve_grounding(na, nb, seams=()) is None


def test_session_grounds_to_client():
    s1 = _wifi_signal("wireless_onboarding_dhcp_failure", EntityType.WIRELESS_SESSION,
                      "wcl-c1:sess1")
    s2 = _wifi_signal("wireless_onboarding_auth_failure", EntityType.WIRELESS_CLIENT,
                      "wcl-c1", ts=T0 + timedelta(seconds=5))
    n1, n2 = build_nodes((s1, s2))
    g = resolve_grounding(n1, n2, seams=())
    assert g is not None and g.rank == 1


# ── the independence gate (report B2) ────────────────────────────────────────

def test_single_controller_witness_caps_at_suspected():
    """Two wireless faults, both via the same WLC: one witness. The verdict
    may be suspected, never confirmed — controller-alone-cannot-confirm."""
    cfg = EngineConfig()
    sigs = (
        _wifi_signal("wireless_ap_down", EntityType.ACCESS_POINT, "ap-abc123",
                     severity=Severity.CRIT),
        _wifi_signal("wireless_radio_down", EntityType.RADIO, "ap-abc123:radio0",
                     ts=T0 + timedelta(seconds=20), severity=Severity.HIGH),
    )
    snaps = run_window(sigs, builtin_catalog(), seams=(), cfg=cfg)
    assert snaps, "a grounded wireless component must form an object"
    for snap in snaps:
        tier = snap.ranking.verdict_tier.value
        assert tier in ("undetermined", "suspected"), (
            f"single-witness wireless must never confirm, got {tier}")


# ── catalog ──────────────────────────────────────────────────────────────────

def test_wireless_templates_load_and_pair():
    ids = {t["id"] for t in BUILTIN_TEMPLATES}
    for want in (
        "sig.ent.wireless.ap-down-power",
        "sig.ent.wireless.ap-software-fault",
        "sig.ent.wireless.rf-co-channel-interference",
        "sig.ent.wireless.rf-coverage-hole",
        "sig.ent.wireless.rf-non-wifi-interference",
        "sig.ent.wireless.capwap-instability",
        "sig.ent.wireless.wlc-failover",
        "sig.ent.wireless.onboarding-auth-radius",
        "sig.ent.wireless.onboarding-dhcp-exhaustion",
    ):
        assert want in ids, f"missing wireless template {want}"
    # The ap-down pair discriminates: software-fault names power as competitor.
    soft = next(t for t in BUILTIN_TEMPLATES if t["id"] == "sig.ent.wireless.ap-software-fault")
    assert soft["discriminators"][0]["else_prefer"] == "sig.ent.wireless.ap-down-power"
    # And the catalog validates as a whole (schema, competitor refs).
    builtin_catalog()


def test_wireless_templates_never_claim_wireless_when_healthy():
    """The spec's thesis: 'wireless not the cause' is NO template — a healthy
    wireless domain contributes no fault signals, so no wireless template may
    require only non-wireless kinds (which could fire wireless blame onto a
    wired-only incident)."""
    for t in BUILTIN_TEMPLATES:
        if not t["id"].startswith("sig.ent.wireless."):
            continue
        mandatory_kinds = {
            k for c in t["requires"] if not c.get("optional")
            for k in str(c["kind"]).split("|")
        }
        assert any(k.startswith("wireless_") or k.startswith("controller_")
                   for k in mandatory_kinds), (
            f"{t['id']}: a wireless template must require wireless evidence")


# ── nested encapsulation (proof model 9, report §15) ─────────────────────────

def test_nested_encapsulation_transformations_never_flatten():
    """CAPWAP inside IPsec inside SD-WAN: each hop keeps ITS OWN transformation
    on the rendered spine — the chain must never flatten to one tunnel, and an
    unresponsive hop inside the nest stays an explicit missing entry."""
    from path_graph import (
        PathGraphView,
        PathHop,
        PathObservation,
        Transformation,
        spine_of,
    )
    obs = PathObservation(
        observation_id="obs-nested-1", path_id="p1", tenant_id="t1",
        observed_at=T0, method="traceroute_icmp",
        hops=(
            PathHop(1, observed_address="10.0.0.2",
                    transformation=Transformation.TUNNEL_INGRESS.value,  # CAPWAP in
                    tenant_id="t1"),
            PathHop(2, observed_address="10.0.0.6",
                    transformation=Transformation.TUNNEL_INGRESS.value,  # IPsec in
                    tenant_id="t1"),
            PathHop(3, state="missing", tenant_id="t1"),                 # dark carrier hop
            PathHop(4, observed_address="172.16.0.9",
                    transformation=Transformation.TUNNEL_EGRESS.value,   # IPsec out
                    tenant_id="t1"),
            PathHop(5, observed_address="192.0.2.10",
                    transformation=Transformation.TUNNEL_EGRESS.value,   # CAPWAP out
                    tenant_id="t1"),
        ))
    spine = spine_of(obs, PathGraphView())
    entries = spine["spine"] if isinstance(spine, dict) and "spine" in spine else spine
    tfs = [e["transformation"] for e in entries if e.get("address") or e.get("state") != "responding"]
    assert tfs[:2] == ["tunnel_ingress", "tunnel_ingress"], (
        "successive ingress transformations must BOTH survive (no flattening)")
    assert tfs[-2:] == ["tunnel_egress", "tunnel_egress"]
    missing = [e for e in entries if e.get("state") == "missing"]
    assert len(missing) == 1 and missing[0]["address"] == "", (
        "the dark hop inside the nest is preserved as an explicit missing entry")
