# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Tests for the NMS controller-event producer (P4)."""
from datetime import datetime, timezone

from controller_events import controller_event_to_signal
from signals import EntityType, ModalityClass, ObserverType, Severity, Source

INGEST = datetime(2026, 7, 3, 12, 0, 0, tzinfo=timezone.utc)


def _vmanage_bfd():
    return {
        "tenant_id": "t-a",
        "integration_id": "int-vm",
        "source_system": "vmanage",
        "vendor": "cisco",
        "normalized_event_type": "controller_bfd_down",
        "severity": "crit",
        "device_id": "10.1.1.1",
        "site_id": "100",
        "tunnel_id": "mpls-biz",
        "event_id": "uuid-1",
        "event_time": "2026-07-03T11:59:00Z",
        "message": "BFD session down",
        "evidence_role": "supporting",
    }


def test_maps_to_management_plane_signal():
    s = controller_event_to_signal(_vmanage_bfd(), INGEST)
    assert s is not None
    # The core mapping: controller source, management-plane modality, controller observer.
    assert s.source == Source.CONTROLLER
    assert s.modality_class == ModalityClass.MANAGEMENT_PLANE
    assert s.observer.observer_type == ObserverType.CONTROLLER
    # via_controller collection path (fate-sharing knows it's not direct-from-device).
    assert s.observer.collection_path == "via_controller"
    assert s.tenant_id == "t-a"
    assert s.severity == Severity.CRIT
    assert s.kind == "controller_bfd_down"
    # A tunnel/BFD event binds to the PATH entity.
    assert s.entity_type == EntityType.PATH
    assert s.entity_id == "mpls-biz"
    assert s.attrs["authority"] == "vendor_controller"
    assert s.attrs["source_system"] == "vmanage"


def test_device_unreachable_binds_device():
    ev = _vmanage_bfd()
    ev["normalized_event_type"] = "controller_device_unreachable"
    ev["tunnel_id"] = ""
    s = controller_event_to_signal(ev, INGEST)
    assert s.entity_type == EntityType.DEVICE
    assert s.entity_id == "10.1.1.1"


def test_policy_change_carries_role():
    ev = _vmanage_bfd()
    ev["normalized_event_type"] = "controller_policy_change"
    ev["evidence_role"] = "discriminating"
    s = controller_event_to_signal(ev, INGEST)
    assert s.attrs["evidence_role"] == "discriminating"


def test_tenant_required():
    ev = _vmanage_bfd()
    ev["tenant_id"] = ""
    assert controller_event_to_signal(ev, INGEST) is None


def test_unbindable_event_dropped():
    # No device/site/tunnel → nothing to correlate → dropped.
    ev = {"tenant_id": "t-a", "normalized_event_type": "controller_alarm", "source_system": "x"}
    assert controller_event_to_signal(ev, INGEST) is None


def test_epoch_millis_time():
    ev = _vmanage_bfd()
    ev["event_time"] = 1751540340000  # epoch millis
    s = controller_event_to_signal(ev, INGEST)
    # millis → seconds, parsed to the exact UTC instant.
    assert s.ts.timestamp() == 1751540340.0
    assert s.ts.tzinfo is not None


def test_vendor_neutral_meraki_and_versa_same_kind_same_shape():
    # A Meraki and a Versa tunnel-down normalize to the SAME kind → identical
    # signal shape (proves no per-vendor signature is needed).
    base = {
        "tenant_id": "t-a", "normalized_event_type": "controller_tunnel_state",
        "severity": "high", "device_id": "dev1", "tunnel_id": "tun1",
        "event_id": "e", "event_time": "2026-07-03T11:59:00Z",
    }
    meraki = dict(base, source_system="meraki")
    versa = dict(base, source_system="versa_director")
    sm = controller_event_to_signal(meraki, INGEST)
    sv = controller_event_to_signal(versa, INGEST)
    assert sm.kind == sv.kind == "controller_tunnel_state"
    assert sm.modality_class == sv.modality_class == ModalityClass.MANAGEMENT_PLANE
    assert sm.entity_type == sv.entity_type == EntityType.PATH


def test_controller_kinds_are_consumed_by_catalog():
    """ACCURACY GUARD (owner: 'build accurately else it won't match'): every
    actionable controller kind the transformers/producer emit must be referenced
    by at least one ENABLED catalog clause — otherwise a controller event would
    normalize fine but silently never match a signature."""
    from catalog import builtin_catalog

    actionable = {
        "controller_tunnel_state",
        "controller_bfd_down",
        "controller_control_connection_loss",
        "controller_device_unreachable",
        "controller_policy_change",
    }
    referenced: set[str] = set()
    for t in builtin_catalog().enabled_templates():
        for clause in t.requires:
            referenced |= clause.kinds()
    missing = actionable - referenced
    assert not missing, f"controller kinds not consumed by any signature: {missing}"


def test_producer_kind_matches_a_catalog_clause():
    """End-to-end: a controller event → producer signal → its kind is present in
    an enabled catalog clause (the wiring actually connects)."""
    from catalog import builtin_catalog

    ev = {
        "tenant_id": "t-a", "source_system": "vmanage",
        "normalized_event_type": "controller_tunnel_state",
        "device_id": "10.1.1.1", "tunnel_id": "t1",
        "event_id": "e1", "event_time": "2026-07-03T11:59:00Z", "severity": "crit",
    }
    sig = controller_event_to_signal(ev, INGEST)
    clause_kinds = {k for t in builtin_catalog().enabled_templates() for c in t.requires for k in c.kinds()}
    assert sig.kind in clause_kinds, f"producer kind {sig.kind} matches no catalog clause"


# --- severity contract (2026-10-24) -------------------------------------------
# The Go connectors emit info|warn|high|crit. Until 2026-10-24 vManage leaked its
# own words (critical|major|minor); "major" fell to WARN here, below the engine's
# severity_open_floor="high", so a POLLED vManage outage (unreachable, BFD down,
# control-connection loss) could never open an incident on its own.

def test_vendor_severity_words_map_to_engine_severities():
    for word, want in (("critical", Severity.CRIT), ("major", Severity.HIGH), ("error", Severity.HIGH),
                       ("minor", Severity.WARN), ("medium", Severity.WARN), ("warning", Severity.WARN),
                       ("low", Severity.INFO), ("high", Severity.HIGH), ("crit", Severity.CRIT)):
        ev = _vmanage_bfd()
        ev["severity"] = word
        assert controller_event_to_signal(ev, INGEST).severity == want, word


def test_lone_polled_vmanage_outage_opens_an_object():
    """NMS-only deployment (owner decision 2026-10-24): a device vManage reports
    unreachable must open an incident from that one witness."""
    from catalog import builtin_catalog
    from engine import run_window

    for sev in ("high", "major"):  # what Go emits now, and the legacy alias
        ev = _vmanage_bfd()
        ev.update(normalized_event_type="controller_device_unreachable", tunnel_id="",
                  severity=sev, event_id=f"uuid-{sev}")
        s = controller_event_to_signal(ev, INGEST)
        assert s is not None
        objs = run_window([s], builtin_catalog(), ())
        assert len(objs) == 1, f"a lone controller outage at severity {sev!r} must open an object"


def test_warn_controller_event_alone_stays_an_episode():
    """The floor still holds: a minor/warn controller event does not page alone."""
    from catalog import builtin_catalog
    from engine import run_window

    ev = _vmanage_bfd()
    ev.update(normalized_event_type="controller_device_unreachable", tunnel_id="", severity="minor")
    assert run_window([controller_event_to_signal(ev, INGEST)], builtin_catalog(), ()) == []


# ── T0 (NMS-first plan, 2026-10-25): one tunnel, whichever end reports it ────
_TID = "10.255.255.20/mpls|10.255.255.51/mpls"   # nms.CanonicalTunnelID shape


def _bfd_end(device, peer, *, tenant="t-a", instance="ci-aaaaaaaaaaaaaaaa", kind="controller_bfd_down",
             event_id="e", tunnel=_TID, sev="high"):
    return {
        "tenant_id": tenant, "integration_id": "nmsi-1", "source_system": "vmanage", "vendor": "cisco",
        "normalized_event_type": kind, "severity": sev, "device_id": device, "peer_id": peer,
        "site_id": "", "tunnel_id": tunnel, "event_id": event_id, "event_time": "2026-07-03T11:59:00Z",
        "controller_instance": instance,
        "correlation_hints": {"tunnel_scheme": "tloc_pair", "controller_instance_basis": "host"},
    }


def test_both_ends_of_one_tunnel_become_one_node():
    from engine import build_nodes

    a = controller_event_to_signal(_bfd_end("10.255.255.20", "10.255.255.51", event_id="a"), INGEST)
    b = controller_event_to_signal(_bfd_end("10.255.255.51", "10.255.255.20", event_id="b"), INGEST)
    assert a.entity_type == b.entity_type == EntityType.PATH
    assert a.entity_id == b.entity_id == f"{_TID}@ci-aaaaaaaaaaaaaaaa"
    nodes = build_nodes((a, b))
    assert len(nodes) == 1 and len(nodes[0].signals) == 2, "the two halves of one session must meet"
    # Each end's own device and the far end stay on the signal as tokens.
    assert {"10.255.255.20", "10.255.255.51"} <= set(a.entity_tokens)


def test_two_overlays_reusing_system_ips_never_merge():
    from engine import build_nodes

    a = controller_event_to_signal(_bfd_end("10.255.255.20", "10.255.255.51", event_id="a"), INGEST)
    b = controller_event_to_signal(_bfd_end("10.255.255.20", "10.255.255.51", event_id="b",
                                            instance="ci-bbbbbbbbbbbbbbbb"), INGEST)
    assert a.entity_id != b.entity_id
    assert len(build_nodes((a, b))) == 2


def test_a_recovery_binds_the_same_tunnel_and_is_never_evidence():
    from catalog import builtin_catalog
    from engine import build_nodes, run_window

    clear = controller_event_to_signal(_bfd_end("10.255.255.20", "10.255.255.51", event_id="c",
                                                kind="controller_bfd_down_clear", sev="info"), INGEST)
    fault = controller_event_to_signal(_bfd_end("10.255.255.20", "10.255.255.51", event_id="f"), INGEST)
    assert clear.entity_type == EntityType.PATH and clear.entity_id == fault.entity_id
    assert build_nodes((clear,)) == ()
    assert run_window([clear], builtin_catalog(), ()) == [], "a recovery must open nothing"
    nodes = build_nodes((fault, clear))
    assert len(nodes) == 1 and all(not s.kind.endswith("_clear") for s in nodes[0].signals)


def test_a_record_without_tunnel_identity_still_binds_as_before():
    ev = _bfd_end("10.255.255.20", "", tunnel="")
    ev.pop("controller_instance")
    ev.pop("correlation_hints")
    s = controller_event_to_signal(ev, INGEST)
    assert s.entity_type == EntityType.PATH and s.entity_id == "10.255.255.20"
    legacy = _vmanage_bfd()  # pre-T0 wire shape: an opaque tunnel id, no scheme hint
    assert controller_event_to_signal(legacy, INGEST).entity_id == "mpls-biz"


def test_controller_instance_is_context_not_a_new_witness():
    from verdicts import witness_of

    a = controller_event_to_signal(_bfd_end("10.255.255.20", "10.255.255.51", event_id="a"), INGEST)
    b = controller_event_to_signal(_bfd_end("10.255.255.20", "10.255.255.51", event_id="b",
                                            instance="ci-bbbbbbbbbbbbbbbb"), INGEST)
    assert a.attrs["controller_instance"] == "ci-aaaaaaaaaaaaaaaa"
    assert a.observer.observer_id == b.observer.observer_id == "vmanage:nmsi-1"
    assert witness_of(a) == witness_of(b), "T0 must not change the verdict's witness model (that is T2)"


def test_identical_tunnels_in_two_tenants_never_share_an_object():
    from catalog import builtin_catalog
    from engine import run_window

    a = controller_event_to_signal(_bfd_end("10.255.255.20", "10.255.255.51", tenant="t-a", event_id="a"), INGEST)
    b = controller_event_to_signal(_bfd_end("10.255.255.20", "10.255.255.51", tenant="t-b", event_id="b"), INGEST)
    assert a.entity_id == b.entity_id  # same ids by design; isolation is by tenant
    objs_a = run_window([a], builtin_catalog(), ())
    objs_b = run_window([b], builtin_catalog(), ())
    assert objs_a and objs_b
    assert {o.tenant_id for o in objs_a} == {"t-a"} and {o.tenant_id for o in objs_b} == {"t-b"}
    try:
        run_window([a, b], builtin_catalog(), ())
    except ValueError:
        pass  # a mixed-tenant window is refused outright (engine.py single-tenant rule)
    else:
        raise AssertionError("a window mixing two tenants' tunnels must be refused")
