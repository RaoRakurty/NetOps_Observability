# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Tracker 430 — a trap BFD signal and the controller's report of the same SD-WAN
tunnel become ONE node (stage [1] canon, `tunnel` axis).

THE DEFECT, pinned first: the trap lane binds a BFD transition to the bare sorted
TLOC pair `<ipA>/<colA>|<ipB>/<colB>`; the controller lane binds
`<pair>@<controller instance>`. `Node.tokens()` drops a token equal to the node's
observer, and the trap's device token IS its observer, so the trap node's only
token is the bare pair, which no other node carries; and `Node.adjacency_key()`
keys a PATH node only by an `@`-scoped id, so the trap node never reached the T4c
tunnel↔endpoint rows. Trap BFD evidence was an island: it grounded to nothing.

THE FIX: with `CORR_IDENTITY_CANON` on, `canon.canonicalize_detailed` rewrites a
trap's bare pair to `<pair>@<ci>` when exactly ONE controller instance's
`sdwan_bfd` rows for that pair, in the signal's own tenant, name the trap's
sender as an endpoint. Otherwise it abstains and the raw pair stays.

Fixture: fixtures/tunnel_scope/lab_430.json — the lab's real sdwan_bfd rows and the
real (pair, sender) pairs of trap.sdwan.bfd signals (tenant id replaced). A
subdirectory on purpose: every top-level fixtures/*.json is a catalog scenario.
"""
from __future__ import annotations

import json
import os
import random
from dataclasses import replace
from datetime import datetime, timezone

import pytest

import main
import producers as P
import signals
from canon import (
    ABSTAIN_AMBIGUOUS,
    ABSTAIN_CONFLICT,
    ABSTAIN_UNKNOWN,
    AXES,
    CANON_ATTR,
    REWRITTEN,
    UNCHANGED,
    TunnelScope,
    canonicalize_detailed,
    tunnel_scope,
)
from catalog import builtin_catalog
from controller_events import controller_event_to_signal
from engine import (
    NO_ADJACENCY,
    TopologyAdjacency,
    build_nodes,
    resolve_grounding,
    run_window,
)
from entity_resolver import identity_resolver_for
from replay import StoredObject, replay
from signals import (
    EntityType,
    Signal,
    set_identity_canon,
    set_origin_observer,
    set_series_admission,
)

HERE = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(HERE, "fixtures", "tunnel_scope", "lab_430.json"), encoding="utf-8") as _fh:
    LAB = json.load(_fh)
TENANT: str = LAB["tenant"]
CI: str = LAB["instance"]
LINKS: list[dict] = LAB["links"]
TRAPS: list[dict] = LAB["traps"]
OTHER = "t-other"
CI_B = "ci-bbbbbbbbbbbbbbbb"
INGEST = datetime(2026, 11, 18, 16, 46, tzinfo=timezone.utc)
VF = "1.3.6.1.4.1.41916.100.1."
CAT = builtin_catalog()


@pytest.fixture(autouse=True)
def _restore_flags():
    """The flags are process state: put every one back, so no later test runs
    with canonicalisation on (the same guard test_identity_canon_wiring_p6e uses)."""
    prev = (signals.origin_observer_enabled(), signals.series_admission_enabled(),
            signals.series_bucket_s(), signals.identity_canon_requested())
    yield
    set_origin_observer(prev[0])
    set_series_admission(prev[1], prev[2])
    set_identity_canon(prev[3])


def _empty_resolver(tenant: str = TENANT):
    return identity_resolver_for({"devices": {}, "interface_ips": {}, "ifindex": {}}, tenant)


def _trap_rec(pair: str, sender: str, *, state: str = "raise", native: str = "critical",
              remote_ip: str | None = None) -> dict:
    a, b = pair.split("|")
    (lip, lcol), (rip, rcol) = a.split("/", 1), b.split("/", 1)
    if remote_ip is not None:
        rip = remote_ip
    return {
        "_signal": "snmptrap", "timestamp": "2026-11-18T16:45:30Z", "device": sender,
        "trap_oid": "1.3.6.1.4.1.41916.100.2.4", "trap_name": "viptelaBfdBfdStateChange",
        "event_type": "viptela_bfd_bfd_state_change", "severity": "notice",
        "event_state": state, "severity_native_text": native,
        "varbinds": [{"oid": VF + "9.0", "value": lip}, {"oid": VF + "10.0", "value": lcol},
                     {"oid": VF + "11.0", "value": rip}, {"oid": VF + "12.0", "value": rcol},
                     {"oid": VF + "13.0", "value": "down(1)" if state == "raise" else "up(0)"}],
    }


def trap(pair: str, sender: str, tenant: str = TENANT, **kw) -> Signal:
    """A trap BFD signal through the PRODUCTION trap rules."""
    sig = P.trap_control_signal(_trap_rec(pair, sender, **kw), tenant, INGEST)
    assert sig is not None
    return sig


def ctl(kind: str, device: str, *, tunnel: str = "", tenant: str = TENANT, ci: str = CI,
        event_id: str = "e") -> Signal:
    """The controller lane's report (controller_events.py), as T4c's tests build it."""
    ev = {
        "tenant_id": tenant, "integration_id": "nmsi-1", "source_system": "vmanage", "vendor": "cisco",
        "normalized_event_type": kind, "severity": "high", "device_id": device, "peer_id": "",
        "site_id": "", "tunnel_id": tunnel, "event_id": event_id,
        "event_time": "2026-11-18T16:45:40Z", "controller_instance": ci,
    }
    if tunnel:
        ev["correlation_hints"] = {"tunnel_scheme": "tloc_pair", "controller_instance_basis": "host"}
    sig = controller_event_to_signal(ev, INGEST)
    assert sig is not None
    return sig


SCOPE = tunnel_scope(TENANT, LINKS)
ADJ = TopologyAdjacency.from_links(LINKS)
PAIR, SENDER = TRAPS[0]["pair"], TRAPS[0]["sender"]
SCOPED = f"{PAIR}@{CI}"
ENDPOINTS = sorted(r["b"] for r in LINKS if r["a"] == SCOPED)


def _node(sigs, entity_id):
    return {n.entity_id: n for n in build_nodes(tuple(sigs))}[entity_id]


# ── 1. the defect, pinned ────────────────────────────────────────────────────

@pytest.mark.parametrize("adj", [NO_ADJACENCY, ADJ], ids=["no_rows", "with_rows"])
def test_without_canon_the_trap_tunnel_node_grounds_to_nothing(adj) -> None:
    t = trap(PAIR, SENDER)
    assert t.entity_type == EntityType.PATH and t.entity_id == PAIR
    c = ctl("controller_bfd_down", ENDPOINTS[0], tunnel=PAIR)
    assert c.entity_id == SCOPED
    devs = [ctl("controller_device_unreachable", d, event_id=d) for d in ENDPOINTS]
    sigs = [t, c, *devs]
    tn = _node(sigs, PAIR)
    assert tn.adjacency_key() is None
    for other in (SCOPED, *ENDPOINTS):
        assert resolve_grounding(tn, _node(sigs, other), (), adj) is None, other


# ── 2. the lab: every real trap pair rewrites ────────────────────────────────

def test_every_recorded_lab_trap_takes_its_controller_instance() -> None:
    assert len(TRAPS) == 44 and len({t["pair"] for t in TRAPS}) == 34
    by_pair: dict[str, set[str]] = {}
    r = _empty_resolver()
    for row in TRAPS:
        sig = trap(row["pair"], row["sender"])
        res = canonicalize_detailed(sig, r, SCOPE)
        assert res.outcome == REWRITTEN, (row, res.axes)
        out = res.signal
        assert out.entity_id == f"{row['pair']}@{CI}"
        assert res.axes == (("tunnel", REWRITTEN),) and res.basis == "tunnel:endpoint"
        assert out.attrs[CANON_ATTR] == {"raw": row["pair"], "basis": "tunnel:endpoint"}
        # identity of the evidence never moves; the bare token becomes the scoped one
        assert out.native_id == sig.native_id and out.signal_id == sig.signal_id
        assert out.attrs["tunnel_id"] == row["pair"]
        assert out.entity_id in out.entity_tokens and row["pair"] not in out.entity_tokens
        by_pair.setdefault(row["pair"], set()).add(out.entity_id)
    assert all(len(ids) == 1 for ids in by_pair.values()), "both ends must land on one node"


def test_after_canon_the_trap_and_the_controller_report_are_one_node_grounded_at_rank_3() -> None:
    t, _ = canonicalize_detailed(trap(PAIR, SENDER), _empty_resolver(), SCOPE).signal, None
    c = ctl("controller_bfd_down", ENDPOINTS[0], tunnel=PAIR)
    devs = [ctl("controller_device_unreachable", d, event_id=d) for d in ENDPOINTS]
    nodes = {n.entity_id: n for n in build_nodes((t, c, *devs))}
    tun = nodes[SCOPED]
    assert {s.source.value for s in tun.signals} == {"trap", "controller"}, "one node"
    assert tun.adjacency_key() == SCOPED
    for d in ENDPOINTS:
        g = resolve_grounding(tun, nodes[d], (), ADJ)
        assert g is not None and g.rank == 3 and g.authoritative, (d, g)
    # no rows: the axis still scopes the id, and grounding is the pre-T4c rank 7 at most
    g = resolve_grounding(tun, nodes[ENDPOINTS[0]], (), NO_ADJACENCY)
    assert g is None or not g.authoritative


# ── 3. abstentions ───────────────────────────────────────────────────────────

def _row(pair: str, ci: str, b: str, tenant: str = TENANT, proto: str = "sdwan_bfd") -> dict:
    return {"tenant_id": tenant, "a": f"{pair}@{ci}", "b": b, "proto": proto}


def test_no_rows_abstains_and_returns_the_input() -> None:
    sig = trap(PAIR, SENDER)
    res = canonicalize_detailed(sig, _empty_resolver(), tunnel_scope(TENANT, []))
    assert res.outcome == ABSTAIN_UNKNOWN and res.axes == (("tunnel", ABSTAIN_UNKNOWN),)
    assert res.signal is sig


def test_a_sender_the_rows_do_not_name_abstains() -> None:
    # Partial reuse: another fabric's tunnel with the same pair, between other boxes.
    scope = tunnel_scope(TENANT, [_row(PAIR, CI, "edge-x"), _row(PAIR, CI, "edge-y")])
    res = canonicalize_detailed(trap(PAIR, SENDER), _empty_resolver(), scope)
    assert res.outcome == ABSTAIN_UNKNOWN and res.signal.entity_id == PAIR


def test_two_instances_naming_the_sender_abstain() -> None:
    scope = tunnel_scope(TENANT, [_row(PAIR, CI, SENDER), _row(PAIR, CI_B, SENDER)])
    res = canonicalize_detailed(trap(PAIR, SENDER), _empty_resolver(), scope)
    assert res.outcome == ABSTAIN_AMBIGUOUS and res.axes == (("tunnel", ABSTAIN_AMBIGUOUS),)
    assert res.signal.entity_id == PAIR


def test_two_disjoint_fabrics_in_one_tenant_each_take_their_own_instance() -> None:
    rows = [_row(PAIR, CI, "a1"), _row(PAIR, CI, "a2"), _row(PAIR, CI_B, "b1"), _row(PAIR, CI_B, "b2")]
    scope = tunnel_scope(TENANT, rows)
    r = _empty_resolver()
    assert canonicalize_detailed(trap(PAIR, "a1"), r, scope).signal.entity_id == f"{PAIR}@{CI}"
    assert canonicalize_detailed(trap(PAIR, "b2"), r, scope).signal.entity_id == f"{PAIR}@{CI_B}"


def test_an_ambiguous_sender_never_picks_a_fabric() -> None:
    raw = {"devices": {TENANT: [{"tenant_id": TENANT, "device": "d1", "name": "edge", "mgmt_ip": "10.0.0.1"},
                                {"tenant_id": TENANT, "device": "d2", "name": "edge", "mgmt_ip": "10.0.0.2"}]},
           "interface_ips": {}, "ifindex": {}}
    scope = tunnel_scope(TENANT, [_row(PAIR, CI, "edge"), _row(PAIR, CI, "d1")])
    res = canonicalize_detailed(trap(PAIR, "edge"), identity_resolver_for(raw, TENANT), scope)
    assert res.outcome == ABSTAIN_AMBIGUOUS and res.axes == (("device", ABSTAIN_AMBIGUOUS),)


def test_a_canonicalised_sender_spelling_still_matches_the_rows() -> None:
    raw = {"devices": {TENANT: [{"tenant_id": TENANT, "device": "vedge-20-02efdcad", "name": "vEdge-20",
                                 "mgmt_ip": "192.168.222.20"}]}, "interface_ips": {}, "ifindex": {}}
    scope = tunnel_scope(TENANT, [_row(PAIR, CI, "vedge-20-02efdcad")])
    res = canonicalize_detailed(trap(PAIR, "vEdge-20"), identity_resolver_for(raw, TENANT), scope)
    assert res.outcome == REWRITTEN and res.signal.entity_id == f"{PAIR}@{CI}"


@pytest.mark.parametrize("row", [
    {"tenant_id": TENANT, "a": f"{PAIR}@{CI}", "b": SENDER, "proto": "sdwan_control"},
    {"tenant_id": TENANT, "a": f"{PAIR}@{CI}", "b": SENDER},
    {"tenant_id": TENANT, "a": f"{PAIR}@CI-0067892AE8F31576", "b": SENDER, "proto": "sdwan_bfd"},
    {"tenant_id": TENANT, "a": f"{PAIR}@ci-0067", "b": SENDER, "proto": "sdwan_bfd"},
    {"tenant_id": TENANT, "a": PAIR, "b": SENDER, "proto": "sdwan_bfd"},
    {"tenant_id": TENANT, "a": f"10.0.0.1/mpls@{CI}", "b": SENDER, "proto": "sdwan_bfd"},
    {"tenant_id": TENANT, "a": f"{PAIR}|10.0.0.9/x@{CI}", "b": SENDER, "proto": "sdwan_bfd"},
    {"tenant_id": TENANT, "a": f"/mpls|10.0.0.2/@{CI}", "b": SENDER, "proto": "sdwan_bfd"},
    {"tenant_id": TENANT, "a": f"{PAIR}@{CI}@{CI}", "b": SENDER, "proto": "sdwan_bfd"},
    {"tenant_id": TENANT, "a": f"{PAIR}@{CI}", "b": "", "proto": "sdwan_bfd"},
    {"tenant_id": TENANT, "a": f"{PAIR}@{CI}", "b": 7, "proto": "sdwan_bfd"},
    {"tenant_id": TENANT, "a": f"{PAIR}@{CI}", "b": "x" * 300, "proto": "sdwan_bfd"},
    {"tenant_id": TENANT, "a": "1.1.1.1/" + "x" * 300 + "|2.2.2.2/y@" + CI, "b": SENDER, "proto": "sdwan_bfd"},
    {"tenant_id": OTHER, "a": f"{PAIR}@{CI}", "b": SENDER, "proto": "sdwan_bfd"},
    {"tenant_id": "", "a": f"{PAIR}@{CI}", "b": SENDER, "proto": "sdwan_bfd"},
    {"tenant_id": None, "a": f"{PAIR}@{CI}", "b": SENDER, "proto": "sdwan_bfd"},
    {"a": f"{PAIR}@{CI}", "b": SENDER, "proto": "sdwan_bfd"},
    "not a row",
], ids=lambda r: "row")
def test_a_malformed_or_foreign_row_is_dropped(row) -> None:
    assert tunnel_scope(TENANT, [row]).by_pair == {}


@pytest.mark.parametrize("rows", [None, "rows", {"a": 1}, 7])
def test_rows_that_are_not_a_list_give_an_empty_scope(rows) -> None:
    assert tunnel_scope(TENANT, rows).by_pair == {}


def test_the_scope_is_order_independent() -> None:
    shuffled = list(LINKS)
    random.Random(430).shuffle(shuffled)
    assert tunnel_scope(TENANT, shuffled) == SCOPE
    assert set(SCOPE.by_pair) == {r["a"].split("@")[0] for r in LINKS}


def test_a_second_pass_is_the_fixed_point() -> None:
    r = _empty_resolver()
    once = canonicalize_detailed(trap(PAIR, SENDER), r, SCOPE).signal
    twice = canonicalize_detailed(once, r, SCOPE)
    assert twice.outcome == UNCHANGED and twice.signal is once


def test_an_already_scoped_or_opaque_or_unschemed_id_is_left_alone() -> None:
    r = _empty_resolver()
    base = trap(PAIR, SENDER)
    scoped = replace(base, entity_id=SCOPED, entity_tokens=(SENDER, SCOPED))
    opaque = replace(base, entity_id="mpls-biz", entity_tokens=(SENDER, "mpls-biz"))
    unschemed = replace(base, attrs={k: v for k, v in base.attrs.items() if k != "tunnel_scheme"})
    for sig in (scoped, opaque, unschemed):
        res = canonicalize_detailed(sig, r, SCOPE)
        assert res.outcome == UNCHANGED and res.signal is sig, sig.entity_id


def test_a_tloc_less_trap_is_device_bound_and_takes_the_device_axis() -> None:
    sig = trap(PAIR, SENDER, remote_ip="not-an-ip")
    assert sig.entity_type == EntityType.DEVICE and sig.entity_id == SENDER
    res = canonicalize_detailed(sig, _empty_resolver(), SCOPE)
    assert [a for a, _ in res.axes] == ["device"]


def test_a_scoped_id_past_the_id_cap_abstains_instead_of_truncating() -> None:
    long_pair = "1.1.1.1/" + "c" * 110 + "|2.2.2.2/" + "d" * 110
    assert len(long_pair) + 1 + len(CI) > 256 >= len(long_pair)
    sig = replace(trap(PAIR, SENDER), entity_id=long_pair, entity_tokens=(SENDER, long_pair))
    scope = TunnelScope(TENANT, {long_pair: {CI: frozenset({SENDER})}})
    res = canonicalize_detailed(sig, _empty_resolver(), scope)
    assert res.outcome == ABSTAIN_CONFLICT and ("length", ABSTAIN_CONFLICT) in res.axes
    assert res.signal is sig


def test_only_the_trap_lane_is_scoped() -> None:
    c = ctl("controller_bfd_down", ENDPOINTS[0], tunnel=PAIR)
    res = canonicalize_detailed(c, _empty_resolver(), SCOPE)
    assert res.outcome == UNCHANGED and res.signal is c


def test_without_a_scope_trap_tunnels_are_not_examined() -> None:
    sig = trap(PAIR, SENDER)
    res = canonicalize_detailed(sig, _empty_resolver())
    assert res.outcome == UNCHANGED and res.signal is sig


def test_tunnel_is_a_closed_axis_label() -> None:
    assert "tunnel" in AXES and "tunnel" in main._CANON_AXIS_LABELS


# ── 4. §3a ───────────────────────────────────────────────────────────────────

def test_another_tenants_rows_never_scope_this_tenants_trap() -> None:
    # The identical pair and sender, but the rows are another tenant's.
    scope = tunnel_scope(TENANT, [_row(PAIR, CI_B, SENDER, tenant=OTHER), _row(PAIR, CI, SENDER)])
    res = canonicalize_detailed(trap(PAIR, SENDER), _empty_resolver(), scope)
    assert res.outcome == REWRITTEN and res.signal.entity_id == f"{PAIR}@{CI}", "not ambiguous"
    only_other = tunnel_scope(TENANT, [_row(PAIR, CI_B, SENDER, tenant=OTHER)])
    assert canonicalize_detailed(trap(PAIR, SENDER), _empty_resolver(), only_other).outcome == ABSTAIN_UNKNOWN


def test_a_scope_built_for_another_tenant_is_refused() -> None:
    sig = trap(PAIR, SENDER)
    foreign = tunnel_scope(OTHER, [_row(PAIR, CI, SENDER, tenant=OTHER)])
    res = canonicalize_detailed(sig, _empty_resolver(), foreign)
    assert res.outcome == ABSTAIN_CONFLICT and res.axes == (("tenant", ABSTAIN_CONFLICT),)
    assert res.signal is sig


def test_global_reads_only_global_rows_and_a_tenant_never_reads_global() -> None:
    rows = [_row(PAIR, CI, SENDER, tenant=""), _row(PAIR, CI_B, SENDER, tenant="global")]
    assert set(tunnel_scope("global", rows).by_pair[PAIR]) == {CI, CI_B}
    assert tunnel_scope(TENANT, rows).by_pair == {}


# ── 5. main: the cache, the seam, the counter ────────────────────────────────

def _links_file(path: str, rows: list[dict]) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(rows, fh)


@pytest.fixture
def links(tmp_path, monkeypatch):
    path = str(tmp_path / "topology_links.json")
    rows = [*LINKS,
            _row(PAIR, CI_B, SENDER, tenant=OTHER),
            _row(PAIR, "ci-cccccccccccccccc", SENDER, tenant="")]
    _links_file(path, rows)
    monkeypatch.setattr(main, "TOPO_LINKS_FILE", path)
    monkeypatch.setattr(main, "_adj_cache", {})
    monkeypatch.setattr(main, "_adj_mtime", -1.0)
    monkeypatch.setattr(main, "_tunnel_scope_cache", {})
    monkeypatch.setattr(main, "_tunnel_scope_cache_mtime", -1.0)
    monkeypatch.setattr(main, "_tunnel_scope_stat_at", -1.0)
    monkeypatch.setattr(main, "TENANT_STAT_EVERY_S", 0.0)
    return path


def test_the_cached_scope_is_the_tenants_own_bucket(links) -> None:
    mine = main.cached_tunnel_scope_for(TENANT)
    assert mine.tenant == TENANT and set(mine.by_pair[PAIR]) == {CI}
    assert set(main.cached_tunnel_scope_for(OTHER).by_pair[PAIR]) == {CI_B}
    glob = main.cached_tunnel_scope_for("global")
    assert set(glob.by_pair[PAIR]) == {"ci-cccccccccccccccc"}
    assert main.cached_tunnel_scope_for("") is glob


def test_the_cache_is_bounded_by_the_files_tenants(links) -> None:
    for i in range(50):
        assert main.cached_tunnel_scope_for(f"t-unknown-{i}").by_pair == {}
    main.cached_tunnel_scope_for(TENANT)
    assert set(main._tunnel_scope_cache) <= {TENANT, OTHER, ""}


def test_the_cache_follows_the_file(links) -> None:
    assert main.cached_tunnel_scope_for(TENANT).by_pair
    _links_file(links, [])
    st = os.stat(links)
    os.utime(links, (st.st_atime, st.st_mtime + 5))
    assert main.cached_tunnel_scope_for(TENANT).by_pair == {}


@pytest.fixture
def window(monkeypatch, tmp_path):
    path = str(tmp_path / "entity_resolver.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"devices": [], "interface_ips": [], "ifindex": []}, fh)
    monkeypatch.setattr(main, "ENTITY_RESOLVER_FILE", path)
    monkeypatch.setattr(main, "_er_raw", {"devices": {}, "interface_ips": {}, "ifindex": {}})
    monkeypatch.setattr(main, "_er_mtime", -1.0)
    monkeypatch.setattr(main, "_resolver_cache", {})
    monkeypatch.setattr(main, "_resolver_cache_mtime", -1.0)
    monkeypatch.setattr(main, "_identity_resolver_cache", {})
    monkeypatch.setattr(main, "_identity_resolver_cache_mtime", -1.0)
    monkeypatch.setattr(main, "IDENTITY_CANON_COUNTS", {})


def _window_row(sig: Signal) -> Signal:
    main.WINDOW_BUFFER.clear()
    main._BUFFERED_ID_ORDER.clear()
    main._BUFFERED_IDS.clear()
    main.buffer_signal(sig)
    assert len(main.WINDOW_BUFFER) == 1
    return main.WINDOW_BUFFER[-1]


@pytest.fixture
def canon_on():
    set_origin_observer(True)
    set_series_admission(True, 60.0)
    set_identity_canon(True)
    assert main.identity_canon_enabled()
    yield


def test_off_the_window_row_is_the_input_and_no_scope_is_built(links, window, monkeypatch) -> None:
    set_identity_canon(False)
    assert not main.identity_canon_enabled()

    def boom(*_a, **_k):
        raise AssertionError("no tunnel scope may be built with the flag off")

    monkeypatch.setattr(main, "cached_tunnel_scope_for", boom)
    sig = trap(PAIR, SENDER)
    row = _window_row(sig)
    assert row.to_ch_row() == sig.to_ch_row() and CANON_ATTR not in row.attrs
    assert main.IDENTITY_CANON_COUNTS == {}


def test_on_the_window_carries_the_scoped_id_and_the_counter_says_so(canon_on, links, window) -> None:
    sig = trap(PAIR, SENDER)
    row = _window_row(sig)
    assert row.entity_id == SCOPED and row.attrs[CANON_ATTR]["raw"] == PAIR
    assert sig.entity_id == PAIR, "the corr_signals row (written before the window) stays raw"
    assert main.IDENTITY_CANON_COUNTS[("trap", "tunnel", REWRITTEN)] == 1
    assert main.IDENTITY_CANON_COUNTS[("trap", "signal", REWRITTEN)] == 1
    text = main._metrics_text(main._health_payload())
    assert 'corr_identity_canon_total{lane="trap",axis="tunnel",outcome="rewritten"} 1' in text


def test_on_only_the_trap_lane_builds_a_scope(canon_on, links, window, monkeypatch) -> None:
    calls: list[str] = []
    real = main.cached_tunnel_scope_for

    def spy(tenant: str):
        calls.append(tenant)
        return real(tenant)

    monkeypatch.setattr(main, "cached_tunnel_scope_for", spy)
    _window_row(ctl("controller_bfd_down", ENDPOINTS[0], tunnel=PAIR))
    assert calls == []
    _window_row(trap(PAIR, SENDER))
    assert calls == [TENANT]


# ── 6. objects, verdicts and replay ──────────────────────────────────────────

def _canon_window() -> list[Signal]:
    t = canonicalize_detailed(trap(PAIR, SENDER), _empty_resolver(), SCOPE).signal
    dev = ctl("controller_device_unreachable", ENDPOINTS[1], event_id="dev")
    return [t, dev]


def test_the_trap_now_grounds_authoritatively_into_an_object() -> None:
    """Before: the trap was an island (a crit singleton with no edge, and the
    device's alarm its own object). After: one object, held by a rank-3 edge, so
    the "no authoritative edge" cap no longer applies — a reviewed shift."""
    win = _canon_window()
    objs = run_window(win, CAT, (), adjacency=ADJ)
    (obj,) = [o for o in objs if SCOPED in {n.entity_id for n in o.nodes}]
    assert {n.entity_id for n in obj.nodes} == {SCOPED, ENDPOINTS[1]}
    assert obj.edges and all(e.grounding.authoritative and e.grounding.rank == 3 for e in obj.edges)
    assert "no authoritative edge" not in obj.hypotheses_blob()
    # without canon the same evidence never meets
    raw = [trap(PAIR, SENDER), win[1]]
    raw_objs = run_window(raw, CAT, (), adjacency=ADJ)
    assert not any(len(o.nodes) > 1 for o in raw_objs)


def test_trap_and_controller_on_one_node_alone_are_not_confirmed() -> None:
    """D1: the controller is a support plane; the merged node's trap + relay pair
    cannot confirm by itself."""
    t = canonicalize_detailed(trap(PAIR, SENDER), _empty_resolver(), SCOPE).signal
    c = ctl("controller_bfd_down", ENDPOINTS[0], tunnel=PAIR)
    objs = run_window([t, c], CAT, (), adjacency=NO_ADJACENCY)
    assert objs
    for o in objs:
        assert o.to_object_row(1)["verdict_tier"] != "confirmed"


def test_the_object_replays_from_its_embedded_adjacency() -> None:
    win = _canon_window()
    (obj,) = [o for o in run_window(win, CAT, (), adjacency=ADJ)
              if SCOPED in {n.entity_id for n in o.nodes}]
    ctx = json.loads(obj.hypotheses_blob())["grounding_context"]
    assert [*sorted((SCOPED, ENDPOINTS[1]))] in ctx["adjacency"]
    stored = StoredObject.from_rows(obj.to_object_row(1), obj.to_edge_rows(1))
    archive = [Signal.from_ch_row({**s.to_ch_row(), "archived_for": obj.correlation_id}) for s in win]
    assert {s.entity_id for s in archive} >= {SCOPED}
    report = replay(stored, archive, CAT)
    assert report.clean, report
