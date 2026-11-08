# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""§3a — stage [1] identity canonicalisation never crosses a tenant (P6 PR-D).

CLAUDE.md §3a requires an isolation test with every feature that stores or
returns data; canonicalisation decides which device a tenant's evidence is bound
to, so a leak here would bind tenant A's syslog to tenant B's box. Plan:
docs/design/P6_CANONICALISATION_PLAN_2026-11-07.md (gate 3, OD2 tenant-only).

Asserted:
  * two tenants whose devices share hostname, management IP and ifNames each
    resolve to THEIR OWN inventory id — through the resolver and through
    canonicalize, for every rule (D1, D2, D4, D5);
  * tenant A's signal is never bound to B's id: a resolver scoped to another tenant
    (the canonicalisation analogue of `as_tenant` into another org) is refused, and
    an unscoped legacy resolver (tenant ∪ global) is refused too;
  * a platform-global ("") row never resolves a tenant's token — not even when it is
    the only row with that spelling — and does not make a tenant's own name
    ambiguous; the global principal ("" ≡ "global") reads only the "" rows;
  * a row filed under the wrong tenant bucket is skipped (defence in depth).
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from canon import (
    ABSTAIN_CONFLICT,
    ABSTAIN_UNKNOWN,
    REWRITTEN,
    canonicalize,
    canonicalize_detailed,
)
from entity_resolver import EntityResolver, identity_resolver_for
from signals import (
    EntityType,
    ModalityClass,
    Observer,
    ObserverType,
    Severity,
    Signal,
    Source,
)

TS = datetime(2026, 11, 1, 17, 0, 1, tzinfo=timezone.utc)
A, B = "t_alpha", "t_bravo"
HOST, MGMT, PEER = "edge-1", "10.20.30.40", "10.0.0.2"


def _rows(tenant: str, device: str) -> dict:
    return {
        "devices": [{"tenant_id": tenant, "device": device, "name": HOST, "mgmt_ip": MGMT}],
        "interface_ips": [{"tenant_id": tenant, "device": device, "ip": "10.1.1.1",
                           "ifname": "GigabitEthernet1"}],
        "ifindex": [{"tenant_id": tenant, "device": device, "ifindex": "1",
                     "ifname": "GigabitEthernet1"}],
    }


def _raw(*parts: tuple[str, str]) -> dict:
    """section → tenant → rows, the shape main._entity_resolver_raw() returns."""
    out: dict = {"devices": {}, "interface_ips": {}, "ifindex": {}}
    for tenant, device in parts:
        for section, rows in _rows(tenant, device).items():
            out[section].setdefault(tenant, []).extend(rows)
    return out


RAW = _raw((A, "dev-a"), (B, "dev-b"), ("", "dev-global"))


def _sig(tenant: str, source: Source, kind: str, etype: EntityType, eid: str,
         attrs: dict | None = None) -> Signal:
    return Signal(
        tenant_id=tenant, ts=TS, source=source, kind=kind,
        observer=Observer(observer_id="obs", observer_type=ObserverType.DEVICE),
        modality_class=ModalityClass.CONTROL_PLANE, entity_type=etype, entity_id=eid,
        severity=Severity.HIGH, native_id=f"{tenant}|{kind}|{eid}", attrs=dict(attrs or {}))


def _cases(tenant: str) -> list[Signal]:
    """The same evidence spelled the same way in either tenant, one per rule."""
    return [
        _sig(tenant, Source.SYSLOG, "device_alarm", EntityType.DEVICE, HOST),            # D2 name
        _sig(tenant, Source.SYSLOG, "device_alarm", EntityType.DEVICE, MGMT),            # D2 mgmt IP
        _sig(tenant, Source.SYSLOG, "bgp_adjacency_change", EntityType.DEVICE, MGMT,
             {"peer": PEER}),                                                            # D1
        _sig(tenant, Source.SYSLOG, "link_state_change", EntityType.INTERFACE,
             f"{HOST}:Gi1", {"interface": "Gi1"}),                                       # D4
        _sig(tenant, Source.SYSLOG, "link_state_change", EntityType.INTERFACE,
             f"{HOST}:1", {"interface": "1"}),                                           # D4 ifIndex
        _sig(tenant, Source.CONTROLLER, "bgp_adjacency_change", EntityType.DEVICE,
             f"{HOST}:pe-x", {"peer_id": "pe-x",
                              "correlation_hints": {"controller_peer_id": PEER}}),       # D5
    ]


def _expected(device: str) -> list[str]:
    return [device, device, f"{device}:{PEER}", f"{device}:gi1", f"{device}:gi1",
            f"{device}:{PEER}"]


@pytest.mark.parametrize("tenant,device", [(A, "dev-a"), (B, "dev-b"), ("global", "dev-global"),
                                           ("", "dev-global")])
def test_each_tenant_resolves_identical_spellings_to_its_own_ids(tenant: str, device: str) -> None:
    r = identity_resolver_for(RAW, tenant)
    assert r.resolve_device(HOST) == (device, "ok")
    assert r.resolve_device(MGMT) == (device, "ok")
    assert r.resolve_device("10.1.1.1") == (device, "ok")
    assert r.ifname(device, "1") == "GigabitEthernet1"
    assert r.iface_key_status(device, "gi1") == "ok"
    out = [canonicalize(s, r) for s in _cases(tenant)]
    assert [o for _, o in out] == [REWRITTEN] * 6
    assert [s.entity_id for s, _ in out] == _expected(device)


def test_no_foreign_id_is_ever_reachable() -> None:
    """Own-only: a tenant's resolver holds no other tenant's (or global's) ids."""
    for tenant, own in ((A, "dev-a"), (B, "dev-b"), ("global", "dev-global")):
        r = identity_resolver_for(RAW, tenant)
        reachable = (set(r.name_to_device.values()) | set(r.ip_to_device.values())
                     | set(r.canon_ip_to_device.values())
                     | {d for d, _ in r.ifindex_to_name} | {d for d, _ in r.iface_key_to_name}
                     | set(r.ifnames_by_device))
        assert reachable == {own}, (tenant, reachable)
        for foreign in {"dev-a", "dev-b", "dev-global"} - {own}:
            assert r.resolve_device(foreign) == (None, "unknown")
            assert r.ifname(foreign, "1") is None


def test_a_signal_is_never_canonicalised_through_another_tenants_resolver() -> None:
    """The `as_tenant` analogue: handing tenant A's evidence B's resolver (or the
    global one) is refused — 404-equivalent: nothing of B's is revealed."""
    for sig in _cases(A):
        for other in (B, "global"):
            out, outcome = canonicalize(sig, identity_resolver_for(RAW, other))
            assert out is sig and outcome == ABSTAIN_CONFLICT
            assert "dev-b" not in out.entity_id and "dev-global" not in out.entity_id


def test_an_unscoped_resolver_is_refused() -> None:
    """tenant ∪ global (main.entity_resolver_for's legacy shape) never canonicalises:
    here the union makes edge-1 ambiguous between A's box and the global one."""
    union = EntityResolver.from_rows(
        RAW["devices"][A] + RAW["devices"][""], RAW["interface_ips"][A] + RAW["interface_ips"][""],
        RAW["ifindex"][A] + RAW["ifindex"][""])
    assert union.tenant is None
    assert union.resolve_device(HOST) == (None, "ambiguous")
    for sig in _cases(A):
        assert canonicalize(sig, union) == (sig, ABSTAIN_CONFLICT)


def test_a_global_row_never_resolves_a_tenant_token() -> None:
    """The "" row is the ONLY row spelled `core-global` / 10.99.0.1 — tenant A still
    cannot reach it, and it does not shadow A's own spellings."""
    raw = _raw((A, "dev-a"))
    raw["devices"][""] = [{"tenant_id": "", "device": "gw-1", "name": "core-global",
                           "mgmt_ip": "10.99.0.1"},
                          {"tenant_id": "", "device": "gw-2", "name": HOST, "mgmt_ip": MGMT}]
    ra = identity_resolver_for(raw, A)
    assert ra.resolve_device("core-global") == (None, "unknown")
    assert ra.resolve_device("10.99.0.1") == (None, "unknown")
    assert ra.resolve_device("gw-1") == (None, "unknown")
    assert ra.resolve_device(HOST) == ("dev-a", "ok")          # not made ambiguous by gw-2
    assert ra.resolve_device(MGMT) == ("dev-a", "ok")
    sig = _sig(A, Source.SYSLOG, "device_alarm", EntityType.DEVICE, "core-global")
    assert canonicalize(sig, ra) == (sig, ABSTAIN_UNKNOWN)
    # and the global principal reads ONLY the "" rows
    rg = identity_resolver_for(raw, "global")
    assert rg.resolve_device("core-global") == ("gw-1", "ok")
    assert rg.resolve_device(HOST) == ("gw-2", "ok")
    assert rg.resolve_device("dev-a") == (None, "unknown")


def test_global_spellings_are_one_principal() -> None:
    assert identity_resolver_for(RAW, "").tenant == identity_resolver_for(RAW, "global").tenant == ""
    sig = _sig("global", Source.SYSLOG, "device_alarm", EntityType.DEVICE, HOST)
    out, outcome = canonicalize(sig, identity_resolver_for(RAW, ""))
    assert outcome == REWRITTEN and out.entity_id == "dev-global"


def test_a_row_filed_under_the_wrong_tenant_is_skipped() -> None:
    raw = _raw((A, "dev-a"))
    raw["devices"][A].append({"tenant_id": B, "device": "smuggled", "name": "smug",
                              "mgmt_ip": "10.66.0.1"})
    raw["ifindex"][A].append({"tenant_id": B, "device": "dev-a", "ifindex": "2",
                              "ifname": "GigabitEthernet2"})
    r = identity_resolver_for(raw, A)
    assert r.resolve_device("smug") == (None, "unknown")
    assert r.resolve_device("10.66.0.1") == (None, "unknown")
    assert r.ifname("dev-a", "2") is None


def test_an_unknown_tenant_resolves_nothing() -> None:
    """A tenant with no rows binds no device and reaches no other tenant's id. Only
    the inventory-free rewrites happen, with the raw device token kept."""
    r = identity_resolver_for(RAW, "t_nobody")
    assert r.tenant == "t_nobody"
    for sig in _cases("t_nobody"):
        res = canonicalize_detailed(sig, r)
        assert dict(res.axes).get("device") == ABSTAIN_UNKNOWN, sig.entity_id
        assert not any(d in res.signal.entity_id for d in ("dev-a", "dev-b", "dev-global"))
        if res.outcome == REWRITTEN:
            # the table-free port key, or D5 putting the controller peer back to its
            # address (a controller device id is kept verbatim when unknown)
            assert (res.signal.entity_id, res.basis) in {(f"{HOST}:gi1", "iface:key"),
                                                         (f"{HOST}:{PEER}", "peer:controller_hint")}
        else:
            assert res.signal is sig
