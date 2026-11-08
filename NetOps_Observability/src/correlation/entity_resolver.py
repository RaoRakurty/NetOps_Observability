# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""EntityResolver — the IP / ifIndex → correlation-entity bridge (C7.1).

The directed-topology direction sources (C7.3 NetFlow, C7.4 traceroute, C7.5
routing) and the G2 canonicalizer all speak **IPs + ifIndexes**; correlation
entities are **device / device:ifName**. This is the shared, tenant-scoped bridge.
The Go API exports `entity_resolver.json` (mgmt IP→device, interface IP→ifName,
(device,ifIndex)→ifName); `main.py` loads it mtime-cached and builds a per-tenant
resolver (a tenant's rows ∪ global — identity never crosses tenants). This module
is the pure lookup over one tenant's slice.

P6 PR-D (docs/design/P6_CANONICALISATION_PLAN_2026-11-07.md) adds, additively — every
existing field, method and result is unchanged:
  * `identity_resolver_for(raw, tenant)` — the TENANT-ONLY entry point stage [1]
    canonicalisation uses: the tenant's own rows; tenant "global" ("") reads only the
    "" rows. Never tenant ∪ global — a global row spelled like a tenant's device would
    otherwise make the tenant's name ambiguous, or worse, bind it to the global box.
  * `resolve_device(token)` — id / name / ANY address spelling (the management IP is
    what cEDGE-81 logs as its syslog hostname) → device, with the REASON when it
    abstains (unknown / ambiguous / generic hostname such as `localhost`, `router`).
  * a per-device (device, canon_iface_key) → ifName index that DROPS collisions, and a
    per-device ifName set (the digit-only rule: HP ProCurve ports are named "1".."48").

Pure + deterministic. **Honest fallback (directed-topology-rca.md):** an unresolved
endpoint returns None → the caller abstains (UNKNOWN), it NEVER guesses. An IP/ifIndex
that resolves to MORE THAN ONE device (ambiguous) is dropped, not arbitrarily picked —
ambiguity resolves to None, same as unknown.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Final

from canon import (
    IFACE_ABSTAIN,
    canon_iface_key,
    canonical_peer,
    ifindex_of,
    is_generic_address,
    is_ifindex_marker,
    tenant_key,
)
from signals import MAX_ID_CHARS

# Hostnames that name no single box: factory defaults, placeholders a syslog relay
# writes when the sender sent none, and bare vendor/role words. A syslog line whose
# hostname is one of these is never bound to a device, even when the tenant's
# inventory happens to hold a device spelled that way (P6 D2 generic guard).
# Compared lower-cased; generic ADDRESSES (127.0.0.1, ::1, fe80::/10, multicast,
# 0.0.0.0) are caught by canon.is_generic_address.
GENERIC_HOSTNAMES: Final = frozenset({
    "localhost", "localhost.localdomain", "localdomain", "local",
    "router", "switch", "firewall", "gateway", "host", "hostname", "device",
    "unknown", "none", "null", "(none)", "n/a", "na", "-", "?", "default",
    "ap", "wlc", "controller", "kernel", "syslog",
    "cisco", "juniper", "arista", "nokia", "sonic", "srlinux", "vedge", "cedge",
    "ios", "iosxe", "iosxr", "nxos", "junos", "eos", "hp", "procurve", "aruba",
})

# resolve_device reasons.
RESOLVED: Final = "ok"
UNKNOWN: Final = "unknown"
AMBIGUOUS: Final = "ambiguous"
GENERIC: Final = "generic"


def _unique_map_tracked(pairs: Iterable[tuple]) -> tuple[dict, frozenset]:
    """`_unique_map` plus the set of keys it dropped as ambiguous."""
    out: dict = {}
    ambiguous: set = set()
    for k, v in pairs:
        if not k or not v:
            continue
        if k in out and out[k] != v:
            ambiguous.add(k)
        else:
            out[k] = v
    for k in ambiguous:
        out.pop(k, None)
    return out, frozenset(ambiguous)


def _unique_map(pairs: Iterable[tuple]) -> dict:
    """Build a dict from (key, value) pairs, DROPPING any key seen with conflicting
    values (ambiguous → unresolvable, never an arbitrary pick). Empty keys/values
    are ignored. Deterministic: independent of input order."""
    return _unique_map_tracked(pairs)[0]


def _iface_index_key(name: str) -> str:
    """The key an inventory ifName is indexed under: its canonical key, or the
    digits themselves for a digit-named port (it IS a name on that device). ""
    for a name no key can be derived from."""
    key = canon_iface_key(name)
    if is_ifindex_marker(key):
        return ifindex_of(key)
    return "" if key == IFACE_ABSTAIN else key


@dataclass(frozen=True)
class EntityResolver:
    ip_to_device: Mapping[str, str]              # mgmt + interface IP → device
    ip_to_iface: Mapping[str, str]               # interface IP → "device:ifName"
    ifindex_to_name: Mapping[tuple, str]         # (device, ifIndex) → ifName
    # device id / device name (lower-cased) → device id. Lets a lane that names
    # a device by hostname (syslog) reach the same canonical id as a lane that
    # names it by inventory id (SNMP, traps). Conflicting names drop out.
    name_to_device: Mapping[str, str] = field(default_factory=dict)
    # ── P6 PR-D (additive; empty unless built by from_rows) ──────────────────
    # The tenant this resolver is scoped to ("" = platform-global), or None for a
    # legacy resolver (tenant ∪ global, or every tenant). canon.canonicalize
    # refuses None and any tenant other than the signal's own.
    tenant: str | None = None
    # Lower-cased names / canonical address text dropped because two devices claim them.
    ambiguous_names: frozenset = frozenset()
    canon_ip_to_device: Mapping[str, str] = field(default_factory=dict)
    ambiguous_ips: frozenset = frozenset()
    # (device, canon_iface_key(ifName)) → ifName; two ports of one device that
    # collapse onto one key drop out into ambiguous_iface_keys.
    iface_key_to_name: Mapping[tuple, str] = field(default_factory=dict)
    ambiguous_iface_keys: frozenset = frozenset()
    ifnames_by_device: Mapping[str, frozenset] = field(default_factory=dict)

    def device_for_ip(self, ip: str | None) -> str | None:
        """The device that owns this IP (mgmt or interface), or None."""
        return self.ip_to_device.get(ip) if ip else None

    def canonical_device(self, token: str | None) -> str | None:
        """The canonical device id a lane's device token denotes — the token may
        be the inventory id, the device name (case-insensitive) or one of its
        addresses — or None when the tenant's inventory does not know it, or
        knows it ambiguously. Pure; never guesses."""
        t = (token or "").strip()
        if not t:
            return None
        return self.name_to_device.get(t.lower()) or self.ip_to_device.get(t)

    def resolve_device(self, token: object) -> tuple[str | None, str]:
        """(device id, reason) for a lane's device token — an inventory id, a device
        name (case-insensitive) or ANY spelling of one of its addresses (a syslog
        sender that logs under its management IP, IPv6 in any notation).

        reason: "ok" (resolved) · "generic" (a hostname or address that names no
        single box — never resolved, even if the inventory holds it) · "ambiguous"
        (two devices claim it, or the name and the address point at different
        devices) · "unknown". Pure; never guesses; never raises."""
        if not isinstance(token, str):
            return None, UNKNOWN
        t = token.strip()
        if not t or len(t) > MAX_ID_CHARS:
            return None, UNKNOWN
        low = t.lower()
        if low in GENERIC_HOSTNAMES or is_generic_address(t):
            return None, GENERIC
        ip = canonical_peer(t)
        if low in self.ambiguous_names or (ip and ip in self.ambiguous_ips):
            return None, AMBIGUOUS
        hits = {d for d in (self.name_to_device.get(low),
                            self.canon_ip_to_device.get(ip) if ip else None) if d}
        if len(hits) > 1:
            return None, AMBIGUOUS
        if hits:
            return next(iter(hits)), RESOLVED
        return None, UNKNOWN

    def device_for_hostname(self, host: object) -> str | None:
        """The device a syslog hostname denotes (name, id or address), or None when
        unknown, ambiguous or generic. See resolve_device for the reason."""
        return self.resolve_device(host)[0]

    def ifnames(self, device: str | None) -> frozenset:
        """Every ifName the inventory knows for `device` (empty when none)."""
        return self.ifnames_by_device.get(device or "", frozenset())

    def iface_key_status(self, device: str | None, key: str | None) -> str:
        """"ok" when exactly one of the device's ports has this canonical key,
        "ambiguous" when several do (never merged), "unknown" otherwise."""
        if not device or not key:
            return UNKNOWN
        if (device, key) in self.ambiguous_iface_keys:
            return AMBIGUOUS
        return RESOLVED if (device, key) in self.iface_key_to_name else UNKNOWN

    def ifname_for_key(self, device: str | None, key: str | None) -> str | None:
        """The inventory ifName (display spelling) behind a canonical key, or None."""
        if not device or not key:
            return None
        return self.iface_key_to_name.get((device, key))

    def iface_for_ip(self, ip: str | None) -> str | None:
        """'device:ifName' for an interface IP, or None (mgmt-only IPs have no iface)."""
        return self.ip_to_iface.get(ip) if ip else None

    def ifname(self, device: str | None, ifindex: str | None) -> str | None:
        """ifName for a (device, ifIndex), or None when unresolved."""
        if not device or ifindex in (None, ""):
            return None
        return self.ifindex_to_name.get((device, str(ifindex)))

    def device_iface(self, device: str | None, ifindex: str | None) -> str | None:
        """'device:ifName' for a (device, ifIndex) — the entity a flow exporter's
        in/out ifIndex maps to — or None when the port can't be resolved."""
        name = self.ifname(device, ifindex)
        return f"{device}:{name}" if name else None

    @classmethod
    def from_rows(cls, devices: Iterable[Mapping], interface_ips: Iterable[Mapping],
                  ifindex: Iterable[Mapping], *, tenant: str | None = None) -> EntityResolver:
        """Build a resolver from already tenant-filtered row lists (the legacy loader
        passes a tenant's rows ∪ global; identity_resolver_for passes the tenant's
        own). Pure; conflicting mappings drop to unresolvable. `tenant` records the
        scope (None = legacy/unscoped)."""
        # The per-device interface-key index (a canon_iface_key regex per port
        # name, plus the per-device ifName sets) is built ONLY for the tenant-only
        # identity resolver (`tenant` set by identity_resolver_for): the legacy
        # loader's builds sit on today's hot path and nothing reads that index
        # until P6 PR-E wires it. The cheap name/address ambiguity tracking is
        # kept everywhere so resolve_device answers the same on any resolver.
        p6 = tenant is not None
        ip_dev_pairs: list[tuple] = []
        name_pairs: list[tuple] = []
        canon_ip_pairs: list[tuple] = []
        port_names: list[tuple[str, str]] = []
        for d in devices:
            dev = d.get("device") or ""
            if d.get("mgmt_ip"):
                ip_dev_pairs.append((d["mgmt_ip"], dev))
                canon_ip_pairs.append((canonical_peer(d["mgmt_ip"]), dev))
            if dev:
                name_pairs.append((dev.lower(), dev))
                name = str(d.get("name") or "").strip()
                if name:
                    name_pairs.append((name.lower(), dev))
        iface_pairs: list[tuple] = []
        for r in interface_ips:
            dev, ip, name = r.get("device") or "", r.get("ip") or "", r.get("ifname") or ""
            if ip and dev:
                ip_dev_pairs.append((ip, dev))               # interface IP also → device
                canon_ip_pairs.append((canonical_peer(ip), dev))
                if name:
                    iface_pairs.append((ip, f"{dev}:{name}"))
            if p6 and dev and isinstance(name, str) and name:
                port_names.append((dev, name))
        ifidx_pairs: list[tuple] = []
        for r in ifindex:
            dev, idx, name = r.get("device") or "", r.get("ifindex"), r.get("ifname") or ""
            if dev and idx not in (None, "") and name:
                ifidx_pairs.append(((dev, str(idx)), name))
                if p6 and isinstance(name, str):
                    port_names.append((dev, name))
        names_by_dev: dict[str, set[str]] = {}
        key_pairs: list[tuple] = []
        for dev, name in port_names:
            names_by_dev.setdefault(dev, set()).add(name)
            key = _iface_index_key(name)
            if key:
                key_pairs.append(((dev, key), name))
        names_map, ambiguous_names = _unique_map_tracked(name_pairs)
        canon_ips, ambiguous_ips = _unique_map_tracked(canon_ip_pairs)
        key_map, ambiguous_keys = _unique_map_tracked(key_pairs)
        return cls(
            ip_to_device=_unique_map(ip_dev_pairs),
            ip_to_iface=_unique_map(iface_pairs),
            ifindex_to_name=_unique_map(ifidx_pairs),
            name_to_device=names_map,
            tenant=tenant,
            ambiguous_names=ambiguous_names,
            canon_ip_to_device=canon_ips,
            ambiguous_ips=ambiguous_ips,
            iface_key_to_name=key_map,
            ambiguous_iface_keys=ambiguous_keys,
            ifnames_by_device={d: frozenset(n) for d, n in names_by_dev.items()},
        )

    def coverage(self) -> dict:
        """Sizes for /healthz — lets live validation confirm the bridge is populated."""
        return {
            "ips": len(self.ip_to_device),
            "iface_ips": len(self.ip_to_iface),
            "ifindexes": len(self.ifindex_to_name),
        }


EMPTY_RESOLVER = EntityResolver(ip_to_device={}, ip_to_iface={}, ifindex_to_name={})

_SECTIONS: Final = ("devices", "interface_ips", "ifindex")


def identity_resolver_for(raw: Mapping[str, Mapping[str, Iterable[Mapping]]],
                          tenant: str) -> EntityResolver:
    """The TENANT-ONLY resolver stage [1] canonicalisation uses (P6 OD2; the plan's
    `cached_identity_resolver_for(tenant)` semantics — PR-E adds the mtime cache in
    main.py over `_entity_resolver_raw()`, whose section → tenant → rows shape this
    takes).

    A tenant reads ONLY its own rows; the platform-global principal ("" or
    "global") reads ONLY the "" rows. Never tenant ∪ global: a global device named
    like one of the tenant's would make the tenant's name ambiguous, or bind the
    tenant's evidence to a box it does not own. Defence in depth: a row whose own
    `tenant_id` disagrees with the bucket it sits in is skipped. Pure."""
    key = tenant_key(tenant)

    def rows(section: str) -> list[Mapping]:
        by_tenant = raw.get(section) if isinstance(raw, Mapping) else None
        bucket = by_tenant.get(key) if isinstance(by_tenant, Mapping) else None
        return [r for r in (bucket or ()) if isinstance(r, Mapping)
                and tenant_key(str(r.get("tenant_id") or "")) == key]

    return EntityResolver.from_rows(*(rows(s) for s in _SECTIONS), tenant=key)
