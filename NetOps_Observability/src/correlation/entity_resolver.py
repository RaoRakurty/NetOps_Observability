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

Pure + deterministic. **Honest fallback (directed-topology-rca.md):** an unresolved
endpoint returns None → the caller abstains (UNKNOWN), it NEVER guesses. An IP/ifIndex
that resolves to MORE THAN ONE device (ambiguous) is dropped, not arbitrarily picked —
ambiguity resolves to None, same as unknown.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass


def _unique_map(pairs: Iterable[tuple]) -> dict:
    """Build a dict from (key, value) pairs, DROPPING any key seen with conflicting
    values (ambiguous → unresolvable, never an arbitrary pick). Empty keys/values
    are ignored. Deterministic: independent of input order."""
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
    return out


@dataclass(frozen=True)
class EntityResolver:
    ip_to_device: Mapping[str, str]              # mgmt + interface IP → device
    ip_to_iface: Mapping[str, str]               # interface IP → "device:ifName"
    ifindex_to_name: Mapping[tuple, str]         # (device, ifIndex) → ifName

    def device_for_ip(self, ip: str | None) -> str | None:
        """The device that owns this IP (mgmt or interface), or None."""
        return self.ip_to_device.get(ip) if ip else None

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
                  ifindex: Iterable[Mapping]) -> EntityResolver:
        """Build a resolver from already tenant-filtered row lists (the loader passes
        a tenant's rows ∪ global). Pure; conflicting mappings drop to unresolvable."""
        ip_dev_pairs: list[tuple] = []
        for d in devices:
            dev = d.get("device") or ""
            if d.get("mgmt_ip"):
                ip_dev_pairs.append((d["mgmt_ip"], dev))
        iface_pairs: list[tuple] = []
        for r in interface_ips:
            dev, ip, name = r.get("device") or "", r.get("ip") or "", r.get("ifname") or ""
            if ip and dev:
                ip_dev_pairs.append((ip, dev))               # interface IP also → device
                if name:
                    iface_pairs.append((ip, f"{dev}:{name}"))
        ifidx_pairs: list[tuple] = []
        for r in ifindex:
            dev, idx, name = r.get("device") or "", r.get("ifindex"), r.get("ifname") or ""
            if dev and idx not in (None, "") and name:
                ifidx_pairs.append(((dev, str(idx)), name))
        return cls(
            ip_to_device=_unique_map(ip_dev_pairs),
            ip_to_iface=_unique_map(iface_pairs),
            ifindex_to_name=_unique_map(ifidx_pairs),
        )

    def coverage(self) -> dict:
        """Sizes for /healthz — lets live validation confirm the bridge is populated."""
        return {
            "ips": len(self.ip_to_device),
            "iface_ips": len(self.ip_to_iface),
            "ifindexes": len(self.ifindex_to_name),
        }


EMPTY_RESOLVER = EntityResolver(ip_to_device={}, ip_to_iface={}, ifindex_to_name={})
