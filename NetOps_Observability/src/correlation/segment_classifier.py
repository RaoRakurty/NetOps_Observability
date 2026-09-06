# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""segment_classifier — address-space segment/device classifier (path-causality RCA P0).

The missing keystone from docs/design/research/path-causality-rca-research.md (Area 2):
classify a single hop (IP + optional device metadata) into a network SEGMENT TYPE and a
device ROLE, so downstream path discovery (P1) and on-path RCA (P2) can reason about
"cloud vs LAN vs WAN vs DC" WITHOUT any static topology map.

Design (docs/design/path-causality-rca.md §3): pattern-based, DEFAULT-CLOSED, MULTI-SIGNAL,
extensible (feeds are data, not code). This module is the executable form of that rule.

Posture mirrors the existing weak-signal discipline in the codebase (path_direction.py
abstains; path_graph.py "an edge that cannot state its evidence is not returned";
verdicts.py suspected/confirmed default-closed): a lone weak signal (rDNS/TTL/hostname)
NEVER yields a confident classification, and NO matching signal yields `unknown` + a human
`reason` — never a guessed type, never assumed healthy.

Purity / safety:
  * Pure + deterministic + offline. No network at runtime: the provider-CIDR trie is built
    once from the BUNDLED snapshot (segmentdata/provider_ip_ranges.json), refreshed out-of-band by
    scripts/refresh_provider_ranges.py.
  * All inputs are UNTRUSTED (CLAUDE.md §8): every IP is validated; a malformed feed entry
    is logged + skipped, never fatal.

Vocabulary reconciliation (research Area 2 "reuse the existing vocabulary"):
  segment_type ∈ {cloud, lan, dc, wan, wan_seam, internet, unknown}
  maps onto path_graph.BOUNDARY_OF_KIND coarse boundaries (LAN / SD-WAN / CARRIER / CLOUD /
  UNKNOWN) via SEGMENT_TO_BOUNDARY, and a wan_seam optionally carries a seams.go seam_kind
  (DX / VPN / SDWAN / DIA / CLOUD_BACKBONE). See SEGMENT_TO_BOUNDARY / SEAM_KINDS below.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
from dataclasses import dataclass, field
from enum import Enum

log = logging.getLogger("segment_classifier")

_IPAddr = ipaddress.IPv4Address | ipaddress.IPv6Address

# ── vocabulary ───────────────────────────────────────────────────────────────


class SegmentType(str, Enum):
    CLOUD = "cloud"
    LAN = "lan"
    DC = "dc"
    WAN = "wan"
    WAN_SEAM = "wan_seam"
    INTERNET = "internet"
    UNKNOWN = "unknown"


class DeviceRole(str, Enum):
    LOAD_BALANCER = "load_balancer"
    WAF = "waf"
    FIREWALL = "firewall"
    DNS_RESOLVER = "dns_resolver"
    ROUTER = "router"
    SWITCH = "switch"
    TUNNEL_GW = "tunnel_gw"
    HOST = "host"
    UNKNOWN = "unknown"


class Confidence(str, Enum):
    STRONG = "strong"
    MEDIUM = "medium"
    WEAK = "weak"
    NONE = "none"


# Coarse boundary the renderer already groups by (path_graph.BOUNDARY_OF_KIND). The new
# segment_type is the RICHER vocabulary; this is the lossy projection to the existing one.
SEGMENT_TO_BOUNDARY: dict[str, str] = {
    SegmentType.CLOUD.value: "CLOUD",
    SegmentType.LAN.value: "LAN",
    SegmentType.DC.value: "LAN",          # DC fabric is private-fabric-like at the coarse grain
    SegmentType.WAN.value: "CARRIER",
    SegmentType.WAN_SEAM.value: "SD-WAN",  # ownership-transition seam
    SegmentType.INTERNET.value: "CARRIER",
    SegmentType.UNKNOWN.value: "UNKNOWN",
}

# Canonical seams.go seam types a wan_seam may carry (informational; a single hop rarely
# proves the seam kind — populated only when a device_role_hint names it).
SEAM_KINDS = frozenset({"DX", "VPN", "SDWAN", "DIA", "CLOUD_BACKBONE"})

# ── constants: RFC1918 / RFC6598 / non-topological ───────────────────────────

_RFC1918 = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]
_RFC4193 = ipaddress.ip_network("fc00::/7")      # IPv6 unique-local — private fabric
_RFC6598 = ipaddress.ip_network("100.64.0.0/10")  # CGNAT / shared address space → carrier/WAN

# ── curated ASN table (research Area 2.2) ────────────────────────────────────
# ASN class → segment hint. Small, checked-in, extensible. ASN is an OPTIONAL input
# (Team Cymru IP→ASN lookup is a separate concern, out of scope for P0).
#   cloud   → cloud ; transit → wan ; eyeball → internet
_ASN_TABLE: dict[int, dict[str, str]] = {
    16509: {"class": "cloud", "provider": "aws"},
    14618: {"class": "cloud", "provider": "aws"},
    8075: {"class": "cloud", "provider": "azure"},
    12076: {"class": "cloud", "provider": "azure"},
    15169: {"class": "cloud", "provider": "gcp"},
    396982: {"class": "cloud", "provider": "gcp"},
    13335: {"class": "cloud", "provider": "cloudflare"},
    # Major transit / Tier-1 backbones → WAN.
    174: {"class": "transit", "provider": "cogent"},
    3356: {"class": "transit", "provider": "lumen"},
    3257: {"class": "transit", "provider": "gtt"},
    1299: {"class": "transit", "provider": "arelion"},
    2914: {"class": "transit", "provider": "ntt"},
    6939: {"class": "transit", "provider": "he"},
    6461: {"class": "transit", "provider": "zayo"},
}

# ── rDNS naming heuristics (research Area 2.4 — HINTS ONLY, never sole basis) ──
_RDNS_PROVIDER = [
    (re.compile(r"(^|\.)compute\.amazonaws\.com$", re.IGNORECASE), "aws"),
    (re.compile(r"(^|\.)amazonaws\.com$", re.IGNORECASE), "aws"),
    (re.compile(r"(^|\.)1e100\.net$", re.IGNORECASE), "gcp"),
    (re.compile(r"(^|\.)googleusercontent\.com$", re.IGNORECASE), "gcp"),
    (re.compile(r"(^|\.)cloudapp\.azure\.com$", re.IGNORECASE), "azure"),
    (re.compile(r"(^|\.)cloudapp\.net$", re.IGNORECASE), "azure"),
]
_RDNS_ROLE = [
    (re.compile(r"(^|[-.])(lb|elb|alb|nlb|lbaas|slb)([-.]|\d|$)", re.IGNORECASE), DeviceRole.LOAD_BALANCER),
    (re.compile(r"(^|[-.])(waf|appgw|appgateway)([-.]|\d|$)", re.IGNORECASE), DeviceRole.WAF),
    (re.compile(r"(^|[-.])(fw|firewall|asa|palo|fgt|fortigate|ngfw)([-.]|\d|$)", re.IGNORECASE), DeviceRole.FIREWALL),
    (re.compile(r"(^|[-.])(dns|resolver|ns\d|unbound|bind)([-.]|\d|$)", re.IGNORECASE), DeviceRole.DNS_RESOLVER),
    (re.compile(r"(^|[-.])(rtr|router|gw|gateway|edge|core)([-.]|\d|$)", re.IGNORECASE), DeviceRole.ROUTER),
    (re.compile(r"(^|[-.])(sw|switch|leaf|spine|tor)([-.]|\d|$)", re.IGNORECASE), DeviceRole.SWITCH),
    (re.compile(r"(^|[-.])(vpn|ipsec|tunnel|nva|dx|expressroute)([-.]|\d|$)", re.IGNORECASE), DeviceRole.TUNNEL_GW),
]

# ── device_role_hint normalization (research Area 2.6 — LLDP/CDP/SNMP role) ───
# A DECLARED telemetry role is a STRONG, trusted signal (unlike rDNS). Maps free-form
# hint text → (DeviceRole, optional segment vote, optional seam_kind).
_ROLE_HINT_MAP: list[tuple[re.Pattern[str], DeviceRole, str | None, str | None]] = [
    (re.compile(r"load[_\- ]?balanc|(^|\W)(lb|elb|alb|nlb|slb)(\W|$)", re.IGNORECASE), DeviceRole.LOAD_BALANCER, None, None),
    (re.compile(r"waf|app[_\- ]?gateway|web[_\- ]?application[_\- ]?firewall", re.IGNORECASE), DeviceRole.WAF, None, None),
    (re.compile(r"firewall|ngfw|(^|\W)(fw|asa|palo|fortigate|fgt)(\W|$)", re.IGNORECASE), DeviceRole.FIREWALL, None, None),
    (re.compile(r"dns|resolver|name[_\- ]?server", re.IGNORECASE), DeviceRole.DNS_RESOLVER, None, None),
    (re.compile(r"spine|leaf|(^|\W)tor(\W|$)|fabric|datacenter|data[_\- ]?center", re.IGNORECASE),
     DeviceRole.SWITCH, SegmentType.DC.value, None),
    (re.compile(r"switch|(^|\W)sw\d", re.IGNORECASE), DeviceRole.SWITCH, SegmentType.LAN.value, None),
    (re.compile(r"express[_\- ]?route", re.IGNORECASE), DeviceRole.TUNNEL_GW, SegmentType.WAN_SEAM.value, "DX"),
    (re.compile(r"direct[_\- ]?connect|(^|\W)dx(\W|$)", re.IGNORECASE), DeviceRole.TUNNEL_GW, SegmentType.WAN_SEAM.value, "DX"),
    (re.compile(r"ipsec|(^|\W)vpn(\W|$)", re.IGNORECASE), DeviceRole.TUNNEL_GW, SegmentType.WAN_SEAM.value, "VPN"),
    (re.compile(r"sd[_\- ]?wan|velocloud|versa", re.IGNORECASE), DeviceRole.TUNNEL_GW, SegmentType.WAN_SEAM.value, "SDWAN"),
    (re.compile(r"(^|\W)nva(\W|$)|network[_\- ]?virtual[_\- ]?appliance|tunnel", re.IGNORECASE),
     DeviceRole.TUNNEL_GW, SegmentType.WAN_SEAM.value, None),
    (re.compile(r"router|(^|\W)(rtr|gw)(\W|$)|gateway|edge", re.IGNORECASE), DeviceRole.ROUTER, None, None),
    (re.compile(r"host|server|instance|(^|\W)vm(\W|$)|endpoint", re.IGNORECASE), DeviceRole.HOST, None, None),
]

# ── signal evidence ──────────────────────────────────────────────────────────


class Tier(str, Enum):
    """A signal's evidentiary weight. AUTHORITATIVE = deterministic system-of-record
    (provider CIDR / declared telemetry role) — strong enough to stand alone for what it
    asserts. STRONG = deterministic but ambiguous-alone (RFC1918 → private, but LAN vs DC vs
    intra-cloud needs corroboration). WEAK = a hint (rDNS/TTL/latency) — never a sole basis."""
    AUTHORITATIVE = "authoritative"
    STRONG = "strong"
    WEAK = "weak"


# A signal FAMILY is an independence group: two signals from the same family do NOT count as
# two INDEPENDENT signals for the ≥2-signal fusion rule (mirrors verdicts.py independence).
class Family(str, Enum):
    ADDRESS_SPACE = "address_space"   # provider CIDR, RFC1918, RFC6598 (mutually exclusive)
    ASN = "asn"
    DEVICE_ROLE = "device_role"       # declared telemetry role
    RDNS = "rdns"                     # naming heuristic (weak)
    TTL_LATENCY = "ttl_latency"       # timing/TTL fingerprint (weak)


@dataclass(frozen=True)
class SegSignal:
    name: str
    family: Family
    tier: Tier
    segment_vote: str | None = None   # a SegmentType value, or None (role-only signal)
    role_vote: str | None = None      # a DeviceRole value, or None
    provider: str = ""
    region: str = ""
    service: str = ""
    seam_kind: str = ""
    detail: str = ""

    def to_dict(self) -> dict:
        d = {"signal": self.name, "family": self.family.value, "tier": self.tier.value}
        for k in ("segment_vote", "role_vote"):
            v = getattr(self, k)
            if v:
                d[k] = v
        for k in ("provider", "region", "service", "seam_kind", "detail"):
            v = getattr(self, k)
            if v:
                d[k] = v
        return d


@dataclass
class Classification:
    segment_type: str
    device_role: str
    confidence: str
    signals: list[SegSignal] = field(default_factory=list)
    reason: str = ""
    provider: str = ""
    region: str = ""
    service: str = ""
    seam_kind: str = ""
    boundary: str = "UNKNOWN"

    def to_dict(self) -> dict:
        return {
            "segment_type": self.segment_type,
            "device_role": self.device_role,
            "confidence": self.confidence,
            "boundary": self.boundary,
            "provider": self.provider,
            "region": self.region,
            "service": self.service,
            "seam_kind": self.seam_kind,
            "reason": self.reason,
            "signals": [s.to_dict() for s in self.signals],
        }


# ── provider-CIDR longest-prefix-match trie ──────────────────────────────────


@dataclass
class _PrefixValue:
    provider: str
    region: str
    service: str
    prefix: str


class _BitTrie:
    """Binary radix trie over address bits (MSB-first). Lookup walks the full address and
    keeps the DEEPEST value seen along the path — that is, by construction, the
    longest-prefix match. Separate tries for v4 (32-bit) and v6 (128-bit)."""

    __slots__ = ("_one", "_value", "_zero")

    def __init__(self) -> None:
        self._zero: _BitTrie | None = None
        self._one: _BitTrie | None = None
        self._value: _PrefixValue | None = None

    def insert(self, bits: int, prefixlen: int, width: int, value: _PrefixValue) -> None:
        # `bits` is the FULL-WIDTH integer; walk the top `prefixlen` bits, MSB-first,
        # indexing from the address width (32 or 128) so insert/lookup agree.
        node = self
        for i in range(prefixlen):
            bit = (bits >> (width - 1 - i)) & 1
            child = node._one if bit else node._zero
            if child is None:
                child = _BitTrie()
                if bit:
                    node._one = child
                else:
                    node._zero = child
            node = child
        node._value = value

    def longest_match(self, bits: int, width: int) -> _PrefixValue | None:
        node: _BitTrie | None = self
        best: _PrefixValue | None = self._value
        for i in range(width):
            if node is None:
                break
            bit = (bits >> (width - 1 - i)) & 1
            node = node._one if bit else node._zero
            if node is not None and node._value is not None:
                best = node._value
        return best


class ProviderTrie:
    """Longest-prefix-match provider lookup built from the bundled snapshot. Malformed
    entries are logged + skipped (never fatal — untrusted feed data, CLAUDE.md §8)."""

    def __init__(self) -> None:
        self._v4 = _BitTrie()
        self._v6 = _BitTrie()
        self.count = 0
        self.synced_at = ""

    @classmethod
    def from_snapshot(cls, path: str) -> ProviderTrie:
        t = cls()
        try:
            with open(path, "r", encoding="utf-8") as fh:
                raw = json.load(fh)
        except (OSError, ValueError) as exc:
            log.warning("provider snapshot unreadable (%s): %s — classifier runs CIDR-blind", path, exc)
            return t
        t.synced_at = str(raw.get("synced_at", ""))
        prefixes = raw.get("prefixes", [])
        if not isinstance(prefixes, list):
            log.warning("provider snapshot 'prefixes' not a list — ignoring")
            return t
        for entry in prefixes:
            t._add(entry)
        return t

    def _add(self, entry: object) -> None:
        if not isinstance(entry, dict):
            log.warning("skipping non-object prefix entry: %r", entry)
            return
        raw_prefix = str(entry.get("prefix", "")).strip()
        try:
            net = ipaddress.ip_network(raw_prefix, strict=False)
        except ValueError as exc:
            log.warning("skipping malformed prefix %r: %s", raw_prefix, exc)
            return
        val = _PrefixValue(
            provider=str(entry.get("provider", "")).strip().lower(),
            region=str(entry.get("region", "")).strip(),
            service=str(entry.get("service", "")).strip(),
            prefix=str(net),
        )
        bits = int(net.network_address)
        if net.version == 4:
            self._v4.insert(bits, net.prefixlen, 32, val)
        else:
            self._v6.insert(bits, net.prefixlen, 128, val)
        self.count += 1

    def lookup(self, ip: _IPAddr) -> _PrefixValue | None:
        if ip.version == 4:
            return self._v4.longest_match(int(ip), 32)
        return self._v6.longest_match(int(ip), 128)


_DEFAULT_SNAPSHOT = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                 "segmentdata", "provider_ip_ranges.json")

# Module-level default trie, built once from the bundled snapshot (offline, deterministic).
_DEFAULT_TRIE: ProviderTrie | None = None


def _default_trie() -> ProviderTrie:
    global _DEFAULT_TRIE
    if _DEFAULT_TRIE is None:
        _DEFAULT_TRIE = ProviderTrie.from_snapshot(_DEFAULT_SNAPSHOT)
    return _DEFAULT_TRIE


# ── the classifier ───────────────────────────────────────────────────────────


class SegmentClassifier:
    """Stateless, pure classifier. Construct once (builds/holds the provider trie); call
    classify() per hop. Thread-safe (read-only after construction)."""

    def __init__(self, trie: ProviderTrie | None = None) -> None:
        self._trie = trie if trie is not None else _default_trie()

    # -- scorers (each returns 0+ SegSignal, per research Area 2 signal list) --

    def _score_address_space(self, ip: _IPAddr) -> list[SegSignal]:
        # Provider CIDR feed — the strongest CLOUD signal (authoritative, system-of-record).
        hit = self._trie.lookup(ip)
        if hit is not None:
            return [SegSignal(
                name="provider_cidr", family=Family.ADDRESS_SPACE, tier=Tier.AUTHORITATIVE,
                segment_vote=SegmentType.CLOUD.value, provider=hit.provider, region=hit.region,
                service=hit.service, detail=f"IP within published {hit.provider or 'cloud'} prefix {hit.prefix}",
            )]
        # RFC6598 CGNAT — deterministic carrier/WAN edge, distinct from RFC1918.
        if ip.version == 4 and ip in _RFC6598:
            return [SegSignal(
                name="rfc6598_cgnat", family=Family.ADDRESS_SPACE, tier=Tier.AUTHORITATIVE,
                segment_vote=SegmentType.WAN.value,
                detail="RFC6598 shared address space (100.64/10) — carrier-grade NAT / SP edge",
            )]
        # RFC1918 / RFC4193 private — deterministic PRIVATE, but ambiguous LAN vs DC vs
        # intra-cloud alone (research 2.3) → STRONG, needs corroboration to become confident.
        priv = (ip.version == 4 and any(ip in n for n in _RFC1918)) or (ip.version == 6 and ip in _RFC4193)
        if priv:
            return [SegSignal(
                name="rfc1918_private", family=Family.ADDRESS_SPACE, tier=Tier.STRONG,
                segment_vote=SegmentType.LAN.value,
                detail="private address space (RFC1918/RFC4193) — LAN/DC fabric or intra-cloud (ambiguous alone)",
            )]
        # A routable public address with no provider-CIDR hit → Internet/transit HINT only:
        # address space alone can't tell transit from eyeball from an un-fed cloud prefix,
        # so it never confirms on its own (the ASN signal is the real classifier here).
        if ip.is_global:
            return [SegSignal(
                name="public_unassigned", family=Family.ADDRESS_SPACE, tier=Tier.WEAK,
                segment_vote=SegmentType.INTERNET.value,
                detail="globally routable public address, no provider-CIDR match — internet/transit hint",
            )]
        return []

    def _score_asn(self, asn: int | None) -> list[SegSignal]:
        if asn is None:
            return []
        row = _ASN_TABLE.get(asn)
        if row is None:
            return [SegSignal(
                name="asn_unknown", family=Family.ASN, tier=Tier.WEAK,
                segment_vote=SegmentType.INTERNET.value,
                detail=f"AS{asn} not in curated cloud/transit table — public/internet hint",
            )]
        cls = row["class"]
        vote = {"cloud": SegmentType.CLOUD.value, "transit": SegmentType.WAN.value,
                "eyeball": SegmentType.INTERNET.value}.get(cls, SegmentType.INTERNET.value)
        return [SegSignal(
            name=f"asn_{cls}", family=Family.ASN, tier=Tier.STRONG, segment_vote=vote,
            provider=row.get("provider", ""),
            detail=f"AS{asn} is a curated {cls} network ({row.get('provider', '')})".strip(),
        )]

    def _score_device_role(self, hint: str | None) -> list[SegSignal]:
        if not hint:
            return []
        text = str(hint).strip()
        if not text:
            return []
        for pat, role, seg_vote, seam_kind in _ROLE_HINT_MAP:
            if pat.search(text):
                return [SegSignal(
                    name="device_role_hint", family=Family.DEVICE_ROLE, tier=Tier.AUTHORITATIVE,
                    role_vote=role.value, segment_vote=seg_vote, seam_kind=seam_kind or "",
                    detail=f"declared device role from telemetry/LLDP/SNMP: {text!r} → {role.value}",
                )]
        return [SegSignal(
            name="device_role_hint", family=Family.DEVICE_ROLE, tier=Tier.WEAK,
            detail=f"device role hint {text!r} did not match a known role pattern",
        )]

    def _score_rdns(self, rdns: str | None) -> list[SegSignal]:
        if not rdns:
            return []
        name = str(rdns).strip().rstrip(".")
        if not name:
            return []
        out: list[SegSignal] = []
        for pat, provider in _RDNS_PROVIDER:
            if pat.search(name):
                out.append(SegSignal(
                    name="rdns_provider", family=Family.RDNS, tier=Tier.WEAK,
                    segment_vote=SegmentType.CLOUD.value, provider=provider,
                    detail=f"rDNS {name!r} matches {provider} naming (hint only)",
                ))
                break
        for pat, role in _RDNS_ROLE:
            if pat.search(name):
                out.append(SegSignal(
                    name="rdns_role", family=Family.RDNS, tier=Tier.WEAK, role_vote=role.value,
                    detail=f"rDNS {name!r} suggests role {role.value} (hint only)",
                ))
                break
        return out

    def _score_ttl_latency(self, ttl: int | None, latency: float | None) -> list[SegSignal]:
        out: list[SegSignal] = []
        if ttl is not None:
            try:
                t = int(ttl)
            except (TypeError, ValueError):
                t = -1
            if 0 < t <= 255:
                # Observed TTL fingerprints the sender's initial-TTL family — a device-family
                # hint, never a segment classifier on its own.
                initial = 64 if t > 32 else 255
                for guess in (64, 128, 255):
                    if 0 < guess - t <= 30:
                        initial = guess
                        break
                out.append(SegSignal(
                    name="ttl_fingerprint", family=Family.TTL_LATENCY, tier=Tier.WEAK,
                    detail=f"observed TTL {t} ~ initial {initial} (device-family hint only)",
                ))
        if latency is not None:
            try:
                ms = float(latency)
            except (TypeError, ValueError):
                ms = -1.0
            if ms >= 40.0:
                out.append(SegSignal(
                    name="latency_longhaul", family=Family.TTL_LATENCY, tier=Tier.WEAK,
                    segment_vote=SegmentType.WAN.value,
                    detail=f"{ms:.0f}ms suggests a long-haul WAN segment (hint only)",
                ))
        return out

    # -- fusion --

    def classify(self, hop: dict) -> Classification:
        """Classify one hop. `hop` keys (all but `ip` optional): ip, rdns, ttl, latency,
        device_role_hint, asn. Returns a Classification (see to_dict())."""
        if not isinstance(hop, dict):
            return _unknown("input is not a hop object")
        raw_ip = str(hop.get("ip", "")).strip()
        if not raw_ip:
            return _unknown("no IP supplied")
        try:
            ip = ipaddress.ip_address(raw_ip)
        except ValueError:
            return _unknown(f"unparseable IP {raw_ip!r}")

        # Non-topological addresses are not path segments — drop them honestly.
        if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved:
            return _unknown(f"{raw_ip} is a non-topological address "
                            "(loopback/link-local/multicast/reserved) — not a path segment")

        asn = _coerce_asn(hop.get("asn"))
        signals: list[SegSignal] = []
        signals += self._score_address_space(ip)
        signals += self._score_asn(asn)
        signals += self._score_device_role(hop.get("device_role_hint"))
        signals += self._score_rdns(hop.get("rdns"))
        signals += self._score_ttl_latency(hop.get("ttl"), hop.get("latency"))

        return _fuse(signals)


# ── fusion rule (default-closed, multi-signal) ───────────────────────────────


# Segment types that REFINE rather than CONTRADICT one another. lan/dc are both
# private-fabric (RFC1918 can't split them alone — device role refines it); wan/internet
# are both public-external. Votes within a group corroborate; across groups contradict.
_COMPAT_GROUPS = [
    frozenset({SegmentType.LAN.value, SegmentType.DC.value}),
    frozenset({SegmentType.WAN.value, SegmentType.INTERNET.value}),
]


def _compatible(a: str, b: str) -> bool:
    if a == b:
        return True
    return any(a in g and b in g for g in _COMPAT_GROUPS)


def _fuse(signals: list[SegSignal]) -> Classification:
    """THE CORE RULE. Default-closed:
      * confidence STRONG  ⇐ an AUTHORITATIVE segment signal (provider CIDR / RFC6598 /
                             declared role), OR ≥2 INDEPENDENT (distinct-family) non-weak
                             signals agreeing (compatible types corroborate).
      * confidence MEDIUM  ⇐ a single STRONG ambiguous-alone signal (RFC1918 → lan), or an
                             AUTHORITATIVE signal contradicted by an independent one.
      * confidence WEAK    ⇐ only weak signals support the winner (a lone rDNS/TTL/hostname
                             NEVER exceeds weak — the honesty rule).
      * segment UNKNOWN    ⇐ no segment-bearing signal at all → + human reason.
    device_role is fused separately: a declared (authoritative) role wins; else a weak rDNS
    role hint; else unknown. A role can be known even when the segment is unknown."""
    device_role, _ = _fuse_role(signals)

    seg_signals = [s for s in signals if s.segment_vote]
    if not seg_signals:
        c = _unknown("no address-space, ASN, device-role or naming signal established a segment type")
        c.device_role = device_role
        c.signals = signals
        return c

    # Tally votes per segment_type: best tier, independent families, carried metadata.
    votes: dict[str, dict[str, object]] = {}
    for s in seg_signals:
        vote = s.segment_vote
        assert vote is not None  # seg_signals is filtered to truthy segment_vote
        v = votes.setdefault(vote, {"families": set(), "best_tier": Tier.WEAK,
                                    "provider": "", "region": "", "service": "", "seam_kind": ""})
        fams = v["families"]
        assert isinstance(fams, set)
        fams.add(s.family)
        if _TIER_RANK[s.tier] > _TIER_RANK[v["best_tier"]]:  # type: ignore[index]
            v["best_tier"] = s.tier
        for k in ("provider", "region", "service", "seam_kind"):
            if not v[k] and getattr(s, k):
                v[k] = getattr(s, k)

    # For each candidate type, aggregate over COMPATIBLE votes (refinements corroborate).
    def _agg(t: str) -> tuple[Tier, set, Tier]:
        fams: set = set()
        best = Tier.WEAK
        for vt, v in votes.items():
            if _compatible(t, vt):
                vfams = v["families"]
                assert isinstance(vfams, set)
                fams |= vfams
                if _TIER_RANK[v["best_tier"]] > _TIER_RANK[best]:  # type: ignore[index]
                    best = v["best_tier"]  # type: ignore[assignment]
        return best, fams, votes[t]["best_tier"]  # type: ignore[return-value]

    # Winner: highest compatible tier, then most independent families, then own tier
    # (prefer the more specific/stronger originating vote, e.g. dc over lan).
    def _score(t: str) -> tuple[int, int, int]:
        best, fams, own = _agg(t)
        return (_TIER_RANK[best], len(fams), _TIER_RANK[own])

    winner_type = max(votes.keys(), key=_score)
    best_tier, wfams, _own = _agg(winner_type)
    independent = len(wfams)

    # Contradiction: an INDEPENDENT non-weak signal voting an INCOMPATIBLE segment.
    contradicted = any(
        not _compatible(winner_type, t) and _TIER_RANK[v["best_tier"]] >= _TIER_RANK[Tier.STRONG]  # type: ignore[index]
        for t, v in votes.items()
    )

    if best_tier == Tier.AUTHORITATIVE:
        confidence = Confidence.STRONG if not contradicted else Confidence.MEDIUM
    elif best_tier == Tier.STRONG:
        confidence = Confidence.STRONG if (independent >= 2 and not contradicted) else Confidence.MEDIUM
    else:
        confidence = Confidence.WEAK  # weak-only support never becomes confident

    wv = votes[winner_type]
    reason = _reason_for(winner_type, wfams, seg_signals, contradicted, confidence)
    return Classification(
        segment_type=winner_type, device_role=device_role, confidence=confidence.value,
        signals=signals, reason=reason, provider=str(wv["provider"]), region=str(wv["region"]),
        service=str(wv["service"]), seam_kind=str(wv["seam_kind"]),
        boundary=SEGMENT_TO_BOUNDARY.get(winner_type, "UNKNOWN"),
    )


def _fuse_role(signals: list[SegSignal]) -> tuple[str, bool]:
    """Declared (authoritative) device role wins; else a weak rDNS role hint; else unknown."""
    for s in signals:
        if s.role_vote and s.tier == Tier.AUTHORITATIVE:
            return s.role_vote, True
    for s in signals:
        if s.role_vote:
            return s.role_vote, False
    return DeviceRole.UNKNOWN.value, False


_TIER_RANK = {Tier.WEAK: 1, Tier.STRONG: 2, Tier.AUTHORITATIVE: 3}


def _reason_for(seg: str, families: set, seg_signals: list[SegSignal],
                contradicted: bool, confidence: Confidence) -> str:
    drivers = ", ".join(sorted({s.name for s in seg_signals if s.segment_vote == seg}))
    parts = [(f"classified {seg} at {confidence.value} confidence from {len(families)} "
             f"independent signal family(ies) [{drivers}]")]
    if confidence == Confidence.WEAK:
        parts.append("only weak/hint evidence (rDNS/TTL/hostname) — never anchors a verdict")
    if contradicted:
        parts.append("an independent signal disagreed — confidence capped")
    return "; ".join(parts)


def _unknown(reason: str) -> Classification:
    return Classification(
        segment_type=SegmentType.UNKNOWN.value, device_role=DeviceRole.UNKNOWN.value,
        confidence=Confidence.NONE.value, signals=[], reason=reason, boundary="UNKNOWN",
    )


def _coerce_asn(v: object) -> int | None:
    if v is None or v == "":
        return None
    try:
        if isinstance(v, str):
            n = int(v.lstrip("Aa Ss").strip())
        elif isinstance(v, (int, float)):
            n = int(v)
        else:
            return None
    except (TypeError, ValueError):
        return None
    return n if n > 0 else None


# Convenience: a shared default instance (built lazily on first import use).
_DEFAULT_CLASSIFIER: SegmentClassifier | None = None


def classify_hop(hop: dict) -> dict:
    """Module-level convenience over the default (bundled-snapshot) classifier."""
    global _DEFAULT_CLASSIFIER
    if _DEFAULT_CLASSIFIER is None:
        _DEFAULT_CLASSIFIER = SegmentClassifier()
    return _DEFAULT_CLASSIFIER.classify(hop).to_dict()
