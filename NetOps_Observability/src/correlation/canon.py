# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Stage [1] identity canonicalisation — pure building blocks (P6 PR-D).

Plan of record: docs/design/P6_CANONICALISATION_PLAN_2026-11-07.md (rules D1, D2,
D4, D5) and docs/design/NMS_DEVICE_IDENTITY_2026-11-01.md. Tracker 374.

Wired by P6 PR-E behind `CORR_IDENTITY_CANON` (default OFF; requires E1 and
series admission — signals.identity_canon_enabled): `main.buffer_signal` calls
`canonicalize_detailed` once per event-lane signal (syslog, trap, controller and
the proactive checks built from them) after `canon_tenant` and before the E1
origin stamp — never before the aggregation plane's `agg_admit`;
`main.handle_metric` calls `canonicalize_series` on the metric lane's series key
before the episode detector. With the flag OFF neither is called and the
engine's behaviour is unchanged.

What it solves: one box, one session or one port reaches the engine under a
different spelling per lane — syslog names the box by its hostname (or, like the
lab's cEDGE-81, by its management address), traps and the controller by its
inventory id; an interface is `Gi1` in one lane and `GigabitEthernet1` in another;
the controller rewrites a BGP peer address to the peer's inventory id. Each
spelling becomes its own node, so the evidence never meets.

Four pure functions:

* `canon_iface_key(name)` — a TABLE-FREE canonical interface key (owner decision
  OD1: `GigabitEthernet0/1` and `Gi0/1` → `gi0/1`; the raw name stays in attrs for
  display). A superset-compatible port of the Go `canonIface`/`ifaceAlias`
  (src/backend/topology_view.go): for every name the Go table covers, the result is
  byte-identical (pinned by a drift test that parses the Go source); the Python
  table only ADDS vendor spellings. Digit-only names are not keys by themselves —
  they come back as an explicit ifIndex marker the caller resolves against the
  device's own ifName set (HP ProCurve names its ports "1".."48").
* `canonical_peer(raw)` — the compressed text of an IPv4/IPv6 address, "" for
  anything else. `identity.yaml` defines a BGP session by the REMOTE ADDRESS.
* `canonicalize(sig, resolver)` — a NEW Signal with `entity_id` (and the raw
  device grounding token) rewritten, `attrs["canon"] = {"raw", "basis"}` stamped on
  a rewrite only. `native_id` and therefore `signal_id` are NEVER touched, so the
  archive identity and replay are unchanged.
* `canonicalize_series(ev, entity_id, tokens, resolver, tenant)` — the same rules
  for a metric-lane series key (`device`, `device:ifName`, `device:peer`,
  `device:neighbour`); the SOURCE-DECLARED ifIndex (`index`) is the only licence
  to read digits as an ifIndex.

Safety properties (all tested in test_canon_identity_p6.py):

* Abstain, never guess. An unknown, ambiguous, generic (`localhost`, `router`, …)
  or conflicting identity keeps the raw spelling and says why in the outcome.
* Tenant-only (§3a). `canonicalize` refuses a resolver that is not scoped to the
  signal's own tenant (`EntityResolver.tenant`, set by
  `entity_resolver.identity_resolver_for`); an unscoped legacy resolver
  (tenant ∪ global) is refused outright.
* Idempotent: canonicalize(canonicalize(x)) == canonicalize(x) — the rules always
  run from the RAW entity (`attrs["canon"]["raw"]` once stamped), and every key is a
  fixed point of `canon_iface_key`.
* Order-independent: a pure function of one signal and an order-independent
  resolver.
* Never raises on hostile or oversized input: every string is length-bounded and
  type-checked; a rebuilt Signal that the model refuses abstains instead.
"""
from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Final

from signals import MAX_ID_CHARS, DeadLetter, EntityType, Signal, Source

if TYPE_CHECKING:  # import cycle: entity_resolver imports this module at runtime
    from entity_resolver import EntityResolver

# ── interface keys ───────────────────────────────────────────────────────────

# The Go table, verbatim (src/backend/topology_view.go `ifaceAlias`). The drift
# test parses the Go source and fails if an entry is added, removed or changed
# there without the same change here.
GO_IFACE_ALIAS: Final[Mapping[str, str]] = {
    "ethernet": "et",
    "eth": "et",
    "gigabitethernet": "gi",
    "gige": "gi",
    "gig": "gi",
    "tengigabitethernet": "te",
    "tengige": "te",
    "twentyfivegige": "twe",
    "twentyfivegigabitethernet": "twe",
    "fortygigabitethernet": "fo",
    "fortygige": "fo",
    "fiftygige": "fi",
    "hundredgige": "hu",
    "hundredgigabitethernet": "hu",
    "fastethernet": "fa",
    "portchannel": "po",
    "bundleether": "be",
    "management": "ma",
    "mgmt": "ma",
    "loopback": "lo",
    "vlan": "vl",
    "tunnel": "tu",
    "serial": "se",
}

# Vendor spellings the Go table lacks (owner rule: every fix covers Cisco,
# Juniper, Nokia, Arista, SONiC and others). Each maps a LONG form (or an
# abbreviation that is not a prefix of its long form) to the short form the
# vendor's own CLI prints, so both lanes' spellings collapse to one key. Short
# forms that already prefix their long name fall through to themselves, as in Go.
EXTRA_IFACE_ALIAS: Final[Mapping[str, str]] = {
    # Cisco IOS-XE / IOS-XR speeds
    "twogigabitethernet": "tw",          # Catalyst mGig: TwoGigabitEthernet1/0/1 = Tw1/0/1
    "twogige": "tw",
    "fivegigabitethernet": "fi",         # FiveGigabitEthernet1/0/1 = Fi1/0/1
    "fivegige": "fi",
    "fiftygigabitethernet": "fi",        # FiftyGigabitEthernet1/0/1 = Fi1/0/1
    "twohundredgige": "th",              # IOS-XR TwoHundredGigE0/0/0/0
    "twohundredgigabitethernet": "th",
    "fourhundredgige": "fh",             # IOS-XR FourHundredGigE0/0/0/0 = FH0/0/0/0
    "fourhundredgigabitethernet": "fh",
    "eighthundredgige": "eh",
    "tf": "twe",                         # IOS-XR abbreviates TwentyFiveGigE as TF
    "appgigabitethernet": "ap",          # Catalyst 9k app-hosting port, Ap1/0/1
    "mgmteth": "ma",                     # IOS-XR MgmtEth0/RP0/CPU0/0
    "mg": "ma",                          # … and its short form Mg0/RP0/CPU0/0
    "null": "nu",                        # Null0 / Nu0 (kept: owner 2026-11-07)
    "virtualaccess": "vi",
    "virtualtemplate": "vt",
    "dialer": "di",
    "multilink": "mu",
    "cellular": "ce",
    "tunnelip": "ti",                    # IOS-XR tunnel-ip1 = ti1
    "tunnelte": "tt",                    # IOS-XR tunnel-te1 = tt1
    # Arista EOS
    "vxlan": "vx",                       # Vxlan1 = Vx1
    # Huawei VRP / HPE Comware
    "xgigabitethernet": "xge",           # Huawei XGigabitEthernet0/0/1 = XGE0/0/1
    "bridgeaggregation": "bagg",         # Comware Bridge-Aggregation1 = BAGG1
}

IFACE_ALIAS: Final[Mapping[str, str]] = {**GO_IFACE_ALIAS, **EXTRA_IFACE_ALIAS}

# Markers. A real key never starts with "?": its first character is a letter of
# the canonical prefix or the first digit of the port part.
IFINDEX_MARKER_PREFIX: Final = "?ifindex:"
IFACE_ABSTAIN: Final = "?abstain"

MAX_IFACE_INPUT: Final = 1024   # raw input (an SR OS ifDescr carries a description)
MAX_IFACE_KEY: Final = 128      # the port name itself, after the ifDescr split
MAX_IFINDEX_DIGITS: Final = 10  # ifIndex is an Integer32 (≤ 2147483647)

# Producer placeholders for "no interface" (events.yaml `trap_iface` falls back to
# the constant `unknown`): never a key.
_IFACE_PLACEHOLDERS: Final = frozenset({"unknown", "none", "null", "n/a", "na", "-", "?"})

_PRINTABLE_ASCII = re.compile(r"[\x20-\x7e]+")
_DIGITS = re.compile(r"[0-9]+")
# SONiC default (non-alias) naming. In alias mode the port names are the
# platform's front-panel aliases (etp1, fortyGigE0/0, Eth1/1, …); no string rule
# can tell which EthernetN they are, so they abstain.
_SONIC_DEFAULT = re.compile(
    r"(?:Ethernet[0-9]+(?:\.[0-9]+)?|PortChannel[0-9]+(?:\.[0-9]+)?|Po[0-9]+(?:\.[0-9]+)?"
    r"|Loopback[0-9]+|Vlan[0-9]+|eth[0-9]+"
    # … and the keys those names canonicalise to, so a key stays a fixed point
    r"|(?:et|po|lo|vl)[0-9]+(?:\.[0-9]+)?)")


def is_ifindex_marker(key: str) -> bool:
    """True for the marker `canon_iface_key` returns for a digit-only name."""
    return key.startswith(IFINDEX_MARKER_PREFIX)


def ifindex_of(key: str) -> str:
    """The digits of an ifIndex marker ("" when `key` is not one)."""
    return key[len(IFINDEX_MARKER_PREFIX):] if is_ifindex_marker(key) else ""


def _go_canon(low: str) -> str:
    """Go `canonIface` on an already-lowercased, stripped ASCII string: split at
    the first digit, keep only a-z in the type prefix, alias the prefix, keep the
    port part verbatim (slots, slashes and dots — distinct ports never collapse)."""
    d = next((i for i, c in enumerate(low) if "0" <= c <= "9"), -1)
    prefix, rest = (low, "") if d < 0 else (low[:d], low[d:])
    prefix = "".join(c for c in prefix if "a" <= c <= "z")
    return IFACE_ALIAS.get(prefix, prefix) + rest


def _is_ip_literal(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
    except ValueError:
        return False
    return True


def canon_iface_key(name: object, vendor_hint: str | None = None) -> str:
    """The canonical interface key for one interface name.

    Returns:
      * the key (`gi0/1`, `et1/1`, `ge0/0/0.0`, `1/1/1`, `ma0/rp0/cpu0/0`, …);
      * `IFINDEX_MARKER_PREFIX + digits` for a digit-only name — an ifIndex
        candidate OR a digit-named port (HP ProCurve); the caller decides against
        the device's ifName set;
      * `IFACE_ABSTAIN` when no key may be derived: a producer placeholder
        (`unknown`), an IP literal, non-printable / non-ASCII text, an oversized
        name, a SONiC alias-mode name (`vendor_hint="sonic"`), or a name with no
        usable characters;
      * "" for an empty name.

    Vendor rules: Junos keeps logical units (`ge-0/0/0.0` → `ge0/0/0.0`); a Nokia
    SR OS ifDescr (`1/1/1, 10/100/Gig Ethernet SFP, "desc"`) keys on its first
    comma-separated field; SR Linux `ethernet-1/1` → `et1/1`; Arista `Ethernet1` /
    `Et1` → `et1`; NX-OS `Eth1/1` → `et1/1`; vEdge `ge0/0` stays `ge0/0`.
    A fixed point: canon_iface_key(k) == k for every key k it returns (markers too).
    Never raises."""
    if not isinstance(name, str) or len(name) > MAX_IFACE_INPUT:
        return IFACE_ABSTAIN
    s = name.strip()
    if not s:
        return ""
    if s == IFACE_ABSTAIN or (is_ifindex_marker(s) and _DIGITS.fullmatch(ifindex_of(s))):
        return s  # markers are fixed points
    if "," in s:  # Nokia SR OS ifDescr: the port is the first field
        s = s.split(",", 1)[0].strip()
    if not s or len(s) > MAX_IFACE_KEY or not _PRINTABLE_ASCII.fullmatch(s):
        return IFACE_ABSTAIN
    low = s.lower()
    if low in _IFACE_PLACEHOLDERS or _is_ip_literal(s):
        return IFACE_ABSTAIN
    if _DIGITS.fullmatch(s):
        return IFINDEX_MARKER_PREFIX + s if len(s) <= MAX_IFINDEX_DIGITS else IFACE_ABSTAIN
    hint = vendor_hint.strip().lower() if isinstance(vendor_hint, str) else ""
    if hint == "sonic" and not _SONIC_DEFAULT.fullmatch(s):
        return IFACE_ABSTAIN
    key = _go_canon(low)
    if not key:
        return IFACE_ABSTAIN
    if _DIGITS.fullmatch(key):  # "-5" → "5": same ambiguity as a digit-only name
        return IFINDEX_MARKER_PREFIX + key if len(key) <= MAX_IFINDEX_DIGITS else IFACE_ABSTAIN
    return key


# ── peers and addresses ──────────────────────────────────────────────────────

MAX_PEER_INPUT: Final = 64  # longest IPv6 text (45) + a bounded zone id


def _parse_ip(raw: object) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    if not isinstance(raw, str) or len(raw) > MAX_PEER_INPUT:
        return None
    s = raw.strip()
    if s.startswith("[") and s.endswith("]"):
        s = s[1:-1]
    if not s or not _PRINTABLE_ASCII.fullmatch(s):
        return None
    try:
        ip = ipaddress.ip_address(s)
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped  # ::ffff:a.b.c.d is the IPv4 peer a.b.c.d
    return ip


def canonical_peer(raw: object) -> str:
    """Compressed address text for an IPv4/IPv6 literal (`2001:0DB8:0:0::1` →
    `2001:db8::1`, `[::1]` → `::1`, `::ffff:10.0.0.1` → `10.0.0.1`), "" for
    anything else (a name, an inventory id, an oversized or hostile string).
    Never raises."""
    ip = _parse_ip(raw)
    return ip.compressed if ip is not None else ""


def is_generic_address(raw: object) -> bool:
    """An address that names no single box: loopback, unspecified, multicast,
    link-local, limited broadcast. A syslog "hostname" like 127.0.0.1 or fe80::1
    is the same text on every device, so it never resolves to one."""
    ip = _parse_ip(raw)
    if ip is None:
        return False
    if ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_link_local:
        return True
    return isinstance(ip, ipaddress.IPv4Address) and ip == ipaddress.IPv4Address("255.255.255.255")


def tenant_key(tenant: object) -> str:
    """The resolver-row key of a tenant: "" and "global" are the ONE platform-global
    principal (main.canon_tenant spells it "global", entity_resolver.json spells it
    ""). Any other id passes through untouched."""
    t = tenant if isinstance(tenant, str) else ""
    return "" if t in ("", "global") else t


# ── signal canonicalisation ──────────────────────────────────────────────────

REWRITTEN: Final = "rewritten"
UNCHANGED: Final = "unchanged"
ABSTAIN_UNKNOWN: Final = "abstain_unknown"
ABSTAIN_AMBIGUOUS: Final = "abstain_ambiguous"
ABSTAIN_CONFLICT: Final = "abstain_conflict"
ABSTAIN_GENERIC: Final = "abstain_generic"
OUTCOMES: Final = (REWRITTEN, UNCHANGED, ABSTAIN_UNKNOWN, ABSTAIN_AMBIGUOUS,
                   ABSTAIN_CONFLICT, ABSTAIN_GENERIC)
# When nothing was rewritten, the signal's outcome is its most serious abstention.
_ABSTAIN_PRECEDENCE: Final = (ABSTAIN_CONFLICT, ABSTAIN_AMBIGUOUS, ABSTAIN_GENERIC, ABSTAIN_UNKNOWN)
_REASON_OUTCOME: Final[Mapping[str, str]] = {
    "unknown": ABSTAIN_UNKNOWN, "ambiguous": ABSTAIN_AMBIGUOUS, "generic": ABSTAIN_GENERIC,
}

CANON_ATTR: Final = "canon"

# Routing-session kinds (controller_events._SESSION_KINDS; the trap rules bind the
# same `{device}:{peer}`).
SESSION_KINDS: Final = frozenset({"bgp_adjacency_change", "ospf_adjacency_change",
                                  "isis_adjacency_change", "routing_adjacency_change"})
# D1 is BGP only: an OSPF syslog "Nbr" is the neighbour's ROUTER-ID while
# ospfNbrTable is keyed by the neighbour's IP — no change without evidence.
# `bgp_session_not_established` is the A4 proactive check built FROM a syslog
# BGP adjacency (proactive.py `proactive.bgp.adjacency_down_persisting`: source
# syslog, the line's host entity, its `peer` attr) — the same session, so it
# binds the same `<device>:<peer>` node as the line it was derived from (PR-E).
_D1_KINDS: Final = frozenset({"bgp_adjacency_change", "bgp_session_not_established"})
# The event lanes PR-E canonicalises in buffer_signal. The metric lane keys its
# series in handle_metric instead (canonicalize_series), and flows are PR-F.
EVENT_SOURCES: Final = frozenset({Source.SYSLOG, Source.TRAP, Source.CONTROLLER})
_IFACE_ATTR_KEYS: Final = ("interface", "interface_name")


@dataclass(frozen=True)
class CanonResult:
    """What `canonicalize_detailed` decided. `axes` lists (axis, outcome) per axis
    examined — `tenant`, `parse`, `device`, `iface`, `peer`, `length`, `model` — for
    PR-E's `corr_identity_canon_total{lane,axis,outcome}`."""
    signal: Signal
    outcome: str
    axes: tuple[tuple[str, str], ...] = ()
    basis: str = ""


@dataclass(frozen=True)
class _Axis:
    value: str
    outcome: str
    basis: str = ""


def _str_attr(attrs: Mapping, key: str) -> str:
    v = attrs.get(key)
    return v.strip() if isinstance(v, str) and len(v) <= MAX_ID_CHARS else ""


def _raw_entity(sig: Signal) -> str:
    """The entity as the producer bound it. Once canonicalised the raw spelling
    rides in attrs["canon"]["raw"], so every pass runs from the same input."""
    canon = sig.attrs.get(CANON_ATTR)
    if isinstance(canon, Mapping):
        raw = canon.get("raw")
        if isinstance(raw, str) and raw and len(raw) <= MAX_ID_CHARS:
            return raw
    return sig.entity_id


def _device_axis(token: str, resolver: EntityResolver) -> _Axis:
    dev, reason = resolver.resolve_device(token)
    if dev is None:
        return _Axis(token, _REASON_OUTCOME.get(reason, ABSTAIN_UNKNOWN))
    if dev == token:
        return _Axis(token, UNCHANGED)
    return _Axis(dev, REWRITTEN, "device:ip" if canonical_peer(token) else "device:name")


def _iface_axis(device: str, raw_iface: str, resolver: EntityResolver,
                vendor_hint: str | None) -> _Axis:
    key = canon_iface_key(raw_iface, vendor_hint)
    if key in ("", IFACE_ABSTAIN):
        return _Axis(raw_iface, ABSTAIN_UNKNOWN)
    basis = "iface:key"
    if is_ifindex_marker(key):
        digits = ifindex_of(key)
        by_index = resolver.ifname(device, digits)
        if digits in resolver.ifnames(device):
            # A digit-NAMED port (HP ProCurve "1".."48"). Ambiguous only when the
            # same digits are also the ifIndex of a DIFFERENTLY named port.
            if by_index is not None and by_index != digits:
                return _Axis(raw_iface, ABSTAIN_AMBIGUOUS)
            key, basis = digits, "iface:digit_name"
        elif by_index is not None:
            resolved = canon_iface_key(by_index, vendor_hint)
            if resolved in ("", IFACE_ABSTAIN) or is_ifindex_marker(resolved):
                return _Axis(raw_iface, ABSTAIN_UNKNOWN)
            key, basis = resolved, "iface:ifindex"
        else:
            return _Axis(raw_iface, ABSTAIN_UNKNOWN)
    if resolver.iface_key_status(device, key) == "ambiguous":
        # Two of this device's ports collapse onto one key: never merge them.
        return _Axis(raw_iface, ABSTAIN_AMBIGUOUS)
    if key == raw_iface:
        return _Axis(raw_iface, UNCHANGED)
    return _Axis(key, REWRITTEN, basis)


def _split_iface_entity(raw: str, attrs: Mapping) -> tuple[str, str] | None:
    """(device token, interface name) of a `<device>:<ifname>` entity. The
    producer's own `interface` / `interface_name` attr disambiguates a host that is
    an IPv6 literal or a port with a colon (Serial0/0/0:1); without one only a
    single-colon id splits."""
    named = [v for v in (_str_attr(attrs, k) for k in _IFACE_ATTR_KEYS) if v]
    for iface in named:
        if raw.endswith(":" + iface) and len(raw) > len(iface) + 1:
            return raw[: -len(iface) - 1], iface
    if named or raw.count(":") != 1:
        return None
    dev, _, iface = raw.partition(":")
    return (dev, iface) if dev and iface else None


def _controller_peer_hint(attrs: Mapping) -> str:
    hints = attrs.get("correlation_hints")
    if not isinstance(hints, Mapping):
        return ""
    return _str_attr(hints, "controller_peer_id")


@dataclass(frozen=True)
class _Plan:
    entity_id: str
    raw_device: str
    device: str
    axes: tuple[tuple[str, str], ...]
    basis: tuple[str, ...]


def _abstain(*axes: tuple[str, str]) -> _Plan:
    return _Plan("", "", "", tuple(axes), ())


def _plan_device(raw: str, resolver: EntityResolver) -> _Plan:
    """D2: a lane's device token → the tenant's canonical device id."""
    d = _device_axis(raw, resolver)
    if d.outcome != REWRITTEN:
        return _abstain(("device", d.outcome))
    return _Plan(d.value, raw, d.value, (("device", d.outcome),), (d.basis,))


def _plan_syslog_bgp(raw: str, attrs: Mapping, resolver: EntityResolver) -> _Plan:
    """D1: a syslog BGP adjacency binds the HOST; the trap and the controller bind
    the session `{device}:{peer}`. Rebind to `<canon device>:<compressed peer>` —
    only when the host resolves (unknown/ambiguous/generic hosts stay host-level)."""
    d = _device_axis(raw, resolver)
    if d.outcome not in (REWRITTEN, UNCHANGED):
        return _abstain(("device", d.outcome))
    axes = [("device", d.outcome)]
    basis = [d.basis] if d.basis else []
    peer_raw = _str_attr(attrs, "peer")
    peer = canonical_peer(peer_raw)
    if not peer:
        if peer_raw:
            axes.append(("peer", ABSTAIN_UNKNOWN))
        return _Plan(d.value, raw, d.value, tuple(axes), tuple(basis))
    axes.append(("peer", REWRITTEN))
    basis.append("peer:ip")
    return _Plan(f"{d.value}:{peer}", raw, d.value, tuple(axes), tuple(basis))


def _plan_session(raw: str, sig: Signal, resolver: EntityResolver) -> _Plan | None:
    """Trap / controller routing sessions `{device}:{peer}`. The peer becomes its
    compressed address; D5: the controller's peer, rewritten to an inventory id by
    nms/identity.go, goes back to the address it kept in
    correlation_hints.controller_peer_id. None when the id is not a session id."""
    is_ctl = sig.source == Source.CONTROLLER
    peer_raw = _str_attr(sig.attrs, "peer_id" if is_ctl else "peer")
    if not peer_raw or not raw.endswith(":" + peer_raw) or len(raw) <= len(peer_raw) + 1:
        return None
    dev_tok = raw[: -len(peer_raw) - 1]
    d = _device_axis(dev_tok, resolver)
    if d.outcome in (ABSTAIN_AMBIGUOUS, ABSTAIN_GENERIC, ABSTAIN_CONFLICT):
        return _abstain(("device", d.outcome))
    # Trap and controller device tokens are inventory ids already (the identity
    # join / nms/identity.go). One the resolver does not know (a controller-only
    # device) is kept verbatim — kept, not guessed.
    axes = [("device", d.outcome)]
    basis = [d.basis] if d.basis else []
    direct = canonical_peer(peer_raw)
    hint = canonical_peer(_controller_peer_hint(sig.attrs)) if is_ctl else ""
    if hint and direct and hint != direct:
        return _abstain(("device", d.outcome), ("peer", ABSTAIN_CONFLICT))
    peer = hint or direct
    if not peer:
        axes.append(("peer", ABSTAIN_UNKNOWN))
        peer = peer_raw
    elif peer == peer_raw:
        axes.append(("peer", UNCHANGED))
    else:
        axes.append(("peer", REWRITTEN))
        basis.append("peer:controller_hint" if hint and not direct else "peer:ip")
    return _Plan(f"{d.value}:{peer}", dev_tok, d.value, tuple(axes), tuple(basis))


def _plan_interface(raw: str, sig: Signal, resolver: EntityResolver) -> _Plan:
    """D4 (+ D2 on the device part): `<canon device>:<canon_iface_key(name)>`."""
    parsed = _split_iface_entity(raw, sig.attrs)
    if parsed is None:
        return _abstain(("parse", ABSTAIN_UNKNOWN))
    dev_tok, iface = parsed
    d = _device_axis(dev_tok, resolver)
    if d.outcome in (ABSTAIN_AMBIGUOUS, ABSTAIN_GENERIC, ABSTAIN_CONFLICT):
        # A generic or ambiguous host names several boxes: canonicalising the port
        # would weld their interfaces together.
        return _abstain(("device", d.outcome))
    i = _iface_axis(d.value, iface, resolver, _str_attr(sig.attrs, "vendor") or None)
    basis = tuple(b for b in (d.basis, i.basis) if b)
    return _Plan(f"{d.value}:{i.value}", dev_tok, d.value,
                 (("device", d.outcome), ("iface", i.outcome)), basis)


def _plan(raw: str, sig: Signal, resolver: EntityResolver) -> _Plan | None:
    kind = sig.kind.removesuffix("_clear")
    if sig.entity_type == EntityType.INTERFACE:
        return _plan_interface(raw, sig, resolver)
    if sig.entity_type != EntityType.DEVICE:
        return None
    if sig.source in (Source.TRAP, Source.CONTROLLER) and kind in SESSION_KINDS:
        session = _plan_session(raw, sig, resolver)
        if session is not None or sig.source == Source.CONTROLLER:
            return session
    if sig.source == Source.SYSLOG and kind in _D1_KINDS:
        return _plan_syslog_bgp(raw, sig.attrs, resolver)
    if sig.source in (Source.SYSLOG, Source.TRAP):
        return _plan_device(raw, resolver)
    # Controller device kinds bind `device or site` — a site id must never be
    # resolved as a hostname. The device there is the inventory id already.
    return None


def _overall(axes: tuple[tuple[str, str], ...]) -> str:
    seen = {o for _, o in axes}
    for o in _ABSTAIN_PRECEDENCE:
        if o in seen:
            return o
    return UNCHANGED


def canonicalize_detailed(sig: Signal, resolver: EntityResolver | None) -> CanonResult:
    """`canonicalize` plus the per-axis outcomes and the basis. Never raises on a
    well-formed Signal, whatever strings it carries."""
    rtenant = getattr(resolver, "tenant", None)
    if resolver is None or rtenant is None or tenant_key(rtenant) != tenant_key(sig.tenant_id):
        # §3a: only the signal's OWN tenant's inventory may rename its evidence.
        return CanonResult(sig, ABSTAIN_CONFLICT, (("tenant", ABSTAIN_CONFLICT),))
    if sig.source not in EVENT_SOURCES:
        return CanonResult(sig, UNCHANGED)
    raw = _raw_entity(sig)
    plan = _plan(raw, sig, resolver)
    if plan is None:
        return CanonResult(sig, UNCHANGED)
    if plan.entity_id and plan.entity_id == sig.entity_id and raw != sig.entity_id:
        # Already canonical (a second pass): the fixed point, nothing to do.
        return CanonResult(sig, UNCHANGED, plan.axes)
    if not plan.entity_id or plan.entity_id == raw:
        # Every axis abstained/kept its spelling: nothing to rewrite or stamp. (On
        # a signal canonicalised under an earlier resolver the stamp is kept.)
        return CanonResult(sig, _overall(plan.axes), plan.axes)
    if len(plan.entity_id) > MAX_ID_CHARS:
        # The model would truncate it, and two truncated ids can collide.
        axes = (*plan.axes, ("length", ABSTAIN_CONFLICT))
        return CanonResult(sig, ABSTAIN_CONFLICT, axes)
    basis = "+".join(plan.basis)
    tokens = sig.entity_tokens
    if plan.device != plan.raw_device and plan.raw_device:
        swapped = [plan.device if t == plan.raw_device else t for t in tokens]
        tokens = tuple(dict.fromkeys(swapped))  # dedupe, first occurrence wins
    attrs = {**sig.attrs, CANON_ATTR: {"raw": raw, "basis": basis}}
    try:
        out = replace(sig, entity_id=plan.entity_id, entity_tokens=tokens, attrs=attrs)
    except DeadLetter:
        axes = (*plan.axes, ("model", ABSTAIN_CONFLICT))
        return CanonResult(sig, ABSTAIN_CONFLICT, axes)
    return CanonResult(out, REWRITTEN, plan.axes, basis)


def canonicalize(sig: Signal, resolver: EntityResolver | None) -> tuple[Signal, str]:
    """(signal, outcome). The signal is the INPUT object when nothing changes, else
    a new Signal (dataclasses.replace, a new attrs dict) whose `entity_id` follows
    D1/D2/D4/D5 and whose attrs carry `canon = {"raw", "basis"}`. `native_id`,
    `signal_id`, `ts`, `observer` and every other field are untouched.
    Outcome ∈ OUTCOMES."""
    r = canonicalize_detailed(sig, resolver)
    return r.signal, r.outcome


# ── metric-lane series keys (P6 PR-E) ────────────────────────────────────────

# Every axis canonicalize_detailed / canonicalize_series reports — the closed
# label set of main's corr_identity_canon_total{lane,axis,outcome}.
AXES: Final = ("tenant", "parse", "device", "iface", "peer", "length", "model")

# metric_identity families whose series key canonicalize_series understands.
# cloud_resource keys a provider resource id, not an inventory device: untouched.
_SERIES_FAMILIES: Final = frozenset({"interface", "bgp", "igp", "device_resource"})


@dataclass(frozen=True)
class SeriesCanon:
    """What `canonicalize_series` decided for one metric sample's series key.
    `entity_id` / `entity_tokens` are the INPUT values unless `outcome` is
    REWRITTEN; `attrs` is `{"canon": {"raw", "basis"}}` on a rewrite, else None."""
    entity_id: str
    entity_tokens: tuple[str, ...]
    outcome: str
    axes: tuple[tuple[str, str], ...] = ()
    basis: str = ""
    attrs: Mapping[str, Mapping[str, str]] | None = None


def _ev_str(ev: Mapping, key: str) -> str:
    v = ev.get(key)
    if isinstance(v, bool) or not isinstance(v, (str, int)):
        return ""
    s = str(v).strip()
    return s if len(s) <= MAX_ID_CHARS else ""


def _index_key(name: str, vendor_hint: str | None) -> str:
    """The canonical key of an inventory ifName: its key, or the digits of a
    digit-named port (as entity_resolver indexes it, plus the vendor hint);
    "" when no key may be derived."""
    key = canon_iface_key(name, vendor_hint)
    if is_ifindex_marker(key):
        return ifindex_of(key)
    return "" if key in ("", IFACE_ABSTAIN) else key


def _metric_iface_axis(device: str, if_name: str, index: str, resolver: EntityResolver,
                       vendor_hint: str | None) -> _Axis:
    """D4 for a MetricEvent port: `if_name` (IF-MIB ifName / the controller's
    ifName) when it names the port, else the SOURCE-DECLARED ifIndex (`index`).

    Digits are read as an ifIndex ONLY when the source declares that index — an
    SNMP walk row always does (metric_events.go `Index`). A digit-only ifName is
    first a NAME (HP ProCurve "1".."48"); when the inventory knows no such port
    the declared ifIndex decides, and an inventory ifName that disagrees with the
    source's own digit name is a conflict, never a pick."""
    raw = if_name or index
    if if_name and not _DIGITS.fullmatch(if_name):
        return _iface_axis(device, if_name, resolver, vendor_hint)
    declared = index if (_DIGITS.fullmatch(index) and len(index) <= MAX_IFINDEX_DIGITS) else ""
    by_index = resolver.ifname(device, declared) if declared else None
    if if_name and if_name in resolver.ifnames(device):
        if by_index is not None and by_index != if_name:
            return _Axis(raw, ABSTAIN_AMBIGUOUS)
        key, basis = if_name, "iface:digit_name"
    elif by_index is not None:
        key = _index_key(by_index, vendor_hint)
        if if_name and key != if_name:
            # The source names the port "5"; the inventory says the declared
            # ifIndex is a differently named port. Two authorities disagree.
            return _Axis(raw, ABSTAIN_CONFLICT)
        if not key:
            return _Axis(raw, ABSTAIN_UNKNOWN)
        basis = "iface:ifindex"
    else:
        return _Axis(raw, ABSTAIN_UNKNOWN)
    if resolver.iface_key_status(device, key) == "ambiguous":
        return _Axis(raw, ABSTAIN_AMBIGUOUS)
    if key == raw:
        return _Axis(raw, UNCHANGED)
    return _Axis(key, REWRITTEN, basis)


def _peer_axis(raw_peer: str, *, opaque_ok: bool) -> _Axis:
    """A BGP peer / IGP neighbour → its compressed address. A non-address is an
    abstention for BGP (identity.yaml keys a session by the remote ADDRESS) but a
    legitimate identity for an IGP neighbour (an IS-IS system-id): `opaque_ok`."""
    peer = canonical_peer(raw_peer)
    if not peer:
        return _Axis(raw_peer, UNCHANGED if opaque_ok else ABSTAIN_UNKNOWN)
    if peer == raw_peer:
        return _Axis(raw_peer, UNCHANGED)
    return _Axis(peer, REWRITTEN, "peer:ip")


def canonicalize_series(ev: Mapping, entity_id: str, entity_tokens: tuple[str, ...],
                        resolver: EntityResolver | None, tenant: str) -> SeriesCanon:
    """The metric lane's series key (`main.metric_identity` output) under rules
    D2 (device) + D4 (port) + peer compression, for the VERIFIED `tenant`.

    Pure; never raises on a hostile event. Abstains (keeps the input key) on a
    resolver not scoped to `tenant` (§3a), an ambiguous or generic device (its
    ports would weld two boxes together), an unparseable key, or a rebuilt key
    longer than MAX_ID_CHARS. An unknown device keeps its spelling — the metric
    lane names devices by inventory id already — while its port / peer is still
    canonicalised, exactly as the event lanes' `_plan_interface` / `_plan_session`
    do. Idempotent: every rebuilt key is a fixed point."""
    rtenant = getattr(resolver, "tenant", None)
    if resolver is None or rtenant is None or tenant_key(rtenant) != tenant_key(tenant):
        return SeriesCanon(entity_id, entity_tokens, ABSTAIN_CONFLICT, (("tenant", ABSTAIN_CONFLICT),))
    family = _ev_str(ev, "signal_family") if isinstance(ev, Mapping) else ""
    device = ev.get("device") if isinstance(ev, Mapping) else None
    if family not in _SERIES_FAMILIES or not isinstance(device, str) or not device:
        return SeriesCanon(entity_id, entity_tokens, UNCHANGED)
    part: str | None = None
    if family != "device_resource":
        if not (entity_id.startswith(device + ":") and len(entity_id) > len(device) + 1):
            return SeriesCanon(entity_id, entity_tokens, ABSTAIN_UNKNOWN, (("parse", ABSTAIN_UNKNOWN),))
        part = entity_id[len(device) + 1:]
    elif entity_id != device:
        return SeriesCanon(entity_id, entity_tokens, ABSTAIN_UNKNOWN, (("parse", ABSTAIN_UNKNOWN),))
    d = _device_axis(device, resolver)
    if d.outcome in (ABSTAIN_AMBIGUOUS, ABSTAIN_GENERIC, ABSTAIN_CONFLICT):
        return SeriesCanon(entity_id, entity_tokens, d.outcome, (("device", d.outcome),))
    axes: list[tuple[str, str]] = [("device", d.outcome)]
    basis = [d.basis] if d.basis else []
    swaps = {device: d.value}
    if part is None:
        new_id = d.value
    elif family == "interface":
        i = _metric_iface_axis(d.value, _ev_str(ev, "if_name"), _ev_str(ev, "index"), resolver,
                               _ev_str(ev, "vendor") or None)
        axes.append(("iface", i.outcome))
        basis += [i.basis] if i.basis else []
        new_id = f"{d.value}:{i.value}"
    else:
        p = _peer_axis(part, opaque_ok=(family == "igp"))
        axes.append(("peer", p.outcome))
        if p.basis:
            basis.append(p.basis)
            swaps[part] = p.value
        new_id = f"{d.value}:{p.value}"
    ax = tuple(axes)
    if new_id == entity_id:
        return SeriesCanon(entity_id, entity_tokens, _overall(ax), ax)
    if len(new_id) > MAX_ID_CHARS:
        return SeriesCanon(entity_id, entity_tokens, ABSTAIN_CONFLICT, (*ax, ("length", ABSTAIN_CONFLICT)))
    tokens = tuple(dict.fromkeys(swaps.get(t, t) for t in entity_tokens))
    joined = "+".join(basis)
    return SeriesCanon(new_id, tokens, REWRITTEN, ax, joined,
                       {CANON_ATTR: {"raw": entity_id, "basis": joined}})
