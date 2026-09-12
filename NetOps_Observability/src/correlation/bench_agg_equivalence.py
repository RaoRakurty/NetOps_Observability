# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""P3 step 3 — the flag-OFF vs flag-ON EQUIVALENCE harness, and its bench mode.

Authority: `docs/design/AGGREGATION_PLANE_P3_2026-08-29.md` §5 and §7 step 3;
owner memo `/var/tmp/Correlix-Bottleneck-Modified.md` §24 (a deliberately new
representation must be proven equivalent, not assumed) and §25 (the checks).

WHY A SUITE AND NOT A HASH
    The Aggregation plane changes WHAT THE ENGINE SEES: one delta signal stands
    for N raw observations of an `AggKey`. `content_hash` and the blob bytes of
    an object built from deltas therefore CANNOT equal those of an object built
    from raw repeats, and pinning byte identity would only pin the flag off
    forever. §5 replaces byte identity with a NAMED list of properties that must
    survive the representation change, and this module is that list, executable.

WHAT IS COMPARED, EXACTLY (the §25 semantics — stated here because a check
whose semantics are not stated proves nothing):

  objects        Objects are matched between the two legs by their NODE KEY SET
                 (`frozenset(n.key)`, i.e. entity_type:entity_id:kind). This is
                 the strictest defensible matcher: the plane may not change
                 which identities exist, so a matched pair is the SAME object
                 under two representations, and an UNMATCHED object is itself
                 the finding (it is a merge or a split, reported as such rather
                 than papered over by a fuzzy match).
  root cause     `ranking.top_hypothesis` equal on every matched pair.
  causal seam    the set of SEAM grounding refs on the object's edges, equal.
                 (Seam-level ownership is the product's RCA claim; an object
                 that changes which seam it blames has changed its answer.)
  owner          the `owner` of the TOP hypothesis, equal. Owner is what an RCA
                 routes to, so it is compared separately from the hypothesis id.
  blast radius   `affected()` compared BUCKET BY BUCKET AS SETS (order inside a
                 bucket is a rendering detail, membership is the claim). The
                 semantics: aggregation may not add or remove an affected
                 entity. It provably cannot — every `AggKey` emits at least a
                 FIRST delta, so every entity that produced any observation
                 still reaches the engine — and this measures that claim.
  raw coverage   THE §24 property, at the level where it is EXACT. Per leg we
                 compute the set of RAW signal ids the object set covers:
                   * flag OFF — the raw signals actually attached to objects;
                   * flag ON  — every raw signal whose `AggKey` is represented
                     by a delta attached to an object (the delta stands for all
                     of them; that is what "lossless" means here).
                 Requirement: OFF ⊆ ON — no raw observation may lose
                 object-level representation. An EXCESS (ON ⊋ OFF) is reported,
                 not failed: it means an aggregated object covers raw evidence
                 the un-aggregated run left unattached, which is a gain in
                 coverage and never a loss. Σ agg_count is deliberately NOT the
                 measure — see `engine.aggregation_block` for the arithmetic on
                 why summing cumulative snapshots double-counts.
  tenancy        No object in EITHER leg may hold signals of two tenants, and no
                 `AggKey` may be shared across tenants (§3a; the tenant is the
                 first component of the key and of the store).
  false merge    Two OFF objects whose signals land in ONE ON object. Where the
                 stream carries GROUND-TRUTH incident labels, additionally: one
                 ON object holding two labelled incidents that no OFF object
                 held together.
  false split    One OFF object whose signals spread over MORE THAN ONE ON
                 object; with labels, an incident covered by more ON objects
                 than OFF objects.
  replay         Every flag-ON object is round-tripped through the REAL archive
                 row builder (`main._archive_row` → `Signal.from_ch_row`) and
                 re-run through `replay.replay`. Clean is required: the
                 aggregation provenance must survive persistence and re-derive.

RUN IT
    python3 bench_agg_equivalence.py --agg-equivalence
"""
from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass, field
from dataclasses import replace as dc_replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

from aggregation import AGG_POLICY_VERSION, AggKey, AggPlane
from catalog import builtin_catalog
from engine import EngineConfig, ObjectSnapshot, SeamView, run_window
from signals import EntityType, ModalityClass, Severity, Signal

# The window horizon and lateness the harness runs the plane on. Fixtures span
# minutes, not hours, so these are chosen to make EXPIRY and EVICTION inert —
# an equivalence run must measure the representation change and nothing else.
# `main` injects the real `RETENTION_REQUIRED_S` / `CORR_PERMITTED_LATENESS_S`;
# both are parameters here for the same reason they are parameters there.
HARNESS_HORIZON_S = 24 * 3600.0
HARNESS_LATENESS_S = 300.0

CAT = builtin_catalog()
CFG = EngineConfig()
T0 = datetime(2026, 8, 29, 12, 0, 0, tzinfo=timezone.utc)


# ═══════════════════════════════════════════════════════════════════════════
# streams
# ═══════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class Stream:
    """One A/B fixture: the raw promoted signals, the seam inventory they
    ground against, and (where it exists) the ground truth.

    `labels` maps a raw `signal_id_str` to the incident it belongs to. Only the
    generated enterprise-chain stream has real labels; for every other fixture
    the flag-OFF object partition IS the ground truth for merge/split, which is
    the honest position — those fixtures assert engine behaviour, and what the
    plane must not do is change it.
    """

    name: str
    signals: tuple[Signal, ...]
    seams: tuple[SeamView, ...] = ()
    labels: dict[str, str] = field(default_factory=dict)
    note: str = ""


def _copy(sigs) -> tuple[Signal, ...]:
    """Independent copies with independent `attrs` dicts.

    NOT optional. `AggPlane.observe` stamps its annotation onto the `attrs` of
    the Signal it is handed (`Signal` is a frozen dataclass but `attrs` is a
    mutable dict), so a leg that shared signal objects with the other leg would
    hand the flag-OFF run pre-annotated evidence and quietly compare a stream
    with itself. `signal_id` is a uuid5 over `source|native_id|ts`, so a copy
    keeps the SAME id — which is what lets the two legs be cross-referenced.
    """
    return tuple(dc_replace(s, attrs=dict(s.attrs)) for s in sigs)


def _ordered(sigs) -> tuple[Signal, ...]:
    return tuple(sorted(sigs, key=lambda s: (s.ts, s.signal_id_str)))


# ── fixture 1: the golden-wire set ──────────────────────────────────────────

def golden_wire_streams(monkeypatch=None) -> list[Stream]:
    """Every `fixtures/golden_wire/*.json`, replayed through the REAL
    normalizers (`golden_wire.replay_fixture_through_engine` builds the same
    signal list the production ingest path builds) and handed here as a stream.

    These carry no repeats by construction — one wire event, one signal — which
    makes them the REGRESSION GUARD of the suite rather than its demonstration:
    with nothing to collapse, every delta is a FIRST and the two legs must agree
    on everything, byte-level blob difference included (an object whose signals
    all carry `agg_*` still gets an aggregation block, so the blob DOES move;
    what may not move is the answer).
    """
    from golden_wire import GOLDEN_DIR
    out: list[Stream] = []
    for path in sorted(Path(GOLDEN_DIR).glob("*.json")):
        stream = golden_wire_stream(path.name, monkeypatch)
        if stream is not None:
            out.append(stream)
    return out


def golden_wire_stream(fixture: str, monkeypatch=None) -> Stream | None:
    """One golden-wire fixture as a stream; None when it produces no signal.

    Split out from `golden_wire_streams` so the pytest wrapper can build ONE
    fixture inside a test that owns a `monkeypatch` — the fixtures' `env` block
    is real runtime config (`CORR_SAAS_HOST_MAP`), and setting it at module
    import would leak into every other test in the session.
    """
    from golden_wire import replay_fixture_through_engine
    signals, _snaps, _rank = replay_fixture_through_engine(fixture, monkeypatch)
    if not signals:
        return None
    return Stream(name=f"golden:{Path(fixture).stem}",
                  signals=_ordered(signals),
                  note="one wire event -> one signal; no repeats")


# ── fixture 2: tracker 166 (bounded cohorts) ────────────────────────────────

def stream_166() -> Stream:
    """The `test_bounded_cohort_166._window` shape: `devices x kinds` interface
    signals on one entity per device, alternating modality.

    Why it belongs here: 166 is the tracker that proved edge admission is
    PAIR-LOCAL — a pair's verdict may not depend on which other pairs were
    scored beside it. Aggregation removes pairs from the window, so if that
    locality were ever untrue this fixture is where it would show.
    """
    from test_engine import sig
    sigs = []
    for d in range(6):
        for k in range(5):
            sigs.append(sig(f"kind{k}", EntityType.INTERFACE, f"leaf{d}:Gi0/1",
                            observer=f"leaf{d}", offset_s=k * 10.0,
                            modality=(ModalityClass.CONTROL_PLANE if k % 2
                                      else ModalityClass.DEVICE_TELEMETRY)))
    return Stream(name="fx166:bounded-cohort", signals=_ordered(sigs),
                  note="6 devices x 5 kinds, pair-local admission")


# ── fixture 3: tracker 162 (continuation index / seam-bridged pairs) ────────

def stream_162() -> Stream:
    """The 162 blocker case plus its entity-indexable neighbours: the
    seam-bridged DX pair with ZERO shared entities (cloud half + network half)
    alongside containment components on ordinary devices.

    Why it belongs here: the seam-bridged pair is the one relationship that
    survives NO entity overlap, so it is the relationship most exposed to
    evidence being collapsed out from under it.
    """
    from test_engine import sig
    from test_seam_affinity_fold import DX_SEAM
    sigs = [
        # the network half of the DX seam
        sig("bgp_adjacency_change", EntityType.DEVICE, "edge-a1",
            offset_s=0.0, observer="dev1",
            modality=ModalityClass.CONTROL_PLANE, severity=Severity.CRIT),
        sig("probe_loss", EntityType.PATH, "vantage-1->edge-a1",
            offset_s=10.0, observer="probe1",
            modality=ModalityClass.ACTIVE_PROBE, severity=Severity.CRIT),
    ]
    for d in range(3):
        sigs.append(sig("device_cpu_high", EntityType.DEVICE, f"agg{d}",
                        offset_s=5.0 + d))
        sigs.append(sig("if_errors", EntityType.INTERFACE, f"agg{d}:Gi0/1",
                        offset_s=25.0 + d))
    return Stream(name="fx162:continuation-index", signals=_ordered(sigs),
                  seams=(DX_SEAM,),
                  note="seam-bridged zero-overlap pair + containment components")


# ── fixture 4: tracker 168 (device-local identity scope) ────────────────────

def stream_168() -> Stream:
    """The 168 reproduction, WITH repeats: the same interface name on two
    unrelated devices, each re-reporting its link-down several times inside one
    aggregation bucket.

    Why it belongs here: 168's rule is that accidental string equality is not a
    relationship. The AggKey contains `entity_id`, and `entity_id` is
    device-qualified, so two devices' `Gi0/5` must land in two different keys —
    if the plane ever keyed on the local name it would re-weld exactly the
    objects 168 split apart, and it would do it BEFORE the engine could refuse.
    """
    from producers import syslog_control_signal
    iface = "GigabitEthernet0/5"
    sigs = []
    for host in ("dc1-switch-a", "branch-77-rtr"):
        for rep in range(4):
            ts = T0 + timedelta(seconds=rep * 5.0)
            got = syslog_control_signal(
                {"hostname": host, "appname": "LINK-3-UPDOWN",
                 "message": (f"%LINK-3-UPDOWN: Interface {iface}, "
                             f"changed state to down"),
                 "severity": "err",
                 "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.000Z")},
                "acme", T0)
            if got is not None:
                # native_id is per-line, so the four repeats are four DISTINCT
                # signals with distinct ids — the window-dedup-by-signal_id that
                # already exists cannot collapse them. That is precisely the
                # population P3 exists to collapse.
                sigs.append(dc_replace(got, native_id=f"{got.native_id}|{rep}",
                                       ts=ts))
    return Stream(name="fx168:local-identity-scope", signals=_ordered(sigs),
                  note="same iface name on 2 devices, 4 repeats each")


# ── fixture 5: the storm fixture from bench_profile_p2 ──────────────────────

def stream_storm(signals: int = 1200, devices: int = 60) -> Stream:
    """`bench_profile_p2.make_signals` — the 2,500-device-SHAPED control-plane
    stream through the REAL producer, scaled down to a suite-sized window.

    This is the fixture with genuine density: bursty per device, several kinds
    per device, states alternating up/down — so it exercises FIRST,
    STATE_TRANSITION, RECOVERY and REPEAT together rather than one at a time.
    """
    from bench_profile_p2 import make_signals
    sigs = make_signals(signals, devices, t_end=T0 + timedelta(seconds=300),
                        span_s=300.0, tenant="global", burst=6)
    return Stream(name="storm:bench_profile_p2", signals=_ordered(sigs),
                  note=f"{len(sigs)} promoted signals over {devices} devices")


def stream_storm_repeats(signals: int = 900, devices: int = 60,
                         repeats: int = 3) -> Stream:
    """The same `bench_profile_p2` stream at a REALISTIC REPEAT SHARE.

    The plain storm fixture above collapses by 0 % — which is not a defect, it
    is the step-0 finding reproduced exactly (design §2 / §6b: the ratified
    `t-nominal` mix pins each device's state for life and gives each identity
    one vantage, so K3 has nothing to collapse). A regression guard that
    exercises no suppression cannot catch a suppression bug, so this rung
    re-reports each signal `repeats` times INSIDE its own 60 s bucket — the
    shape of §6b's 25 % rung, where aggregation is the dominant lever and
    therefore where a false merge would first appear.
    """
    from bench_profile_p2 import make_signals
    base = make_signals(signals, devices, t_end=T0 + timedelta(seconds=300),
                        span_s=300.0, tenant="global", burst=6)
    out: list[Signal] = []
    for sig in base:
        out.append(sig)
        for rep in range(1, max(1, repeats)):
            # +2 s per repeat: far inside the 60 s bucket, so the repeat shares
            # its original's AggKey (a repeat that crossed the bucket edge would
            # mint a new key and collapse nothing — see the module docstring).
            out.append(dc_replace(sig, ts=sig.ts + timedelta(seconds=2.0 * rep),
                                  native_id=f"{sig.native_id}|r{rep}"))
    return Stream(name=f"storm:repeats-x{repeats}", signals=_ordered(out),
                  note=f"{len(out)} signals, each identity re-reported {repeats}x")


# ── fixture 6: the enterprise-chain stream, WITH ground truth ───────────────

def stream_chain(sites: int = 4) -> Stream:
    """A small `scripts/enterprise_outage_chain`-derived stream with LABELS.

    Built from the chain module's own WIRE VOCABULARY (`link`, `lineproto`,
    `ospf_adj`, `bgp_adj`, `stp_port`, `mac_flap`) — the exact `(appname,
    message, severity)` triples the 2.5K harness puts on the bus — pushed
    through the REAL `producers.syslog_control_signal`. So the signals here are
    the signals the benchmark produces, not a re-imagining of them, and
    `RECOVERY_STATES` means the same thing on both sides.

    THE GROUND TRUTH is the site: every signal of site N is labelled `site-N`.
    A false merge is an object holding two sites; a false split is one site
    needing more objects under the flag than without it.

    TWO TENANTS, IDENTICAL DEVICE NAMES AND IDENTICAL MESSAGES. That is the
    sharpest possible §3a probe: every field of the AggKey except `tenant_id`
    collides, so a plane that dropped the tenant from the key would collapse
    the two tenants' evidence into one state and the check would see it
    immediately.

    Repeats are placed INSIDE one 60 s bucket on purpose — the K3 bucket is the
    key's last component, so a repeat that crossed the bucket edge would be a
    new key and would collapse nothing.
    """
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
    import enterprise_outage_chain as chain

    from producers import syslog_control_signal

    sigs: list[Signal] = []
    labels: dict[str, str] = {}

    def emit(tenant: str, host: str, line, at: float, label: str,
             tag: str) -> None:
        appname, message, severity = line
        ts = T0 + timedelta(seconds=at)
        got = syslog_control_signal(
            {"hostname": host, "appname": appname, "message": message,
             "severity": severity,
             "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"},
            tenant, T0)
        if got is None:          # not promoted (the chain has such lines)
            return
        # The harness's own uniqueness rule: one syslog LINE is one signal, so a
        # repeat must be a distinct native_id or the existing window dedup (by
        # signal_id) would collapse it before the plane ever sees it.
        got = dc_replace(got, native_id=f"{tenant}|{host}|{tag}|{at}", ts=ts)
        sigs.append(got)
        labels[got.signal_id_str] = f"{tenant}/{label}"

    for tenant in ("acme", "globex"):
        for site in range(sites):
            label = f"site-{site}"
            core, uplink = f"core-{site}", "GigabitEthernet0/1"
            peer = f"10.{site}.0.1"
            base = site * 5.0
            # phase 1 — the physical port, re-reported 5x inside one bucket
            for rep in range(5):
                emit(tenant, core, chain.link(uplink, "down"),
                     base + rep * 2.0, label, f"link-down-{rep}")
            emit(tenant, core, chain.lineproto(uplink, "down"),
                 base + 1.0, label, "lp-down")
            # phase 2 — the routing adjacency on the same port
            emit(tenant, core, chain.ospf_adj(peer, uplink, "down"),
                 base + 12.0, label, "ospf-down")
            # phase 3 — the BGP session
            emit(tenant, core, chain.bgp_adj(peer, "down"),
                 base + 16.0, label, "bgp-down")
            # phase 4 — L2 reconvergence on the access layer
            for acc in range(2):
                sw = f"acc-{site}-{acc}"
                emit(tenant, sw, chain.stp_port(f"GigabitEthernet0/{acc}", "down"),
                     base + 20.0 + acc, label, f"stp-{acc}")
                emit(tenant, sw, chain.mac_flap(chain.mac_address(site * 10 + acc),
                                                100 + site, "Gi0/1", "Gi0/2"),
                     base + 22.0 + acc, label, f"mac-{acc}")
            # recovery — half the sites come back inside the window
            if site % 2 == 0:
                emit(tenant, core, chain.link(uplink, "up"),
                     base + 40.0, label, "link-up")
                emit(tenant, core, chain.ospf_adj(peer, uplink, "up"),
                     base + 44.0, label, "ospf-up")
                emit(tenant, core, chain.bgp_adj(peer, "up"),
                     base + 46.0, label, "bgp-up")
    return Stream(name="chain:enterprise-outage", signals=_ordered(sigs),
                  labels=labels,
                  note=f"{sites} sites x 2 tenants, labelled; 5x link repeats")


def all_streams(monkeypatch=None) -> list[Stream]:
    """Every fixture the §5 equivalence suite runs on."""
    return [*golden_wire_streams(monkeypatch), stream_166(), stream_162(),
            stream_168(), stream_storm(), stream_storm_repeats(),
            stream_chain()]


# ═══════════════════════════════════════════════════════════════════════════
# the two legs
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class Leg:
    """One run of the engine over one stream, under one flag setting."""

    aggregated: bool
    window: tuple[Signal, ...]           # what the engine was actually given
    snaps: tuple[ObjectSnapshot, ...]
    plane: AggPlane | None = None


def run_leg(stream: Stream, *, aggregate: bool,
            horizon_s: float = HARNESS_HORIZON_S,
            lateness_s: float = HARNESS_LATENESS_S) -> Leg:
    """Run one leg. The ONLY difference between the two is the plane.

    THE SHAPE IS PRODUCTION'S, not a convenience: ONE plane sees the whole
    interleaved multi-tenant stream (that is the only arrangement in which a
    cross-tenant leak is even POSSIBLE, so it is the only one worth testing),
    and `run_window` — which refuses a multi-tenant window by contract — is then
    run once PER TENANT over that tenant's share. `main` does exactly this: one
    module-level `AGG_PLANE` at the ingest boundary, per-tenant engine windows.
    """
    sigs = _ordered(_copy(stream.signals))
    plane: AggPlane | None = None
    if aggregate:
        plane = AggPlane(horizon_s=horizon_s, lateness_s=lateness_s)
        window = tuple(s for s in (plane.observe(x) for x in sigs)
                       if s is not None)
    else:
        window = sigs
    by_tenant: dict[str, list[Signal]] = {}
    for s in window:
        by_tenant.setdefault(s.tenant_id, []).append(s)
    snaps: list[ObjectSnapshot] = []
    for tenant in sorted(by_tenant):
        snaps.extend(run_window(tuple(by_tenant[tenant]), CAT,
                                stream.seams, CFG))
    return Leg(aggregated=aggregate, window=window, snaps=tuple(snaps),
               plane=plane)


# ═══════════════════════════════════════════════════════════════════════════
# the comparison (memo §25)
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class Verdict:
    stream: str
    checks: dict[str, tuple[bool, str]] = field(default_factory=dict)
    metrics: dict[str, object] = field(default_factory=dict)

    def record(self, name: str, ok: bool, detail: str = "") -> None:
        self.checks[name] = (ok, detail)

    @property
    def ok(self) -> bool:
        return all(ok for ok, _ in self.checks.values())

    def failures(self) -> list[str]:
        return [f"{n}: {d or 'differs'}"
                for n, (ok, d) in sorted(self.checks.items()) if not ok]


def _nodekeys(snap: ObjectSnapshot) -> tuple[str, frozenset[str]]:
    """The object's match key across the two legs.

    TENANT-QUALIFIED, and that is not decoration: the chain fixture runs two
    tenants with IDENTICAL device names, so an un-qualified node-key set would
    make two different tenants' objects collide in the match map and hide the
    very leak the fixture exists to detect."""
    return (snap.tenant_id, frozenset(n.key for n in snap.nodes))


def _sids(snap: ObjectSnapshot) -> set[str]:
    return {s.signal_id_str for n in snap.nodes for s in n.signals}


def _seam_refs(snap: ObjectSnapshot) -> frozenset[str]:
    return frozenset(e.grounding.ref for e in snap.edges
                     if e.grounding.kind == "seam")


def _owner(snap: ObjectSnapshot) -> str:
    r = snap.ranking
    for h in r.hypotheses:
        if h.template_id == r.top_hypothesis:
            return str(h.owner)
    return ""


def _affected_sets(snap: ObjectSnapshot) -> dict[str, frozenset[str]]:
    return {k: frozenset(v) for k, v in snap.affected().items()}


def _tenants(snap: ObjectSnapshot) -> set[str]:
    return {s.tenant_id for n in snap.nodes for s in n.signals}


def _obj_index(snaps) -> dict[str, int]:
    """raw signal id -> index of the object holding it."""
    out: dict[str, int] = {}
    for i, snap in enumerate(snaps):
        for sid in _sids(snap):
            out[sid] = i
    return out


def _raw_coverage(stream: Stream, leg: Leg, bucket_s: int) -> set[str]:
    """The RAW signal ids this leg's object set covers — see the module
    docstring's `raw coverage` paragraph for why the two legs compute it
    differently and why that is the honest comparison."""
    if not leg.aggregated:
        return {sid for snap in leg.snaps for sid in _sids(snap)}
    covered_keys = {
        str(s.attrs.get("agg_key"))
        for snap in leg.snaps for n in snap.nodes for s in n.signals
        if isinstance(s.attrs, dict) and s.attrs.get("agg_key")}
    return {s.signal_id_str for s in stream.signals
            if AggKey.of(s, bucket_s).token() in covered_keys}


def compare(stream: Stream, *, bucket_s: int | None = None,
            do_replay: bool = True) -> Verdict:
    """Run both legs over `stream` and evaluate every §25 property."""
    off = run_leg(stream, aggregate=False)
    on = run_leg(stream, aggregate=True)
    plane = on.plane
    assert plane is not None
    bucket_s = plane.bucket_s if bucket_s is None else bucket_s
    v = Verdict(stream=stream.name)
    v.metrics.update({
        "signals": len(stream.signals),
        "deltas": len(on.window),
        "suppressed": plane.suppressed,
        "suppressed_ratio": round(plane.suppressed / max(1, plane.observed), 4),
        "objects_off": len(off.snaps),
        "objects_on": len(on.snaps),
        "policy": AGG_POLICY_VERSION,
        "classes": dict(sorted(plane.forwarded_by_class.items())),
        "state_transitions": plane.state_transitions,
        "recoveries": plane.recoveries,
    })

    # ── object matching by node-key set ─────────────────────────────────────
    off_by = {_nodekeys(s): s for s in off.snaps}
    on_by = {_nodekeys(s): s for s in on.snaps}
    matched = sorted(set(off_by) & set(on_by), key=lambda k: (k[0], sorted(k[1])))
    only_off = sorted(set(off_by) - set(on_by), key=lambda k: (k[0], sorted(k[1])))
    only_on = sorted(set(on_by) - set(off_by), key=lambda k: (k[0], sorted(k[1])))
    v.metrics["matched"] = len(matched)
    v.record("object_set", not only_off and not only_on,
             (f"{len(only_off)} object(s) only in the OFF leg, "
              f"{len(only_on)} only in the ON leg"
              if (only_off or only_on) else ""))

    # ── the four per-object answers ─────────────────────────────────────────
    for name, project in (("root_cause", lambda s: s.ranking.top_hypothesis),
                          ("verdict_tier", lambda s: s.ranking.verdict_tier.value),
                          ("causal_seam", _seam_refs),
                          ("owner", _owner),
                          ("blast_radius", _affected_sets)):
        bad = [k for k in matched if project(off_by[k]) != project(on_by[k])]
        v.record(name, not bad,
                 (f"{len(bad)} matched object(s) differ, e.g. "
                  f"{bad[0][0]}/{sorted(bad[0][1])[:2]}: {project(off_by[bad[0]])!r} vs "
                  f"{project(on_by[bad[0]])!r}") if bad else "")

    # ── Σ raw coverage ──────────────────────────────────────────────────────
    cov_off = _raw_coverage(stream, off, bucket_s)
    cov_on = _raw_coverage(stream, on, bucket_s)
    lost = cov_off - cov_on
    v.metrics["coverage_off"] = len(cov_off)
    v.metrics["coverage_on"] = len(cov_on)
    v.metrics["coverage_excess"] = len(cov_on - cov_off)
    # THE HONESTY LINE. `grounding_context.aggregation.raw_signal_count` is a
    # per-object LOWER BOUND on raw coverage (repeats after a key's last delta
    # are absorbed and never re-announced — see `engine.aggregation_block`).
    # Reporting it beside the exact key-level number keeps the gap VISIBLE
    # instead of letting a reader mistake the blob figure for the ledger.
    v.metrics["blob_raw_lower_bound"] = sum(
        int(snap.agg_provenance().get("raw_signal_count", 0))
        for snap in on.snaps)
    v.record("raw_coverage", not lost,
             f"{len(lost)} raw signal(s) lost object-level representation"
             if lost else "")

    # ── tenancy (§3a) ───────────────────────────────────────────────────────
    #
    # THREE separate claims, because they can fail independently:
    #   1. no object in either leg holds two tenants (the engine's own contract,
    #      re-asserted because the plane now sits upstream of it);
    #   2. every delta's `agg_key` is stamped with ITS OWN signal's tenant — the
    #      tenant is the key's first component, so this is the annotation-level
    #      statement of "a key cannot be read or written across tenants";
    #   3. no full key token is ever seen under two tenants.
    # What is DELIBERATELY NOT a failure: two tenants sharing a key SUFFIX. The
    # chain fixture is built so they always do (identical device names, identical
    # messages, identical minute), which is exactly what makes it a sharp probe —
    # the suffix collision count is recorded as a METRIC proving the fixture
    # exercises the risk, and the tenant prefix is what must keep them apart.
    mixed = [snap for leg in (off, on) for snap in leg.snaps
             if len(_tenants(snap)) > 1]
    mis_stamped = 0
    key_tenants: dict[str, set[str]] = {}
    suffix_tenants: dict[str, set[str]] = {}
    for snap in on.snaps:
        for n in snap.nodes:
            for sg in n.signals:
                token = sg.attrs.get("agg_key") if isinstance(sg.attrs, dict) else None
                if not token:
                    continue
                token = str(token)
                if token.split("|", 1)[0] != sg.tenant_id:
                    mis_stamped += 1
                key_tenants.setdefault(token, set()).add(sg.tenant_id)
                suffix_tenants.setdefault(
                    token.split("|", 1)[-1], set()).add(sg.tenant_id)
    shared = [k for k, t in key_tenants.items() if len(t) > 1]
    v.metrics["colliding_key_suffixes"] = sum(
        1 for t in suffix_tenants.values() if len(t) > 1)
    v.record("tenant_isolation", not mixed and not shared and not mis_stamped,
             (f"{len(mixed)} object(s) hold two tenants; "
              f"{mis_stamped} delta(s) stamped with another tenant's key; "
              f"{len(shared)} full AggKey(s) shared across tenants")
             if (mixed or shared or mis_stamped) else "")

    # ── false merge / false split ───────────────────────────────────────────
    off_of, on_of = _obj_index(off.snaps), _obj_index(on.snaps)
    merged: dict[int, set[int]] = {}
    split: dict[int, set[int]] = {}
    for sid, oi in on_of.items():
        fi = off_of.get(sid)
        if fi is None:
            continue
        merged.setdefault(oi, set()).add(fi)
        split.setdefault(fi, set()).add(oi)
    bad_merge = {i: v2 for i, v2 in merged.items() if len(v2) > 1}
    bad_split = {i: v2 for i, v2 in split.items() if len(v2) > 1}
    detail_merge = (f"{len(bad_merge)} ON object(s) absorb signals of "
                    f"{sorted(len(x) for x in bad_merge.values())} OFF objects"
                    if bad_merge else "")
    detail_split = (f"{len(bad_split)} OFF object(s) spread over "
                    f"{sorted(len(x) for x in bad_split.values())} ON objects"
                    if bad_split else "")

    # ...and the same two questions against GROUND TRUTH, where it exists.
    if stream.labels:
        def by_label(snaps):
            out: dict[str, set[int]] = {}
            for i, snap in enumerate(snaps):
                for sid in _sids(snap):
                    lab = stream.labels.get(sid)
                    if lab:
                        out.setdefault(lab, set()).add(i)
            return out
        off_lab, on_lab = by_label(off.snaps), by_label(on.snaps)

        def labels_per_object(snaps):
            out: dict[int, set[str]] = {}
            for i, snap in enumerate(snaps):
                for sid in _sids(snap):
                    lab = stream.labels.get(sid)
                    if lab:
                        out.setdefault(i, set()).add(lab)
            return out
        off_multi = {frozenset(v2) for v2 in labels_per_object(off.snaps).values()
                     if len(v2) > 1}
        on_multi = [v2 for v2 in labels_per_object(on.snaps).values()
                    if len(v2) > 1 and frozenset(v2) not in off_multi]
        if on_multi:
            detail_merge += (f"; ground truth: {len(on_multi)} ON object(s) hold "
                             f"2+ incidents, e.g. {sorted(on_multi[0])}")
            bad_merge[-1] = set()
        wider = {lab for lab, objs in on_lab.items()
                 if len(objs) > len(off_lab.get(lab, ()))}
        if wider:
            detail_split += (f"; ground truth: {len(wider)} incident(s) spread "
                             f"over more objects, e.g. {min(wider)}")
            bad_split[-1] = set()
        v.metrics["incidents"] = len(off_lab)

    v.record("no_false_merge", not bad_merge, detail_merge)
    v.record("no_false_split", not bad_split, detail_split)

    # ── replay with the flag ON ─────────────────────────────────────────────
    if do_replay:
        drift = replay_findings(on.snaps)
        v.record("replay_clean", not drift,
                 f"{len(drift)} object(s) drifted: {drift[0]}" if drift else "")
        v.metrics["replayed"] = len(on.snaps)
    return v


def replay_findings(snaps) -> list[str]:
    """Round-trip every snapshot through the REAL archive row builder and
    `replay.replay`; return one string per object that drifted.

    `main._archive_row` (not a hand-rolled dict) on purpose: the claim under
    test is that the aggregation annotations survive THE PRODUCTION ARCHIVE
    PATH, and the only way to test that claim is to run it.
    """
    import main
    from replay import StoredObject, replay
    out: list[str] = []
    for snap in snaps:
        rows = [main._archive_row(s, snap.correlation_id, 1, cache=False)
                for n in snap.nodes for s in n.signals]
        window = [Signal.from_ch_row(r) for r in rows]
        stored = StoredObject.from_rows(snap.to_object_row(1),
                                        snap.to_edge_rows(1))
        report = replay(stored, window)
        if not report.clean:
            out.append(f"{snap.correlation_id}: {report.differences}")
    return out


# ═══════════════════════════════════════════════════════════════════════════
# the §25 table
# ═══════════════════════════════════════════════════════════════════════════

_COLS = ("object_set", "root_cause", "verdict_tier", "causal_seam", "owner",
         "blast_radius", "raw_coverage", "tenant_isolation", "no_false_merge",
         "no_false_split", "replay_clean")


def print_table(verdicts: list[Verdict]) -> None:
    name_w = max([len(v.stream) for v in verdicts] + [8])
    head = (f"{'fixture':<{name_w}}  {'sigs':>6} {'delta':>6} {'supp%':>6} "
            f"{'objOFF':>6} {'objON':>6}  " + " ".join(f"{c[:9]:>9}" for c in _COLS))
    print(head)
    print("-" * len(head))
    for v in verdicts:
        m = v.metrics
        cells = []
        for c in _COLS:
            ok, _ = v.checks.get(c, (True, ""))
            cells.append(f"{'ok' if ok else 'FAIL':>9}")
        print(f"{v.stream:<{name_w}}  {m.get('signals', 0):>6} "
              f"{m.get('deltas', 0):>6} "
              f"{100.0 * float(m.get('suppressed_ratio', 0.0)):>5.1f}% "
              f"{m.get('objects_off', 0):>6} {m.get('objects_on', 0):>6}  "
              + " ".join(cells))
    print()
    for v in verdicts:
        if not v.ok:
            print(f"{v.stream}:")
            for line in v.failures():
                print(f"    {line}")
    print()
    print(f"policy={AGG_POLICY_VERSION}  "
          f"fixtures={len(verdicts)}  "
          f"failing={sum(1 for v in verdicts if not v.ok)}")
    for v in verdicts:
        print(f"  {v.stream}: {v.metrics}")


def main_cli() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--agg-equivalence", action="store_true", default=True,
                    help="run the §25 equivalence table (the only mode today)")
    ap.add_argument("--fixture", default="",
                    help="substring filter over fixture names")
    ap.add_argument("--no-replay", dest="replay", action="store_false",
                    default=True, help="skip the archive round-trip check")
    args = ap.parse_args()
    streams = [s for s in all_streams()
               if not args.fixture or args.fixture in s.name]
    if not streams:
        print("no fixture matched", file=sys.stderr)
        return 2
    verdicts = [compare(s, do_replay=args.replay) for s in streams]
    print_table(verdicts)
    return 0 if all(v.ok for v in verdicts) else 1


if __name__ == "__main__":
    raise SystemExit(main_cli())
