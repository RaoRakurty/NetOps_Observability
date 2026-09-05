"""Digital Experience Monitoring — integration fixtures for the owner's Phase O
acceptance scenarios B, E, F and H.

The DEM design of record (`docs/design/DEM_2026-09-05.md` §M.10, owner scenario
list in `docs/design/research/DEM_OWNER_DESIGN_2026-09-05.md`) asks for
integration fixtures proving that a digital-experience diagnosis is only ever as
strong as the evidence behind it:

  * **B** — network degradation while the backend stays healthy: the diagnosis
    must land on the network/path family, and it may confirm because a synthetic
    vantage and a device control plane are genuinely independent witnesses.
  * **E** — a cloud security-policy change immediately before the failure: the
    change record RAISES the policy hypothesis but may never confirm it on its
    own, because a change is a record of intent, not a measurement of impact.
  * **F** — a flaky synthetic with nothing else: one modality, one observer, so
    the honest answer is `suspected`, never `confirmed`.
  * **H** — the DNS/trace lane is dark: real multi-source evidence exists, so the
    verdict is not `undetermined`, but no single signature binds both sources, so
    it is not `confirmed` either.

These tests exist to pin the ENGINE'S ACTUAL BEHAVIOUR, not the design's
expectation of it, and where the two differ the difference is written down here
in full rather than assumed away. Two such differences are load-bearing:

  1. **The published tier is the top hypothesis's gate, not the object's total
     evidence.** `scoring.rank` computes the verdict from the signals that
     SATISFIED THE WINNING TEMPLATE'S CLAUSES (`scoring.py` line ~351), so an
     object can hold two independent modalities and still publish `suspected`
     when the winning signature only matched one of them. That is the mechanism
     behind scenario H, and it is why scenario B has to reach `confirmed`
     through a signature that names BOTH the network fault and the app symptom.
  2. **`run_window` adds a grounding gate that `rank` does not have.** Contract
     §3/§4: an object held together only by shared tokens (rank-7 candidate
     edges) is capped at `suspected` even when the verdict gate confirmed —
     "a shared name is a coincidence detector, not a relationship". Only an
     OBSERVED relation (here: a shared structural identity between the tunnel's
     path id and the app endpoint) lets the object publish `confirmed`.

No catalog template is added or changed by this module; every assertion is made
against templates that already ship.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import verdicts
from catalog import builtin_catalog
from engine import run_window
from scoring import CONFIDENCE_FLOOR, rank, score_template
from signals import (
    EntityType,
    ModalityClass,
    Observer,
    ObserverType,
    Severity,
    Signal,
    Source,
)
from synthetic_normalize import synthetic_app_signal
from verdicts import VerdictTier

T0 = datetime(2026, 9, 5, 14, 0, 0, tzinfo=timezone.utc)
CAT = builtin_catalog()

APP_EXPERIENCE = "sig.ent.app.saas-experience-degraded"
TUNNEL_MTU_BLACKHOLE = "sig.ent.wan-edge.tunnel-mtu-blackhole"
SG_NACL_BLOCK = "sig.ent.cloud.sg-nacl-block"
EDGE_DNS_FAILURE = "sig.ent.app.edge-dns-failure"

# The monitored subject is an internal portal rather than a mapped SaaS host, so
# `synthetic_normalize.resolve_app` falls back to the hostname. That fallback is
# what makes the app entity share a STRUCTURAL identity ref with a path named by
# its endpoints — the join scenario B needs (see the module docstring, point 2).
PORTAL = "portal.acme.example"

_seq = 0


# ── wire-shaped builders (the netops.probes / signal shapes, not hand-made objects) ──

def portal_probe_event(
    *, ok: bool = False, fail_class: str | None = None, status_code: int | None = None,
    prober: str = "syn-frisco", offset_s: float = 0.0, total_ms: float | None = None,
) -> dict:
    """One raw synthetic HTTPS ProbeEvent as `collectors/synthetics.go` puts it on
    `netops.probes`. Built as a wire dict — never as a Signal — so the test drives
    the same normalization path production does."""
    ev: dict = {
        "kind": "http", "ok": ok, "prober": prober, "site_id": "frisco",
        "target": f"https://{PORTAL}",
        "ts": (T0 + timedelta(seconds=offset_s)).isoformat(),
    }
    if fail_class:
        ev["fail_class"] = fail_class
    if status_code is not None:
        ev["status_code"] = status_code
    if total_ms is not None:
        ev["total_ms"] = total_ms
    return ev


def synthetic(monkeypatch, ev: dict) -> Signal:
    """Normalize a probe event into the semantic app-experience Signal AND run it
    through `main.classify_probe`, exactly as the ingest path does.

    The vantage is registered in the trust registry here because the normalizer
    deliberately stamps no authority of its own (truthfulness epic, Phase 0
    finding A4): a DEM prober earns confirm capability from the registry, never
    by default. Without this the probe would classify LOW and could not anchor a
    confirming pair — which would make scenario B pass for the wrong reason."""
    import main

    monkeypatch.setattr(main, "_INTERNAL_PROBE_TARGETS", set())
    monkeypatch.setattr(main, "_MEASUREMENT_PROBE_OBSERVERS", {str(ev["prober"])})
    monkeypatch.setattr(main, "_TRUSTED_PROBE_OBSERVERS", {str(ev["prober"])})
    sig = synthetic_app_signal(ev, "acme", T0)
    assert sig is not None, "a failing synthetic must produce a semantic app signal"
    main.classify_probe(ev, sig)
    return sig


def other_signal(
    kind: str, modality: ModalityClass, observer_id: str, observer_type: ObserverType,
    entity_type: EntityType, entity_id: str, *, source: Source, offset_s: float = 0.0,
    deviation: float = 3.0, collection_path: str = "direct",
    tokens: tuple[str, ...] = (), severity: Severity = Severity.HIGH,
) -> Signal:
    """A non-synthetic witness (device control plane, cloud API, flow exporter).
    Deliberately generic: the DEM lane must correlate against the evidence the
    platform already produces, not against a DEM-only signal shape."""
    global _seq
    _seq += 1
    return Signal(
        tenant_id="acme",
        ts=T0 + timedelta(seconds=offset_s),
        source=source,
        kind=kind,
        observer=Observer(observer_id=observer_id, observer_type=observer_type,
                          collection_path=collection_path),
        modality_class=modality,
        entity_type=entity_type,
        entity_id=entity_id,
        severity=severity,
        native_id=f"dem|{_seq}|{kind}",
        deviation=deviation,
        entity_tokens=tokens,
    )


def wan_tunnel_degraded(*, entity_id: str, offset_s: float = -20.0,
                        tokens: tuple[str, ...] = ()) -> Signal:
    """The branch edge's own control plane reporting its overlay tunnel degraded.
    A DIFFERENT modality class (control_plane) reported by a DIFFERENT observer
    (the device's syslog) than the synthetic vantage — the two-witness shape the
    independence rule demands."""
    return other_signal(
        "tunnel_degraded", ModalityClass.CONTROL_PLANE, "syslog-frisco-edge",
        ObserverType.DEVICE, EntityType.PATH, entity_id, source=Source.SYSLOG,
        offset_s=offset_s, deviation=3.0, tokens=tokens)


def cloud_security_policy_change(*, offset_s: float = -60.0) -> Signal:
    """A CloudTrail-shaped security-group edit landing shortly BEFORE the failure.
    control_plane over `via_cloud_api`: the provider API is the effective witness,
    so it is a measurement AUTHORITY, not mere transport (verdicts.py)."""
    return other_signal(
        "cloud_audit", ModalityClass.CONTROL_PLANE, "cloud:1234:us-east-1",
        ObserverType.CLOUD_API, EntityType.CLOUD_RESOURCE, "sg-portal-egress",
        source=Source.CLOUD, offset_s=offset_s, deviation=0.0,
        collection_path="via_cloud_api",
        tokens=(PORTAL, f"host:{PORTAL}"), severity=Severity.WARN)


def cloud_app_health(*, offset_s: float = 20.0) -> Signal:
    """The provider's own health view of the application — device_telemetry from
    the cloud API, i.e. a second measurement plane and a second observer."""
    return other_signal(
        "cloud_health", ModalityClass.DEVICE_TELEMETRY, "cloud:1234:us-east-1",
        ObserverType.CLOUD_API, EntityType.APP, PORTAL, source=Source.CLOUD,
        offset_s=offset_s, deviation=4.0, collection_path="via_cloud_api",
        tokens=(PORTAL, f"host:{PORTAL}"))


def _by_id(result, template_id: str):
    return next((h for h in result.hypotheses if h.template_id == template_id), None)


# ── B — network degradation while the backend stays healthy ───────────────────

def test_b_network_degradation_confirms_and_blames_the_path_not_the_app(monkeypatch):
    """The site's overlay tunnel toward the portal is degraded and the synthetic
    from that site fails; nothing anywhere reports the backend unwell.

    The verdict is CONFIRMED because the two witnesses are genuinely independent:
    a vantage agent measuring from the outside (active_probe) and the branch
    edge's own control plane (control_plane) are different modality classes with
    different observers and no shared measurement authority, which is exactly the
    pair `verdicts.assess` demands. The ranked outcome is the WAN-edge signature
    rather than the application one because `sig.ent.wan-edge.tunnel-mtu-blackhole`
    matches two clauses — the tunnel fault AND the app symptom — while the
    app-experience signature matches only the symptom; at equal confidence the
    scorer prefers the explanation that accounts for more of the evidence."""
    syn = synthetic(monkeypatch, portal_probe_event())
    tun = wan_tunnel_degraded(entity_id="frisco-edge->" + PORTAL)

    res = rank(CAT, [tun, syn])
    assert res.top_hypothesis == TUNNEL_MTU_BLACKHOLE
    assert res.verdict_tier is VerdictTier.CONFIRMED
    top = _by_id(res, TUNNEL_MTU_BLACKHOLE)
    assert top is not None and top.owner == "netops"
    assert any("independent confirming pair" in r for r in top.verdict_gate.reasons)

    # "The backend stays healthy" is expressed by ABSENCE: no lb/app/cloud
    # telemetry ever entered the window. The catalogue has no "backend is well"
    # predicate, so the honest assertion is the one the design's fallback names —
    # no application-tier hypothesis owns the outcome. The app-experience
    # signature is still scored and still visible (it is a real competing
    # explanation, and hiding it would be the black-box behaviour the catalog
    # exists to avoid), but it cannot confirm on its own single modality.
    assert not res.top_hypothesis.startswith("sig.ent.app.")
    app = _by_id(res, APP_EXPERIENCE)
    assert app is not None and app.verdict_gate.tier is VerdictTier.SUSPECTED
    assert not any(
        h.template_id.startswith("sig.ent.app.")
        and h.verdict_gate.tier is VerdictTier.CONFIRMED
        and h.confidence_rank >= CONFIDENCE_FLOOR
        for h in res.hypotheses
    ), "a backend-healthy world must not confirm any application-tier hypothesis"

    # End to end through the engine: both signals fold into ONE object (the
    # tunnel's path id names the app endpoint, so they share a structural
    # identity ref — an OBSERVED relationship, not a shared free-text token) and
    # that object publishes the confirmed network verdict naming the app.
    snaps = run_window((tun, syn), CAT, ())
    assert len(snaps) == 1
    snap = snaps[0]
    assert snap.ranking.top_hypothesis == TUNNEL_MTU_BLACKHOLE
    assert snap.ranking.verdict_tier is VerdictTier.CONFIRMED
    assert any(e.grounding.authoritative for e in snap.edges)
    assert PORTAL in snap.affected().get("services", [])


def test_b_token_only_colocation_is_capped_to_suspected(monkeypatch):
    """The same two witnesses, but the tunnel is named the way an SD-WAN edge
    usually names it (`frisco-edge-tun1`) so the only thing joining it to the app
    is a shared free-text token.

    `rank` still confirms — the evidence independence is unchanged — but
    `run_window` DOWNGRADES the published object to `suspected` under contract
    §3/§4: a shared name is a coincidence detector, not a relationship, and an
    object standing on rank-7 candidate edges alone has no observed relation to
    confirm. This is a real gate the DEM design does not mention, and it is the
    reason scenario B above has to give the path a structural identity: a DEM
    incident confirms only when the topology actually says the network fault is
    on the app's path."""
    syn = synthetic(monkeypatch, portal_probe_event())
    tun = wan_tunnel_degraded(entity_id="frisco-edge-tun1",
                              tokens=(PORTAL, f"host:{PORTAL}", "site:frisco"))

    assert rank(CAT, [tun, syn]).verdict_tier is VerdictTier.CONFIRMED

    snaps = run_window((tun, syn), CAT, ())
    assert len(snaps) == 1
    snap = snaps[0]
    assert snap.ranking.top_hypothesis == TUNNEL_MTU_BLACKHOLE
    assert snap.ranking.verdict_tier is VerdictTier.SUSPECTED
    assert not any(e.grounding.authoritative for e in snap.edges)
    assert any("no authoritative edge" in m for m in snap.ranking.evidence_missing)


# ── E — a cloud security-policy change immediately before the failure ─────────

def test_e_change_record_raises_the_policy_hypothesis_but_cannot_confirm(monkeypatch):
    """A security-group edit lands sixty seconds before the synthetic to the
    portal starts failing.

    The change RAISES the policy hypothesis in two measurable ways: without it
    `sig.ent.cloud.sg-nacl-block` scores 0.50 and does not even make the visible
    top-K, and with it the change satisfies the signature's supporting clause,
    lifting it to 0.55 and into second place.

    It nonetheless stays SUSPECTED, and the gate says precisely why: the
    signature demands a passive_flow witness — a flow-log REJECT on the failing
    5-tuple — and no such witness exists. A change record proves that policy was
    edited; it does not prove that the edit is what is dropping the traffic, so
    it can never be the thing that confirms. Note what the change record DOES
    buy: the single-modality and single-observer complaints disappear from the
    gate's reasons, because a cloud control plane and a synthetic vantage really
    are two independent witnesses. What is left is purely the missing
    measurement of the failure itself."""
    syn = synthetic(monkeypatch, portal_probe_event())
    chg = cloud_security_policy_change()

    before = rank(CAT, [syn])
    assert _by_id(before, SG_NACL_BLOCK) is None, (
        "without a change record the policy hypothesis is not among the ranked "
        "explanations at all")
    # Scored directly, because `rank` only publishes the visible top-K and the
    # claim being made is about the SCORE moving, not about visibility alone.
    policy_template = next(t for t in CAT.enabled_templates() if t.id == SG_NACL_BLOCK)
    assert score_template(policy_template, (syn,)).confidence_rank == 0.50

    after = rank(CAT, [chg, syn])
    policy = _by_id(after, SG_NACL_BLOCK)
    assert policy is not None
    assert policy.supporting_hit is True
    assert policy.confidence_rank == 0.55
    assert policy.verdict_gate.tier is VerdictTier.SUSPECTED
    assert policy.verdict_gate.reasons == (
        "required modality missing (no trusted witness): passive_flow",
    )
    assert "cloud_flow_reject|policy_diff_block" in policy.missing

    # The object as a whole is still the app-experience story, still suspected:
    # only one modality actually MEASURED the failure, and precedence in time is
    # not evidence of causation.
    assert after.top_hypothesis == APP_EXPERIENCE
    assert after.verdict_tier is VerdictTier.SUSPECTED
    snaps = run_window((chg, syn), CAT, ())
    assert len(snaps) == 1
    assert snaps[0].ranking.verdict_tier is VerdictTier.SUSPECTED
    assert "sg-portal-egress" in snaps[0].affected().get("cloud_resources", [])


# ── F — a flaky synthetic while everything else is healthy ───────────────────

def test_f_lone_flaky_synthetic_is_suspected_never_confirmed(monkeypatch):
    """One vantage fails one check and nothing else in the estate agrees.

    This is the case the verdict gate exists for. `assess` reports SUSPECTED with
    both mechanical complaints — one modality class and one observer — because
    every modality has a blind spot and a single vantage cannot distinguish "the
    application is down" from "my own egress is broken". Confirming here would be
    exactly the false P1 the DEM design forbids."""
    syn = synthetic(monkeypatch, portal_probe_event(fail_class="timeout"))

    verdict = verdicts.assess([syn])
    assert verdict.tier is VerdictTier.SUSPECTED
    assert verdict.reasons == (
        "single modality class (active_probe); need ≥2 — every modality has a blind spot",
        "single observer (syn-frisco); need ≥2",
    )
    cov = verdicts.coverage([syn])
    assert cov.modality_count == 1 and cov.observer_count == 1
    assert cov.independent_pair is None
    # The probe IS trusted — the point is not that we distrust the vantage, it is
    # that one trusted vantage is still one vantage.
    assert cov.trusted_modalities == frozenset({ModalityClass.ACTIVE_PROBE})

    res = rank(CAT, [syn])
    assert res.top_hypothesis == APP_EXPERIENCE
    assert res.verdict_tier is VerdictTier.SUSPECTED

    # Re-running the flaky check does not accumulate into confirmation: a second
    # failure from the SAME vantage is the same witness twice, and the gate
    # counts witnesses, not samples.
    again = synthetic(monkeypatch, portal_probe_event(fail_class="timeout", offset_s=120))
    repeated = verdicts.coverage([syn, again])
    assert repeated.observer_count == 1 and repeated.modality_count == 1
    assert verdicts.assess([syn, again]).tier is VerdictTier.SUSPECTED

    # And "everything else is healthy" is not a signal at all: a passing check
    # emits nothing, so a recovered probe cannot dilute or contradict — it simply
    # stops feeding the incident (synthetic_normalize's anti-noise stance).
    assert synthetic_app_signal(
        portal_probe_event(ok=True, status_code=200, total_ms=42.0, offset_s=180),
        "acme", T0) is None


# ── H — missing DNS/trace data, multi-source evidence, suspected diagnosis ────

def test_h_dark_dns_lane_yields_suspected_not_confirmed_and_not_undetermined(monkeypatch):
    """The synthetic vantage sees the portal failing and the provider's own API
    reports the application unhealthy — two real sources, two independent
    observers, two modality classes — but the DNS lane that would say WHERE it
    breaks never delivered.

    Assessed as a raw evidence set this window CONFIRMS: `verdicts.assess` finds
    the independent cross-modality pair. The published verdict is nonetheless
    SUSPECTED, and the mechanism is the one named at the top of this module — the
    tier comes from the WINNING signature's own matched evidence. The signature
    that would bind both witnesses, `sig.ent.app.edge-dns-failure`, is missing its
    `cloud_dns_log` clause (that is the dark lane), so it only reaches 0.55; the
    signature that wins at 1.0 matched the synthetic alone and therefore sees one
    modality. Absence of a source does not fabricate certainty — and it does not
    fabricate ignorance either: the tier is not UNDETERMINED, because real
    evidence from two sources is present and the object names what is missing."""
    syn = synthetic(monkeypatch, portal_probe_event())
    health = cloud_app_health()

    raw = verdicts.assess([syn, health])
    assert raw.tier is VerdictTier.CONFIRMED, (
        "premise: the raw evidence set really does clear the independence rule, "
        "so a SUSPECTED published tier is a signature-coverage decision and not "
        "an evidence shortage")

    res = rank(CAT, [syn, health])
    assert res.verdict_tier is VerdictTier.SUSPECTED
    # Not UNDETERMINED, and provably so rather than by restating the line above:
    # `rank` returns UNDETERMINED only when the best explanation falls under the
    # confidence floor, and this window's best explanation is well clear of it.
    top = _by_id(res, res.top_hypothesis)
    assert top is not None and top.confidence_rank >= CONFIDENCE_FLOOR
    # Deterministic tie-break: two signatures score 1.0 with one matched clause
    # each, so `rank` falls through to template id (scoring.py sort key) and
    # `sig.ent.app.…` sorts before `sig.ent.cloud.…`.
    assert res.top_hypothesis == APP_EXPERIENCE

    # The dark lane is DECLARED, never papered over: the signature that needs the
    # DNS evidence still appears, still says what it is missing, and its own gate
    # confirmed — a reader can see that the only thing between this object and a
    # confirmed DNS attribution is a source that did not report.
    dns = _by_id(res, EDGE_DNS_FAILURE)
    assert dns is not None
    assert dns.missing == ("cloud_dns_log",)
    assert dns.verdict_gate.tier is VerdictTier.CONFIRMED
    assert dns.confidence_rank < 1.0

    # The object carries the gate's shortfall as a machine-readable checklist —
    # "what would confirm", derived from the data rather than from boilerplate.
    assert any("single modality class (active_probe)" in m
               for m in res.evidence_missing)

    snaps = run_window((syn, health), CAT, ())
    assert len(snaps) == 1
    assert snaps[0].ranking.verdict_tier is VerdictTier.SUSPECTED
