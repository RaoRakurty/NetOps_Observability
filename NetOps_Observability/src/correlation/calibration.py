"""Replay-driven calibration harness (C9 / design P4).

The engine's constants (`EngineConfig`: tau, thresholds, weights) ship as deterministic
DEFAULTS. P4 calls for RE-FITTING them against LABELED incidents instead of tuning them
by feel. This module is that harness: given a set of labeled incidents (a window + the
outcome it SHOULD produce) and a grid of candidate constant values, it replays the pure
engine over every incident under every candidate config, scores the outcomes, and ranks
the configs — best first, deterministically.

It is the MECHANISM, not the fit: the actual re-fit needs a corpus of labeled incidents
(accumulated from end-to-end testing / real RCA outcomes), which is owner-supplied. With
the single golden fixture it already demonstrates the loop and guards against regressions.

Replay-honest by construction: a chosen re-fit config has a DIFFERENT `config_hash` →
a different `engine_version`, so replay of objects scored under the old config reports a
pin mismatch (expected evolution, never a silent substitution — replay.py contract).

Pure + deterministic: no I/O, no clock; the caller supplies the labeled corpus.
"""
from __future__ import annotations

import dataclasses
import itertools
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from catalog import Catalog, builtin_catalog
from engine import (
    EngineConfig, ObjectSnapshot, SeamView, TopologyAdjacency, engine_version, run_window,
)
from signals import (
    EntityType, ModalityClass, Observer, ObserverType, Severity, Signal, Source,
)

# A label of "" means "no correlation object should form" — the negative case that keeps
# calibration honest (maximizing recall alone would over-correlate; precision needs these).
NO_OBJECT = ""


@dataclass(frozen=True)
class LabeledIncident:
    """One window with the outcome a correct engine should produce. `expected_hypothesis`
    is the template_id the top hypothesis must equal (or 'undetermined', or NO_OBJECT to
    assert NOTHING correlates). `expected_verdict` is checked only when non-empty."""

    name: str
    window: tuple[Signal, ...]
    seams: tuple[SeamView, ...] = ()
    adjacency: TopologyAdjacency = TopologyAdjacency()
    expected_hypothesis: str = NO_OBJECT
    expected_verdict: str = ""


@dataclass(frozen=True)
class IncidentScore:
    name: str
    correct: bool          # hypothesis AND (verdict, if checked) both match
    hypothesis_ok: bool
    verdict_ok: bool
    got_hypothesis: str    # "" when no object formed
    got_verdict: str


@dataclass
class CalibrationResult:
    overrides: dict        # the constants this candidate changed from the base
    config: EngineConfig
    config_hash: str
    engine_version: str
    score: float           # mean correctness over the labeled corpus (0..1)
    hypothesis_acc: float
    verdict_acc: float
    scores: list[IncidentScore] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "overrides": self.overrides,
            "config_hash": self.config_hash,
            "engine_version": self.engine_version,
            "score": round(self.score, 4),
            "hypothesis_acc": round(self.hypothesis_acc, 4),
            "verdict_acc": round(self.verdict_acc, 4),
        }


def _primary(snapshots: list[ObjectSnapshot]) -> ObjectSnapshot | None:
    """The object a labeled window is 'about' — the largest by evidence, tie-broken by
    confidence then id (deterministic). None when the window correlated nothing."""
    if not snapshots:
        return None
    return max(snapshots, key=lambda s: (s.signal_count(), s.top_confidence(), s.correlation_id))


def score_incident(cfg: EngineConfig, inc: LabeledIncident, catalog: Catalog) -> IncidentScore:
    snaps = run_window(inc.window, catalog, inc.seams, cfg, adjacency=inc.adjacency)
    prim = _primary(snaps)
    got_hyp = prim.ranking.top_hypothesis if prim else NO_OBJECT
    got_verdict = prim.ranking.verdict_tier.value if prim else ""

    if inc.expected_hypothesis == NO_OBJECT:
        hyp_ok = prim is None                      # nothing should have correlated
    else:
        hyp_ok = prim is not None and got_hyp == inc.expected_hypothesis
    verdict_ok = (not inc.expected_verdict) or got_verdict == inc.expected_verdict
    return IncidentScore(inc.name, hyp_ok and verdict_ok, hyp_ok, verdict_ok, got_hyp, got_verdict)


def evaluate(cfg: EngineConfig, labeled: list[LabeledIncident],
             catalog: Catalog | None = None) -> CalibrationResult:
    """Score one config over the labeled corpus."""
    catalog = catalog or builtin_catalog()
    scores = [score_incident(cfg, inc, catalog) for inc in labeled]
    n = max(len(scores), 1)
    return CalibrationResult(
        overrides={}, config=cfg, config_hash=cfg.config_hash(), engine_version=engine_version(cfg),
        score=sum(s.correct for s in scores) / n,
        hypothesis_acc=sum(s.hypothesis_ok for s in scores) / n,
        verdict_acc=sum(s.verdict_ok for s in scores) / n,
        scores=scores,
    )


def grid_search(labeled: list[LabeledIncident], grid: dict[str, list],
                base_cfg: EngineConfig | None = None,
                catalog: Catalog | None = None) -> list[CalibrationResult]:
    """Replay the corpus under every combination of `grid` constant overrides and return
    the candidates ranked best-first (highest score; ties broken by FEWEST changes from
    the base, then config_hash — so the smallest config that fits a tie wins, deterministic).
    An empty grid evaluates just the base config."""
    base_cfg = base_cfg or EngineConfig()
    catalog = catalog or builtin_catalog()
    keys = sorted(grid)
    combos = list(itertools.product(*(grid[k] for k in keys))) or [()]
    results: list[CalibrationResult] = []
    for combo in combos:
        overrides = {k: v for k, v in zip(keys, combo)
                     if v != getattr(base_cfg, k)}  # only real changes from the base
        cfg = dataclasses.replace(base_cfg, **dict(zip(keys, combo)))
        res = evaluate(cfg, labeled, catalog)
        res.overrides = overrides
        results.append(res)
    results.sort(key=lambda r: (-r.score, len(r.overrides), r.config_hash))
    return results


def best_config(labeled: list[LabeledIncident], grid: dict[str, list],
                base_cfg: EngineConfig | None = None,
                catalog: Catalog | None = None) -> CalibrationResult:
    """The top-ranked candidate — the re-fit the owner would adopt (its config_hash is the
    new pin). Falls back to the base config's score when the grid is empty."""
    return grid_search(labeled, grid, base_cfg, catalog)[0]


# ── labeled-corpus loading (the owner-supplied fit data) ──────────────────────────
#
# A corpus is JSON: {"incidents": [{name, expected_hypothesis, expected_verdict?, seams?,
# adjacency?, signals: [<spec>]}]}. Each signal <spec> uses the SAME shape as the golden
# replay fixture (kind/entity_type/entity_id/observer_id/modality/severity/ts_offset_s/…),
# so a confirmed real object's archived window can be exported straight into a corpus and
# labeled with its (operator-validated) outcome.

_MODALITY_SOURCE = {
    ModalityClass.ACTIVE_PROBE: Source.PROBE,
    ModalityClass.PASSIVE_FLOW: Source.FLOW,
    ModalityClass.CONTROL_PLANE: Source.TOPOLOGY,
    ModalityClass.DEVICE_TELEMETRY: Source.METRIC,
}

CORPUS_T0 = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)  # fixed epoch → deterministic


def _signal_from_spec(spec: dict, t0: datetime, i: int) -> Signal:
    modality = ModalityClass(spec["modality"])
    attrs = dict(spec.get("attrs", {}))
    if modality is ModalityClass.ACTIVE_PROBE:
        attrs.setdefault("probe_authority", spec.get("probe_authority", "high"))
    return Signal(
        tenant_id=str(spec.get("tenant_id", "")),
        ts=t0 + timedelta(seconds=float(spec.get("ts_offset_s", i))),
        source=_MODALITY_SOURCE[modality],
        kind=spec["kind"],
        observer=Observer(
            observer_id=spec["observer_id"],
            observer_type=ObserverType(spec.get("observer_type", "device")),
            collection_path=spec.get("collection_path", "direct"),
        ),
        modality_class=modality,
        entity_type=EntityType(spec.get("entity_type", "device")),
        entity_id=spec.get("entity_id", spec["observer_id"]),
        severity=Severity(spec.get("severity", "warn")),
        native_id=f"corpus|{i}|{spec['kind']}",
        entity_tokens=tuple(spec.get("entity_tokens", ())),
        deviation=float(spec.get("deviation", 0.0)),
        attrs=attrs,
    )


def load_corpus(data: dict, t0: datetime = CORPUS_T0) -> list[LabeledIncident]:
    """Parse a labeled-corpus dict into LabeledIncidents (deterministic event times off a
    fixed epoch). Raises KeyError/ValueError on a malformed spec — fail loud, never guess."""
    out: list[LabeledIncident] = []
    for inc in data.get("incidents", []):
        sigs = tuple(_signal_from_spec(s, t0, i) for i, s in enumerate(inc.get("signals", [])))
        seams = tuple(SeamView.from_dict(d) for d in inc.get("seams", ()))
        adj = TopologyAdjacency.from_links(inc.get("adjacency", []))
        out.append(LabeledIncident(
            name=str(inc.get("name", f"incident-{len(out)}")),
            window=sigs, seams=seams, adjacency=adj,
            expected_hypothesis=str(inc.get("expected_hypothesis", NO_OBJECT)),
            expected_verdict=str(inc.get("expected_verdict", "")),
        ))
    return out


def format_report(results: list[CalibrationResult], top: int = 10) -> str:
    """A ranked human-readable report for the CLI — best config first."""
    lines = [f"calibration: {len(results)} candidate config(s), best first",
             f"{'score':>6}  {'hyp':>5}  {'verdict':>7}  {'config_hash':>14}  overrides"]
    for r in results[:top]:
        ov = ", ".join(f"{k}={v}" for k, v in sorted(r.overrides.items())) or "(base)"
        lines.append(f"{r.score:>6.3f}  {r.hypothesis_acc:>5.2f}  {r.verdict_acc:>7.2f}  "
                     f"{r.config_hash:>14}  {ov}")
    best = results[0]
    lines.append("")
    lines.append(f"adopt → engine_version {best.engine_version} "
                 f"({'no change' if not best.overrides else 'config-hash bumped; replay reports the pin'})")
    for s in best.scores:
        mark = "ok " if s.correct else "MISS"
        lines.append(f"  [{mark}] {s.name}: got hyp={s.got_hypothesis or '(none)'} "
                     f"verdict={s.got_verdict or '-'}")
    return "\n".join(lines)


def _default_grid() -> dict[str, list]:
    """A conservative default sweep around the shipped defaults — the constants whose
    tuning most affects precision/recall. The owner overrides with a --grid JSON."""
    return {
        "tau_s": [200.0, 300.0, 450.0],
        "attach_threshold": [0.25, 0.3, 0.35],
        "reinforce_cross_modality": [1.15, 1.25, 1.35],
    }


def main(argv: list[str] | None = None) -> int:
    import argparse
    p = argparse.ArgumentParser(description="Replay-driven engine calibration (C9 / P4).")
    p.add_argument("corpus", help="labeled-corpus JSON ({incidents:[...]})")
    p.add_argument("--grid", help="grid JSON ({param:[values]}); default sweeps tau/attach/reinforce")
    p.add_argument("--top", type=int, default=10, help="how many ranked candidates to print")
    args = p.parse_args(argv)
    with open(args.corpus) as f:
        corpus = load_corpus(json.load(f))
    grid = _default_grid()
    if args.grid:
        with open(args.grid) as f:
            grid = json.load(f)
    if not corpus:
        print("calibration: empty corpus — nothing to fit")
        return 1
    results = grid_search(corpus, grid)
    print(format_report(results, top=args.top))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
