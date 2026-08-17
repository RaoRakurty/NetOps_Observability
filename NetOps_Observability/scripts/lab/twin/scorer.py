"""RCA accuracy scorer (tracker 152, design §5/§8.4 — closing G-2).

Joins the run's `ground_truth.jsonl` labels against the engine's output in
ClickHouse (`netops.corr_objects_latest` — verdict_tier / top_hypothesis /
top_confidence / node_count / affected / hypotheses, the columns
`correlation_e2e.py` already validates live; seam grounding is read from
`netops.corr_edges` grounding_kind='seam'). Produces `accuracy-report.json`
and a human `accuracy-report.md`.

Scoring contract (design §5): story PASS = every `expect` clause holds and no
`forbid` clause fires. Negative controls count toward accuracy as SPECIFICITY
— a false positive there is an accuracy failure exactly like a miss. A miss is
reported with its EVIDENCE TRAIL (events journaled? signals formed? object
formed but wrong verdict?) so an engine gap and a twin bug are tellable apart.
"""
from __future__ import annotations

import json
import re

from stack import Stack

_TIER_RANK = {"undetermined": 0, "suspected": 1, "confirmed": 2}
_SAFE = re.compile(r"^[A-Za-z0-9._/:-]+$")


def _lit(s: str) -> str:
    """Refuse to embed anything but our own run-tagged identifiers in SQL —
    zero-trust even on our own state files."""
    if not _SAFE.match(s or ""):
        raise ValueError(f"identifier {s!r} is not SQL-embed safe")
    return s


def _objects_for(stack: Stack, names: list[str]) -> list[dict]:
    """Distinct latest objects whose affected JSON names ANY of `names`."""
    seen: dict[str, dict] = {}
    for name in names:
        rows = stack.ch_json(
            "SELECT toString(correlation_id) AS id, toString(state) AS state, "
            "toString(verdict_tier) AS verdict_tier, top_hypothesis, "
            "round(top_confidence,3) AS conf, node_count, affected, hypotheses "
            "FROM netops.corr_objects_latest "
            f"WHERE position(affected, '{_lit(name)}') > 0")
        for r in rows:
            seen[r["id"]] = r
    return list(seen.values())


def _seam_edge_refs(stack: Stack, correlation_id: str) -> set[str]:
    rows = stack.ch_json(
        "SELECT DISTINCT grounding_ref FROM netops.corr_edges "
        f"WHERE toString(correlation_id) = '{_lit(correlation_id)}' "
        "AND grounding_kind = 'seam'")
    return {r["grounding_ref"] for r in rows}


def _top_owner(obj: dict) -> str:
    """verdict.owner of the ranked-top hypothesis in the hypotheses JSON."""
    try:
        doc = json.loads(obj.get("hypotheses") or "{}")
    except json.JSONDecodeError:
        return ""
    # Live column shape (verified 2026-08-17 on-stack): a dict
    # {"grounding_context": {...}, "ranking": {"hypotheses": [...],
    #  "top_hypothesis": ..., ...}} — each ranked entry carries
    # verdict.owner (scoring.py HypothesisScore.to_dict).
    if isinstance(doc, dict):
        hyps = (doc.get("ranking") or {}).get("hypotheses") or []
    elif isinstance(doc, list):  # tolerate a bare ranked list
        hyps = doc
    else:
        return ""
    hyps = [h for h in hyps if isinstance(h, dict)]
    for h in hyps:
        if h.get("id") == obj.get("top_hypothesis"):
            return str((h.get("verdict") or {}).get("owner") or "")
    if hyps:
        return str((hyps[0].get("verdict") or {}).get("owner") or "")
    return ""


def _evidence_trail(stack: Stack, names: list[str],
                    journal_counts: dict[str, int]) -> dict:
    kinds: dict[str, int] = {}
    for name in names:
        rows = stack.ch_json(
            "SELECT kind, count() AS n FROM netops.corr_signals "
            f"WHERE entity_id LIKE '%{_lit(name)}%' GROUP BY kind")
        for r in rows:
            kinds[r["kind"]] = kinds.get(r["kind"], 0) + int(r["n"])
    return {"events_journaled": journal_counts, "signals_by_kind": kinds}


def score_story(stack: Stack, gt: dict, prefix: str,
                device_tenants: dict[str, str],
                journal_counts: dict[str, int]) -> dict:
    """One ground-truth record → clause-by-clause verdict."""
    expect = gt.get("expect") or {}
    rca = expect.get("rca") or {}
    seam_exp = expect.get("seam") or {}
    forbid = expect.get("forbid") or {}

    twx_devices = [prefix + d for d in gt["affected"].get("devices") or []]
    extra_entities = [prefix + e for e in gt.get("extra_entities") or []]
    names = twx_devices + extra_entities
    objects = [o for o in _objects_for(stack, names)
               if o.get("state") != "merged"]

    clauses: list[dict] = []

    def clause(name: str, ok: bool, detail: str) -> None:
        clauses.append({"clause": name, "ok": bool(ok), "detail": detail})

    positive = bool(rca) or bool(seam_exp)
    best = max(objects,
               key=lambda o: _TIER_RANK.get(o["verdict_tier"], 0),
               default=None)

    if positive:
        clause("detected", best is not None,
               f"{len(objects)} object(s) touch the story's entities")
    if rca.get("verdict_tier_at_least"):
        want = _TIER_RANK[rca["verdict_tier_at_least"]]
        have = _TIER_RANK.get(best["verdict_tier"], 0) if best else -1
        clause("verdict_tier_at_least",
               best is not None and have >= want,
               f"want ≥ {rca['verdict_tier_at_least']}, got "
               f"{best['verdict_tier'] if best else 'NO OBJECT'}")
    if rca.get("hypothesis_matches"):
        pat = re.compile(rca["hypothesis_matches"])
        hyp = best["top_hypothesis"] if best else ""
        clause("hypothesis_matches", bool(best and pat.search(hyp)),
               f"pattern {rca['hypothesis_matches']!r} vs "
               f"top_hypothesis {hyp!r}")
    if rca.get("affected_includes"):
        missing = []
        if best:
            for d in rca["affected_includes"]:
                if (prefix + d) not in (best.get("affected") or ""):
                    missing.append(d)
        clause("affected_includes",
               best is not None and not missing,
               f"missing from object.affected: {missing or 'none'}"
               if best else "no object")
    if rca.get("single_incident"):
        clause("single_incident", len(objects) == 1,
               f"{len(objects)} non-merged object(s) span the story "
               f"(cascade must fold to ONE)")

    if seam_exp:
        seam_id = prefix + seam_exp["seam_id"]
        refs: set[str] = set()
        if best:
            refs = _seam_edge_refs(stack, best["id"])
        clause("seam_grounded",
               best is not None and seam_id in refs,
               f"want seam edge ref {seam_id!r}, object has "
               f"{sorted(refs) or 'none'}")
        if seam_exp.get("owner"):
            owner = _top_owner(best) if best else ""
            clause("seam_owner", owner == seam_exp["owner"],
                   f"want owner {seam_exp['owner']!r}, hypothesis verdict "
                   f"names {owner!r}")

    if forbid.get("cross_tenant_merge"):
        violators = []
        for o in objects:
            tenants_hit = {t for d, t in device_tenants.items()
                           if (prefix + d) in (o.get("affected") or "")}
            if len(tenants_hit) > 1:
                violators.append({"object": o["id"],
                                  "tenants": sorted(tenants_hit)})
        clause("forbid.cross_tenant_merge", not violators,
               f"objects spanning tenants: {violators or 'none'}")
    if forbid.get("confirmed"):
        confirmed = [o["id"] for o in objects
                     if o["verdict_tier"] == "confirmed"]
        clause("forbid.confirmed", not confirmed,
               f"confirmed objects: {confirmed or 'none'}")

    ok = all(c["ok"] for c in clauses)
    out = {
        "story_id": gt["story_id"],
        "template": gt["template"],
        "kind": "positive" if positive else "negative_control",
        "status": "PASS" if ok else "FAIL",
        "fired_at": gt.get("fired_at"),
        "clauses": clauses,
        "objects": [{k: o[k] for k in
                     ("id", "verdict_tier", "top_hypothesis", "conf",
                      "node_count")} for o in objects],
    }
    if not ok:
        out["evidence_trail"] = _evidence_trail(stack, names, journal_counts)
    return out


def score_run(stack: Stack, ground_truth: list[dict], state: dict,
              journal_by_story: dict[str, dict[str, int]]) -> dict:
    prefix = state["prefix"]
    device_tenants = state.get("device_tenants") or {}
    results = []
    for gt in ground_truth:
        try:
            results.append(score_story(
                stack, gt, prefix, device_tenants,
                journal_by_story.get(gt["story_id"], {})))
        except Exception as exc:  # noqa: BLE001 — one story's scoring crash
            # must not lose every other story's verdict (and previously lost
            # the whole report to teardown); it is recorded as a LOUD failure.
            results.append({
                "story_id": gt.get("story_id", "?"),
                "template": gt.get("template", "?"),
                "kind": "positive",
                "status": "FAIL",
                "fired_at": gt.get("fired_at"),
                "clauses": [{"clause": "scorer_error", "ok": False,
                             "detail": f"scoring crashed: {exc!r}"}],
                "objects": [],
            })
    total = len(results)
    passed = sum(1 for r in results if r["status"] == "PASS")
    positives = [r for r in results if r["kind"] == "positive"]
    negatives = [r for r in results if r["kind"] == "negative_control"]

    def _rate(items: list[dict]) -> float:
        return round(sum(1 for r in items if r["status"] == "PASS")
                     / len(items), 4) if items else 1.0

    def _clause_rate(items: list[dict], clause: str) -> float:
        hits = ok = 0
        for r in items:
            for c in r["clauses"]:
                if c["clause"] == clause:
                    hits += 1
                    ok += 1 if c["ok"] else 0
        return round(ok / hits, 4) if hits else 1.0

    per_template: dict[str, dict[str, int]] = {}
    for r in results:
        t = per_template.setdefault(r["template"], {"pass": 0, "fail": 0})
        t["pass" if r["status"] == "PASS" else "fail"] += 1

    return {
        "runid": state["runid"],
        "accuracy_slo": round(passed / total, 4) if total else None,
        "stories_total": total,
        "stories_passed": passed,
        "detection_rate": _clause_rate(positives, "detected"),
        "positive_pass_rate": _rate(positives),
        "specificity": _rate(negatives),
        "per_template": per_template,
        "stories": results,
    }


def render_md(report: dict) -> str:
    lines = [
        f"# Twin accuracy report — run {report['runid']}",
        "",
        (f"- **RCA accuracy SLO: "
         f"{report['stories_passed']}/{report['stories_total']} stories "
         f"({(report['accuracy_slo'] or 0) * 100:.0f}%)**"),
        (f"- Positive stories pass rate: "
         f"{report['positive_pass_rate'] * 100:.0f}% · "
         f"specificity (negative controls): "
         f"{report['specificity'] * 100:.0f}%"),
        "",
        "| Story | Template | Kind | Status |",
        "|---|---|---|---|",
    ]
    for r in report["stories"]:
        lines.append(f"| {r['story_id']} | {r['template']} | {r['kind']} | "
                     f"{r['status']} |")
    lines.append("")
    for r in report["stories"]:
        lines.append(f"## {r['story_id']} ({r['status']})")
        for c in r["clauses"]:
            mark = "✔" if c["ok"] else "✘"
            lines.append(f"- {mark} `{c['clause']}` — {c['detail']}")
        if r.get("objects"):
            lines.append("- objects: "
                         + "; ".join(f"{o['id'][:8]} "
                                     f"{o['verdict_tier']}/"
                                     f"{o['top_hypothesis']} "
                                     f"conf={o['conf']} nodes={o['node_count']}"
                                     for o in r["objects"]))
        if r.get("evidence_trail"):
            lines.append(f"- evidence trail: "
                         f"{json.dumps(r['evidence_trail'], sort_keys=True)}")
        lines.append("")
    return "\n".join(lines) + "\n"
