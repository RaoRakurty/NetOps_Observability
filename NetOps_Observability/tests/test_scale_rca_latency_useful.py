"""tracker 205 STEP 1 — the "Useful RCA" clause evaluator and its four timings.

`scripts/scale-rca-latency.py --ground-truth <run-dir>` turns a run's OWN
seeded ground truth plus the persisted version history into four latencies per
story (`time_to_first_candidate` / `time_to_first_correct` / `time_to_useful` /
`time_to_stable`), defined in `docs/scale/USEFUL_RCA_DEFINITION_2026-09-02.md`.

WHAT THESE TESTS PIN — the properties a wrong answer here would be invisible
without, because the live instrument runs against a 10,000-version corpus
nobody eyeballs:

  * clause evaluation is TIME-INDEXED: correct-from-v1, correct-only-at-v3, and
    never-correct must produce three different answers, not one;
  * a story that never satisfies a clause is CENSORED and COUNTED, never
    silently dropped from a percentile (the failure mode that makes a latency
    table lie by omission);
  * `time_to_stable` is the first version after which the top hypothesis never
    changes again — not the last change, and not the first version;
  * a contradiction that outranks the top hypothesis makes a story NOT useful
    even when the cause is named;
  * percentiles are nearest-rank over the non-censored subset, with n and the
    censored count travelling beside them;
  * the TSV / JSON schema is stable (release-qualify.py and the next tail-
    classification step read these files);
  * a real (trimmed) ground-truth pair parses, cross-checks and yields onsets.

No docker: every test drives the pure functions with synthetic version rows.

Run:  python3 -m pytest tests/test_scale_rca_latency_useful.py -v
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "tests" / "fixtures" / "ttur-gt"


def _load_tool():
    path = ROOT / "scripts" / "scale-rca-latency.py"
    spec = importlib.util.spec_from_file_location("scale_rca_latency_useful", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["scale_rca_latency_useful"] = mod
    spec.loader.exec_module(mod)
    return mod


rl = _load_tool()

ONSET_MS = 1_000_000_000_000


def version(cid: str, at_s: float, *, hyp: str = "sig.cause",
            affected_devices: tuple[str, ...] = ("dev-1",),
            tier: str = "suspected", conf: float = 0.9, nodes: int = 3,
            n_modality: int = 2, n_observer: int = 2, indep_pair: int = 0,
            contra_ge_top: int = 0, state: str = "open",
            version_no: int = 1) -> object:
    """One VersionRow, in the shape the ClickHouse scan hands back."""
    return rl.VersionRow({
        "cid": cid,
        "version": version_no,
        "ca_ms": ONSET_MS + int(at_s * 1000),
        "ws_ms": ONSET_MS,
        "state": state,
        "tier": tier,
        "conf": conf,
        "nodes": nodes,
        "affected": json.dumps({"devices": list(affected_devices)}),
        "hyp": hyp,
        "owner": "netops",
        "n_modality": n_modality,
        "n_observer": n_observer,
        "indep_pair": indep_pair,
        "contra_ge_top": contra_ge_top,
        "top_fallback": 0,
    })


def story(story_id: str = "I0001", entities=("dev-1", "dev-2"),
          cause=("dev-1",), blast=("dev-1", "dev-2")) -> object:
    return rl.Story(
        story_id=story_id, template="local_link_fault", onset_s=10.0,
        onset_ms=ONSET_MS, entities=list(entities), cause_names=list(cause),
        blast_truth=list(blast), owner_class="device_local",
        seam_class="lan_access", tier_floor="suspected")


def history(cid: str, versions) -> object:
    obj = rl.ObjectHistory(cid)
    obj.versions.extend(versions)
    obj.finish()
    return obj


def measure(st, objs):
    return rl.measure_story(st, objs, 2)


# ── clause evaluation, time-indexed ──────────────────────────────────────────

def test_correct_from_the_first_version():
    """Cause named at v1 -> first_correct == first_candidate, nothing censored."""
    obj = history("a", [version("a", 5.0), version("a", 9.0, version_no=2)])
    row = measure(story(), [obj])
    assert row["time_to_first_candidate"] == pytest.approx(5.0)
    assert row["time_to_first_correct"] == pytest.approx(5.0)
    assert row["censored_not_correct"] is False
    assert row["censored_no_candidate"] is False


def test_correct_only_at_v3_is_not_credited_to_v1():
    """The blast radius grows into the cause device at v3.

    THE BUG THIS CATCHES: evaluating the clauses on the object's LATEST
    version (what an end-state scorer does) and stamping that verdict on the
    first version's timestamp — which would report a 4 s time-to-correct for
    an answer that was wrong until second 20.
    """
    obj = history("a", [
        version("a", 4.0, affected_devices=("dev-2",), version_no=1),
        version("a", 12.0, affected_devices=("dev-2",), version_no=2),
        version("a", 20.0, affected_devices=("dev-2", "dev-1"), version_no=3),
    ])
    row = measure(story(), [obj])
    assert row["time_to_first_candidate"] == pytest.approx(4.0)
    assert row["time_to_first_correct"] == pytest.approx(20.0)
    assert row["censored_not_correct"] is False


def test_never_correct_is_censored_not_zero():
    """No version ever names the cause -> censored, and the timing is None.

    A censored story must not silently become a 0 s (or a max-value) sample:
    that is the omission that makes a p95 table lie.
    """
    obj = history("a", [version("a", 6.0, affected_devices=("dev-2",))])
    row = measure(story(), [obj])
    assert row["time_to_first_candidate"] == pytest.approx(6.0)
    assert row["time_to_first_correct"] is None
    assert row["censored_not_correct"] is True
    assert row["censored_not_useful"] is True


def test_no_touching_object_is_censored_everywhere():
    row = measure(story(), [])
    assert row["censored_no_candidate"] is True
    assert row["censored_never_stable"] is True
    for key in rl.GT_TIMINGS:
        assert row[key] is None


def test_stable_only_after_a_flip():
    """Top hypothesis A, A, B, B -> stable at the FIRST B, not the last."""
    obj = history("a", [
        version("a", 2.0, hyp="sig.A", version_no=1),
        version("a", 5.0, hyp="sig.A", version_no=2),
        version("a", 9.0, hyp="sig.B", version_no=3),
        version("a", 14.0, hyp="sig.B", version_no=4),
    ])
    row = measure(story(), [obj])
    assert row["time_to_stable"] == pytest.approx(9.0)
    assert row["top_hypothesis_final"] == "sig.B"


def test_stable_at_the_first_version_when_nothing_ever_changes():
    obj = history("a", [version("a", 3.0, version_no=1),
                        version("a", 8.0, version_no=2)])
    row = measure(story(), [obj])
    assert row["time_to_stable"] == pytest.approx(3.0)


def test_contradiction_outranking_the_top_blocks_useful():
    """Cause named, tier fine, two modalities — but a contradicted hypothesis
    ranks at or above the top one, so clause (e) fails and the story is not
    useful. `time_to_first_correct` is unaffected: correctness and usefulness
    are different questions."""
    obj = history("a", [version("a", 5.0, contra_ge_top=1)])
    row = measure(story(), [obj])
    assert row["time_to_first_correct"] == pytest.approx(5.0)
    assert row["time_to_useful"] is None
    assert row["time_to_first_uncontradicted"] is None
    assert row["censored_not_useful"] is True


def test_useful_needs_every_measured_clause():
    """One version short on evidence, the next carrying it: useful is stamped
    on the SECOND, and only the measurable clauses are required."""
    obj = history("a", [
        version("a", 5.0, n_modality=1, version_no=1),
        version("a", 11.0, n_modality=2, version_no=2),
    ])
    row = measure(story(), [obj])
    assert row["time_to_first_correct"] == pytest.approx(5.0)
    assert row["time_to_first_evidence"] == pytest.approx(11.0)
    assert row["time_to_useful"] == pytest.approx(11.0)
    assert row["useful_clauses_measured"] == list(rl.USEFUL_CLAUSES_MEASURED)
    assert rl.CLAUSE_OWNER not in rl.USEFUL_CLAUSES_MEASURED
    assert rl.CLAUSE_OWNER in rl.USEFUL_CLAUSES_NOT_MEASURABLE


def test_undetermined_tier_fails_the_evidence_clause():
    obj = history("a", [version("a", 5.0, tier="undetermined")])
    row = measure(story(), [obj])
    assert row["time_to_useful"] is None
    assert row["time_to_first_evidence"] is None


def test_merged_objects_are_excluded_like_scorer_v2():
    """A merged object contributes no verdict — the same exclusion scorer v2
    applies (`o.get("state") != "merged"`), here time-indexed."""
    obj = history("a", [version("a", 5.0, state="merged")])
    row = measure(story(), [obj])
    assert row["time_to_first_candidate"] == pytest.approx(5.0)
    assert row["time_to_first_correct"] is None


def test_coverage_is_over_the_union_of_touching_objects():
    """scorer v2 evaluates `affected_includes` over the UNION (tracker 191).

    Object A names dev-2 only; object B names the cause dev-1. Neither alone
    satisfies the clause on its own affected set; together they do, from the
    moment B's first version lands.
    """
    a = history("a", [version("a", 3.0, affected_devices=("dev-2",))])
    b = history("b", [version("b", 7.0, affected_devices=("dev-1",))])
    row = measure(story(), [a, b])
    assert row["time_to_first_candidate"] == pytest.approx(3.0)
    assert row["time_to_first_correct"] == pytest.approx(7.0)


def test_best_object_is_deterministic_in_list_order():
    """tracker 191: the best object depends on CONTENT, never on list order."""
    lo = version("aaaa", 1.0, tier="suspected", nodes=9, conf=0.4)
    hi = version("zzzz", 1.0, tier="confirmed", nodes=1, conf=0.1)
    assert rl._best_version([lo, hi]).cid == "zzzz"
    assert rl._best_version([hi, lo]).cid == "zzzz"


def test_blast_recall_is_reported_not_gated():
    """Only half the truth blast radius is ever named — the story is still
    correct and the recall is reported as a diagnostic."""
    obj = history("a", [version("a", 5.0, affected_devices=("dev-1",))])
    row = measure(story(blast=("dev-1", "dev-2")), [obj])
    assert row["blast_recall"] == pytest.approx(0.5)
    assert row["time_to_first_correct"] == pytest.approx(5.0)


def test_negative_latency_is_reported_not_clamped():
    """A version persisted before the ground-truth onset is skew, and skew is
    the thing this measurement exists to expose."""
    obj = history("a", [rl.VersionRow({
        "cid": "a", "version": 1, "ca_ms": ONSET_MS - 4000, "ws_ms": ONSET_MS,
        "state": "open", "tier": "suspected", "conf": 0.9, "nodes": 3,
        "affected": json.dumps({"devices": ["dev-1"]}), "hyp": "sig.cause",
        "owner": "netops", "n_modality": 2, "n_observer": 2, "indep_pair": 0,
        "contra_ge_top": 0, "top_fallback": 0})])
    row = measure(story(), [obj])
    assert row["time_to_first_candidate"] == pytest.approx(-4.0)


# ── membership ───────────────────────────────────────────────────────────────

def test_membership_matches_any_version_of_an_object():
    """scorer v2 membership: ANY version naming a story entity binds the whole
    object to the story, including the versions before and after it."""
    obj = history("a", [
        version("a", 2.0, affected_devices=("other",), version_no=1),
        version("a", 6.0, affected_devices=("dev-2",), version_no=2),
    ])
    hit = rl.object_story_map({"a": obj}, [story()])
    assert [o.cid for o in hit["I0001"]] == ["a"]


def test_membership_indexes_interface_tokens_by_device():
    """`<device>:<ifname>` in `affected.interfaces` names the device."""
    obj = rl.ObjectHistory("a")
    obj.versions.append(rl.VersionRow({
        "cid": "a", "version": 1, "ca_ms": ONSET_MS, "ws_ms": ONSET_MS,
        "state": "open", "tier": "suspected", "conf": 0.5, "nodes": 1,
        "affected": json.dumps({"devices": [],
                                "interfaces": ["dev-1:GigabitEthernet0/1"]}),
        "hyp": "h", "owner": "netops", "n_modality": 1, "n_observer": 1,
        "indep_pair": 0, "contra_ge_top": 0, "top_fallback": 0}))
    obj.finish()
    hit = rl.object_story_map({"a": obj}, [story()])
    assert [o.cid for o in hit["I0001"]] == ["a"]


def test_membership_falls_back_to_the_substring_rule():
    """A story name that is not a token anywhere still resolves through the
    raw substring test scorer v2 states."""
    obj = rl.ObjectHistory("a")
    obj.versions.append(rl.VersionRow({
        "cid": "a", "version": 1, "ca_ms": ONSET_MS, "ws_ms": ONSET_MS,
        "state": "open", "tier": "suspected", "conf": 0.5, "nodes": 1,
        "affected": json.dumps({"devices": ["peer-10.1.0.200-x"]}),
        "hyp": "h", "owner": "netops", "n_modality": 1, "n_observer": 1,
        "indep_pair": 0, "contra_ge_top": 0, "top_fallback": 0}))
    obj.finish()
    hit = rl.object_story_map({"a": obj}, [story(entities=("10.1.0.200",))])
    assert [o.cid for o in hit["I0001"]] == ["a"]


# ── percentiles with censoring ───────────────────────────────────────────────

def _rows(spec):
    """spec: list of (t_candidate, t_correct, t_useful, t_stable) with None for
    censored — the shape summarize_gt() reduces."""
    out = []
    for i, (cand, corr, use, stab) in enumerate(spec):
        out.append({
            "story_id": f"I{i:04d}", "template": "local_link_fault",
            "time_to_first_candidate": cand, "time_to_first_correct": corr,
            "time_to_useful": use, "time_to_stable": stab,
            "time_to_first_evidence": use,
            "time_to_first_uncontradicted": corr,
            "blast_recall": 1.0, "best_owner": "netops",
            "expected_owner_class": "device_local",
            "expected_seam_class": "lan_access",
            "max_modality_coverage": 1, "max_observer_coverage": 1,
            "independent_pair_seen": False,
            "censored_no_candidate": cand is None,
            "censored_not_correct": corr is None,
            "censored_not_useful": use is None,
            "censored_never_stable": stab is None,
        })
    return out


def test_percentiles_use_only_non_censored_stories():
    rows = _rows([(1.0, 1.0, 1.0, 1.0), (2.0, 2.0, None, 2.0),
                  (3.0, None, None, 3.0), (4.0, 4.0, 4.0, 4.0)])
    s = rl.summarize_gt(rows)
    assert s["stories"] == 4
    assert s["timings"]["time_to_first_candidate"]["n"] == 4
    assert s["timings"]["time_to_first_correct"]["n"] == 3
    assert s["timings"]["time_to_useful"]["n"] == 2
    assert s["timings"]["time_to_useful"]["p50_s"] == pytest.approx(1.0)
    assert s["timings"]["time_to_useful"]["censored"] == 2
    assert s["timings"]["time_to_useful"]["censored_pct"] == pytest.approx(50.0)


def test_censored_counts_are_reported_beside_the_percentiles():
    rows = _rows([(1.0, None, None, 1.0), (None, None, None, None)])
    s = rl.summarize_gt(rows)
    assert s["censored"] == {"no_candidate": 1, "not_correct": 2,
                             "not_useful": 2, "never_stable": 1}
    assert s["clause_never_satisfied"][rl.CLAUSE_CAUSE] == 2
    assert s["clause_never_satisfied"][rl.CLAUSE_EVIDENCE] == 2


def test_a_fully_censored_timing_reports_none_not_zero():
    """Every story censored -> n=0 and None percentiles. A 0.0 here would read
    as "instant", the exact opposite of the truth."""
    rows = _rows([(1.0, 1.0, None, 1.0), (2.0, 2.0, None, 2.0)])
    s = rl.summarize_gt(rows)
    t = s["timings"]["time_to_useful"]
    assert t["n"] == 0
    assert t["p50_s"] is None and t["p95_s"] is None and t["p99_s"] is None
    assert t["censored"] == 2


def test_percentile_is_nearest_rank():
    rows = _rows([(float(i), float(i), float(i), float(i))
                  for i in range(1, 101)])
    s = rl.summarize_gt(rows)["timings"]["time_to_first_candidate"]
    assert s["p50_s"] == pytest.approx(50.0)
    assert s["p95_s"] == pytest.approx(95.0)
    assert s["p99_s"] == pytest.approx(99.0)


def test_blast_recall_diagnostic_uses_ratio_keys_not_seconds():
    """A ratio must never be published under a `_s` key — somebody will read
    0.97 as 0.97 seconds."""
    s = rl.summarize_gt(_rows([(1.0, 1.0, 1.0, 1.0)]))
    diag = s["blast_radius_recall_diagnostic"]
    assert set(diag) == {"n", "min", "p50", "p95", "p99", "max", "mean",
                         "full_recall_stories"}


# ── output schema ────────────────────────────────────────────────────────────

def test_tsv_schema_and_shape():
    # n_modality=1 -> the evidence clause never holds, so time_to_useful is
    # censored and must render as an EMPTY cell (never 0, never "None").
    rows = [measure(story(),
                    [history("a", [version("a", 5.0, n_modality=1)])])]
    text = rl.render_gt_tsv(rows)
    lines = text.rstrip("\n").split("\n")
    assert lines[0].split("\t") == list(rl.GT_TSV_COLUMNS)
    assert len(lines) == 2
    cells = dict(zip(rl.GT_TSV_COLUMNS, lines[1].split("\t")))
    assert cells["story_id"] == "I0001"
    assert cells["time_to_first_candidate"] == "5.000"
    assert cells["time_to_useful"] == ""          # censored renders EMPTY
    assert cells["censored_not_useful"] == "1"
    assert cells["useful_clauses_measured"] == ",".join(
        rl.USEFUL_CLAUSES_MEASURED)
    for column in ("time_to_first_candidate", "time_to_first_correct",
                   "time_to_useful", "time_to_stable"):
        assert column in rl.GT_TSV_COLUMNS


def test_tsv_cells_never_contain_a_tab_or_newline():
    rows = [measure(story(), [history("a", [version("a", 5.0)])])]
    for line in rl.render_gt_tsv(rows).rstrip("\n").split("\n"):
        assert len(line.split("\t")) == len(rl.GT_TSV_COLUMNS)


def test_summary_json_is_serialisable_and_names_the_definition():
    s = rl.summarize_gt(_rows([(1.0, 1.0, 1.0, 1.0)]))
    json.dumps(s)                       # must not raise
    assert rl.USEFUL_DEF_DOC.endswith(".md")
    assert set(rl.GT_TIMINGS) == set(s["timings"])


def test_t1_is_never_relabelled_ttur():
    """The standing terminology rule: T1 = time to first correlated version,
    and this mode's `time_to_first_candidate` is that same quantity. Neither
    may be printed as TTUR."""
    joined = " ".join(rl.GT_CAVEATS)
    assert "NOT TTUR" in joined
    assert "time_to_first_candidate" in joined


# ── ground-truth parsing ─────────────────────────────────────────────────────

def test_ground_truth_fixture_parses():
    gt, stories = rl.load_ground_truth(str(FIXTURE), 1_000_000_000_000)
    assert gt["schema"] == rl.GT_SCHEMA
    assert len(stories) == 3
    ids = [s.story_id for s in stories]
    assert ids == sorted(ids)
    for st in stories:
        assert st.cause_names, "every story must carry a cause to match"
        assert st.entities
        assert st.onset_ms == 1_000_000_000_000 + round(st.onset_s * 1000)
        assert st.owner_class and st.seam_class
        assert st.tier_floor in rl.TIER_RANK


def test_ground_truth_rejects_a_foreign_schema(tmp_path):
    doc = json.loads((FIXTURE / "ground-truth.json").read_text())
    doc["schema"] = "something.else/9"
    (tmp_path / "ground-truth.json").write_text(json.dumps(doc))
    (tmp_path / "ground_truth.jsonl").write_text(
        (FIXTURE / "ground_truth.jsonl").read_text())
    with pytest.raises(SystemExit):
        rl.load_ground_truth(str(tmp_path), 0)


def test_ground_truth_rejects_disagreeing_onsets(tmp_path):
    """The two renderings of one scenario must agree, or no timing derived
    from them is trustworthy."""
    doc = json.loads((FIXTURE / "ground-truth.json").read_text())
    doc["incidents"][0]["onset_ts"] = doc["incidents"][0]["onset_ts"] + 5.0
    (tmp_path / "ground-truth.json").write_text(json.dumps(doc))
    (tmp_path / "ground_truth.jsonl").write_text(
        (FIXTURE / "ground_truth.jsonl").read_text())
    with pytest.raises(SystemExit):
        rl.load_ground_truth(str(tmp_path), 0)


def test_ground_truth_rejects_a_story_count_mismatch(tmp_path):
    doc = json.loads((FIXTURE / "ground-truth.json").read_text())
    doc["incidents"] = doc["incidents"][:2]
    (tmp_path / "ground-truth.json").write_text(json.dumps(doc))
    (tmp_path / "ground_truth.jsonl").write_text(
        (FIXTURE / "ground_truth.jsonl").read_text())
    with pytest.raises(SystemExit):
        rl.load_ground_truth(str(tmp_path), 0)


# ── SQL / query construction ─────────────────────────────────────────────────

def test_version_scan_sql_is_tenant_and_window_bounded():
    sql = rl.sql_gt_versions("global", "bb1e46d6-5462-54dc-8465-777c707b9329",
                             "2026-09-01 21:40:55", "2026-09-01 21:55:55")
    assert sql.lstrip().upper().startswith("WITH")
    assert "tenant_id = 'global'" in sql
    assert "created_at >=" in sql and "created_at <" in sql
    # tracker 201: the storm-aggregate object carries a ~1 GiB hypotheses blob.
    assert "correlation_id != toUUID(" in sql
    # the 26 KB blob must never cross the wire
    assert "SELECT\n  toString(correlation_id)" in sql
    assert "\n  hypotheses," not in sql


def test_query_refuses_a_non_select():
    ch = rl.ClickHouse("netops", 5)
    ok, _, err = ch.query("DROP TABLE netops.corr_objects")
    assert not ok and "refusing non-SELECT" in err


def test_query_refuses_an_unsafe_setting_or_format():
    ch = rl.ClickHouse("netops", 5)
    ok, _, err = ch.query("SELECT 1", settings={"max_threads; DROP": 1})
    assert not ok and "unsafe ClickHouse setting" in err
    ok, _, err = ch.query("SELECT 1", fmt="TSV; DROP")
    assert not ok and "unsafe FORMAT" in err
    ok, _, err = ch.query("SELECT 1", settings={"max_threads": "2"})
    assert not ok and "must be an int" in err
