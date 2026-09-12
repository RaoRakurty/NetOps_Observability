# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""tracker 205 STEP 2 — the tail classifier's pure functions.

`scripts/scale-rca-tail.py` answers one question — *does a small identity class
dominate the RCA latency tail?* — and answers it with three statistics that are
easy to get subtly wrong and impossible to eyeball on a 345-story corpus:

  * BUCKETING: fixed, documented edges, so two runs are comparable and an
    out-of-range value is visible instead of absorbed into a real bucket;
  * TAIL SHARE / CONCENTRATION: the tracker's own test — a bucket holding
    > 50 % of the tail while holding < 25 % of the stories. Both a synthetic
    case where one bucket DOES dominate and one where none does are pinned,
    because a statistic that can only say "yes" is not a test;
  * NA HANDLING: a story with no value for a dimension must land in an explicit
    "NA" bucket that is REPORTED and EXCLUDED from the dominance test. An NA
    class silently becoming a real bucket would manufacture exactly the
    "small identity class" finding the tracker row is asking about — the single
    most dangerous failure mode in this file;
  * the ONSET-BAND window (the 5k rung's 154 s clue): the tightest window
    containing 80 % of a population, nearest-rank;
  * the TSV / JSON schemas the report and any follow-up step read.

Also pinned: censoring is preserved end to end (an empty TSV cell is None and
never 0.0), and a fully censored timing produces "not classified", never an
empty win.

No docker: every test drives the pure functions with synthetic rows.

Run:  python3 -m pytest tests/test_scale_rca_tail.py -v
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parent.parent


def _load_tool() -> Any:
    path = ROOT / "scripts" / "scale-rca-tail.py"
    spec = importlib.util.spec_from_file_location("scale_rca_tail", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["scale_rca_tail"] = mod
    spec.loader.exec_module(mod)
    return mod


tail = _load_tool()


def pct(sorted_vals: list[float], q: float) -> float | None:
    """Step 1's nearest-rank percentile, reproduced here ONLY as a test double
    so these tests never need the sibling tool (and never need docker). The
    live tool imports the real one."""
    if not sorted_vals:
        return None
    k = max(1, int(-(-q * len(sorted_vals) // 100)))
    return sorted_vals[min(k, len(sorted_vals)) - 1]


def story(sid: str, timing: float | None = 100.0, **dims: Any) -> dict[str, Any]:
    row: dict[str, Any] = {"story_id": sid, "time_to_first_candidate": timing,
                           "time_to_first_correct": timing,
                           "time_to_useful": None,
                           "time_to_stable": timing}
    row.update(dims)
    return row


# ---------------------------------------------------------------------------
# Bucketing
# ---------------------------------------------------------------------------

class TestBucketing:
    def test_numeric_edges_are_inclusive_upper_bounds(self) -> None:
        edges = (1, 2, 9, 24, 39)
        assert tail.bucket_numeric(1, edges, 1) == "1"
        assert tail.bucket_numeric(2, edges, 1) == "2"
        assert tail.bucket_numeric(3, edges, 1) == "3-9"
        assert tail.bucket_numeric(9, edges, 1) == "3-9"
        assert tail.bucket_numeric(10, edges, 1) == "10-24"
        assert tail.bucket_numeric(39, edges, 1) == "25-39"
        assert tail.bucket_numeric(40, edges, 1) == "40+"
        assert tail.bucket_numeric(4000, edges, 1) == "40+"

    def test_numeric_first_bucket_spans_from_lo0(self) -> None:
        # The bug this pins: a first edge > lo0 must produce "1-4", not "4".
        assert tail.bucket_numeric(1, (4, 16), 1) == "1-4"
        assert tail.bucket_numeric(4, (4, 16), 1) == "1-4"
        assert tail.bucket_numeric(5, (4, 16), 1) == "5-16"
        assert tail.bucket_numeric(0, (0, 1, 2, 9), 0) == "0"
        assert tail.bucket_numeric(1, (0, 1, 2, 9), 0) == "1"

    def test_numeric_below_range_is_its_own_visible_bucket(self) -> None:
        assert tail.bucket_numeric(0, (1, 2, 9), 1) == "<1"
        assert tail.bucket_numeric(-3, (1, 2, 9), 1) == "<1"

    def test_exact_folds_at_the_cap(self) -> None:
        assert tail.bucket_exact(0, 4) == "0"
        assert tail.bucket_exact(3, 4) == "3"
        assert tail.bucket_exact(4, 4) == "4+"
        assert tail.bucket_exact(99, 4) == "4+"

    def test_onset_bands_are_fixed_width_not_quantile(self) -> None:
        assert tail.bucket_onset(0.0) == "0-99s"
        assert tail.bucket_onset(99.9) == "0-99s"
        assert tail.bucket_onset(100.0) == "100-199s"
        assert tail.bucket_onset(880.4) == "800-899s"
        assert tail.bucket_onset(-1.0) == "<0"

    def test_every_bucketed_dimension_has_a_bucketer(self) -> None:
        assert set(tail.BUCKETED) == set(tail.BUCKETERS)
        for name in tail.BUCKETED:
            assert tail.DIMS_BY_NAME[name].status in (tail.MEASURABLE, tail.PROXY)

    def test_not_measurable_dimensions_produce_no_bucket(self) -> None:
        not_measurable = [d.name for d in tail.DIMENSIONS
                          if d.status == tail.NOT_MEASURABLE]
        assert not_measurable, "the 15-dimension list must record its gaps"
        for name in not_measurable:
            assert name not in tail.BUCKETED
            assert tail.DIMS_BY_NAME[name].note, (
                f"{name} is NOT MEASURABLE and must carry the reason")

    def test_unknown_dimension_raises_rather_than_silently_returning_na(self) -> None:
        with pytest.raises(KeyError):
            tail.bucket_of("no_such_dimension", 1)


# ---------------------------------------------------------------------------
# NA handling — the most dangerous failure mode in this file
# ---------------------------------------------------------------------------

class TestNAHandling:
    def test_none_buckets_to_the_explicit_na_label(self) -> None:
        assert tail.bucket_numeric(None, (1, 2, 9), 1) == tail.NA
        assert tail.bucket_exact(None, 4) == tail.NA
        assert tail.bucket_onset(None) == tail.NA
        assert tail.bucket_categorical(None) == tail.NA
        assert tail.bucket_categorical("") == tail.NA

    def test_na_is_reported_but_never_wins_the_concentration_test(self) -> None:
        # 20 stories: 16 have NO template value and hold the ENTIRE tail.
        # If NA were treated as a real bucket it would score tail_share 1.00 in
        # a 0.20 story share and be declared a dominating identity class.
        rows = [story(f"S{i}", 1000.0, template=None) for i in range(16)]
        rows += [story(f"F{i}", 10.0, template="local_link_fault")
                 for i in range(4)]
        out = tail.classify_dimension(rows, "template",
                                      "time_to_first_candidate", 100.0, pct)
        labels = {b["bucket"]: b for b in out["buckets"]}
        assert tail.NA in labels
        assert labels[tail.NA]["stories"] == 16
        assert labels[tail.NA]["tail_share"] == 1.0
        assert out["na_stories"] == 16
        # ...and yet:
        assert out["top_bucket"] != tail.NA
        assert out["dominates"] is False
        assert out["concentration"] == 0.0

    def test_missing_dimension_key_is_na_not_zero(self) -> None:
        rows = [story("S1", 10.0)]          # no `component_size` key at all
        out = tail.classify_dimension(rows, "component_size",
                                      "time_to_first_candidate", 5.0, pct)
        assert [b["bucket"] for b in out["buckets"]] == [tail.NA]


# ---------------------------------------------------------------------------
# Tail share + the concentration statistic
# ---------------------------------------------------------------------------

class TestConcentration:
    def test_one_bucket_dominates(self) -> None:
        # 100 stories. 10 of them (10 % of stories) are `bgp_peer_flap` and are
        # ALL slow; the tail (>p90) is 10 stories, all of them that template.
        rows = [story(f"B{i}", 900.0, template="bgp_peer_flap")
                for i in range(10)]
        rows += [story(f"L{i}", 50.0, template="local_link_fault")
                 for i in range(90)]
        values = sorted(float(r["time_to_first_candidate"]) for r in rows)
        threshold = pct(values, 90.0)
        assert threshold == 50.0
        out = tail.classify_dimension(rows, "template",
                                      "time_to_first_candidate",
                                      float(threshold), pct)
        assert out["tail_stories"] == 10
        assert out["top_bucket"] == "bgp_peer_flap"
        assert out["top_bucket_tail_share"] == 1.0
        assert out["top_bucket_story_share"] == 0.1
        assert out["top_bucket_lift"] == 10.0
        assert out["dominates"] is True

    def test_nothing_dominates_when_the_tail_is_spread(self) -> None:
        # Four templates, 25 stories each, each contributing a quarter of the
        # tail. No bucket clears >50 % of the tail, and none is <25 % of the
        # stories either — the "Y-shaped tail" case.
        rows: list[dict[str, Any]] = []
        for name in ("a", "b", "c", "d"):
            rows += [story(f"{name}-slow-{i}", 900.0, template=name)
                     for i in range(3)]
            rows += [story(f"{name}-fast-{i}", 50.0, template=name)
                     for i in range(22)]
        out = tail.classify_dimension(rows, "template",
                                      "time_to_first_candidate", 100.0, pct)
        assert out["tail_stories"] == 12
        assert out["top_bucket_tail_share"] == 0.25
        assert out["top_bucket_story_share"] == 0.25
        assert out["dominates"] is False

    def test_a_big_bucket_holding_the_tail_does_not_dominate(self) -> None:
        # The other half of the test: 80 % of the tail in a bucket that is also
        # 80 % of the stories is NOT a small identity class. Holding the tail
        # in proportion to your size explains nothing.
        rows = [story(f"B{i}", 900.0, template="big") for i in range(8)]
        rows += [story(f"b{i}", 50.0, template="big") for i in range(72)]
        rows += [story(f"S{i}", 900.0, template="small") for i in range(2)]
        rows += [story(f"s{i}", 50.0, template="small") for i in range(18)]
        out = tail.classify_dimension(rows, "template",
                                      "time_to_first_candidate", 100.0, pct)
        assert out["top_bucket"] == "big"
        assert out["top_bucket_tail_share"] == 0.8
        assert out["top_bucket_story_share"] == 0.8
        assert out["top_bucket_lift"] == 1.0
        assert out["dominates"] is False

    def test_tail_share_and_tail_rate_are_different_questions(self) -> None:
        # `tail_rate` = how often THIS bucket is slow. `tail_share` = how much
        # of the WHOLE tail it holds. A tiny always-slow bucket has rate 1.0 and
        # a small share; conflating them is the classic mis-read.
        rows = [story("T1", 900.0, template="tiny")]
        rows += [story(f"B{i}", 900.0, template="bulk") for i in range(9)]
        rows += [story(f"b{i}", 10.0, template="bulk") for i in range(90)]
        out = tail.classify_dimension(rows, "template",
                                      "time_to_first_candidate", 100.0, pct)
        by = {b["bucket"]: b for b in out["buckets"]}
        assert by["tiny"]["tail_rate"] == 1.0
        assert by["tiny"]["tail_share"] == 0.1
        assert by["bulk"]["tail_rate"] == pytest.approx(9 / 99, abs=1e-4)
        assert by["bulk"]["tail_share"] == 0.9

    def test_censored_stories_are_excluded_from_the_tail_not_counted_as_fast(self) -> None:
        rows = [story("S1", 900.0, template="a"), story("S2", 10.0, template="a"),
                story("S3", None, template="b")]
        out = tail.classify_dimension(rows, "template",
                                      "time_to_first_candidate", 100.0, pct)
        assert out["stories_scored"] == 2
        assert [b["bucket"] for b in out["buckets"]] == ["a"]

    def test_ranking_orders_dimensions_by_concentration(self) -> None:
        rows = [story(f"B{i}", 900.0, template="bgp", seam_type="wan_transport")
                for i in range(10)]
        rows += [story(f"L{i}", 50.0, template=f"t{i % 5}",
                       seam_type="wan_transport") for i in range(90)]
        out = tail.classify_all(rows, pct)
        entry = out["time_to_first_candidate"]
        assert entry["classified"] is True
        ranking = entry["ranking"]
        assert ranking[0]["dimension"] == "template"
        assert ranking[0]["dominates"] is True
        # seam_type is a single bucket holding 100 % of the tail AND 100 % of
        # the stories: it can never dominate.
        seam = next(r for r in ranking if r["dimension"] == "seam_type")
        assert seam["story_share"] == 1.0
        assert seam["dominates"] is False
        assert entry["dominating_dimensions"] == ["template"]
        assert [r["rank"] for r in ranking] == list(range(1, len(ranking) + 1))

    def test_fully_censored_timing_is_not_classified_not_an_empty_win(self) -> None:
        rows = [story(f"S{i}", 100.0, template="a") for i in range(5)]
        out = tail.classify_all(rows, pct)
        useful = out["time_to_useful"]
        assert useful["classified"] is False
        assert useful["censored"] == 5
        assert useful["stories_scored"] == 0
        assert useful["tail_threshold_s"] is None
        assert useful["dimensions"] == []
        assert useful["onset_band"] is None
        assert "reason" in useful


# ---------------------------------------------------------------------------
# The onset-band window (the 5k clue)
# ---------------------------------------------------------------------------

class TestOnsetBand:
    def test_tightest_window_finds_the_cluster_not_the_first_n(self) -> None:
        values = [0.0, 500.0, 900.0, 300.0, 310.0, 320.0, 330.0, 340.0,
                  350.0, 360.0]
        out = tail.tightest_window(values, 0.8)
        assert out["n"] == 10
        assert out["need"] == 8
        # sorted: 0 300 310 320 330 340 350 360 500 900. The 8-wide windows
        # are [0..360]=360, [300..500]=200, [310..900]=590 — the middle one
        # wins. A "first n" implementation would have returned 360.
        assert out["lo_s"] == 300.0
        assert out["hi_s"] == 500.0
        assert out["width_s"] == 200.0
        # ...and with a coverage the cluster alone satisfies, the window
        # collapses onto the cluster rather than spanning the outliers.
        tight = tail.tightest_window(values, 0.7)
        assert tight["need"] == 7
        assert tight["lo_s"] == 300.0
        assert tight["hi_s"] == 360.0
        assert tight["width_s"] == 60.0

    def test_need_is_nearest_rank_and_never_overstates_coverage(self) -> None:
        values = [float(i) for i in range(10)]
        assert tail.tightest_window(values, 0.8)["need"] == 8
        assert tail.tightest_window(values, 0.75)["need"] == 8   # ceil(7.5)
        assert tail.tightest_window(values, 0.01)["need"] == 1
        assert tail.tightest_window([], 0.8) == {
            "n": 0, "need": 0, "lo_s": None, "hi_s": None, "width_s": None}

    def test_tail_band_narrower_than_the_all_band_is_the_clustering_signal(self) -> None:
        # 20 stories spread over a 900 s burst; the 5 slow ones all injected in
        # a 40 s window — the 5k rung's shape, in miniature.
        rows = [story(f"F{i}", 10.0, onset_offset_s=float(i * 45))
                for i in range(15)]
        rows += [story(f"S{i}", 900.0, onset_offset_s=300.0 + i * 10)
                 for i in range(5)]
        out = tail.onset_band_check(rows, "time_to_first_candidate", 100.0)
        assert out["tail"]["n"] == 5
        assert out["all"]["n"] == 20
        assert out["tail"]["width_s"] < out["all"]["width_s"]
        assert out["tail"]["lo_s"] == 300.0
        assert out["tail"]["hi_s"] == 330.0

    def test_no_clustering_gives_a_tail_band_as_wide_as_the_population(self) -> None:
        rows = [story(f"S{i}", 900.0 if i % 2 else 10.0,
                      onset_offset_s=float(i * 45)) for i in range(20)]
        out = tail.onset_band_check(rows, "time_to_first_candidate", 100.0)
        assert out["tail"]["width_s"] >= 0.6 * float(out["all"]["width_s"])

    def test_a_story_with_no_onset_is_dropped_from_both_populations(self) -> None:
        rows = [story("S1", 900.0, onset_offset_s=10.0),
                story("S2", 900.0, onset_offset_s=None)]
        out = tail.onset_band_check(rows, "time_to_first_candidate", 100.0)
        assert out["all"]["n"] == 1
        assert out["tail"]["n"] == 1


# ---------------------------------------------------------------------------
# Cohort reconstruction (dimension 13)
# ---------------------------------------------------------------------------

class TestCohorts:
    def test_gap_splits_the_persist_stream_into_cohorts(self) -> None:
        stream = [0, 100, 250, 400,            # cohort 1
                  10_000, 10_050,              # cohort 2 (10 s gap)
                  30_000]                      # cohort 3
        starts = tail.reconstruct_cohorts(stream, 2.0)
        assert starts == [0, 10_000, 30_000]

    def test_a_cohort_wider_than_the_gap_is_still_one_cohort(self) -> None:
        stream = list(range(0, 75_000, 500))   # 75 s of 0.5 s spacing
        assert tail.reconstruct_cohorts(stream, 2.0) == [0]

    def test_unsorted_input_and_empty_input(self) -> None:
        assert tail.reconstruct_cohorts([30_000, 0, 10_000], 2.0) == \
            [0, 10_000, 30_000]
        assert tail.reconstruct_cohorts([], 2.0) == []

    def test_cohorts_between_is_half_open_and_never_negative(self) -> None:
        starts = [0, 10_000, 20_000, 30_000]
        assert tail.cohorts_between(starts, 0, 30_000) == 3      # (0, 30000]
        assert tail.cohorts_between(starts, -1, 0) == 1
        assert tail.cohorts_between(starts, 30_000, 10_000) == 0
        assert tail.cohorts_between(starts, 30_000, 30_000) == 0


# ---------------------------------------------------------------------------
# Schemas — the TSV / JSON other steps read
# ---------------------------------------------------------------------------

class TestSchemas:
    def test_step1_tsv_round_trips_and_keeps_censoring(self) -> None:
        text = ("story_id\ttemplate\tonset_offset_s\ttime_to_first_candidate\t"
                "time_to_first_correct\ttime_to_useful\ttime_to_stable\n"
                "I0001\tlocal_link_fault\t125.600\t53.337\t127.335\t\t53.337\n")
        rows = tail.parse_step1_tsv(text)
        assert len(rows) == 1
        row = rows[0]
        assert row["story_id"] == "I0001"
        assert row["onset_offset_s"] == pytest.approx(125.6)
        assert row["time_to_first_candidate"] == pytest.approx(53.337)
        # THE censoring rule: an empty cell is None, never 0.0.
        assert row["time_to_useful"] is None
        assert row["time_to_useful"] != 0.0

    def test_step1_tsv_missing_column_is_fatal(self) -> None:
        text = "story_id\ttemplate\n" "I0001\tlocal_link_fault\n"
        with pytest.raises(SystemExit) as exc:
            tail.parse_step1_tsv(text)
        assert exc.value.code == 1

    def test_step1_tsv_ragged_row_is_fatal(self) -> None:
        text = ("story_id\ttemplate\tonset_offset_s\ttime_to_first_candidate\t"
                "time_to_first_correct\ttime_to_useful\ttime_to_stable\n"
                "I0001\tlocal_link_fault\t1.0\n")
        with pytest.raises(SystemExit):
            tail.parse_step1_tsv(text)

    def test_tail_tsv_has_a_column_for_every_bucketed_dimension(self) -> None:
        for name in tail.BUCKETED:
            if name == "onset_band":      # rendered as its raw onset_offset_s
                assert "onset_offset_s" in tail.TAIL_TSV_COLUMNS
                continue
            assert name in tail.TAIL_TSV_COLUMNS, f"{name} missing from the TSV"
        for timing in tail.TIMINGS:
            assert timing in tail.TAIL_TSV_COLUMNS

    def test_tail_tsv_renders_none_as_empty_and_floats_at_3dp(self) -> None:
        rows = [{"story_id": "I0001", "template": "local_link_fault",
                 "component_size": None, "onset_offset_s": 125.6,
                 "time_to_first_candidate": 53.3371}]
        text = tail.render_tsv(rows)
        header, body = text.splitlines()[0].split("\t"), text.splitlines()[1].split("\t")
        cell = dict(zip(header, body, strict=True))
        assert cell["component_size"] == ""
        assert cell["onset_offset_s"] == "125.600"
        assert cell["time_to_first_candidate"] == "53.337"
        assert len(body) == len(tail.TAIL_TSV_COLUMNS)

    def test_dimension_catalog_covers_the_owners_15(self) -> None:
        # Every one of the owner's 15 dimensions is present exactly once, each
        # with a status and, when it is not plainly measurable, a reason.
        owner = [d.owner_name for d in tail.DIMENSIONS]
        assert len(owner) == len(set(owner))
        for keyword in ("seam type", "root-cause class", "incident size",
                        "topology depth", "affected-device count",
                        "evidence-modality count", "vantage",
                        "template-index", "candidate", "repeated evidence",
                        "forwarded vs suppressed", "relative to burst",
                        "cohorts", "ownership lookup", "component size"):
            assert any(keyword in name for name in owner), keyword
        for dim in tail.DIMENSIONS:
            assert dim.status in (tail.MEASURABLE, tail.PROXY,
                                  tail.NOT_MEASURABLE)
            assert dim.source
            if dim.status != tail.MEASURABLE:
                assert dim.note, f"{dim.name} must justify its status"

    def test_classification_json_is_serialisable_and_shaped(self) -> None:
        rows = [story(f"B{i}", 900.0, template="bgp", onset_offset_s=300.0)
                for i in range(10)]
        rows += [story(f"L{i}", 50.0, template="lan", onset_offset_s=float(i))
                 for i in range(90)]
        out = tail.classify_all(rows, pct)
        doc = json.loads(json.dumps(out))
        assert set(doc) == set(tail.TIMINGS)
        entry = doc["time_to_first_candidate"]
        for key in ("timing", "stories_scored", "censored", "tail_quantile",
                    "tail_threshold_s", "classified", "dimensions", "ranking",
                    "onset_band", "dominating_dimensions"):
            assert key in entry
        for dim in entry["dimensions"]:
            for key in ("dimension", "timing", "stories_scored",
                        "tail_stories", "tail_threshold_s", "buckets",
                        "na_stories", "top_bucket", "top_bucket_tail_share",
                        "top_bucket_story_share", "top_bucket_lift",
                        "concentration", "dominates"):
                assert key in dim, f"{dim['dimension']} missing {key}"
            for bucket in dim["buckets"]:
                for key in ("bucket", "stories", "story_share", "tail_stories",
                            "tail_share", "tail_rate", "lift", "p50_s",
                            "p95_s"):
                    assert key in bucket

    def test_markdown_renders_the_verdict_sentence_both_ways(self) -> None:
        def doc_for(rows: list[dict[str, Any]]) -> dict[str, Any]:
            return {"run": {"runid": "r", "profile": "p", "seed": 1,
                            "tenant": "global"},
                    "stories": len(rows), "generated_at": "now",
                    "caveats": tail.TAIL_CAVEATS,
                    "cohort_reconstruction": {"gap_s": 2.0, "reconstructed": 44,
                                              "engine_total": 46, "note": "n"},
                    "classification": tail.classify_all(rows, pct)}

        concentrated = [story(f"B{i}", 900.0, template="bgp")
                        for i in range(10)]
        concentrated += [story(f"L{i}", 50.0, template=f"t{i % 5}")
                         for i in range(90)]
        text = tail.render_markdown(doc_for(concentrated))
        assert "A small identity class DOES dominate" in text
        assert "`template`" in text
        assert "Onset-band check" in text
        assert "corr_engine_cohorts_total" in text
        # NOT MEASURABLE dimensions and their reasons must reach the reader.
        assert tail.NOT_MEASURABLE in text
        assert "ownership_lookup" in text

        spread: list[dict[str, Any]] = []
        for name in ("a", "b", "c", "d"):
            spread += [story(f"{name}s{i}", 900.0, template=name)
                       for i in range(3)]
            spread += [story(f"{name}f{i}", 50.0, template=name)
                       for i in range(22)]
        text2 = tail.render_markdown(doc_for(spread))
        assert "no small identity class dominates" in text2

    def test_markdown_says_not_classified_for_a_censored_timing(self) -> None:
        rows = [story(f"S{i}", 100.0, template="a") for i in range(5)]
        doc = {"run": {}, "stories": 5, "generated_at": "now",
               "caveats": [], "classification": tail.classify_all(rows, pct)}
        text = tail.render_markdown(doc)
        assert "**Not classified.**" in text


# ---------------------------------------------------------------------------
# timing_value — the boundary between "censored" and "zero"
# ---------------------------------------------------------------------------

class TestTimingValue:
    def test_none_and_missing_are_censored(self) -> None:
        assert tail.timing_value({}, "t") is None
        assert tail.timing_value({"t": None}, "t") is None

    def test_zero_is_a_real_latency_not_a_censoring(self) -> None:
        assert tail.timing_value({"t": 0.0}, "t") == 0.0

    def test_a_bool_flag_is_never_read_as_a_latency(self) -> None:
        assert tail.timing_value({"t": True}, "t") is None
        assert tail.timing_value({"t": False}, "t") is None

    def test_a_string_is_not_coerced(self) -> None:
        assert tail.timing_value({"t": "53.337"}, "t") is None


# ---------------------------------------------------------------------------
# Ranking statistic — excess, not raw tail share
# ---------------------------------------------------------------------------

class TestExcessRanking:
    def test_a_single_bucket_dimension_never_outranks_a_real_one(self) -> None:
        # `modality_count` is one bucket on the V1 syslog-only workload: it
        # holds 100 % of every tail by construction. Ranking on raw tail share
        # would put it first and bury the dimension that actually concentrates.
        rows = [story(f"B{i}", 900.0, template="bgp", modality_count=1)
                for i in range(10)]
        rows += [story(f"L{i}", 50.0, template=f"t{i % 5}", modality_count=1)
                 for i in range(90)]
        out = tail.classify_all(rows, pct)["time_to_first_candidate"]
        by = {d["dimension"]: d for d in out["dimensions"]}
        assert by["modality_count"]["concentration"] == 1.0
        assert by["modality_count"]["concentration_excess"] == 0.0
        assert by["modality_count"]["dominates"] is False
        order = [r["dimension"] for r in out["ranking"]]
        assert order.index("template") < order.index("modality_count")

    def test_excess_is_tail_share_minus_story_share(self) -> None:
        rows = [story(f"B{i}", 900.0, template="bgp") for i in range(10)]
        rows += [story(f"L{i}", 50.0, template="lan") for i in range(90)]
        out = tail.classify_dimension(rows, "template",
                                      "time_to_first_candidate", 100.0, pct)
        by = {b["bucket"]: b for b in out["buckets"]}
        assert by["bgp"]["excess"] == pytest.approx(1.0 - 0.1)
        assert by["lan"]["excess"] == pytest.approx(0.0 - 0.9)
        assert out["top_bucket"] == "bgp"
        assert out["concentration_excess"] == pytest.approx(0.9)

    def test_dominance_is_tested_over_every_bucket_not_only_the_top(self) -> None:
        # `wide` has the biggest excess; `narrow` is the one that clears the
        # dominance thresholds. Both must be visible.
        rows = [story(f"N{i}", 900.0, template="narrow") for i in range(6)]
        rows += [story(f"n{i}", 10.0, template="narrow") for i in range(4)]
        rows += [story(f"W{i}", 900.0, template="wide") for i in range(4)]
        rows += [story(f"w{i}", 10.0, template="wide") for i in range(86)]
        out = tail.classify_dimension(rows, "template",
                                      "time_to_first_candidate", 100.0, pct)
        assert out["tail_stories"] == 10
        assert out["dominating_buckets"] == ["narrow"]
        assert out["dominates"] is True

    def test_dominating_dimension_ranks_above_a_higher_excess_one(self) -> None:
        # The ordering contract: clearing the tracker's own test outranks a
        # merely larger excess, because the row asks "does a SMALL identity
        # class dominate", not "which bucket is biggest".
        rows = [story(f"S{i}", 900.0, template="small", seam_type="a")
                for i in range(9)]
        rows += [story(f"s{i}", 10.0, template="small", seam_type="a")
                 for i in range(1)]
        rows += [story(f"B{i}", 900.0, template="big", seam_type="b")
                 for i in range(1)]
        rows += [story(f"b{i}", 10.0, template="big", seam_type="b")
                 for i in range(89)]
        out = tail.classify_all(rows, pct)["time_to_first_candidate"]
        ranking = out["ranking"]
        assert ranking[0]["dominates"] is True
        assert out["dominating_dimensions"]


# ---------------------------------------------------------------------------
# Offline re-classify — the dimensions TSV this tool writes, read back
# ---------------------------------------------------------------------------

class TestDimensionsTsvRoundTrip:
    def test_render_then_parse_preserves_values_and_na(self) -> None:
        rows = [{"story_id": "I0001", "template": "bgp_peer_flap",
                 "seam_type": "wan_transport", "onset_offset_s": 645.1,
                 "affected_devices": 2, "component_size": None,
                 "agg_suppression": "forwarded_only",
                 "cohorts_before_verdict": 11,
                 "time_to_first_candidate": 883.6,
                 "time_to_first_correct": 883.6,
                 "time_to_useful": None, "time_to_stable": 883.6}]
        back = tail.parse_dimensions_tsv(tail.render_tsv(rows))
        assert len(back) == 1
        row = back[0]
        assert row["story_id"] == "I0001"
        assert row["affected_devices"] == 2
        assert row["cohorts_before_verdict"] == 11
        assert row["onset_offset_s"] == pytest.approx(645.1)
        assert row["time_to_first_candidate"] == pytest.approx(883.6)
        # NA survives as NA, in both a numeric and a timing column.
        assert row["component_size"] is None
        assert row["time_to_useful"] is None
        # ...and the mirrored onset lets the bucketer work off the parsed row.
        assert tail.bucket_of("onset_band", row["onset_band"]) == "600-699s"
        assert tail.bucket_of("component_size", row["component_size"]) == tail.NA

    def test_parsed_rows_classify_identically_to_the_originals(self) -> None:
        rows: list[dict[str, Any]] = []
        for i in range(10):
            rows.append(story(f"B{i}", 900.0, template="bgp",
                              onset_offset_s=640.0 + i, component_size=3))
        for i in range(90):
            rows.append(story(f"L{i}", 50.0, template="lan",
                              onset_offset_s=float(i), component_size=3))
        for row in rows:
            row["onset_band"] = row["onset_offset_s"]
        direct = tail.classify_all(rows, pct)
        back = tail.parse_dimensions_tsv(tail.render_tsv(rows))
        assert tail.classify_all(back, pct) == direct

    def test_missing_required_column_is_fatal(self) -> None:
        with pytest.raises(SystemExit):
            tail.parse_dimensions_tsv("story_id\ttemplate\nI0001\tbgp\n")
