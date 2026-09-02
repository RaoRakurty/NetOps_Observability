#!/usr/bin/env python3
"""tracker 205 STEP 2 — classify the RCA latency TAIL, before any optimization.

Step 1 (`scripts/scale-rca-latency.py --ground-truth`,
`docs/scale/USEFUL_RCA_DEFINITION_2026-09-02.md`) defined "Useful RCA" and
measured four per-story latencies.  This tool answers the ONE question the
tracker row asks next: **does a small identity class dominate the long tail?**

It joins every story to the owner's 15 tail dimensions and, for each timing and
each measurable dimension, reports the p50/p95 inside every bucket, the bucket's
share of the tail (stories above the timing's overall p90) and a CONCENTRATION
statistic — a bucket that holds > 50 % of the tail while holding < 25 % of the
stories is the "small identity class dominates" test.  Dimensions are ranked by
that concentration.  It also runs the 5k rung's onset-band check
(`docs/scale/HOST_CEILING_2026-08-31.md` §3): the tightest window containing
80 % of the TAIL stories' onset offsets against the same window for ALL stories.

IT PROPOSES NOTHING.  Naming the contributor is the deliverable; the fix is not.

READ-ONLY.  Two bounded SELECT scans of `netops.corr_objects`, both tenant- and
burst-window-scoped, both excluding the storm-aggregate object (whose
`hypotheses` blob is ~1 GiB), both sliced with `max_execution_time`,
`max_memory_usage`, `max_block_size` and `max_threads` set — the same
containment step 1 uses, because the same defect (tracker 201) applies.

REUSE, NOT REIMPLEMENTATION.  `scripts/scale-rca-latency.py` is imported by path
and supplies the ClickHouse access layer, the ground-truth loader, the version
scan, the scorer-v2 story->object membership map and the nearest-rank
percentile.  A second story->object mapping would be a second answer to a
question that already has one.

THE TIMINGS ARE NOT RE-MEASURED.  They are read from step 1's own
`ttur-useful.tsv`, so every number here indexes the published measurement rather
than a fresh one that could differ.

WHERE EACH ENGINE-SIDE DIMENSION IS SAMPLED: at the story's FIRST CANDIDATE —
the first persisted version of any object that touches it.  That is the moment
the latency being explained ends, so it is the state that can explain it.
Run-maximum variants are emitted beside it as diagnostics, never as buckets.

Usage:
    python3 scripts/scale-rca-tail.py <run-dir> [--tenant global]
                                      [--out-dir <dir>] [--step1-tsv <path>]

Outputs, into --out-dir (default: the run dir):
    tail-dimensions.tsv        one row per story, 15 dimensions + timings
    tail-classification.json   per timing x dimension bucket stats + ranking
    tail-classification.md     the same, human-readable

Tests: tests/test_scale_rca_tail.py (no docker; pure functions only).
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
from collections.abc import Callable, Sequence
from datetime import datetime, timedelta, timezone
from itertools import pairwise
from typing import Any, NoReturn

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(SCRIPT_DIR)

STEP1_TOOL = "scripts/scale-rca-latency.py"
STEP1_TSV = "ttur-useful.tsv"
STEP1_SUMMARY = "ttur-useful-summary.json"
DIM_TSV = "tail-dimensions.tsv"
CLASS_JSON = "tail-classification.json"
CLASS_MD = "tail-classification.md"
DEF_DOC = "docs/scale/USEFUL_RCA_DEFINITION_2026-09-02.md"
CEILING_DOC = "docs/scale/HOST_CEILING_2026-08-31.md"

# The timings this tool classifies. `time_to_useful` is 100 % censored on the
# V1 (syslog-only) workload — it is carried anyway so that a future
# multi-modality run classifies it with no code change, and so that its absence
# is a reported censoring rather than a silent omission.
TIMINGS = ("time_to_first_candidate", "time_to_first_correct",
           "time_to_useful", "time_to_stable")

# The tail is "above the overall p90 of this timing", over the NON-CENSORED
# stories of that timing. p90 (not p95) so the tail set is large enough for a
# per-bucket share to mean anything at n=345.
TAIL_QUANTILE = 90.0

# The tracker's own test, as two numbers: a bucket DOMINATES the tail when it
# holds more than half of it while holding less than a quarter of the stories.
DOMINATE_TAIL_SHARE = 0.50
DOMINATE_STORY_SHARE = 0.25

# The onset-band check from the 5k clue: the tightest window containing this
# share of a population's onset offsets.
BAND_COVERAGE = 0.80

# Query containment, identical in spirit to step 1's (which owns the constants
# for its own scan; these bound the companion scan).
DIM_SLICE_TIMEOUT = 60
DIM_CH_MAX_MEMORY = 2 << 30
DIM_CH_MAX_BLOCK = 256
DIM_CH_MAX_THREADS = 2
DEFAULT_DIM_SLICES = 6
DEFAULT_MAX_VERSIONS = 400_000

# Cohort reconstruction: the engine persists a correlation transaction's
# versions in one burst, so a gap in the GLOBAL created_at stream is a cohort
# boundary. Validated against `corr_engine_cohorts_total` in metrics-final.txt
# and reported with that comparison — never asserted silently.
DEFAULT_COHORT_GAP_S = 2.0

NA = "NA"

TAIL_CAVEATS = [
    ("The timings are READ from step 1's ttur-useful.tsv, not re-measured: "
     "this tool classifies the published measurement rather than a second one."),
    ("Engine-side dimensions are sampled AT THE STORY'S FIRST CANDIDATE (the "
     "state at the moment the latency ends). Run-maximum variants are emitted "
     "as diagnostics and are never used as buckets."),
    ("A story whose dimension has no value gets the explicit bucket \"NA\". NA "
     "is reported with its counts and is EXCLUDED from the concentration test "
     "— an unmeasured story must never look like a small identity class."),
    ("The tail is defined per timing as \"above the overall p90 of that "
     "timing\", over that timing's NON-CENSORED stories only. A fully censored "
     "timing (time_to_useful on the V1 syslog-only workload) yields no tail and "
     "is reported as such, never as an empty win."),
    ("Percentiles are NEAREST-RANK (step 1's `pct`, imported), so a bucket of "
     "n<20 has a p95 that is one story. Bucket n travels with every number."),
    ("Dimensions are RANKED by EXCESS (a bucket's tail share minus its story "
     "share), not by raw tail share: a dimension with only one bucket holds "
     "100 % of the tail by construction and explains nothing. Raw tail share "
     "is reported beside it."),
    ("Correlation, not causation: a bucket that holds the tail is where the "
     "latency IS, not proof of why. The row asks to NAME the contributor "
     "before optimizing, and that is all this tool does."),
]


# ---------------------------------------------------------------------------
# Structured logging + fatal errors (CLAUDE.md 10: no silent failures)
# ---------------------------------------------------------------------------

def log(event: str, **fields: object) -> None:
    """One structured line per event: `rca-tail event k=v k=v`."""
    parts = [f"rca-tail {event}"]
    for key in sorted(fields):
        value = fields[key]
        text = f"{value:.3f}" if isinstance(value, float) else str(value)
        parts.append(f"{key}={text}")
    print(" ".join(parts), file=sys.stderr, flush=True)


def die(msg: str, code: int = 2) -> NoReturn:
    print(f"rca-tail ERROR {msg}", file=sys.stderr, flush=True)
    sys.exit(code)


def load_step1() -> Any:
    """Import `scripts/scale-rca-latency.py` (dashed name -> by path).

    It owns the ClickHouse layer, the ground-truth loader, the version scan and
    the scorer-v2 story->object membership map. Re-deriving any of those here
    would be a SECOND answer to a question that already has one, and the two
    would drift. Import failure is fatal."""
    path = os.path.join(SCRIPT_DIR, "scale-rca-latency.py")
    spec = importlib.util.spec_from_file_location("scale_rca_latency", path)
    if spec is None or spec.loader is None:
        die(f"cannot load {path} — it owns the step-1 helpers this mode reuses")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["scale_rca_latency"] = mod
    try:
        spec.loader.exec_module(mod)
    except Exception as exc:      # noqa: BLE001 — report, never swallow
        die(f"importing {path} failed: {exc!r}")
    for name in ("ClickHouse", "load_ab_driver", "load_ground_truth",
                 "object_story_map", "fetch_gt_versions", "ObjectHistory",
                 "read_json_file", "pct", "SAFE_TOKEN_RE", "sql_str",
                 "env_get", "DEFAULT_ENV_FILE", "CRON_PATH"):
        if not hasattr(mod, name):
            die(f"{path} has no {name} — the step-1 contract moved; refusing "
                f"to re-implement it here")
    return mod


# ---------------------------------------------------------------------------
# Step-1 TSV
# ---------------------------------------------------------------------------

STEP1_REQUIRED = ("story_id", "template", "onset_offset_s",
                  "time_to_first_candidate", "time_to_first_correct",
                  "time_to_useful", "time_to_stable")


def parse_step1_tsv(text: str) -> list[dict[str, object]]:
    """Step 1's `ttur-useful.tsv` -> rows. An EMPTY cell is a censored timing
    (None), never 0.0 — the distinction is the whole point of step 1's
    censoring rules, so it is preserved here rather than coerced."""
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if not lines:
        die(f"{STEP1_TSV} is empty — step 1 has not run on this leg", 1)
    header = lines[0].split("\t")
    missing = [c for c in STEP1_REQUIRED if c not in header]
    if missing:
        die(f"{STEP1_TSV} is missing column(s) {missing} — this is not a "
            f"tracker-205 step-1 TSV", 1)
    idx = {name: i for i, name in enumerate(header)}
    numeric = {"onset_offset_s", "time_to_first_candidate",
               "time_to_first_correct", "time_to_useful", "time_to_stable",
               "blast_recall"}
    integer = {"onset_ms", "objects", "versions", "max_modality_coverage",
               "max_observer_coverage"}
    rows: list[dict[str, object]] = []
    for lineno, line in enumerate(lines[1:], 2):
        cells = line.split("\t")
        if len(cells) != len(header):
            die(f"{STEP1_TSV}:{lineno} has {len(cells)} cells, header has "
                f"{len(header)}", 1)
        row: dict[str, object] = {}
        for name, i in idx.items():
            raw = cells[i]
            if name in numeric:
                row[name] = None if raw == "" else _as_float(raw, name, lineno)
            elif name in integer:
                row[name] = None if raw == "" else _as_int(raw, name, lineno)
            else:
                row[name] = raw
        if not row.get("story_id"):
            die(f"{STEP1_TSV}:{lineno} carries no story_id", 1)
        rows.append(row)
    return rows


def _as_float(raw: str, name: str, lineno: int,
              where: str = STEP1_TSV) -> float:
    try:
        return float(raw)
    except ValueError:
        die(f"{where}:{lineno} column {name}: {raw!r} is not a number", 1)


def _as_int(raw: str, name: str, lineno: int, where: str = STEP1_TSV) -> int:
    try:
        return int(raw)
    except ValueError:
        die(f"{where}:{lineno} column {name}: {raw!r} is not an integer", 1)


DIM_TSV_FLOAT = ("onset_offset_s",) + TIMINGS
DIM_TSV_INT = ("objects", "affected_devices", "truth_vantage_count",
               "blast_wave_depth", "engine_evidence_size", "component_size",
               "candidate_count", "hyp_satisfied_count", "modality_count",
               "observer_count", "agg_forwarded", "agg_suppressed",
               "cohorts_before_verdict")


def parse_dimensions_tsv(text: str) -> list[dict[str, object]]:
    """This tool's OWN `tail-dimensions.tsv` -> rows, for `--from-dimensions`.

    Re-classifying an already-joined leg must not require a second 6-minute
    read of ClickHouse; the join is the expensive part and it is already on
    disk. An empty cell stays None (NA), never 0 — the same rule the step-1
    reader follows, for the same reason."""
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if not lines:
        die(f"{DIM_TSV} is empty", 1)
    header = lines[0].split("\t")
    missing = [c for c in ("story_id", "onset_offset_s") + TIMINGS
               if c not in header]
    if missing:
        die(f"{DIM_TSV} is missing column(s) {missing}", 1)
    rows: list[dict[str, object]] = []
    for lineno, line in enumerate(lines[1:], 2):
        cells = line.split("\t")
        if len(cells) != len(header):
            die(f"{DIM_TSV}:{lineno} has {len(cells)} cells, header "
                f"has {len(header)}", 1)
        row: dict[str, object] = {}
        for name, raw in zip(header, cells, strict=True):
            if raw == "":
                row[name] = None
            elif name in DIM_TSV_FLOAT:
                row[name] = _as_float(raw, name, lineno, DIM_TSV)
            elif name in DIM_TSV_INT:
                row[name] = _as_int(raw, name, lineno, DIM_TSV)
            else:
                row[name] = raw
        # `onset_band` buckets off the raw onset, which the TSV stores under
        # its own name; mirror it so the bucketer finds it.
        row["onset_band"] = row.get("onset_offset_s")
        rows.append(row)
    return rows


# ---------------------------------------------------------------------------
# The companion version scan — the per-version dimension columns
# ---------------------------------------------------------------------------

def sql_dim_versions(sql_str: Callable[[str], str], tenant: str, agg_cid: str,
                     lo: str, hi: str) -> str:
    """One row per persisted version, carrying ONLY the tail-dimension columns.

    Every JSON parse is SERVER-side: the 26 KB `hypotheses` blob never crosses
    the wire. Kept disjoint from step 1's own scan so neither tool's contract
    moves when the other's does."""
    return f"""
WITH
  JSONExtractArrayRaw(JSONExtractRaw(hypotheses, 'ranking'), 'hypotheses') AS hs,
  JSONExtractRaw(hypotheses, 'grounding_context', 'aggregation') AS agg
SELECT
  toString(correlation_id) AS cid,
  toUInt32(version) AS version,
  toUnixTimestamp64Milli(created_at) AS ca_ms,
  toUInt16(length(hs)) AS n_hyp,
  toUInt16(length(arrayFilter(x -> JSONLength(x, 'satisfied') > 0, hs))) AS n_hyp_satisfied,
  toUInt32(node_count) AS nodes,
  toUInt32(signal_count) AS signals,
  toUInt32(JSONExtractUInt(agg, 'deltas')) AS agg_deltas,
  toUInt32(JSONExtractUInt(agg, 'keys')) AS agg_keys,
  toUInt32(JSONExtractUInt(agg, 'raw_signal_count')) AS agg_raw,
  arrayStringConcat(arraySort(JSONExtractKeys(JSONExtractRaw(agg, 'classes'))), '+') AS agg_classes,
  toUInt8(JSONExtractRaw(hypotheses, 'grounding_context', 'seams') NOT IN ('', 'null', '[]')) AS has_seams,
  toUInt8(attribution NOT IN ('', '{{}}')) AS has_attribution
FROM netops.corr_objects
WHERE tenant_id = {sql_str(tenant)}
  AND created_at >= toDateTime64({sql_str(lo)}, 3)
  AND created_at < toDateTime64({sql_str(hi)}, 3)
  AND correlation_id != toUUID({sql_str(agg_cid)})
""".strip()


DIM_INT_FIELDS = ("version", "ca_ms", "n_hyp", "n_hyp_satisfied", "nodes",
                  "signals", "agg_deltas", "agg_keys", "agg_raw", "has_seams",
                  "has_attribution")


def fetch_dim_versions(ch: Any, sql_str: Callable[[str], str], tenant: str,
                       agg_cid: str, lo: str, hi: str, slices: int,
                       max_rows: int) -> dict[tuple[str, int], dict[str, Any]]:
    """The companion scan, in bounded created_at slices. Keyed by (cid, ca_ms)
    so it joins onto step 1's version rows without assuming version numbers are
    unique (an engine restart resets the per-object counter)."""
    lo_dt = datetime.strptime(lo, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    hi_dt = datetime.strptime(hi, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    span = (hi_dt - lo_dt).total_seconds()
    if span <= 0:
        die(f"dimension scan window {lo} .. {hi} is empty or inverted", 1)
    step = span / slices
    out: dict[tuple[str, int], dict[str, Any]] = {}
    for i in range(slices):
        a = lo_dt + timedelta(seconds=step * i)
        b = hi_dt if i == slices - 1 else lo_dt + timedelta(seconds=step * (i + 1))
        a_lit = a.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        b_lit = b.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        log("dim_scan_slice", slice=f"{i + 1}/{slices}", lo=a_lit, hi=b_lit)
        ok, text, err = ch.query(
            sql_dim_versions(sql_str, tenant, agg_cid, a_lit, b_lit),
            settings={"max_execution_time": DIM_SLICE_TIMEOUT,
                      "max_memory_usage": DIM_CH_MAX_MEMORY,
                      "max_block_size": DIM_CH_MAX_BLOCK,
                      "max_threads": DIM_CH_MAX_THREADS},
            fmt="JSONEachRow", timeout=DIM_SLICE_TIMEOUT + 30)
        if not ok:
            die(f"dimension scan slice {i + 1}/{slices} ({a_lit} .. {b_lit}) "
                f"FAILED: {err} — narrow with --dim-slices rather than "
                f"reporting a partial corpus", 1)
        for line in text.splitlines():
            if not line.strip():
                continue
            try:
                doc = json.loads(line)
                rec: dict[str, Any] = {k: int(doc[k]) for k in DIM_INT_FIELDS}
                rec["cid"] = str(doc["cid"])
                rec["agg_classes"] = str(doc["agg_classes"])
            except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
                die(f"malformed dimension row in slice {i + 1}: {exc}", 1)
            out[(rec["cid"], rec["ca_ms"])] = rec
        if len(out) > max_rows:
            die(f"dimension scan exceeded --max-versions ({max_rows:,})", 1)
    if not out:
        die("the dimension scan returned NO rows for the leg's scope — empty "
            "is an error, not a zero", 1)
    return out


# ---------------------------------------------------------------------------
# Cohort reconstruction (dimension 13)
# ---------------------------------------------------------------------------

def reconstruct_cohorts(ca_ms: Sequence[int], gap_s: float) -> list[int]:
    """Cohort START timestamps, from a gap in the GLOBAL persist stream.

    The engine drains one correlation transaction (a cohort) and persists its
    versions in a burst; a quiet interval longer than `gap_s` between two
    consecutive persists is therefore a cohort boundary. This is a
    RECONSTRUCTION, not a persisted field — no per-object cohort id exists —
    so the caller compares the count against the engine's own
    `corr_engine_cohorts_total` and reports both."""
    if not ca_ms:
        return []
    gap_ms = int(gap_s * 1000)
    ordered = sorted(ca_ms)
    starts = [ordered[0]]
    for prev, cur in pairwise(ordered):
        if cur - prev > gap_ms:
            starts.append(cur)
    return starts


def cohorts_between(starts: Sequence[int], lo_ms: int, hi_ms: int) -> int:
    """Cohorts that STARTED in (lo_ms, hi_ms]. Negative spans give 0, never a
    negative count."""
    if hi_ms <= lo_ms:
        return 0
    return sum(1 for s in starts if lo_ms < s <= hi_ms)


# ---------------------------------------------------------------------------
# Bucketing — deterministic edges, never data-derived (so a test can pin them
# and two runs are comparable)
# ---------------------------------------------------------------------------

def bucket_numeric(value: float | None, edges: Sequence[int],
                   lo0: int = 1) -> str:
    """`edges` are the INCLUSIVE upper bounds of every bucket but the last;
    `lo0` is the smallest value the dimension can take.

    `bucket_numeric(3, (1, 2, 9), lo0=1)` -> "3-9";
    `bucket_numeric(3, (4, 16), lo0=1)` -> "1-4".

    None -> "NA". A value below `lo0` gets its own "<lo0" bucket rather than
    being folded into the first real one — an out-of-range value must be
    visible, not absorbed."""
    if value is None:
        return NA
    if value < lo0:
        return f"<{lo0}"
    lo = lo0
    for hi in edges:
        if value <= hi:
            return str(hi) if lo == hi else f"{lo}-{hi}"
        lo = hi + 1
    return f"{edges[-1] + 1}+"


def bucket_exact(value: float | None, cap: int) -> str:
    """Exact small integers, everything at or above `cap` folded into "<cap>+"."""
    if value is None:
        return NA
    n = int(value)
    return f"{cap}+" if n >= cap else str(n)


def bucket_categorical(value: object) -> str:
    if value is None:
        return NA
    text = str(value)
    return text if text else NA


def bucket_onset(value: float | None, width: float = 100.0) -> str:
    """Onset offset within the burst, in fixed `width`-second bands. Fixed, not
    quantile, bands: the 5k clue is a 154 s WALL-CLOCK band, and a quantile band
    would move with the population."""
    if value is None:
        return NA
    if value < 0:
        return "<0"
    lo = int(value // width) * int(width)
    return f"{lo}-{lo + int(width) - 1}s"


# ---------------------------------------------------------------------------
# The 15 dimensions
# ---------------------------------------------------------------------------

MEASURABLE = "MEASURABLE"
PROXY = "PROXY"
NOT_MEASURABLE = "NOT MEASURABLE"


class Dimension:
    """One of the owner's 15 tail dimensions, and where its value comes from."""

    __slots__ = ("column", "name", "note", "owner_name", "source", "status")

    def __init__(self, name: str, owner_name: str, status: str, source: str,
                 note: str = "", column: str = ""):
        self.name = name
        self.owner_name = owner_name
        self.status = status
        self.source = source
        self.note = note
        self.column = column or name

    def as_dict(self) -> dict[str, str]:
        return {"dimension": self.name, "owner_dimension": self.owner_name,
                "status": self.status, "source": self.source,
                "note": self.note, "column": self.column}


DIMENSIONS: tuple[Dimension, ...] = (
    Dimension(
        "seam_type", "seam type", MEASURABLE,
        "ground_truth.jsonl labels.expected_seam_class (== ground-truth.json "
        "incidents[].expected_seam_class)",
        "TRUTH SIDE ONLY. The engine persists no seam grounding on this "
        "corpus: `grounding_context.seams` is [] on every version and "
        "corr_edges carries no grounding_kind='seam' row, because the "
        "miniladder onboards devices with no seam configuration (step 1 §1b). "
        "The bucket is therefore the INJECTED seam class, which is exactly what "
        "a tail classification needs — it identifies the story, it does not "
        "score the engine."),
    Dimension(
        "template", "root-cause class (template)", MEASURABLE,
        "ground_truth.jsonl template (== ground-truth.json cause_kind)"),
    Dimension(
        "incident_size", "incident size (scenario events per story)",
        NOT_MEASURABLE,
        "no artifact carries a per-story scenario event count",
        "ground-truth.json counts.chain_events_by_type is CORPUS-GLOBAL; "
        "burst-chunks.json is per-10 s-chunk global (lanes/scenario totals, no "
        "story id); only the 15 enterprise_outage stories carry "
        "`unpromotable_events`, and no story carries a promoted-event count. "
        "The engine-side stand-in `engine_evidence_size` (signal_count at first "
        "candidate) is emitted as a SEPARATE, explicitly-labelled proxy — it is "
        "post-aggregation and is shared by every story folded into the same "
        "correlation object, so it is not the owner's quantity."),
    Dimension(
        "engine_evidence_size", "incident size — engine-side proxy", PROXY,
        "corr_objects.signal_count of the best object at first candidate",
        "Post-aggregation and object-shared; a proxy for incident size, NOT the "
        "scenario event count the owner named."),
    Dimension(
        "topology_depth", "topology depth", NOT_MEASURABLE,
        "no topology is provisioned on the miniladder fleet",
        "`grounding_context.seams` is [] and `topology_gap_hints` is 0 on all "
        "10,826 versions; there is no adjacency graph to take a depth over. The "
        "INJECTED propagation depth is available and is emitted as the labelled "
        "proxy `blast_wave_depth`."),
    Dimension(
        "blast_wave_depth", "topology depth — injected-propagation proxy", PROXY,
        "ground-truth.json incidents[].blast_radius_waves (count of waves)",
        "The number of propagation waves the generator injected from the cause "
        "entity. A depth in the INJECTED fault, not in the estate's topology."),
    Dimension(
        "affected_devices", "affected-device count", MEASURABLE,
        "ground_truth.jsonl labels.blast_radius (length)"),
    Dimension(
        "modality_count", "evidence-modality count", MEASURABLE,
        "hypotheses.ranking.hypotheses[top].verdict.modality_coverage (length) "
        "at first candidate",
        "DEGENERATE on this corpus: the V1 workload is syslog-only, so every "
        "story sits in one bucket. Reported, and its single-bucket state is "
        "stated rather than dressed up as a 100 % concentration."),
    Dimension(
        "observer_count", "independent vantage (observer) count", MEASURABLE,
        "hypotheses.ranking.hypotheses[top].verdict.observer_coverage (length) "
        "at first candidate"),
    Dimension(
        "truth_vantage_count", "independent vantage count — truth side",
        MEASURABLE,
        "ground-truth.json incidents[].vantages (length)"),
    Dimension(
        "template_index", "template-index hit vs fallback", NOT_MEASURABLE,
        "the tracker-167 kind index keeps only GLOBAL counters",
        "`corr_template_scored_total` / `corr_template_candidates_total` / "
        "`corr_template_ungrounded_total` (scoring.py) are process-wide "
        "counters in the metrics exposition; nothing per-object records whether "
        "a given template was admitted by the kind index or elided. The "
        "per-object stand-ins are emitted as labelled proxies: "
        "`hyp_satisfied_count` (ranked hypotheses whose `satisfied` clause list "
        "is non-empty = templates the evidence actually reached) and "
        "`top_rank_fallback` (the object's top_hypothesis id is absent from its "
        "own ranking — step 1's `top_fallback`, 5 versions of 10,826). The "
        "tracker-157 structural refusal never fired on this corpus (0 versions "
        "carry the 'suppressed: this signature names' note), so that gate "
        "contributes no variance either."),
    Dimension(
        "hyp_satisfied_count", "template-index hit — per-object proxy", PROXY,
        "count of ranking.hypotheses[] with a non-empty `satisfied` list, at "
        "first candidate",
        "A template with a satisfied clause is one the evidence REACHED — the "
        "same population the kind index admits — but this counts the ranking's "
        "OUTPUT, not the index's decision, and it cannot see a template the "
        "index elided analytically. A proxy for the gate, not the gate."),
    Dimension(
        "candidate_count", "candidate (hypothesis) count", MEASURABLE,
        "length(hypotheses.ranking.hypotheses) at first candidate"),
    Dimension(
        "evidence_recurrence", "first occurrence vs repeated evidence",
        MEASURABLE,
        "hypotheses.grounding_context.aggregation.classes (the DeltaClass "
        "histogram: first / state_transition / recovery / repeat / "
        "count_threshold), at first candidate — the bucket is the sorted set of "
        "classes present"),
    Dimension(
        "agg_suppression", "aggregation forwarded vs suppressed", MEASURABLE,
        "hypotheses.grounding_context.aggregation: forwarded = `deltas`, "
        "suppressed = `raw_signal_count` - `deltas`, at first candidate",
        "`raw_signal_count` is a LOWER BOUND on raw coverage by the engine's "
        "own docstring (Σ over key of MAX(agg_count)); repeats arriving after a "
        "key's last delta are absorbed and never re-announced. So "
        "'some_suppressed' is sound and 'forwarded_only' means 'no suppression "
        "VISIBLE to the object', not a proof of none."),
    Dimension(
        "onset_band", "incident creation time relative to burst", MEASURABLE,
        "ground-truth.json incidents[].onset_ts (seconds into the 900 s burst), "
        "in fixed 100 s bands"),
    Dimension(
        "cohorts_before_verdict", "number of cohorts before first verdict",
        PROXY,
        "reconstructed: cohort boundaries are gaps > --cohort-gap-s in the "
        "GLOBAL corr_objects created_at stream; the dimension counts cohorts "
        "that started in (onset, first_correct]",
        "No per-object cohort id is persisted. The reconstruction is validated "
        "against the engine's own `corr_engine_cohorts_total` in "
        "metrics-final.txt and BOTH numbers are reported; a disagreement is "
        "printed, never hidden. AND IT IS PARTLY CIRCULAR: the count is taken "
        "over (onset, first_correct], so it grows WITH the latency it is meant "
        "to explain — a story that took longer necessarily spans more cohorts. "
        "It is measured because the owner named it, and it must be read as a "
        "RESTATEMENT of the latency in cohort units, never as a cause."),
    Dimension(
        "ownership_lookup", "ownership lookup path", NOT_MEASURABLE,
        "corr_objects.attribution is '{}' on every version in scope",
        "Measured, not assumed: 0 of 10,826 in-scope versions carry a non-empty "
        "`attribution`, `grounding_context.seams` is [] everywhere, and "
        "`verdict.owner` is DECLARED by the matched catalog template rather than "
        "resolved through a lookup — so there is no path to bucket. Step 1 "
        "already recorded the same gap for the ownership_domain clause."),
    Dimension(
        "component_size", "component size", MEASURABLE,
        "corr_objects.node_count of the best object at first candidate"),
)

DIMS_BY_NAME = {d.name: d for d in DIMENSIONS}

# Every dimension that produces a bucket (MEASURABLE or PROXY). NOT MEASURABLE
# dimensions produce no column and no bucket — they are carried in the output
# so the reader sees all 15 with their reasons.
BUCKETED = tuple(d.name for d in DIMENSIONS if d.status != NOT_MEASURABLE)

BUCKETERS: dict[str, Callable[[object], str]] = {
    "seam_type": bucket_categorical,
    "template": bucket_categorical,
    "engine_evidence_size": lambda v: bucket_numeric(
        _num(v), (4, 16, 64, 256, 1024), 1),
    "blast_wave_depth": lambda v: bucket_exact(_num(v), 4),
    "affected_devices": lambda v: bucket_numeric(_num(v), (1, 2, 9, 24, 39), 1),
    "modality_count": lambda v: bucket_exact(_num(v), 3),
    "observer_count": lambda v: bucket_numeric(_num(v), (0, 1, 2, 9), 0),
    "truth_vantage_count": lambda v: bucket_numeric(_num(v), (1, 2, 9), 1),
    "hyp_satisfied_count": lambda v: bucket_exact(_num(v), 12),
    "candidate_count": lambda v: bucket_numeric(_num(v), (4, 8, 12, 17), 1),
    "evidence_recurrence": bucket_categorical,
    "agg_suppression": bucket_categorical,
    "onset_band": lambda v: bucket_onset(_fnum(v)),
    "cohorts_before_verdict": lambda v: bucket_exact(_num(v), 10),
    "component_size": lambda v: bucket_numeric(
        _num(v), (1, 4, 16, 64, 256, 1024), 1),
}


def _num(value: object) -> int | None:
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float)):
        return int(value)
    try:
        return int(float(str(value)))
    except ValueError:
        return None


def _fnum(value: object) -> float | None:
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    try:
        return float(str(value))
    except ValueError:
        return None


def bucket_of(dimension: str, value: object) -> str:
    """The bucket label for one dimension value. An unknown dimension is a
    programming error, not a silent NA."""
    fn = BUCKETERS.get(dimension)
    if fn is None:
        raise KeyError(f"no bucketer for dimension {dimension!r}")
    return fn(value)


# ---------------------------------------------------------------------------
# Per-story dimension values
# ---------------------------------------------------------------------------

def story_dimensions(story: Any, tsv_row: dict[str, object],
                     objs: Sequence[Any],
                     dims: dict[tuple[str, int], dict[str, Any]],
                     incident: dict[str, object],
                     cohort_starts: Sequence[int]) -> dict[str, object]:
    """Every dimension value for one story.

    Engine-side dimensions are read at the story's FIRST CANDIDATE: the first
    persisted version of any touching object. Truth-side dimensions come from
    the ground truth. A value that does not exist is None, which buckets to NA
    — it is never defaulted to 0, which would put an unmeasured story into a
    real bucket."""
    out: dict[str, object] = {
        "story_id": story.story_id,
        "template": story.template,
        "seam_type": story.seam_class or None,
        "expected_owner_class": story.owner_class or None,
        "affected_devices": len(story.blast_truth) or None,
        "onset_band": story.onset_s,
        "onset_offset_s": story.onset_s,
        "truth_vantage_count": _list_len(incident.get("vantages")),
        "blast_wave_depth": _list_len(incident.get("blast_radius_waves")),
        "objects": len(objs),
    }
    for name in ("engine_evidence_size", "modality_count", "observer_count",
                 "hyp_satisfied_count", "candidate_count",
                 "evidence_recurrence", "agg_suppression", "component_size"):
        out[name] = None
    out["agg_forwarded"] = None
    out["agg_suppressed"] = None
    out["cohorts_before_verdict"] = None

    events = sorted({v.ca_ms for obj in objs for v in obj.versions})
    if not events:
        return out
    at = events[0]
    snap = [s for s in (o.snapshot(at) for o in objs) if s is not None]
    live = [v for v in snap if v.state != "merged"]
    best = _best_of(live)
    if best is not None:
        out["modality_count"] = best.n_modality
        out["observer_count"] = best.n_observer
        out["component_size"] = best.nodes
        rec = dims.get((best.cid, best.ca_ms))
        if rec is not None:
            out["engine_evidence_size"] = rec["signals"]
            out["hyp_satisfied_count"] = rec["n_hyp_satisfied"]
            out["candidate_count"] = rec["n_hyp"]
            out["evidence_recurrence"] = rec["agg_classes"] or None
            forwarded = rec["agg_deltas"]
            suppressed = max(0, rec["agg_raw"] - rec["agg_deltas"])
            out["agg_forwarded"] = forwarded
            out["agg_suppressed"] = suppressed
            out["agg_suppression"] = ("some_suppressed" if suppressed > 0
                                      else "forwarded_only")

    first_correct = tsv_row.get("time_to_first_correct")
    if isinstance(first_correct, float):
        verdict_ms = story.onset_ms + int(first_correct * 1000)
        out["cohorts_before_verdict"] = cohorts_between(
            cohort_starts, story.onset_ms, verdict_ms)
    return out


def _best_of(live: Sequence[Any]) -> Any:
    """scorer v2 `_best_object`, as step 1 implements it. Kept as a two-line
    delegation so the tie-break ordering has exactly one definition in the
    repo; the step-1 module's private helper is bound at call time."""
    if not live:
        return None
    tier_rank = {"undetermined": 0, "suspected": 1, "confirmed": 2}
    return min(live, key=lambda v: (-tier_rank.get(v.tier, 0), -float(v.nodes),
                                    -v.conf, v.cid))


def _list_len(value: object) -> int | None:
    return len(value) if isinstance(value, list) and value else None


# ---------------------------------------------------------------------------
# The classification itself
# ---------------------------------------------------------------------------

def timing_value(row: dict[str, object], key: str) -> float | None:
    """A latency (or onset) cell as a float, or None when it is CENSORED.

    `isinstance(x, bool)` is excluded deliberately: a bool is an int in Python
    and a flag column must never be read as a latency of 1 second."""
    value = row.get(key)
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    return None


def classify_dimension(rows: Sequence[dict[str, object]], dimension: str,
                       timing: str, threshold: float,
                       pctf: Callable[[list[float], float], float | None]
                       ) -> dict[str, Any]:
    """Bucket stats + the concentration statistic for ONE dimension and ONE
    timing.

    Only stories with a NON-CENSORED value for `timing` participate: a censored
    story has no latency to attribute. NA buckets are reported with their counts
    and EXCLUDED from the dominance test."""
    scored = [(r, t) for r, t in
              ((r, timing_value(r, timing)) for r in rows) if t is not None]
    buckets: dict[str, list[float]] = {}
    for row, value in scored:
        label = bucket_of(dimension, row.get(dimension))
        buckets.setdefault(label, []).append(value)
    total = len(scored)
    tail_total = sum(1 for _, t in scored if t > threshold)
    out_buckets: list[dict[str, Any]] = []
    real: list[dict[str, Any]] = []      # every bucket except NA
    best: dict[str, Any] | None = None
    for label in sorted(buckets):
        values = sorted(buckets[label])
        n_tail = sum(1 for v in values if v > threshold)
        story_share = len(values) / total if total else 0.0
        tail_share = n_tail / tail_total if tail_total else 0.0
        entry: dict[str, Any] = {
            "bucket": label,
            "stories": len(values),
            "story_share": round(story_share, 4),
            "tail_stories": n_tail,
            "tail_share": round(tail_share, 4),
            "tail_rate": round(n_tail / len(values), 4) if values else 0.0,
            "lift": round(tail_share / story_share, 3) if story_share else None,
            # EXCESS is the ranking statistic, and raw tail share is not.
            # A dimension with ONE bucket holds 100 % of the tail by
            # construction (modality_count on a syslog-only workload does
            # exactly that) and explains nothing; excess = tail share MINUS
            # story share is 0 for it, and large only when a bucket holds more
            # of the tail than of the corpus. Raw `tail_share` is reported
            # beside it because the tracker row asks for it.
            "excess": round(tail_share - story_share, 4),
            "p50_s": pctf(values, 50.0),
            "p95_s": pctf(values, 95.0),
        }
        out_buckets.append(entry)
        if label == NA:
            continue
        real.append(entry)
    # The dominance test runs over EVERY real bucket, not only the selected
    # one: "does ANY small identity class hold the tail" is the question.
    dominating = [b for b in real
                  if float(b["tail_share"]) > DOMINATE_TAIL_SHARE
                  and float(b["story_share"]) < DOMINATE_STORY_SHARE]
    for entry in real:
        if best is None or (float(entry["excess"]), float(entry["tail_share"])) \
                > (float(best["excess"]), float(best["tail_share"])):
            best = entry
    na = next((b for b in out_buckets if b["bucket"] == NA), None)
    return {
        "dimension": dimension,
        "timing": timing,
        "stories_scored": total,
        "tail_stories": tail_total,
        "tail_threshold_s": threshold,
        "buckets": out_buckets,
        "na_stories": int(na["stories"]) if na else 0,
        "top_bucket": (best or {}).get("bucket"),
        "top_bucket_tail_share": (best or {}).get("tail_share"),
        "top_bucket_story_share": (best or {}).get("story_share"),
        "top_bucket_lift": (best or {}).get("lift"),
        "top_bucket_excess": (best or {}).get("excess"),
        "concentration": float((best or {}).get("tail_share") or 0.0),
        "concentration_excess": float((best or {}).get("excess") or 0.0),
        "dominating_buckets": [str(b["bucket"]) for b in dominating],
        "dominates": bool(dominating),
    }


def onset_band_check(rows: Sequence[dict[str, object]], timing: str,
                     threshold: float,
                     coverage: float = BAND_COVERAGE) -> dict[str, Any]:
    """The 5k clue, run on this leg: do the TAIL stories' onset offsets cluster?

    Reports the tightest window containing `coverage` of the tail's onsets and
    the same window over ALL scored stories. A tail band materially narrower
    than the all-stories band is clustering; a band of the same width is not."""
    pairs: list[tuple[float, float]] = []
    for row in rows:
        latency = timing_value(row, timing)
        onset = timing_value(row, "onset_offset_s")
        if latency is None or onset is None:
            continue
        pairs.append((onset, latency))
    all_onsets = sorted(onset for onset, _ in pairs)
    tail_onsets = sorted(onset for onset, lat in pairs if lat > threshold)
    return {
        "timing": timing,
        "coverage": coverage,
        "all": tightest_window(all_onsets, coverage),
        "tail": tightest_window(tail_onsets, coverage),
    }


def tightest_window(values: Sequence[float], coverage: float) -> dict[str, Any]:
    """The narrowest [lo, hi] containing at least `coverage` of `values`.

    Nearest-rank: `need = ceil(coverage * n)` points must fall inside, so a
    window is never credited with coverage it does not have."""
    n = len(values)
    if n == 0:
        return {"n": 0, "need": 0, "lo_s": None, "hi_s": None, "width_s": None}
    ordered = sorted(values)
    need = int(-(-coverage * n // 1))
    need = max(1, min(need, n))
    best_lo, best_hi = ordered[0], ordered[need - 1]
    for i in range(n - need + 1):
        lo, hi = ordered[i], ordered[i + need - 1]
        if (hi - lo) < (best_hi - best_lo):
            best_lo, best_hi = lo, hi
    return {"n": n, "need": need, "lo_s": round(best_lo, 3),
            "hi_s": round(best_hi, 3), "width_s": round(best_hi - best_lo, 3)}


def classify_all(rows: Sequence[dict[str, object]],
                 pctf: Callable[[list[float], float], float | None]
                 ) -> dict[str, Any]:
    """Every timing x every bucketed dimension, plus the ranking and the onset
    band."""
    out: dict[str, Any] = {}
    for timing in TIMINGS:
        values = sorted(v for v in (timing_value(r, timing) for r in rows)
                        if v is not None)
        censored = len(rows) - len(values)
        threshold = pctf(values, TAIL_QUANTILE)
        entry: dict[str, Any] = {
            "timing": timing,
            "stories_scored": len(values),
            "censored": censored,
            "tail_quantile": TAIL_QUANTILE,
            "tail_threshold_s": threshold,
        }
        if threshold is None:
            entry["classified"] = False
            entry["reason"] = (
                "every story is CENSORED for this timing — there is no tail to "
                "classify (step 1's structural finding, not a failure here)")
            entry["dimensions"] = []
            entry["ranking"] = []
            entry["onset_band"] = None
            out[timing] = entry
            continue
        dims = [classify_dimension(rows, name, timing, threshold, pctf)
                for name in BUCKETED]
        # Ranked by EXCESS (see `classify_dimension`), with a dimension that
        # actually clears the dominance test first — never by raw tail share,
        # which a single-bucket dimension wins for free.
        ranking = sorted(
            dims, key=lambda d: (0 if d["dominates"] else 1,
                                 -float(d["concentration_excess"]),
                                 -float(d["top_bucket_lift"] or 0.0),
                                 str(d["dimension"])))
        entry["classified"] = True
        entry["dimensions"] = dims
        entry["ranking"] = [
            {"rank": i + 1, "dimension": d["dimension"],
             "top_bucket": d["top_bucket"],
             "tail_share": d["top_bucket_tail_share"],
             "story_share": d["top_bucket_story_share"],
             "lift": d["top_bucket_lift"],
             "excess": d["top_bucket_excess"],
             "dominates": d["dominates"]}
            for i, d in enumerate(ranking)]
        entry["onset_band"] = onset_band_check(rows, timing, threshold)
        entry["dominating_dimensions"] = [d["dimension"] for d in dims
                                          if d["dominates"]]
        out[timing] = entry
    return out


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

TAIL_TSV_COLUMNS = (
    "story_id", "template", "seam_type", "expected_owner_class",
    "onset_offset_s", "objects",
    "affected_devices", "truth_vantage_count", "blast_wave_depth",
    "engine_evidence_size", "component_size", "candidate_count",
    "hyp_satisfied_count", "modality_count", "observer_count",
    "evidence_recurrence", "agg_forwarded", "agg_suppressed",
    "agg_suppression", "cohorts_before_verdict",
    "time_to_first_candidate", "time_to_first_correct", "time_to_useful",
    "time_to_stable",
)


def render_tsv(rows: Sequence[dict[str, object]]) -> str:
    def cell(value: object) -> str:
        if value is None:
            return ""
        if isinstance(value, bool):
            return "1" if value else "0"
        if isinstance(value, float):
            return f"{value:.3f}"
        return str(value)

    lines = ["\t".join(TAIL_TSV_COLUMNS)]
    for row in rows:
        lines.append("\t".join(cell(row.get(c)) for c in TAIL_TSV_COLUMNS))
    return "\n".join(lines) + "\n"


def _dict(value: object) -> dict[str, object]:
    """A nested JSON node as a dict, or an empty one. Renderers must not raise
    on a shape they did not produce, and an `assert` in a shipped tool is a
    crash under -O rather than a check."""
    return value if isinstance(value, dict) else {}


def _rows(value: object) -> list[dict[str, object]]:
    """A nested JSON node as a list of dicts; non-dict members are dropped."""
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _list(value: object) -> list[object]:
    """A nested JSON node as a list, or an empty one."""
    return value if isinstance(value, list) else []


def _f(value: object, nd: int = 2) -> str:
    if value is None:
        return "–"
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return f"{value:,.{nd}f}"
    return str(value)


def render_markdown(doc: dict[str, object], top_n: int = 5) -> str:
    run = _dict(doc.get("run"))
    out: list[str] = []
    out.append("# Tail classification — tracker 205 STEP 2")
    out.append("")
    out.append(f"Run `{run.get('runid')}` (`{run.get('profile')}`, seed "
               f"{run.get('seed')}), tenant `{run.get('tenant')}`, "
               f"{doc.get('stories')} stories. Generated "
               f"{doc.get('generated_at')}. READ-ONLY.")
    out.append("")
    out.append(f"Timings are READ from step 1's `{STEP1_TSV}` "
               f"(`{DEF_DOC}`); they are not re-measured here.")
    out.append("")

    out.append("## 0. The owner's 15 dimensions (+ the labelled proxies) — where each comes from")
    out.append("")
    out.append("| # | owner's dimension | status | column | source |")
    out.append("|--:|---|---|---|---|")
    for i, dim in enumerate(DIMENSIONS, 1):
        out.append(f"| {i} | {dim.owner_name} | **{dim.status}** | "
                   f"`{dim.column if dim.status != NOT_MEASURABLE else '—'}` | "
                   f"{dim.source} |")
    out.append("")
    for dim in DIMENSIONS:
        if dim.note:
            out.append(f"* **{dim.name}** ({dim.status}) — {dim.note}")
    out.append("")

    cohorts = _dict(doc.get("cohort_reconstruction"))
    if cohorts:
        out.append("## 0b. Cohort reconstruction (dimension 13)")
        out.append("")
        out.append(f"Gap threshold {cohorts.get('gap_s')} s over the global "
                   f"`created_at` stream reconstructs "
                   f"**{cohorts.get('reconstructed')}** cohorts; the engine's "
                   f"own `corr_engine_cohorts_total` reads "
                   f"**{_f(cohorts.get('engine_total'), 0)}**"
                   + (f" ({cohorts.get('note')})" if cohorts.get("note") else "")
                   + ".")
        out.append("")

    for timing in TIMINGS:
        entry = _dict(_dict(doc.get("classification")).get(timing))
        if not entry:
            continue
        out.append(f"## {timing}")
        out.append("")
        if not entry.get("classified"):
            out.append(f"**Not classified.** {entry.get('reason')} "
                       f"(censored {entry.get('censored')} of "
                       f"{doc.get('stories')}).")
            out.append("")
            continue
        out.append(f"n = {entry.get('stories_scored')} scored "
                   f"({entry.get('censored')} censored). Tail = above the "
                   f"overall p{TAIL_QUANTILE:.0f} = "
                   f"**{_f(entry.get('tail_threshold_s'))} s**.")
        out.append("")
        out.append(f"### Top {top_n} dimensions by tail concentration")
        out.append("")
        out.append("Ordered by the dominance test first, then by **excess** "
                   "(tail share − story share). Raw tail share is shown but is "
                   "NOT the ordering: a dimension with one bucket holds 100 % "
                   "of the tail for free.")
        out.append("")
        out.append("| rank | dimension | top bucket | tail share | story share "
                   "| excess | lift | dominates? |")
        out.append("|--:|---|---|--:|--:|--:|--:|---|")
        ranking = _rows(entry.get("ranking"))
        for item in ranking[:top_n]:
            out.append(
                f"| {item['rank']} | `{item['dimension']}` | "
                f"`{item['top_bucket']}` | {_f(item['tail_share'], 3)} | "
                f"{_f(item['story_share'], 3)} | {_f(item.get('excess'), 3)} | "
                f"{_f(item['lift'], 2)} | "
                f"{'**YES**' if item['dominates'] else 'no'} |")
        out.append("")
        dominating = [str(d) for d in _list(entry.get("dominating_dimensions"))]
        if dominating:
            out.append("**A small identity class DOES dominate this timing's "
                       f"tail:** {', '.join('`' + str(d) + '`' for d in dominating)} "
                       f"(> {DOMINATE_TAIL_SHARE:.0%} of the tail in < "
                       f"{DOMINATE_STORY_SHARE:.0%} of the stories).")
        else:
            out.append(f"**No bucket of any dimension holds > "
                       f"{DOMINATE_TAIL_SHARE:.0%} of the tail while holding < "
                       f"{DOMINATE_STORY_SHARE:.0%} of the stories** — no small "
                       f"identity class dominates this timing's tail.")
        out.append("")
        band = _dict(entry.get("onset_band"))
        if band:
            allw = _dict(band.get("all"))
            tailw = _dict(band.get("tail"))
            out.append("### Onset-band check (the 5k clue)")
            out.append("")
            out.append("| population | n | need | tightest window "
                       f"({BAND_COVERAGE:.0%}) | width |")
            out.append("|---|--:|--:|---|--:|")
            out.append(f"| all stories | {allw.get('n')} | {allw.get('need')} | "
                       f"{_f(allw.get('lo_s'), 1)} – {_f(allw.get('hi_s'), 1)} s "
                       f"| {_f(allw.get('width_s'), 1)} s |")
            out.append(f"| tail stories | {tailw.get('n')} | {tailw.get('need')} "
                       f"| {_f(tailw.get('lo_s'), 1)} – "
                       f"{_f(tailw.get('hi_s'), 1)} s | "
                       f"{_f(tailw.get('width_s'), 1)} s |")
            out.append("")
        out.append("### Every measurable dimension, bucket by bucket")
        out.append("")
        for dstat in _rows(entry.get("dimensions")):
            out.append(f"#### `{dstat['dimension']}`"
                       + (f" — NA in {dstat['na_stories']} stories"
                          if dstat.get("na_stories") else ""))
            out.append("")
            out.append("| bucket | stories | story share | tail | tail share | "
                       "excess | tail rate | p50 s | p95 s |")
            out.append("|---|--:|--:|--:|--:|--:|--:|--:|--:|")
            for b in _rows(dstat.get("buckets")):
                out.append(
                    f"| `{b['bucket']}` | {b['stories']} | "
                    f"{_f(b['story_share'], 3)} | {b['tail_stories']} | "
                    f"{_f(b['tail_share'], 3)} | {_f(b.get('excess'), 3)} | "
                    f"{_f(b['tail_rate'], 3)} | "
                    f"{_f(b['p50_s'])} | {_f(b['p95_s'])} |")
            out.append("")

    out.append("## Caveats (they travel with every number above)")
    out.append("")
    for c in _list(doc.get("caveats")):
        out.append(f"* {c}")
    out.append("")
    return "\n".join(out)


def write_text_file(path: str, text: str) -> None:
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
    except OSError as exc:
        die(f"could not write {path}: {exc.strerror or exc}", 1)
    log("wrote", path=path, bytes=len(text.encode("utf-8")))


# ---------------------------------------------------------------------------
# Engine cohort total, for validating the reconstruction
# ---------------------------------------------------------------------------

def engine_cohort_total(run_dir: str) -> int | None:
    """`corr_engine_cohorts_total` from the leg's metrics-final.txt, or None.

    A MISSING file is not fatal — the reconstruction stands on its own and the
    output says the cross-check was unavailable rather than pretending it
    passed."""
    path = os.path.join(run_dir, "metrics-final.txt")
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                if line.startswith("corr_engine_cohorts_total "):
                    try:
                        return int(float(line.split()[1]))
                    except (IndexError, ValueError):
                        log("cohort_metric_unparsable", line=line.strip()[:120])
                        return None
    except OSError as exc:
        log("cohort_metric_unavailable", path=path,
            err=str(exc.strerror or exc))
    return None


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="scale-rca-tail.py",
        description=("READ-ONLY tracker-205 STEP 2: classify the RCA latency "
                     "tail by the owner's 15 dimensions. Issues SELECTs only."),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("The tail is 'above the overall p90 of the timing'. A bucket "
                "DOMINATES when it holds >50%% of the tail in <25%% of the "
                "stories. NA is a reported bucket, never a silent one."))
    ap.add_argument("run_dir", help="a scale run directory (holds report.json, "
                                    "ground-truth.json, " + STEP1_TSV + ")")
    ap.add_argument("--tenant", default="",
                    help="tenant to scope every query to (default: read from "
                         "the run's ttur-scope.json)")
    ap.add_argument("--out-dir", default="",
                    help="where to write the three outputs (default: run_dir)")
    ap.add_argument("--step1-tsv", default="",
                    help="path to step 1's " + STEP1_TSV + " (default: in run_dir)")
    ap.add_argument("--from-dimensions", default="",
                    help="re-classify from an existing " + DIM_TSV + " instead "
                         "of reading ClickHouse (the join is already on disk; "
                         "issues NO query)")
    ap.add_argument("--dim-slices", type=int, default=DEFAULT_DIM_SLICES,
                    help="created_at slices for the companion scan "
                         f"(default {DEFAULT_DIM_SLICES})")
    ap.add_argument("--gt-slices", type=int, default=DEFAULT_DIM_SLICES,
                    help="created_at slices for step 1's version scan "
                         f"(default {DEFAULT_DIM_SLICES})")
    ap.add_argument("--max-versions", type=int, default=DEFAULT_MAX_VERSIONS,
                    help=f"refuse a scan larger than this (default "
                         f"{DEFAULT_MAX_VERSIONS:,})")
    ap.add_argument("--cohort-gap-s", type=float, default=DEFAULT_COHORT_GAP_S,
                    help="quiet interval in the global persist stream that "
                         f"marks a cohort boundary (default "
                         f"{DEFAULT_COHORT_GAP_S})")
    ap.add_argument("--project", default="",
                    help="compose project name (default: from the .env)")
    ap.add_argument("--env-file", default="",
                    help="compose .env holding COMPOSE_PROJECT_NAME")
    ap.add_argument("--ch-timeout", type=int, default=600,
                    help="ClickHouse client timeout, seconds (default 600)")
    ap.add_argument("--top-n", type=int, default=5,
                    help="dimensions to show in each ranking table (default 5)")
    return ap


def main(argv: list[str]) -> int:
    args = build_parser().parse_args(argv)
    step1 = load_step1()
    os.environ["PATH"] = step1.CRON_PATH
    if args.dim_slices < 1 or args.gt_slices < 1:
        die("--dim-slices / --gt-slices must be >= 1")
    if args.cohort_gap_s <= 0:
        die("--cohort-gap-s must be > 0")

    run_dir = os.path.abspath(args.run_dir)
    if not os.path.isdir(run_dir):
        die(f"{run_dir!r} is not a directory")
    out_dir = os.path.abspath(args.out_dir or run_dir)
    if not os.path.isdir(out_dir):
        die(f"--out-dir {out_dir!r} is not a directory")

    tsv_path = args.step1_tsv or os.path.join(run_dir, STEP1_TSV)
    try:
        with open(tsv_path, encoding="utf-8") as f:
            tsv_rows = parse_step1_tsv(f.read())
    except OSError as exc:
        die(f"cannot read step-1 output {tsv_path!r}: {exc.strerror or exc} — "
            f"run `{STEP1_TOOL} --ground-truth {run_dir}` first", 1)
    by_story = {str(r["story_id"]): r for r in tsv_rows}
    log("step1_loaded", path=tsv_path, stories=len(tsv_rows))

    driver = step1.load_ab_driver()
    report = step1.read_json_file(os.path.join(run_dir, "report.json"),
                                 "run report")
    try:
        scope = driver.burst_scope(report)
    except Exception as exc:      # noqa: BLE001 — report, never swallow
        die(f"cannot derive the burst scope from {run_dir}/report.json: {exc}",
            1)

    tenant = args.tenant
    scope_path = os.path.join(run_dir, "ttur-scope.json")
    if not tenant and os.path.exists(scope_path):
        tenant = str(step1.read_json_file(scope_path, "ttur scope")
                     .get("tenant") or "")
    if not tenant:
        die("--tenant is required (and the run dir carries no "
            "ttur-scope.json): an unscoped read of corr_objects is the defect "
            "tracker 201 records")
    if not step1.SAFE_TOKEN_RE.match(tenant):
        die(f"tenant {tenant!r} rejected: allowed charset is [A-Za-z0-9._:-]")
    agg = driver.agg_cid(tenant)
    burst_start = driver.parse_iso_z(scope["burst_start"].replace(" ", "T") + "Z")
    burst_start_ms = int(burst_start.timestamp() * 1000)
    burst_end_ms = int(driver.parse_iso_z(
        scope["burst_end"].replace(" ", "T") + "Z").timestamp() * 1000)

    gt, stories = step1.load_ground_truth(run_dir, burst_start_ms)
    incidents = {str(i.get("incident_id") or ""): i
                 for i in gt.get("incidents", [])}
    log("ground_truth", stories=len(stories), runid=gt.get("runid"),
        profile=gt.get("profile"), seed=gt.get("seed"))
    missing = [s.story_id for s in stories if s.story_id not in by_story]
    if missing:
        die(f"{len(missing)} ground-truth story/stories are absent from "
            f"{tsv_path} (first: {missing[0]}) — the step-1 TSV was produced "
            f"from a different run", 1)

    rows: list[dict[str, object]] = []
    corpus: dict[str, object] = {}
    cohort_note: dict[str, object] = {}
    engine_total = engine_cohort_total(run_dir)

    if args.from_dimensions:
        # OFFLINE RE-CLASSIFY. The expensive part — joining 10k versions to
        # 345 stories — is already on disk, so re-running the STATISTICS must
        # not re-read ClickHouse. No query is issued on this path at all.
        try:
            with open(args.from_dimensions, encoding="utf-8") as f:
                rows = parse_dimensions_tsv(f.read())
        except OSError as exc:
            die(f"cannot read --from-dimensions {args.from_dimensions!r}: "
                f"{exc.strerror or exc}", 1)
        seen = {str(r["story_id"]) for r in rows}
        absent = [s.story_id for s in stories if s.story_id not in seen]
        if absent:
            die(f"{len(absent)} ground-truth story/stories are absent from "
                f"{args.from_dimensions} (first: {absent[0]}) — that file was "
                f"produced from a different run", 1)
        log("from_dimensions", path=args.from_dimensions, stories=len(rows),
            note="offline re-classify; NO ClickHouse query issued")
        corpus = {"source": args.from_dimensions,
                  "note": "offline re-classify: no ClickHouse read"}
        cohort_note = {"gap_s": None, "reconstructed": None,
                       "engine_total": engine_total,
                       "note": ("carried from the joined TSV; the "
                                "reconstruction is not re-derived offline")}
        return _finish(args, argv, rows, run_dir, out_dir, tsv_path, gt, tenant,
                       scope, agg, corpus, cohort_note, step1)

    project = args.project or step1.env_get(
        args.env_file or step1.DEFAULT_ENV_FILE, "COMPOSE_PROJECT_NAME") or "netops"
    ch = step1.ClickHouse(project, args.ch_timeout)
    log("scope", tenant=tenant, project=project,
        burst_start=scope["burst_start"], converged=scope["converged"],
        excluded_agg_cid=agg)

    versions = step1.fetch_gt_versions(ch, tenant, agg, scope["burst_start"],
                                       scope["converged"], args.gt_slices,
                                       args.max_versions)
    objects: dict[str, Any] = {}
    for v in versions:
        objects.setdefault(v.cid, step1.ObjectHistory(v.cid)).versions.append(v)
    for obj in objects.values():
        obj.finish()
    in_scope = {cid: obj for cid, obj in objects.items()
                if burst_start_ms <= min(v.ws_ms for v in obj.versions) < burst_end_ms}
    if not in_scope:
        die("no object's first event time falls inside the burst window — "
            "empty is an error, not a zero", 1)
    log("corpus", versions=len(versions), objects=len(objects),
        objects_in_scope=len(in_scope))

    dims = fetch_dim_versions(ch, step1.sql_str, tenant, agg,
                              scope["burst_start"], scope["converged"],
                              args.dim_slices, args.max_versions)
    log("dim_corpus", rows=len(dims))
    joined = sum(1 for v in versions if (v.cid, v.ca_ms) in dims)
    if joined != len(versions):
        log("dim_join_gap", versions=len(versions), joined=joined,
            note="versions without a dimension row bucket to NA")

    cohort_starts = reconstruct_cohorts([v.ca_ms for v in versions],
                                        args.cohort_gap_s)
    log("cohorts", reconstructed=len(cohort_starts),
        engine_total=engine_total if engine_total is not None else "unavailable",
        gap_s=args.cohort_gap_s)

    touching = step1.object_story_map(in_scope, stories)
    for story in stories:
        tsv_row = by_story[story.story_id]
        row = story_dimensions(story, tsv_row, touching[story.story_id], dims,
                               incidents.get(story.story_id, {}), cohort_starts)
        for timing in TIMINGS:
            row[timing] = tsv_row.get(timing)
        rows.append(row)

    corpus = {
        "versions_read": len(versions),
        "objects_read": len(objects),
        "objects_in_burst_scope": len(in_scope),
        "dimension_rows": len(dims),
        "versions_joined_to_dimensions": joined,
    }
    cohort_note = {
        "gap_s": args.cohort_gap_s,
        "reconstructed": len(cohort_starts),
        "engine_total": engine_total,
        "note": ("engine counter covers the WHOLE process lifetime; the "
                 "reconstruction covers the burst..converged scope only"),
    }
    return _finish(args, argv, rows, run_dir, out_dir, tsv_path, gt, tenant,
                   scope, agg, corpus, cohort_note, step1)


def _finish(args: argparse.Namespace, argv: list[str],
            rows: list[dict[str, object]], run_dir: str, out_dir: str,
            tsv_path: str, gt: dict[str, Any], tenant: str,
            scope: dict[str, Any], agg: str, corpus: dict[str, object],
            cohort_note: dict[str, object], step1: Any) -> int:
    """Classify, render, write, summarise. Shared by the live and the offline
    path so the two can never produce differently-shaped outputs."""
    classification = classify_all(rows, step1.pct)

    doc: dict[str, object] = {
        "tool": "scripts/scale-rca-tail.py",
        "mode": "tail classification (tracker 205 STEP 2)",
        "step1_tool": STEP1_TOOL,
        "step1_tsv": tsv_path,
        "definition_doc": DEF_DOC,
        "clue_doc": CEILING_DOC + " §3 (the 5k rung's 154 s onset band)",
        "generated_at": datetime.now(timezone.utc)
                                .strftime("%Y-%m-%dT%H:%M:%SZ"),
        "command": "python3 scripts/scale-rca-tail.py " + " ".join(argv),
        "read_only": True,
        "stories": len(rows),
        "run": {
            "run_dir": run_dir,
            "runid": gt.get("runid"),
            "profile": gt.get("profile"),
            "scenario": gt.get("scenario"),
            "seed": gt.get("seed"),
            "digest": gt.get("digest"),
            "tenant": tenant,
            "scope": scope,
            "excluded_agg_cid": agg,
        },
        "corpus": corpus,
        "cohort_reconstruction": cohort_note,
        "tail_definition": {
            "quantile": TAIL_QUANTILE,
            "dominate_tail_share": DOMINATE_TAIL_SHARE,
            "dominate_story_share": DOMINATE_STORY_SHARE,
            "band_coverage": BAND_COVERAGE,
        },
        "dimensions": [d.as_dict() for d in DIMENSIONS],
        "caveats": TAIL_CAVEATS,
        "classification": classification,
    }

    write_text_file(os.path.join(out_dir, DIM_TSV), render_tsv(rows))
    write_text_file(os.path.join(out_dir, CLASS_JSON),
                    json.dumps(doc, indent=2, sort_keys=False) + "\n")
    write_text_file(os.path.join(out_dir, CLASS_MD),
                    render_markdown(doc, args.top_n))

    print(f"tracker-205 STEP 2 tail classification — {len(rows)} stories, "
          f"tenant {tenant}, run {gt.get('runid')}")
    for timing in TIMINGS:
        entry = _dict(classification[timing])
        if not entry.get("classified"):
            print(f"{timing:<26} NOT CLASSIFIED — "
                  f"{entry.get('censored')} censored")
            continue
        ranking = _rows(entry.get("ranking"))
        head: dict[str, object] = ranking[0] if ranking else {}
        dominating = [str(d) for d in _list(entry.get("dominating_dimensions"))]
        print(f"{timing:<26} tail>p90={_f(entry['tail_threshold_s'])}s  "
              f"top={head.get('dimension')}:{head.get('top_bucket')} "
              f"tail_share={_f(head.get('tail_share'), 3)} "
              f"story_share={_f(head.get('story_share'), 3)}  "
              f"dominates={dominating or 'NONE'}")
    print("This tool NAMES the tail's contributor. It proposes no optimization.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
