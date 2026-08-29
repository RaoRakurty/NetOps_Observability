#!/usr/bin/env python3
"""Time-to-Useful-RCA (TTUR) lifecycle measurement — READ-ONLY.

Measures the RCA lifecycle latencies and verdict churn that the correlation
engine ALREADY persists, with **no engine change and no writes of any kind**.
Every query this tool issues is a `SELECT`; it never inserts, alters, mutates,
or drops. It is the P0 instrumentation step of
`docs/design/STORM_PLANE_SEPARATION_RESEARCH_2026-08-28.md` (metric definition:
owner memo `Correlix-Bottleneck-Modified.md` sections 5-9).

WHAT IT MEASURES
----------------
`netops.corr_objects` is an append-only version history: one row per
(correlation_id, version) snapshot of an incident. Replaying that history in
persist order reconstructs the customer-visible incident lifecycle:

  T0  window_start of the FIRST persisted version — the first causal symptom's
      EVENT time. CAVEAT: event time is assigned by the emitting device /
      load generator, not by the engine; every T*-minus-T0 figure therefore
      mixes a generator clock with the engine's wall clock (see --help notes
      and the report's caveats section).
  T1  created_at of the first persisted version — incident created.
  T2  created_at of the first version whose top_hypothesis is not
      'undetermined' — first plausible causal candidate.
  T3  created_at of the first version with a non-empty owner AND a blast
      radius (node_count > 0 or a non-empty affected.devices).
  T4  "First Useful RCA" — first version with verdict_tier >= suspected AND a
      non-empty owner AND top_confidence >= --useful-confidence.

      *** T4 IS A PROXY, NOT THE MEMO'S DEFINITION. ***
      Owner memo section 8 requires T4 to also assert the causal seam / root
      cause is CORRECT. The scale-harness runs carry no ground-truth cause
      label, so correctness CANNOT be scored from persisted data. What this
      tool reports is "time to a confident, owned, tiered verdict" — an upper
      bound on quality, a lower bound on time. Read every T4 number with that
      caveat attached.
  T6  "Stable RCA" — created_at of the LAST version whose material verdict
      tuple (top_hypothesis, owner, verdict_tier) differs from the previous
      version. After T6 the verdict never changes again. An incident whose
      verdict never changed is stable at T1.

  churn  number of material verdict changes that happened after T4
         (memo section 9: a in 8 seconds answer that changes root cause five
         times is not an 8-second TTUR).

T5 (corroborated), T7 (full evidence graph) and T8 (evidence backlog drained)
are NOT derivable from `corr_objects` alone and are not reported.

GROUND TRUTH (t-storm profiles) — THE T4-CORRECTNESS CONTRACT, NOT YET SCORED
----------------------------------------------------------------------------
The T4 caveat above ("the scale-harness runs carry no ground-truth cause label")
is true of `t-nominal-2.5k` and of every profile that predates it. It is NOT
true of a `--profile t-storm-*` run: `scale-miniladder.py` writes a
`ground-truth.json` into the run dir naming exactly what it injected. THIS TOOL
DOES NOT YET READ IT — the file and this contract exist so a correctness scorer
can be written without re-deriving the interface, and so nobody scores T4
against a file whose meaning they guessed.

FILE. `<run_dir>/ground-truth.json`, `schema: "correlix.scale.ground-truth/1"`.
Top level: `profile`, `scenario`, `seed`, `runid`, `window_s`, `chunk_secs`,
`planned_total_events`, `digest` (SHA-256 of the plan — two runs of one seed on
one device list MUST print the same digest, or the A/B is not an A/B),
`devices {total, scenario, noise_pool}`, `templates {...}`, `counts {...}`
(the measured dynamics: state_transitions, recoveries, repeats_within_60s,
multi_vantage_incidents, contradictions, blast_radius_expansions), and
`incidents[]`.

INCIDENT. Each entry carries:
  incident_id           "I0001" — also stamped into every raw line it caused,
                        as the `[mlx seq N inc I0001]` marker
  cause_kind            upstream_link_failure | local_link_fault |
                        bgp_peer_flap | ospf_adjacency_flap
  cause_entity          {entity_type: interface|device|peer, device, interface,
                         entity_id, peer}. `entity_id` is the token the ENGINE
                        keys on: `host:ifname` for an interface cause, `host`
                        for a device cause, the peer ADDRESS for a peer cause
                        (which is a shared `entity_tokens` entry, not an
                        entity_id — a scorer must match it against the
                        hypothesis' tokens, not against `corr_objects.entity`).
  onset_ts / recovery_ts  SECONDS FROM BURST T0, not wall clock (the harness
                        cannot know the engine's clock). `recovery_ts: null`
                        means the fault was still open when the window closed.
  blast_radius          every device that emitted a symptom of this incident
  blast_radius_waves    [{at, devices}] — the expansion, in order
  vantages              the DISTINCT DEVICES that observed the cause. In a
                        syslog-only harness the observer is always the emitting
                        device, so this is vantage on the CAUSE, never two
                        observers of one entity_id.
  contradictions        [{device, at, entity_id}] healthy observations emitted
                        while the fault was open
  symptom_kinds         the correlation kinds this incident generates
  expected_owner_class / expected_seam_class
                        SCENARIO LABELS. mlx- devices are onboarded with no
                        seam configuration, so the engine has nothing to
                        attribute ownership to; treat these as INFORMATIONAL
                        until the harness provisions seams, and never report an
                        owner-correctness score derived from them as if the
                        engine had failed.

MATCHING (the contract a scorer must implement). Convert `onset_ts` to wall
clock with the burst t0 from the run's `report.json` (phase `burst`), then match
a persisted incident to a ground-truth incident when BOTH hold:
  1. the persisted incident's cause entity (top hypothesis) equals the
     ground-truth `cause_entity.entity_id`, or contains it as a token; AND
  2. its T0/window_start falls within a tolerance of the ground-truth onset —
     the chunk clock quantizes injection to 10 s, so the tolerance can never be
     tighter than `chunk_secs` and should be stated with every score.
Then report, per memo section 25: matched (true positive), ground-truth
incidents with no match (missed cause), persisted incidents matching no ground
truth (false cause) — and, separately, FALSE MERGE (one persisted incident
covering two ground-truth cause entities) and FALSE SPLIT (one ground-truth
incident spread over several persisted incidents). Background events are
generated ONLY from a device pool disjoint from every incident, so a persisted
incident whose cause entity is a noise device is a false cause by construction.

Nothing above is implemented here yet. When it is, T4's caveat gets a second
line — "scored against ground truth on t-storm runs" — and not before.

HOW IT QUERIES
--------------
Exactly the way `scale-miniladder.py` does: `docker exec <clickhouse container>
clickhouse-client --query "<sql> SETTINGS tenant_scope='__all__'"`, container
resolved by compose project+service labels. All reduction (per-incident
argMin/arrays/GROUP BY) happens ClickHouse-side; Python only receives ONE ROW
PER INCIDENT and computes percentiles/curves from it. A scope wider than
--max-incidents is refused rather than streamed.

EXIT CODES
----------
0 = measurement produced; 1 = query/stack failure or empty scope; 2 = usage.
An empty result is an ERROR, never a silent zero (CLAUDE.md 16.1).
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import subprocess
import sys
from datetime import datetime, timezone

# Cron-proof PATH (CLAUDE.md 16.2): docker lives in /usr/bin or /usr/local/bin
# on supported hosts; an interactive profile is never sourced. Applied in
# main(), not at import, so merely importing this module for its parser does
# not clobber a developer's PATH (the lesson scale-miniladder.py records).
CRON_PATH = "/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(SCRIPT_DIR)
DEFAULT_ENV_FILE = os.path.join(REPO_ROOT, "deployment", "docker", ".env")

DOCKER_TIMEOUT = 30          # bound EVERY docker call (16.3) — a wedged dockerd
DEFAULT_CH_TIMEOUT = 600     # the history scan JSON-parses the hypotheses blob

# Owner memo section 7. These are PROPOSED CORRELIX PRODUCT SLOs, not industry
# standards — the memo says to make that explicit wherever they are printed.
PROPOSED_SLO_P95_S = {"T1": 5.0, "T2": 10.0, "T3": 15.0, "T4": 30.0, "T6": 120.0}

STAGES = ("T1", "T2", "T3", "T4", "T6")
DEFAULT_CURVE_OFFSETS = "5,10,20,30,60,120,300"

# Every number this tool prints travels with these. Kept as one list so the
# JSON, the markdown and --help cannot drift apart.
CAVEATS = [
    ("T4 is a PROXY (confident + owned + tiered verdict); causal CORRECTNESS is"
     " NOT scored here (owner memo section 8). Pre-t-storm runs have no"
     " ground-truth cause label at all; a --profile t-storm-* run writes one"
     " (ground-truth.json), but this tool does not yet read it — see the"
     " GROUND TRUTH section of the module docstring."),
    ("T0 is EVENT time (window_start, generator/device assigned); T1..T6 are"
     " ENGINE persist wall-clock (created_at). Latencies straddle two clocks."),
    "Negative latencies are reported, not clamped: they are event/ingest skew.",
    ("Version history is ordered by (created_at, version), not version alone —"
     " an engine restart resets the per-object version counter."),
    "T5/T7/T8 are not derivable from corr_objects and are not reported.",
    ("The SLO column holds PROPOSED CORRELIX PRODUCT SLOs (owner memo section"
     " 7), NOT industry standards."),
]

# A device/run token that may be embedded in a LIKE pattern. Deliberately
# narrow: the value is interpolated into SQL, so it is validated, not escaped
# and hoped for (zero-trust on every input boundary, CLAUDE.md section 3).
SAFE_TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


def log(msg: str) -> None:
    print(f"rca-latency: {msg}", file=sys.stderr, flush=True)


def die(msg: str, code: int = 2) -> None:
    print(f"rca-latency: ERROR: {msg}", file=sys.stderr, flush=True)
    sys.exit(code)


def run(cmd: list[str], timeout: int, input_text: str | None = None) -> tuple[int, str, str]:
    """Bounded subprocess. Never raises on non-zero exit — callers must look at
    rc and REPORT stderr (CLAUDE.md 16.1: no swallowed errors)."""
    try:
        p = subprocess.run(
            cmd, input=input_text, capture_output=True, text=True,
            timeout=timeout, check=False,
        )
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout after {timeout}s: {' '.join(cmd[:4])} ..."
    except FileNotFoundError as exc:
        return 127, "", str(exc)


def env_get(env_file: str, key: str) -> str:
    """First KEY= value from the compose .env.

    A MISSING KEY returns "" — callers decide whether empty is fatal (the one
    caller falls back to the "netops" project name). An UNREADABLE FILE does
    NOT: this tool resolves the ClickHouse container through the compose
    project it reads from that file, so a missing/permission-denied .env means
    every subsequent query would fail against the WRONG (or no) container. That
    is exactly the warn-and-continue class CLAUDE.md 16.1 bans, so it dies with
    the path and the errno instead of returning a silent "".
    """
    try:
        with open(env_file, encoding="utf-8") as f:
            for line in f:
                if line.startswith(key + "="):
                    return line.rstrip("\n").split("=", 1)[1]
    except OSError as exc:
        die(f"cannot read compose env file {env_file!r}: "
            f"{exc.strerror or exc} (errno {exc.errno}) — this tool needs "
            f"COMPOSE_PROJECT_NAME from it to find the ClickHouse container; "
            f"pass --env-file <path> or --project <name> explicitly")
    return ""


class ClickHouse:
    """Read-only access layer for the stack's ClickHouse. Every call bounded;
    every failure carries its stderr."""

    def __init__(self, project: str, timeout: int):
        self.project = project
        self.timeout = timeout
        self._cid = ""

    def cid(self) -> tuple[str, str]:
        if not self._cid:
            rc, out, err = run(
                ["docker", "ps", "-q",
                 "--filter", f"label=com.docker.compose.project={self.project}",
                 "--filter", "label=com.docker.compose.service=clickhouse"],
                DOCKER_TIMEOUT)
            if rc != 0:
                return "", f"docker ps failed (rc={rc}): {err.strip()[:400]}"
            ids = out.split()
            if not ids:
                return "", f"no running clickhouse container in compose project {self.project!r}"
            self._cid = ids[0]
        return self._cid, ""

    def query(self, sql: str) -> tuple[bool, str, str]:
        """Returns (ok, stdout, error). Read-only by construction: this tool
        only ever builds SELECTs, and the guard below refuses anything else
        before it reaches the server."""
        head = sql.lstrip().split(None, 1)[0].upper() if sql.strip() else ""
        if head not in ("SELECT", "WITH"):
            return False, "", f"refusing non-SELECT statement (starts with {head!r})"
        cid, err = self.cid()
        if not cid:
            return False, "", err
        rc, out, cherr = run(
            ["docker", "exec", cid, "clickhouse-client", "--query",
             sql + " SETTINGS tenant_scope='__all__'"],
            self.timeout)
        if rc != 0:
            return False, "", f"clickhouse-client rc={rc}: {cherr.strip()[:600]}"
        return True, out, ""


# ---------------------------------------------------------------------------
# SQL construction
# ---------------------------------------------------------------------------

def sql_str(value: str) -> str:
    """Single-quoted ClickHouse string literal with backslash/quote escaped."""
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def parse_ts(value: str, flag: str) -> str:
    """ISO-8601 -> ClickHouse DateTime64 literal body. Unparsable is fatal."""
    text = value.strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        die(f"{flag}: not an ISO-8601 timestamp: {value!r} "
            f"(e.g. 2026-08-28T15:00:00 or 2026-08-28 15:00:00)")
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def scope_predicates(args: argparse.Namespace) -> list[str]:
    """Predicates that SELECT THE INCIDENT SET. Note the semantics: --since /
    --until / --device-prefix pick WHICH INCIDENTS to measure; the lifecycle of
    a selected incident is then read WHOLE, including versions persisted after
    --until. Clipping the history would truncate T6 and undercount churn."""
    preds: list[str] = []
    if args.tenant:
        preds.append(f"tenant_id = {sql_str(args.tenant)}")
    if args.since:
        preds.append(f"created_at >= toDateTime64({sql_str(args.since)}, 3)")
    if args.until:
        preds.append(f"created_at <= toDateTime64({sql_str(args.until)}, 3)")
    if args.device_prefix:
        preds.append(f"affected LIKE {sql_str('%' + args.device_prefix + '%')}")
    return preds


def scope_clause(args: argparse.Namespace) -> str:
    preds = scope_predicates(args)
    if not preds:
        return ""
    inner = " AND ".join(preds)
    # The incident set is chosen by the predicates; ALL versions of those
    # incidents are then measured. correlation_id is the 2nd primary-key column
    # so the IN-set prunes granules server-side.
    return (" WHERE (tenant_id, correlation_id) IN ("
            f"SELECT tenant_id, correlation_id FROM netops.corr_objects WHERE {inner})")


def sql_scope_summary(args: argparse.Namespace) -> str:
    return (
        "SELECT count(), uniqExact(correlation_id), uniqExact(tenant_id), "
        "toString(min(created_at)), toString(max(created_at)), "
        "toString(min(window_start)), toString(max(window_end)) "
        "FROM netops.corr_objects" + scope_clause(args)
    )


def sql_overall_extent() -> str:
    return ("SELECT count(), uniqExact(correlation_id), toString(min(created_at)), "
            "toString(max(created_at)) FROM netops.corr_objects")


def sql_runs(since: str) -> str:
    """Distinct scale-harness run tokens (`mlx-<run>-NNNNN` device residue)."""
    return (
        "SELECT extract(affected, 'mlx-([0-9a-z]+)-') AS run, count() AS versions, "
        "uniqExact(correlation_id) AS incidents, toString(min(created_at)), "
        "toString(max(created_at)) FROM netops.corr_objects "
        f"WHERE created_at >= toDateTime64({sql_str(since)}, 3) AND run != '' "
        "GROUP BY run ORDER BY min(created_at)"
    )


def sql_incidents(args: argparse.Namespace) -> str:
    """One row per incident, ALL reduction done ClickHouse-side.

    Ordering is by (created_at, version), NOT by version alone: an engine
    restart resets the per-object version counter (see the corr_current comment
    in init.sql), and 27% of the incidents in the 2026-08-28 2.5k run carry
    duplicate version numbers. Persist time is the only monotonic lifecycle
    clock available.
    """
    thr = float(args.useful_confidence)
    return f"""
SELECT
  tenant_id, cid, versions, t0_ms, t1_ms, t2_ms, t3_ms, t4_ms, t6_ms,
  changes_total, churn_after_t4, last_tier, last_conf, last_state
FROM (
  SELECT
    tenant_id,
    toString(correlation_id) AS cid,
    count() AS versions,
    arraySort(t -> (t.1, t.2), groupArray(tuple(
      ca_ms, version, hyp, owner, tier, conf, nodes, ws_ms, blast, st))) AS s,
    arrayMap(t -> t.1, s) AS times,
    arrayMap(t -> concat(t.3, char(1), t.4, char(1), toString(t.5)), s) AS keys,
    arrayFilter(i -> keys[i] != keys[i - 1], arraySlice(arrayEnumerate(keys), 2)) AS chg,
    arrayFirstIndex(t -> (t.3 != 'undetermined') AND (t.3 != ''), s) AS i2,
    arrayFirstIndex(t -> (t.4 != '') AND (t.9 > 0), s) AS i3,
    arrayFirstIndex(t -> (t.5 >= 1) AND (t.4 != '') AND (t.6 >= {thr}), s) AS i4,
    s[1].8 AS t0_ms,
    s[1].1 AS t1_ms,
    if(i2 > 0, times[i2], -1) AS t2_ms,
    if(i3 > 0, times[i3], -1) AS t3_ms,
    if(i4 > 0, times[i4], -1) AS t4_ms,
    if(empty(chg), times[1], times[chg[-1]]) AS t6_ms,
    toInt64(length(chg)) AS changes_total,
    if(i4 > 0, toInt64(length(arrayFilter(i -> (i > i4), chg))), -1) AS churn_after_t4,
    toUInt8(s[-1].5) AS last_tier,
    toFloat64(s[-1].6) AS last_conf,
    s[-1].10 AS last_state
  FROM (
    SELECT
      tenant_id, correlation_id, version,
      toUnixTimestamp64Milli(created_at) AS ca_ms,
      toUnixTimestamp64Milli(window_start) AS ws_ms,
      top_hypothesis AS hyp,
      toUInt8(verdict_tier) AS tier,
      toFloat64(top_confidence) AS conf,
      toUInt32(node_count) AS nodes,
      toUInt8((node_count > 0) OR (JSONLength(affected, 'devices') > 0)) AS blast,
      toString(state) AS st,
      JSONExtractString(arrayElement(JSONExtractArrayRaw(
        JSONExtractRaw(hypotheses, 'ranking'), 'hypotheses'), 1), 'verdict', 'owner') AS owner
    FROM netops.corr_objects{scope_clause(args)}
  )
  GROUP BY tenant_id, correlation_id
)
""".strip()


# ---------------------------------------------------------------------------
# Statistics (stdlib only)
# ---------------------------------------------------------------------------

def pct(sorted_vals: list[float], q: float) -> float | None:
    """Nearest-rank percentile (the convention latency SLOs are stated in)."""
    if not sorted_vals:
        return None
    rank = max(1, math.ceil(q / 100.0 * len(sorted_vals)))
    return sorted_vals[min(rank, len(sorted_vals)) - 1]


def summarize(values: list[float]) -> dict:
    vals = sorted(values)
    return {
        "n": len(vals),
        "min_s": vals[0] if vals else None,
        "p50_s": pct(vals, 50),
        "p95_s": pct(vals, 95),
        "p99_s": pct(vals, 99),
        "max_s": vals[-1] if vals else None,
        "mean_s": (sum(vals) / len(vals)) if vals else None,
    }


class Incident:
    """One reconstructed incident lifecycle. Times are epoch milliseconds;
    -1 means the stage was never reached."""

    __slots__ = (
        "changes", "churn", "cid", "last_conf", "last_state", "last_tier",
        "t", "tenant", "versions",
    )

    def __init__(self, row: list[str]):
        if len(row) != 14:
            raise ValueError(f"expected 14 columns, got {len(row)}: {row!r}")
        self.tenant = row[0]
        self.cid = row[1]
        self.versions = int(row[2])
        t0, t1, t2, t3, t4, t6 = (int(row[i]) for i in range(3, 9))
        self.t = {"T0": t0, "T1": t1, "T2": t2, "T3": t3, "T4": t4, "T6": t6}
        self.changes = int(row[9])
        self.churn = int(row[10])
        self.last_tier = int(row[11])
        self.last_conf = float(row[12])
        self.last_state = row[13]

    def latency_s(self, stage: str, base: str = "T0") -> float | None:
        """Stage latency relative to `base`, in seconds. None if never reached.

        A NEGATIVE value is possible and is NOT clamped: it means the engine
        persisted the version before the window's event time, i.e. real
        event-time/ingest-time skew. Clamping would hide exactly the defect
        this measurement exists to expose, so it is surfaced instead.
        """
        v, b = self.t[stage], self.t[base]
        if v < 0 or b < 0:
            return None
        return (v - b) / 1000.0


def aggregate(incidents: list[Incident], offsets: list[int], thr: float) -> dict:
    total = len(incidents)
    stages: dict[str, dict] = {}
    for stage in STAGES:
        reached = [i for i in incidents if i.t[stage] >= 0]
        lat = [i.latency_s(stage) for i in reached]
        lat = [v for v in lat if v is not None]
        summary = summarize(lat)
        summary["reached"] = len(reached)
        summary["never_reached"] = total - len(reached)
        summary["reached_pct"] = (100.0 * len(reached) / total) if total else None
        summary["negative_latency"] = sum(1 for v in lat if v < 0)
        slo = PROPOSED_SLO_P95_S.get(stage)
        summary["proposed_slo_p95_s"] = slo
        p95 = summary["p95_s"]
        summary["meets_proposed_slo"] = (None if (slo is None or p95 is None)
                                         else bool(p95 <= slo))
        stages[stage] = summary

    # SECOND VIEW, T1-relative. T*-minus-T0 mixes two costs: how long the
    # incident waited in the ingest/reconciliation queue before it existed at
    # all (T1-T0), and how long the ENGINE then took to decide (T2..T6 minus
    # T1). Reporting only the first hides which of the two a fix must attack.
    stages_from_t1: dict[str, dict] = {}
    for stage in ("T2", "T3", "T4", "T6"):
        lat = [v for v in (i.latency_s(stage, "T1") for i in incidents) if v is not None]
        summary = summarize(lat)
        summary["reached"] = len(lat)
        summary["never_reached"] = total - len(lat)
        summary["reached_pct"] = (100.0 * len(lat) / total) if total else None
        stages_from_t1[stage] = summary

    useful = [i for i in incidents if i.t["T4"] >= 0]
    churn_hist: dict[str, int] = {}
    for inc in useful:
        bucket = str(inc.churn) if inc.churn < 5 else "5+"
        churn_hist[bucket] = churn_hist.get(bucket, 0) + 1
    churn_vals = sorted(float(i.churn) for i in useful)
    version_vals = sorted(float(i.versions) for i in incidents)
    change_vals = sorted(float(i.changes) for i in incidents)

    curve = []
    for off in offsets:
        cutoff_ms = off * 1000
        row = {"offset_s": off}
        for stage in STAGES:
            hit = sum(1 for i in incidents
                      if i.t[stage] >= 0 and (i.t[stage] - i.t["T0"]) <= cutoff_ms)
            row[stage] = {"n": hit,
                          "fraction": (hit / total) if total else None}
        curve.append(row)

    return {
        "incidents": total,
        "versions": int(sum(version_vals)),
        "versions_per_incident": {
            "mean": (sum(version_vals) / total) if total else None,
            "p50": pct(version_vals, 50), "p95": pct(version_vals, 95),
            "p99": pct(version_vals, 99),
            "max": version_vals[-1] if version_vals else None,
        },
        "material_verdict_changes_total": int(sum(change_vals)),
        "material_changes_per_incident": {
            "mean": (sum(change_vals) / total) if total else None,
            "p50": pct(change_vals, 50), "p95": pct(change_vals, 95),
            "max": change_vals[-1] if change_vals else None,
        },
        "stages": stages,
        "stages_from_t1": stages_from_t1,
        "useful_rca": {
            "definition": ("PROXY: verdict_tier >= suspected AND owner != '' AND "
                           f"top_confidence >= {thr}. NOT scored for causal "
                           "correctness (owner memo section 8) — no ground truth "
                           "in the persisted data."),
            "confidence_threshold": thr,
            "incidents_reaching_t4": len(useful),
            "incidents_never_useful": total - len(useful),
        },
        "churn_after_t4": {
            "n": len(useful),
            "mean": (sum(churn_vals) / len(churn_vals)) if churn_vals else None,
            "p50": pct(churn_vals, 50), "p95": pct(churn_vals, 95),
            "p99": pct(churn_vals, 99),
            "max": churn_vals[-1] if churn_vals else None,
            "zero_churn": churn_hist.get("0", 0),
            "zero_churn_pct": ((100.0 * churn_hist.get("0", 0) / len(useful))
                               if useful else None),
            # Sorted by bucket (0,1,2,...,5+), not by count: this is a
        # distribution, and a count-ordered one is unreadable.
        "histogram": dict(sorted(churn_hist.items(),
                                 key=lambda kv: (kv[0] == "5+", kv[0].rjust(4)))),
        },
        "quality_curve": curve,
        "final_state": _tally(i.last_state for i in incidents),
        "final_verdict_tier": _tally(
            {0: "undetermined", 1: "suspected", 2: "confirmed"}.get(i.last_tier, "?")
            for i in incidents),
    }


def _tally(values) -> dict[str, int]:
    out: dict[str, int] = {}
    for v in values:
        out[v] = out.get(v, 0) + 1
    return dict(sorted(out.items(), key=lambda kv: -kv[1]))


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def _fmt(v: float | None, nd: int = 2) -> str:
    return "-" if v is None else f"{v:,.{nd}f}"


def render_markdown(result: dict) -> str:
    out: list[str] = []
    scope = result["scope"]
    out.append("# Time-to-Useful-RCA (TTUR) — measured baseline")
    out.append("")
    out.append(f"- generated: `{result['generated_at']}`")
    out.append(f"- command: `{result['command']}`")
    out.append(f"- scope: {scope['description']}")
    out.append(f"- versions in scope: {scope['versions']:,} across "
               f"{scope['incidents']:,} incidents, {scope['tenants']} tenant(s)")
    out.append(f"- persist window (created_at): `{scope['created_at_min']}` .. "
               f"`{scope['created_at_max']}`")
    out.append(f"- event window (window_start/window_end): `{scope['window_start_min']}` .. "
               f"`{scope['window_end_max']}`")
    out.append("")
    out.append("### Caveats that travel with every number below")
    out.append("")
    for c in result["caveats"]:
        out.append(f"- {c}")
    out.append("")

    for label, agg in [("overall", result["overall"])] + \
                      [(f"tenant `{t}`", a) for t, a in sorted(result["per_tenant"].items())]:
        out.append(f"## Lifecycle latency — {label}")
        out.append("")
        out.append("| stage | meaning | reached | % | p50 s | p95 s | p99 s | max s | "
                   "proposed p95 SLO | verdict |")
        out.append("|---|---|--:|--:|--:|--:|--:|--:|--:|---|")
        meanings = {
            "T1": "incident created (T1-T0)",
            "T2": "first causal candidate",
            "T3": "owner + blast radius",
            "T4": "first useful RCA (proxy)",
            "T6": "stable RCA (last material change)",
        }
        for stage in STAGES:
            s = agg["stages"][stage]
            slo = s["proposed_slo_p95_s"]
            met = s["meets_proposed_slo"]
            verdict = "-" if met is None else ("MEETS" if met else "MISSES")
            out.append(
                f"| {stage} | {meanings[stage]} | {s['reached']:,} | "
                f"{_fmt(s['reached_pct'], 1)} | {_fmt(s['p50_s'])} | {_fmt(s['p95_s'])} | "
                f"{_fmt(s['p99_s'])} | {_fmt(s['max_s'])} | {_fmt(slo, 0)} | {verdict} |")
        out.append("")
        out.append(f"#### Engine-decision latency only (relative to T1) — {label}")
        out.append("")
        out.append("Separates queue wait (T1-T0) from the engine's own decision time. "
                   "No SLO column: the memo's targets are stated from T0.")
        out.append("")
        out.append("| stage | reached | p50 s | p95 s | p99 s | max s |")
        out.append("|---|--:|--:|--:|--:|--:|")
        for stage in ("T2", "T3", "T4", "T6"):
            s1 = agg["stages_from_t1"][stage]
            out.append(
                f"| {stage}-T1 | {s1['reached']:,} | {_fmt(s1['p50_s'])} | "
                f"{_fmt(s1['p95_s'])} | {_fmt(s1['p99_s'])} | {_fmt(s1['max_s'])} |")
        out.append("")
        out.append(f"- incidents: {agg['incidents']:,} · versions: {agg['versions']:,} "
                   f"(mean {_fmt(agg['versions_per_incident']['mean'])}/incident, "
                   f"p95 {_fmt(agg['versions_per_incident']['p95'], 0)}, "
                   f"max {_fmt(agg['versions_per_incident']['max'], 0)})")
        c = agg["churn_after_t4"]
        out.append(f"- material verdict changes: {agg['material_verdict_changes_total']:,} "
                   f"total (mean {_fmt(agg['material_changes_per_incident']['mean'])}/incident)")
        out.append(f"- churn AFTER T4: n={c['n']:,} · mean {_fmt(c['mean'])} · "
                   f"p50 {_fmt(c['p50'], 0)} · p95 {_fmt(c['p95'], 0)} · "
                   f"p99 {_fmt(c['p99'], 0)} · max {_fmt(c['max'], 0)} · "
                   f"zero-churn {_fmt(c['zero_churn_pct'], 1)}%")
        out.append(f"- churn histogram: `{json.dumps(c['histogram'])}`")
        out.append(f"- never reached T4: {agg['useful_rca']['incidents_never_useful']:,}")
        out.append(f"- final state: `{json.dumps(agg['final_state'])}` · "
                   f"final tier: `{json.dumps(agg['final_verdict_tier'])}`")
        out.append("")
        out.append(f"### Quality curve — {label} (fraction of incidents that have "
                   "reached each stage by T0 + offset)")
        out.append("")
        out.append("| offset s | " + " | ".join(STAGES) + " |")
        out.append("|--:|" + "--:|" * len(STAGES))
        for row in agg["quality_curve"]:
            cells = [f"{100.0 * row[s]['fraction']:.1f}%" if row[s]["fraction"] is not None
                     else "-" for s in STAGES]
            out.append(f"| {row['offset_s']} | " + " | ".join(cells) + " |")
        out.append("")
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="scale-rca-latency.py",
        description=(
            "READ-ONLY Time-to-Useful-RCA (TTUR) measurement from netops.corr_objects. "
            "Reconstructs each incident's lifecycle (T0/T1/T2/T3/T4/T6) from the "
            "persisted version history and reports p50/p95/p99 latencies, verdict "
            "churn and a quality curve. Issues SELECTs only; changes nothing."),
        epilog=(
            "CAVEATS THAT TRAVEL WITH EVERY NUMBER:\n"
            "  * T4 ('first useful RCA') is a PROXY: verdict_tier >= suspected AND a\n"
            "    non-empty owner AND top_confidence >= --useful-confidence. The owner\n"
            "    memo (section 8) additionally requires the CAUSAL SEAM / ROOT CAUSE\n"
            "    to be CORRECT. The 2.5k production-mix scale runs carry no ground-truth\n"
            "    cause label, so correctness CANNOT be scored from persisted data.\n"
            "    Treat T4 as an upper bound on quality and a lower bound on time.\n"
            "  * T0 is EVENT time (window_start), assigned by the emitting device or the\n"
            "    load generator; T1..T6 are ENGINE WALL-CLOCK persist times (created_at).\n"
            "    Every latency therefore straddles two clocks. Negative latencies are\n"
            "    reported, not clamped, because they ARE the skew.\n"
            "  * T5 (corroborated), T7 (graph materialized) and T8 (evidence backlog\n"
            "    drained) are not derivable from corr_objects and are not reported.\n"
            "  * The proposed SLOs shown next to measurements are PROPOSED CORRELIX\n"
            "    PRODUCT SLOs (owner memo section 7), NOT industry standards.\n"),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--project", default="",
                    help="compose project name (default COMPOSE_PROJECT_NAME or netops)")
    ap.add_argument("--env-file", default=DEFAULT_ENV_FILE,
                    help="compose .env to read COMPOSE_PROJECT_NAME from")
    ap.add_argument("--tenant", default="",
                    help="restrict to one tenant_id")
    ap.add_argument("--device-prefix", default="",
                    help="select incidents whose affected devices carry this prefix "
                         "(e.g. mlx-08281519gjez- for one scale-harness run)")
    ap.add_argument("--since", default="",
                    help="select incidents with a version persisted at/after this "
                         "ISO-8601 time (UTC)")
    ap.add_argument("--until", default="",
                    help="select incidents with a version persisted at/before this "
                         "ISO-8601 time (UTC)")
    ap.add_argument("--useful-confidence", type=float, default=0.5,
                    help="top_confidence floor for the T4 proxy (default 0.5)")
    ap.add_argument("--curve-offsets", default=DEFAULT_CURVE_OFFSETS,
                    help=f"quality-curve offsets in seconds (default {DEFAULT_CURVE_OFFSETS})")
    ap.add_argument("--max-incidents", type=int, default=200000,
                    help="refuse to stream more than this many incident rows into "
                         "Python (default 200000); narrow the scope instead")
    ap.add_argument("--ch-timeout", type=int, default=DEFAULT_CH_TIMEOUT,
                    help=f"per-query timeout in seconds (default {DEFAULT_CH_TIMEOUT})")
    ap.add_argument("--json", dest="json_path", default="",
                    help="write the full result as JSON to this path")
    ap.add_argument("--list-runs", action="store_true",
                    help="list scale-harness run tokens (mlx-<run>-NNNNN device "
                         "residue) with counts and time windows, then exit")
    ap.add_argument("--list-runs-since", default="2026-01-01T00:00:00",
                    help="lower bound for --list-runs (default 2026-01-01T00:00:00)")
    return ap


def validate(args: argparse.Namespace) -> None:
    if args.device_prefix and not SAFE_TOKEN_RE.match(args.device_prefix):
        die(f"--device-prefix {args.device_prefix!r} rejected: allowed charset is "
            "[A-Za-z0-9._:-], first char alphanumeric, max 128 chars")
    if args.tenant and not SAFE_TOKEN_RE.match(args.tenant):
        die(f"--tenant {args.tenant!r} rejected: allowed charset is "
            "[A-Za-z0-9._:-], first char alphanumeric, max 128 chars")
    if not 0.0 <= args.useful_confidence <= 1.0:
        die(f"--useful-confidence must be in [0,1], got {args.useful_confidence}")
    if args.max_incidents < 1:
        die("--max-incidents must be >= 1")
    if args.ch_timeout < 5:
        die("--ch-timeout must be >= 5")
    if args.since:
        args.since = parse_ts(args.since, "--since")
    if args.until:
        args.until = parse_ts(args.until, "--until")
    args.list_runs_since = parse_ts(args.list_runs_since, "--list-runs-since")
    try:
        args.offsets = sorted({int(x) for x in args.curve_offsets.split(",") if x.strip()})
    except ValueError:
        die(f"--curve-offsets: not a comma-separated integer list: {args.curve_offsets!r}")
    if not args.offsets or any(o < 0 for o in args.offsets):
        die("--curve-offsets must be a non-empty list of non-negative integers")


def scope_description(args: argparse.Namespace) -> str:
    bits = []
    if args.device_prefix:
        bits.append(f"device-prefix `{args.device_prefix}`")
    if args.tenant:
        bits.append(f"tenant `{args.tenant}`")
    if args.since:
        bits.append(f"since `{args.since}`")
    if args.until:
        bits.append(f"until `{args.until}`")
    return " AND ".join(bits) if bits else "ENTIRE corr_objects history (unfiltered)"


def do_list_runs(ch: ClickHouse, args: argparse.Namespace) -> int:
    ok, out, err = ch.query(sql_runs(args.list_runs_since))
    if not ok:
        die(f"run listing failed: {err}", 1)
    rows = [ln.split("\t") for ln in out.strip().splitlines() if ln.strip()]
    if not rows:
        die(f"no scale-harness runs found since {args.list_runs_since} — "
            "empty result is an error, not a zero", 1)
    print(f"{'run':<16} {'versions':>10} {'incidents':>10}  first_persist         last_persist")
    for r in rows:
        if len(r) != 5:
            die(f"unexpected run row shape: {r!r}", 1)
        print(f"{r[0]:<16} {int(r[1]):>10,} {int(r[2]):>10,}  {r[3]:<21} {r[4]}")
    print(f"\nuse: --device-prefix mlx-<run>-   (e.g. --device-prefix mlx-{rows[-1][0]}-)")
    return 0


def main(argv: list[str]) -> int:
    os.environ["PATH"] = CRON_PATH + os.pathsep + os.environ.get("PATH", "")
    args = build_parser().parse_args(argv)
    validate(args)
    if not args.project:
        args.project = env_get(args.env_file, "COMPOSE_PROJECT_NAME") or "netops"

    ch = ClickHouse(args.project, args.ch_timeout)
    cid, err = ch.cid()
    if not cid:
        die(err, 1)

    if args.list_runs:
        return do_list_runs(ch, args)

    # -- 0. what exists at all (context for the report) ----------------------
    ok, out, err = ch.query(sql_overall_extent())
    if not ok:
        die(f"corr_objects extent query failed: {err}", 1)
    ext = out.strip().split("\t")
    if len(ext) != 4:
        die(f"corr_objects extent query returned an unexpected shape: {out.strip()!r}", 1)
    if int(ext[0]) == 0:
        die("netops.corr_objects is EMPTY — nothing to measure "
            "(empty result is an error, not a zero)", 1)
    table_extent = {"versions": int(ext[0]), "incidents": int(ext[1]),
                    "created_at_min": ext[2], "created_at_max": ext[3]}
    log(f"corr_objects holds {table_extent['versions']:,} versions / "
        f"{table_extent['incidents']:,} incidents, "
        f"{table_extent['created_at_min']} .. {table_extent['created_at_max']}")

    # -- 1. scope summary ----------------------------------------------------
    ok, out, err = ch.query(sql_scope_summary(args))
    if not ok:
        die(f"scope summary query failed: {err}", 1)
    row = out.strip().split("\t")
    if len(row) != 7:
        die(f"scope summary returned an unexpected shape: {out.strip()!r}", 1)
    scope = {
        "description": scope_description(args),
        "versions": int(row[0]), "incidents": int(row[1]), "tenants": int(row[2]),
        "created_at_min": row[3], "created_at_max": row[4],
        "window_start_min": row[5], "window_end_max": row[6],
    }
    if scope["incidents"] == 0:
        die(f"scope matched ZERO incidents ({scope['description']}) — "
            "empty result is an error, not a zero", 1)
    if scope["incidents"] > args.max_incidents:
        die(f"scope matches {scope['incidents']:,} incidents, above --max-incidents "
            f"({args.max_incidents:,}). Narrow with --device-prefix/--since/--until, "
            "or raise the cap deliberately.", 1)
    log(f"scope: {scope['incidents']:,} incidents / {scope['versions']:,} versions "
        f"({scope['description']})")

    # -- 2. per-incident lifecycle (one ClickHouse pass) ---------------------
    log("reconstructing per-incident lifecycles (this parses the hypotheses blob "
        "server-side; it can take minutes)...")
    ok, out, err = ch.query(sql_incidents(args))
    if not ok:
        die(f"lifecycle query failed: {err}", 1)
    incidents: list[Incident] = []
    for line in out.splitlines():
        if not line.strip():
            continue
        try:
            incidents.append(Incident(line.split("\t")))
        except ValueError as exc:
            die(f"malformed lifecycle row: {exc}", 1)
    if not incidents:
        die("lifecycle query returned no rows despite a non-empty scope — "
            "empty result is an error, not a zero", 1)
    if len(incidents) != scope["incidents"]:
        log(f"WARNING: lifecycle rows ({len(incidents):,}) != scope incidents "
            f"({scope['incidents']:,}); ClickHouse may have merged parts between "
            "queries — the lifecycle count is authoritative for the tables below")

    # -- 3. aggregate --------------------------------------------------------
    by_tenant: dict[str, list[Incident]] = {}
    for inc in incidents:
        by_tenant.setdefault(inc.tenant or "(empty)", []).append(inc)

    result = {
        "tool": "scripts/scale-rca-latency.py",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "command": "python3 scripts/scale-rca-latency.py " + " ".join(argv),
        "read_only": True,
        "table_extent": table_extent,
        "scope": scope,
        "curve_offsets_s": args.offsets,
        "caveats": CAVEATS,
        "proposed_slo_p95_s": PROPOSED_SLO_P95_S,
        "overall": aggregate(incidents, args.offsets, args.useful_confidence),
        "per_tenant": {t: aggregate(v, args.offsets, args.useful_confidence)
                       for t, v in by_tenant.items()},
    }

    if args.json_path:
        try:
            with open(args.json_path, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=2, sort_keys=False)
                f.write("\n")
        except OSError as exc:
            die(f"could not write --json {args.json_path}: {exc}", 1)
        log(f"wrote {args.json_path}")

    print(render_markdown(result))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
