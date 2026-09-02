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
import importlib.util
import json
import math
import os
import re
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from typing import NoReturn

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

# Same rule for the two other things this tool interpolates into a statement:
# ClickHouse setting names and an output FORMAT. Both are tool-supplied today,
# validated anyway (never trust an input because of where it came from).
SAFE_SETTING_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
SAFE_FORMAT_RE = re.compile(r"^[A-Za-z][A-Za-z0-9]{0,31}$")


def log(msg: str) -> None:
    print(f"rca-latency: {msg}", file=sys.stderr, flush=True)


def die(msg: str, code: int = 2) -> NoReturn:
    """Terminates. Typed NoReturn so a caller that dies on a bad value is not
    also required to prove the value is good afterwards."""
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

    def query(self, sql: str, settings: dict[str, object] | None = None,
              fmt: str = "", timeout: int = 0) -> tuple[bool, str, str]:
        """Returns (ok, stdout, error). Read-only by construction: this tool
        only ever builds SELECTs, and the guard below refuses anything else
        before it reaches the server.

        `settings` / `fmt` / `timeout` are OPTIONAL and default to the exact
        statement the original modes issued: `<sql> SETTINGS
        tenant_scope='__all__'` at the instance timeout. The ground-truth mode
        needs per-query containment (its scan JSON-parses the hypotheses blob)
        and JSONEachRow, so it passes them; nothing else does.
        """
        head = sql.lstrip().split(None, 1)[0].upper() if sql.strip() else ""
        if head not in ("SELECT", "WITH"):
            return False, "", f"refusing non-SELECT statement (starts with {head!r})"
        cid, err = self.cid()
        if not cid:
            return False, "", err
        parts = ["tenant_scope='__all__'"]
        for key in sorted(settings or {}):
            if not SAFE_SETTING_RE.match(key):
                return False, "", f"refusing unsafe ClickHouse setting name {key!r}"
            value = (settings or {})[key]
            if not isinstance(value, int) or isinstance(value, bool):
                return False, "", (f"ClickHouse setting {key!r} must be an int, "
                                   f"got {value!r}")
            parts.append(f"{key}={value}")
        stmt = sql + " SETTINGS " + ", ".join(parts)
        if fmt:
            if not SAFE_FORMAT_RE.match(fmt):
                return False, "", f"refusing unsafe FORMAT {fmt!r}"
            stmt += " FORMAT " + fmt
        rc, out, cherr = run(
            ["docker", "exec", cid, "clickhouse-client", "--query", stmt],
            timeout or self.timeout)
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
        lat: list[float] = [v for v in (i.latency_s(stage) for i in reached)
                            if v is not None]
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
        lat1: list[float] = [v for v in (i.latency_s(stage, "T1")
                                        for i in incidents) if v is not None]
        summary = summarize(lat1)
        summary["reached"] = len(lat1)
        summary["never_reached"] = total - len(lat1)
        summary["reached_pct"] = (100.0 * len(lat1) / total) if total else None
        stages_from_t1[stage] = summary

    useful = [i for i in incidents if i.t["T4"] >= 0]
    churn_hist: dict[str, int] = {}
    for inc in useful:
        bucket = str(inc.churn) if inc.churn < 5 else "5+"
        churn_hist[bucket] = churn_hist.get(bucket, 0) + 1
    churn_vals = sorted(float(i.churn) for i in useful)
    version_vals = sorted(float(i.versions) for i in incidents)
    change_vals = sorted(float(i.changes) for i in incidents)

    curve: list[dict[str, object]] = []
    for off in offsets:
        cutoff_ms = off * 1000
        row: dict[str, object] = {"offset_s": off}
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
            cells = [f"{100.0 * row[s]['fraction']:.1f}%"
                     if row[s]["fraction"] is not None else "-"
                     for s in STAGES]
            out.append(f"| {row['offset_s']} | " + " | ".join(cells) + " |")
        out.append("")
    return "\n".join(out)


# ---------------------------------------------------------------------------
# tracker 205 STEP 1 — "Useful RCA" measured against a run's ground truth
# ---------------------------------------------------------------------------
#
# THIS SECTION IS A SEPARATE MODE (`--ground-truth <run-dir>`). It does NOT
# touch, reuse or reinterpret T0..T6 above; the T4 proxy stays exactly what its
# caveat says it is. The four numbers emitted here are the TRACKER-205
# DEFINITIONS and are labelled as such everywhere they are printed:
#
#   time_to_first_candidate  onset -> the first persisted version of any object
#                            that explains the story. For one story this is the
#                            SAME quantity V1 section 8(b) publishes as T1
#                            ("time to first correlated version"). It is NOT
#                            TTUR and must never be printed as TTUR.
#   time_to_first_correct    onset -> the first moment clause (a) holds.
#   time_to_useful           onset -> the first moment every MEASURABLE useful
#                            clause holds simultaneously.
#   time_to_stable           onset -> the earliest moment after which the
#                            story's top hypothesis never changes again.
#
# `onset` is the ground truth's own onset for the story (seconds from burst T0,
# converted to wall clock with the leg's burst_start), NOT window_start. The
# full clause set, its data sources and the NOT-MEASURABLE ones are specified
# in docs/scale/USEFUL_RCA_DEFINITION_2026-09-02.md — this code implements that
# document and nothing else.

USEFUL_DEF_DOC = "docs/scale/USEFUL_RCA_DEFINITION_2026-09-02.md"
GT_SCHEMA = "correlix.scale.ground-truth/1"
TIER_RANK = {"undetermined": 0, "suspected": 1, "confirmed": 2}

# Clause ids. The order is the document's (a)..(e).
CLAUSE_CAUSE = "cause_named"
CLAUSE_OWNER = "ownership_domain"
CLAUSE_BLAST = "blast_radius"
CLAUSE_EVIDENCE = "sufficient_evidence"
CLAUSE_CONTRA = "no_ignored_contradiction"

# Clauses that `time_to_useful` is defined over TODAY. `ownership_domain` is
# absent on purpose: see USEFUL_CLAUSES_NOT_MEASURABLE.
USEFUL_CLAUSES_MEASURED = (CLAUSE_CAUSE, CLAUSE_BLAST, CLAUSE_EVIDENCE,
                           CLAUSE_CONTRA)
USEFUL_CLAUSES_NOT_MEASURABLE = {
    CLAUSE_OWNER: (
        "the truth side exists and is deterministic (ground-truth "
        "`expected_owner_class` / `expected_seam_class`, one value per "
        "template) but the engine side speaks a DIFFERENT vocabulary "
        "(hypothesis verdict.owner: netops|carrier|isp|app_team|...) and no "
        "ratified crosswalk between the two exists; the ground-truth contract "
        "itself declares those labels INFORMATIONAL because the miniladder "
        "onboards devices with no seam configuration (grounding_context.seams "
        "is empty, corr_edges carries no grounding_kind='seam' row). Both "
        "sides are emitted as diagnostics so a crosswalk can be built from "
        "measured data; the clause is NOT part of time_to_useful."),
}

GT_TIMINGS = ("time_to_first_candidate", "time_to_first_correct",
              "time_to_useful", "time_to_stable")

# Per-slice ClickHouse containment. The version scan JSON-parses the
# `hypotheses` blob server-side; measured 2026-09-02 on the s11 corpus at
# ~36 s / 8,100 versions with these settings, so the scan is SLICED by
# created_at and every slice carries its own <= 60 s bound (tracker 201: an
# unbounded corr_objects read is the defect, not the data).
GT_SLICE_TIMEOUT = 60
GT_CH_MAX_MEMORY = 2 << 30       # 2 GiB — one storm-aggregate row is ~1 GiB
GT_CH_MAX_BLOCK = 256            # 26 KB/row blob: small blocks or 1 GiB chunks
GT_CH_MAX_THREADS = 2            # a measurement tool must not own the box
DEFAULT_GT_SLICES = 6

GT_CAVEATS = [
    ("These four numbers are the TRACKER-205 definitions. "
     "`time_to_first_candidate` is the same quantity V1 section 8(b) publishes "
     "as T1 (time to first correlated version); it is NOT TTUR and is never to "
     "be printed as TTUR."),
    ("`onset` is GROUND-TRUTH event time (burst_start + onset_ts, generator "
     "clock, quantised to the scenario's chunk_secs); the four T's are ENGINE "
     "persist wall clock (created_at). Every latency straddles two clocks and "
     "carries at least chunk_secs of injection quantisation. Negative values "
     "are reported, not clamped."),
    ("Clause evaluation reuses scorer v2 verbatim (membership = an object "
     "whose `affected` names one of the story's entities; coverage clauses "
     "over the UNION of the touching objects; quality clauses on the "
     "deterministic `_best_object`), time-indexed: at time t the union is the "
     "latest version of each touching object persisted at or before t."),
    ("`ownership_domain` is NOT MEASURABLE today and is EXCLUDED from "
     "time_to_useful — see `useful_clauses_measured` in every output."),
    ("Stories that never reach a stage are CENSORED and counted, never "
     "dropped: percentiles are over the non-censored stories only and every "
     "table states n plus the censored counts."),
]


def load_ab_driver() -> object:
    """Import `scale-ab-driver.py` for `burst_scope` / `agg_cid`.

    The scope of a tracker-205 measurement MUST be the same scope V1 section
    8(b) publishes T1 over, or the two numbers describe different corpora.
    Re-deriving it here would be a second implementation of a contract that
    already exists, so the driver's own function is imported by path (the
    module name carries dashes; it is import-side-effect free — constants and
    defs only). A failure to import is FATAL: a guessed window is worse than
    no number (the driver's own rule)."""
    path = os.path.join(SCRIPT_DIR, "scale-ab-driver.py")
    spec = importlib.util.spec_from_file_location("scale_ab_driver", path)
    if spec is None or spec.loader is None:
        die(f"cannot load {path} — it holds burst_scope(), the V1 section 8(b) "
            f"scope this mode must reuse")
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    except Exception as exc:      # noqa: BLE001 — report, never swallow
        die(f"importing {path} failed: {exc!r}")
    for name in ("burst_scope", "agg_cid", "parse_iso_z"):
        if not hasattr(mod, name):
            die(f"{path} has no {name}() — the scope contract moved; refusing "
                f"to re-derive it here")
    return mod


def read_json_file(path: str, what: str) -> dict:
    try:
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
    except OSError as exc:
        die(f"cannot read {what} {path!r}: {exc.strerror or exc}", 1)
    except json.JSONDecodeError as exc:
        die(f"{what} {path!r} is not valid JSON: {exc}", 1)
    if not isinstance(doc, dict):
        die(f"{what} {path!r} is not a JSON object", 1)
    return doc


class Story:
    """One ground-truth incident, in the shape the clauses need."""

    __slots__ = ("blast_truth", "cause_names", "entities", "onset_ms",
                 "onset_s", "owner_class", "seam_class", "story_id",
                 "template", "tier_floor")

    def __init__(self, story_id: str, template: str, onset_s: float,
                 onset_ms: int, entities: list[str], cause_names: list[str],
                 blast_truth: list[str], owner_class: str, seam_class: str,
                 tier_floor: str):
        self.story_id = story_id
        self.template = template
        self.onset_s = onset_s
        self.onset_ms = onset_ms
        self.entities = entities
        self.cause_names = cause_names
        self.blast_truth = blast_truth
        self.owner_class = owner_class
        self.seam_class = seam_class
        self.tier_floor = tier_floor


def load_ground_truth(run_dir: str, burst_start_ms: int) -> tuple[dict, list[Story]]:
    """`ground-truth.json` + `ground_truth.jsonl` + `state.json` -> stories.

    Both files are read and CROSS-CHECKED against each other (same ids, same
    onsets). They are two renderings of one scenario; if they disagree the
    scenario is not knowable and no timing derived from it is trustworthy, so
    a disagreement is fatal rather than a warning (zero trust on our own state
    files, CLAUDE.md section 3)."""
    gt = read_json_file(os.path.join(run_dir, "ground-truth.json"),
                        "ground truth")
    if gt.get("schema") != GT_SCHEMA:
        die(f"ground-truth.json schema is {gt.get('schema')!r}, expected "
            f"{GT_SCHEMA!r} — refusing to score against a shape this tool has "
            f"not been taught", 1)
    incidents = gt.get("incidents")
    if not isinstance(incidents, list) or not incidents:
        die("ground-truth.json carries no incidents[] — nothing to measure", 1)

    state_path = os.path.join(run_dir, "state.json")
    prefix = ""
    if os.path.exists(state_path):
        prefix = str(read_json_file(state_path, "twin state").get("prefix") or "")

    jsonl_path = os.path.join(run_dir, "ground_truth.jsonl")
    twin: dict[str, dict] = {}
    try:
        with open(jsonl_path, encoding="utf-8") as f:
            for lineno, line in enumerate(f, 1):
                if not line.strip():
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError as exc:
                    die(f"{jsonl_path}:{lineno} is not valid JSON: {exc}", 1)
                if not isinstance(rec, dict) or not rec.get("story_id"):
                    die(f"{jsonl_path}:{lineno} carries no story_id", 1)
                twin[str(rec["story_id"])] = rec
    except OSError as exc:
        die(f"cannot read {jsonl_path}: {exc.strerror or exc} — the twin "
            f"record shape carries the `expect` clauses scorer v2 grades, and "
            f"this mode reuses them verbatim", 1)

    if len(twin) != len(incidents):
        die(f"ground_truth.jsonl has {len(twin)} stories but "
            f"ground-truth.json has {len(incidents)} incidents — the two "
            f"renderings of the scenario disagree", 1)

    stories: list[Story] = []
    for inc in incidents:
        sid = str(inc.get("incident_id") or "")
        rec = twin.get(sid)
        if rec is None:
            die(f"incident {sid!r} is in ground-truth.json but not in "
                f"ground_truth.jsonl", 1)
        onset = inc.get("onset_ts")
        if not isinstance(onset, (int, float)):
            die(f"incident {sid!r} has no numeric onset_ts", 1)
        twin_onset = rec.get("t0_offset_s")
        if not isinstance(twin_onset, (int, float)) or \
                abs(float(twin_onset) - float(onset)) > 1e-6:
            die(f"incident {sid!r}: onset_ts {onset!r} != jsonl t0_offset_s "
                f"{twin_onset!r} — the two files describe different runs", 1)
        rca = ((rec.get("expect") or {}).get("rca") or {})
        cause = [prefix + str(d) for d in (rca.get("affected_includes") or [])]
        if not cause:
            die(f"story {sid!r} carries no expect.rca.affected_includes — "
                f"clause (a) has no truth to match against", 1)
        labels = rec.get("labels") or {}
        entities = [prefix + str(d)
                    for d in ((rec.get("affected") or {}).get("devices") or [])]
        entities += [prefix + str(e) for e in (rec.get("extra_entities") or [])]
        stories.append(Story(
            story_id=sid,
            template=str(rec.get("template") or inc.get("cause_kind") or ""),
            onset_s=float(onset),
            onset_ms=burst_start_ms + round(float(onset) * 1000),
            entities=list(dict.fromkeys(entities)),
            cause_names=cause,
            blast_truth=[prefix + str(d)
                         for d in (labels.get("blast_radius") or [])],
            owner_class=str(labels.get("expected_owner_class")
                            or inc.get("expected_owner_class") or ""),
            seam_class=str(labels.get("expected_seam_class")
                           or inc.get("expected_seam_class") or ""),
            tier_floor=str(rca.get("verdict_tier_at_least") or "suspected"),
        ))
    stories.sort(key=lambda s: s.story_id)
    return gt, stories


def sql_gt_versions(tenant: str, agg_cid: str, lo: str, hi: str) -> str:
    """One row per persisted version in [lo, hi), all JSON parsed SERVER-side.

    Only scalars and the (small) `affected` blob cross the wire; the 26 KB
    `hypotheses` column never leaves ClickHouse. `th` is the ranked entry whose
    id IS the object's top_hypothesis, falling back to rank 1 (the ranking is
    confidence-descending) and reporting the fallback in `top_fallback` so a
    catalog/ranking drift is visible instead of silent."""
    return f"""
WITH
  JSONExtractArrayRaw(JSONExtractRaw(hypotheses, 'ranking'), 'hypotheses') AS hs,
  arrayFirstIndex(x -> JSONExtractString(x, 'id') = top_hypothesis, hs) AS ti,
  if(ti > 0, hs[ti], if(length(hs) > 0, hs[1], '{{}}')) AS th,
  JSONExtractFloat(th, 'confidence') AS tconf
SELECT
  toString(correlation_id) AS cid,
  toUInt32(version) AS version,
  toUnixTimestamp64Milli(created_at) AS ca_ms,
  toUnixTimestamp64Milli(window_start) AS ws_ms,
  toString(state) AS state,
  toString(verdict_tier) AS tier,
  toFloat64(top_confidence) AS conf,
  toUInt32(node_count) AS nodes,
  affected,
  top_hypothesis AS hyp,
  JSONExtractString(th, 'verdict', 'owner') AS owner,
  toUInt16(JSONLength(th, 'verdict', 'modality_coverage')) AS n_modality,
  toUInt16(JSONLength(th, 'verdict', 'observer_coverage')) AS n_observer,
  toUInt8(JSONExtractRaw(th, 'verdict', 'independent_pair') NOT IN ('', 'null')) AS indep_pair,
  toUInt16(length(arrayFilter(
    x -> JSONExtractBool(x, 'contradicted')
         AND (JSONExtractFloat(x, 'confidence') >= tconf), hs))) AS contra_ge_top,
  toUInt8(ti = 0) AS top_fallback
FROM netops.corr_objects
WHERE tenant_id = {sql_str(tenant)}
  AND created_at >= toDateTime64({sql_str(lo)}, 3)
  AND created_at < toDateTime64({sql_str(hi)}, 3)
  AND correlation_id != toUUID({sql_str(agg_cid)})
""".strip()


class VersionRow:
    """One persisted version, already reduced to what the clauses need."""

    __slots__ = ("affected", "ca_ms", "cid", "conf", "contra_ge_top", "hyp",
                 "indep_pair", "n_modality", "n_observer", "nodes", "owner",
                 "state", "tier", "top_fallback", "version", "ws_ms")

    def __init__(self, doc: dict):
        self.cid = str(doc["cid"])
        self.version = int(doc["version"])
        self.ca_ms = int(doc["ca_ms"])
        self.ws_ms = int(doc["ws_ms"])
        self.state = str(doc["state"])
        self.tier = str(doc["tier"])
        self.conf = float(doc["conf"])
        self.nodes = int(doc["nodes"])
        self.affected = str(doc["affected"])
        self.hyp = str(doc["hyp"])
        self.owner = str(doc["owner"])
        self.n_modality = int(doc["n_modality"])
        self.n_observer = int(doc["n_observer"])
        self.indep_pair = bool(int(doc["indep_pair"]))
        self.contra_ge_top = int(doc["contra_ge_top"])
        self.top_fallback = bool(int(doc["top_fallback"]))


def fetch_gt_versions(ch: ClickHouse, tenant: str, agg_cid: str,
                      lo: str, hi: str, slices: int,
                      max_rows: int) -> list[VersionRow]:
    """The version history of the leg, read in bounded created_at slices."""
    lo_dt = datetime.strptime(lo, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    hi_dt = datetime.strptime(hi, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    span = (hi_dt - lo_dt).total_seconds()
    if span <= 0:
        die(f"version scan window {lo} .. {hi} is empty or inverted", 1)
    step = span / slices
    rows: list[VersionRow] = []
    for i in range(slices):
        a = lo_dt + timedelta(seconds=step * i)
        b = hi_dt if i == slices - 1 else lo_dt + timedelta(seconds=step * (i + 1))
        a_lit = a.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        b_lit = b.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        log(f"version scan slice {i + 1}/{slices}: {a_lit} .. {b_lit}")
        ok, out, err = ch.query(
            sql_gt_versions(tenant, agg_cid, a_lit, b_lit),
            settings={"max_execution_time": GT_SLICE_TIMEOUT,
                      "max_memory_usage": GT_CH_MAX_MEMORY,
                      "max_block_size": GT_CH_MAX_BLOCK,
                      "max_threads": GT_CH_MAX_THREADS},
            fmt="JSONEachRow", timeout=GT_SLICE_TIMEOUT + 30)
        if not ok:
            die(f"version scan slice {i + 1}/{slices} ({a_lit} .. {b_lit}) "
                f"FAILED: {err} — narrow with --gt-slices rather than "
                f"reporting a partial corpus", 1)
        for line in out.splitlines():
            if not line.strip():
                continue
            try:
                rows.append(VersionRow(json.loads(line)))
            except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
                die(f"malformed version row in slice {i + 1}: {exc}", 1)
        if len(rows) > max_rows:
            die(f"version scan exceeded --max-versions ({max_rows:,}) — narrow "
                f"the scope or raise the cap deliberately", 1)
    if not rows:
        die("the version scan returned NO rows for the leg's scope — empty is "
            "an error, not a zero (was the run's corpus purged by cleanup?)", 1)
    return rows


def _affected_tokens(blob: str) -> set[str]:
    """Every entity name an `affected` blob can be said to NAME.

    scorer v2's rule is a substring test (`name in affected`). This indexes the
    blob's own tokens instead — the members of every array it carries, plus the
    part before each ':' (an interface token is `<device>:<ifname>`) — so a
    story's names can be looked up rather than scanned for. On this corpus the
    two are equivalent (device ids are fixed-width and never a substring of one
    another); a name that resolves through NEITHER index falls back to the raw
    substring test in `object_story_map`, so the scorer's rule still bounds the
    answer."""
    out: set[str] = set()
    try:
        doc = json.loads(blob or "{}")
    except json.JSONDecodeError:
        return out
    if not isinstance(doc, dict):
        return out
    for value in doc.values():
        if not isinstance(value, list):
            continue
        for item in value:
            if not isinstance(item, str) or not item:
                continue
            out.add(item)
            if ":" in item:
                out.update(p for p in item.split(":") if p)
    return out


class ObjectHistory:
    """Every persisted version of one correlation object, in persist order."""

    __slots__ = ("cid", "text", "tokens", "versions")

    def __init__(self, cid: str):
        self.cid = cid
        self.versions: list[VersionRow] = []
        self.tokens: set[str] = set()
        self.text = ""

    def finish(self) -> None:
        # Persist order, not version order: an engine restart resets the
        # per-object version counter (the same reason sql_incidents sorts by
        # (created_at, version)).
        self.versions.sort(key=lambda v: (v.ca_ms, v.version))
        seen: set[str] = set()
        for v in self.versions:
            if v.affected in seen:
                continue
            seen.add(v.affected)
            self.tokens |= _affected_tokens(v.affected)
        self.text = "\x00".join(sorted(seen))

    def snapshot(self, at_ms: int) -> VersionRow | None:
        """The latest version persisted at or before `at_ms` (None if none)."""
        found: VersionRow | None = None
        for v in self.versions:
            if v.ca_ms > at_ms:
                break
            found = v
        return found


def object_story_map(objects: dict[str, ObjectHistory],
                     stories: list[Story]) -> dict[str, list[ObjectHistory]]:
    """story_id -> the objects that touch it (scorer v2 membership, verbatim:
    ANY version of the object names one of the story's entities)."""
    by_token: dict[str, list[ObjectHistory]] = {}
    for obj in objects.values():
        for tok in obj.tokens:
            by_token.setdefault(tok, []).append(obj)
    out: dict[str, list[ObjectHistory]] = {}
    for story in stories:
        hits: dict[str, ObjectHistory] = {}
        for name in story.entities:
            direct = by_token.get(name)
            if direct is not None:
                for obj in direct:
                    hits[obj.cid] = obj
                continue
            # Not a token anywhere — fall back to the scorer's substring rule.
            for obj in objects.values():
                if name in obj.text:
                    hits[obj.cid] = obj
        out[story.story_id] = [hits[c] for c in sorted(hits)]
    return out


def _best_version(snap: list[VersionRow]) -> VersionRow | None:
    """scorer v2 `_best_object`, verbatim: tier, then node_count, then
    confidence, then correlation_id ASC as a total-order backstop. Depends on
    the CONTENT of the list, never on its order (tracker 191)."""
    if not snap:
        return None
    return min(snap, key=lambda v: (-TIER_RANK.get(v.tier, 0), -float(v.nodes),
                                    -v.conf, v.cid))


def evaluate_clauses(snap: list[VersionRow], story: Story,
                     min_streams: int) -> dict[str, bool]:
    """The document's clauses, evaluated over ONE time-indexed snapshot."""
    live = [v for v in snap if v.state != "merged"]
    best = _best_version(live)
    # (a) correct cause — COVERAGE over the union (scorer v2 affected_includes).
    cause = bool(live) and all(
        any(name in v.affected for v in live) for name in story.cause_names)
    # (c) meaningful blast radius — scorer v2 states exactly one blast-radius
    # rule and it is `affected_includes`; on the storm corpus its argument IS
    # the cause device, so the clause is identical to (a) by construction. It
    # is kept as a named clause (a future workload may assert a wider set) and
    # NOT re-derived with an invented threshold.
    blast = cause
    # (d) sufficient evidence — QUALITY, on `best`.
    evidence = bool(
        best is not None
        and TIER_RANK.get(best.tier, 0) >= TIER_RANK.get(story.tier_floor, 1)
        and best.n_modality >= min_streams)
    # (e) no ignored major contradiction — QUALITY, on `best`.
    contra = bool(best is not None and best.contra_ge_top == 0)
    return {CLAUSE_CAUSE: cause, CLAUSE_BLAST: blast,
            CLAUSE_EVIDENCE: evidence, CLAUSE_CONTRA: contra}


def measure_story(story: Story, objs: list[ObjectHistory],
                  min_streams: int) -> dict:
    """The four tracker-205 timings for one story, plus its diagnostics."""
    events = sorted({v.ca_ms for obj in objs for v in obj.versions})
    row: dict[str, object] = {
        "story_id": story.story_id,
        "template": story.template,
        "onset_offset_s": story.onset_s,
        "onset_ms": story.onset_ms,
        "objects": len(objs),
        "versions": sum(len(o.versions) for o in objs),
        "expected_owner_class": story.owner_class,
        "expected_seam_class": story.seam_class,
        "useful_clauses_measured": list(USEFUL_CLAUSES_MEASURED),
    }
    for key in GT_TIMINGS:
        row[key] = None
    row["time_to_first_evidence"] = None
    row["time_to_first_uncontradicted"] = None
    row["blast_recall"] = None
    row["best_owner"] = ""
    max_modality = 0
    max_observer = 0
    row["max_modality_coverage"] = max_modality
    row["max_observer_coverage"] = max_observer
    row["independent_pair_seen"] = False
    row["top_hypothesis_final"] = ""
    row["censored_no_candidate"] = not events
    row["censored_not_correct"] = True
    row["censored_not_useful"] = True
    row["censored_never_stable"] = not events
    if not events:
        return row

    def rel(ms: int) -> float:
        return (ms - story.onset_ms) / 1000.0

    row["time_to_first_candidate"] = rel(events[0])
    tops: list[str] = []
    named: set[str] = set()
    for at in events:
        snap = [s for s in (o.snapshot(at) for o in objs) if s is not None]
        live = [v for v in snap if v.state != "merged"]
        best = _best_version(live)
        tops.append(best.hyp if best is not None else "")
        if best is not None:
            row["best_owner"] = best.owner
            max_modality = max(max_modality, best.n_modality)
            max_observer = max(max_observer, best.n_observer)
            if best.indep_pair:
                row["independent_pair_seen"] = True
        for name in story.blast_truth:
            if name not in named and any(name in v.affected for v in live):
                named.add(name)
        ok = evaluate_clauses(snap, story, min_streams)
        if ok[CLAUSE_CAUSE] and row["time_to_first_correct"] is None:
            row["time_to_first_correct"] = rel(at)
            row["censored_not_correct"] = False
        if ok[CLAUSE_EVIDENCE] and row["time_to_first_evidence"] is None:
            row["time_to_first_evidence"] = rel(at)
        if ok[CLAUSE_CONTRA] and row["time_to_first_uncontradicted"] is None:
            row["time_to_first_uncontradicted"] = rel(at)
        if all(ok[c] for c in USEFUL_CLAUSES_MEASURED) and \
                row["time_to_useful"] is None:
            row["time_to_useful"] = rel(at)
            row["censored_not_useful"] = False
    row["top_hypothesis_final"] = tops[-1]
    row["max_modality_coverage"] = max_modality
    row["max_observer_coverage"] = max_observer
    if story.blast_truth:
        row["blast_recall"] = len(named) / len(story.blast_truth)
    # time_to_stable: the earliest event after which the story's top hypothesis
    # never changes again. Always defined once a candidate exists (the last
    # event is trivially stable), so it is censored only with no candidate.
    idx = len(tops) - 1
    while idx > 0 and tops[idx - 1] == tops[idx]:
        idx -= 1
    row["time_to_stable"] = rel(events[idx])
    return row


def summarize_gt(rows: list[dict]) -> dict:
    """p50/p95/p99 per timing over the NON-CENSORED stories, with the censored
    counts beside them. A censored story is never silently dropped."""
    out: dict[str, object] = {}
    timings: dict[str, dict] = {}
    for key in GT_TIMINGS:
        vals = [float(r[key]) for r in rows if r[key] is not None]
        summary = summarize(vals)
        summary["censored"] = len(rows) - len(vals)
        summary["censored_pct"] = ((100.0 * (len(rows) - len(vals)) / len(rows))
                                   if rows else None)
        summary["negative_latency"] = sum(1 for v in vals if v < 0)
        timings[key] = summary
    out["stories"] = len(rows)
    out["timings"] = timings
    out["censored"] = {
        "no_candidate": sum(1 for r in rows if r["censored_no_candidate"]),
        "not_correct": sum(1 for r in rows if r["censored_not_correct"]),
        "not_useful": sum(1 for r in rows if r["censored_not_useful"]),
        "never_stable": sum(1 for r in rows if r["censored_never_stable"]),
    }
    out["clause_first_satisfied"] = {
        CLAUSE_EVIDENCE: summarize(
            [float(r["time_to_first_evidence"]) for r in rows
             if r["time_to_first_evidence"] is not None]),
        CLAUSE_CONTRA: summarize(
            [float(r["time_to_first_uncontradicted"]) for r in rows
             if r["time_to_first_uncontradicted"] is not None]),
    }
    out["clause_never_satisfied"] = {
        CLAUSE_CAUSE: sum(1 for r in rows if r["time_to_first_correct"] is None),
        CLAUSE_BLAST: sum(1 for r in rows if r["time_to_first_correct"] is None),
        CLAUSE_EVIDENCE: sum(1 for r in rows
                             if r["time_to_first_evidence"] is None),
        CLAUSE_CONTRA: sum(1 for r in rows
                           if r["time_to_first_uncontradicted"] is None),
    }
    recalls = sorted(float(r["blast_recall"]) for r in rows
                     if r["blast_recall"] is not None)
    # A RATIO, not a latency — its own keys, so nothing reads `p50_s` seconds
    # off a fraction. Reported, never gated: scorer v2 states no blast-radius
    # threshold and this tool does not invent one (see USEFUL_DEF_DOC).
    out["blast_radius_recall_diagnostic"] = {
        "n": len(recalls),
        "min": recalls[0] if recalls else None,
        "p50": pct(recalls, 50), "p95": pct(recalls, 95),
        "p99": pct(recalls, 99),
        "max": recalls[-1] if recalls else None,
        "mean": (sum(recalls) / len(recalls)) if recalls else None,
        "full_recall_stories": sum(1 for v in recalls if v >= 1.0),
    }
    out["owner_diagnostic"] = {
        "note": USEFUL_CLAUSES_NOT_MEASURABLE[CLAUSE_OWNER],
        "expected_owner_class": _tally(str(r["expected_owner_class"]) for r in rows),
        "expected_seam_class": _tally(str(r["expected_seam_class"]) for r in rows),
        "engine_owner_of_best": _tally(str(r["best_owner"]) for r in rows),
    }
    out["independence_diagnostic"] = {
        "max_modality_coverage": _tally(str(r["max_modality_coverage"])
                                        for r in rows),
        "max_observer_coverage": _tally(str(r["max_observer_coverage"])
                                        for r in rows),
        "independent_pair_seen": sum(1 for r in rows
                                     if r["independent_pair_seen"]),
    }
    return out


GT_TSV_COLUMNS = (
    "story_id", "template", "onset_offset_s", "onset_ms", "objects", "versions",
    "time_to_first_candidate", "time_to_first_correct", "time_to_useful",
    "time_to_stable", "time_to_first_evidence", "time_to_first_uncontradicted",
    "blast_recall", "best_owner", "expected_owner_class", "expected_seam_class",
    "max_modality_coverage", "max_observer_coverage", "independent_pair_seen",
    "top_hypothesis_final", "censored_no_candidate", "censored_not_correct",
    "censored_not_useful", "censored_never_stable", "useful_clauses_measured",
)


def render_gt_tsv(rows: list[dict]) -> str:
    def cell(value: object) -> str:
        if value is None:
            return ""
        if isinstance(value, bool):
            return "1" if value else "0"
        if isinstance(value, float):
            return f"{value:.3f}"
        if isinstance(value, list):
            return ",".join(str(v) for v in value)
        return str(value)

    lines = ["\t".join(GT_TSV_COLUMNS)]
    for row in rows:
        lines.append("\t".join(cell(row.get(c)) for c in GT_TSV_COLUMNS))
    return "\n".join(lines) + "\n"


def write_text_file(path: str, text: str) -> None:
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
    except OSError as exc:
        die(f"could not write {path}: {exc.strerror or exc}", 1)
    log(f"wrote {path}")


def do_ground_truth(ch: ClickHouse, args: argparse.Namespace,
                    argv: list[str]) -> int:
    """`--ground-truth <run-dir>` — the tracker-205 STEP 1 measurement."""
    run_dir = os.path.abspath(args.ground_truth)
    if not os.path.isdir(run_dir):
        die(f"--ground-truth {run_dir!r} is not a directory", 2)
    driver = load_ab_driver()
    report = read_json_file(os.path.join(run_dir, "report.json"), "run report")
    try:
        scope = driver.burst_scope(report)            # type: ignore[attr-defined]
    except Exception as exc:                          # noqa: BLE001
        die(f"cannot derive the V1 section 8(b) burst scope from "
            f"{run_dir}/report.json: {exc} — a timing over a guessed window is "
            f"worse than no timing", 1)
    tenant = args.tenant
    scope_path = os.path.join(run_dir, "ttur-scope.json")
    if not tenant and os.path.exists(scope_path):
        tenant = str(read_json_file(scope_path, "ttur scope").get("tenant") or "")
    if not tenant:
        die("--tenant is required in --ground-truth mode (and the run dir "
            "carries no ttur-scope.json to read it from): an unscoped read of "
            "corr_objects is the defect tracker 201 records", 2)
    if not SAFE_TOKEN_RE.match(tenant):
        die(f"tenant {tenant!r} rejected: allowed charset is [A-Za-z0-9._:-]")
    agg = driver.agg_cid(tenant)                      # type: ignore[attr-defined]

    burst_start = driver.parse_iso_z(               # type: ignore[attr-defined]
        scope["burst_start"].replace(" ", "T") + "Z")
    burst_start_ms = int(burst_start.timestamp() * 1000)
    burst_end_ms = int(driver.parse_iso_z(          # type: ignore[attr-defined]
        scope["burst_end"].replace(" ", "T") + "Z").timestamp() * 1000)

    gt, stories = load_ground_truth(run_dir, burst_start_ms)
    log(f"ground truth: {len(stories)} stories, runid {gt.get('runid')!r}, "
        f"profile {gt.get('profile')!r}, seed {gt.get('seed')!r}")
    log(f"scope: tenant {tenant!r}, burst {scope['burst_start']} .. "
        f"{scope['burst_end']}, converged {scope['converged']}, "
        f"agg cid {agg} excluded")

    versions = fetch_gt_versions(ch, tenant, agg, scope["burst_start"],
                                 scope["converged"], args.gt_slices,
                                 args.max_versions)
    objects: dict[str, ObjectHistory] = {}
    for v in versions:
        objects.setdefault(v.cid, ObjectHistory(v.cid)).versions.append(v)
    for obj in objects.values():
        obj.finish()
    # V1 section 8(b) scope, applied per object: an incident belongs to the leg
    # when its FIRST event time falls inside the burst window. Same rule, same
    # corpus as the published T1 — so the two numbers describe one population.
    in_scope = {cid: obj for cid, obj in objects.items()
                if burst_start_ms <= min(v.ws_ms for v in obj.versions) < burst_end_ms}
    fallbacks = sum(1 for v in versions if v.top_fallback)
    log(f"corpus: {len(versions):,} versions / {len(objects):,} objects read; "
        f"{len(in_scope):,} objects inside the section-8(b) burst scope"
        + (f"; {fallbacks} version(s) fell back to ranked entry 1 because no "
           f"ranked hypothesis carried the object's top_hypothesis id"
           if fallbacks else ""))
    if not in_scope:
        die("no object's first event time falls inside the burst window — "
            "empty is an error, not a zero", 1)

    touching = object_story_map(in_scope, stories)
    rows = [measure_story(s, touching[s.story_id], args.independent_streams)
            for s in stories]
    summary = summarize_gt(rows)

    out_dir = os.path.abspath(args.out_dir or run_dir)
    if not os.path.isdir(out_dir):
        die(f"--out-dir {out_dir!r} is not a directory", 2)
    doc = {
        "tool": "scripts/scale-rca-latency.py",
        "mode": "ground-truth (tracker 205 STEP 1)",
        "definition_doc": USEFUL_DEF_DOC,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "command": "python3 scripts/scale-rca-latency.py " + " ".join(argv),
        "read_only": True,
        "run": {
            "run_dir": run_dir,
            "runid": gt.get("runid"),
            "profile": gt.get("profile"),
            "scenario": gt.get("scenario"),
            "seed": gt.get("seed"),
            "digest": gt.get("digest"),
            "chunk_secs": gt.get("chunk_secs"),
            "tenant": tenant,
            "scope": scope,
            "excluded_agg_cid": agg,
        },
        "corpus": {
            "stories": len(stories),
            "versions_read": len(versions),
            "objects_read": len(objects),
            "objects_in_burst_scope": len(in_scope),
            "top_hypothesis_rank_fallbacks": fallbacks,
        },
        "useful_clauses_measured": list(USEFUL_CLAUSES_MEASURED),
        "useful_clauses_not_measurable": USEFUL_CLAUSES_NOT_MEASURABLE,
        "independent_streams_threshold": args.independent_streams,
        "independent_streams_field": (
            "hypotheses.ranking.hypotheses[top].verdict.modality_coverage "
            "(the engine's own independence test: its evidence_missing reason "
            "string is \"single modality class (...); need >=2\")"),
        "caveats": GT_CAVEATS,
        "summary": summary,
    }
    tsv_path = os.path.join(out_dir, "ttur-useful.tsv")
    json_path = os.path.join(out_dir, "ttur-useful-summary.json")
    write_text_file(tsv_path, render_gt_tsv(rows))
    write_text_file(json_path, json.dumps(doc, indent=2, sort_keys=False) + "\n")

    print(f"tracker-205 useful-RCA measurement — {len(stories)} stories, "
          f"tenant {tenant}, run {gt.get('runid')}")
    print(f"clauses measured: {', '.join(USEFUL_CLAUSES_MEASURED)} "
          f"(NOT MEASURABLE: {', '.join(USEFUL_CLAUSES_NOT_MEASURABLE)})")
    print(f"{'timing':<26} {'n':>5} {'p50 s':>10} {'p95 s':>10} {'p99 s':>10} "
          f"{'max s':>10} {'censored':>9}")
    for key in GT_TIMINGS:
        s = summary["timings"][key]
        print(f"{key:<26} {s['n']:>5} {_fmt(s['p50_s']):>10} "
              f"{_fmt(s['p95_s']):>10} {_fmt(s['p99_s']):>10} "
              f"{_fmt(s['max_s']):>10} {s['censored']:>9}")
    print(f"censored: {json.dumps(summary['censored'])}")
    print("time_to_first_candidate is the tracker-205 name for the same "
          "quantity V1 section 8(b) publishes as T1; it is NOT TTUR.")
    return 0


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
    gt = ap.add_argument_group(
        "ground-truth mode (tracker 205 STEP 1)",
        "Scores the persisted version history against a t-storm run's OWN "
        "ground truth and emits the four tracker-205 timings. Leaves every "
        "other mode untouched. See " + USEFUL_DEF_DOC + ".")
    gt.add_argument("--ground-truth", default="", metavar="RUN_DIR",
                    help="a t-storm run directory holding ground-truth.json, "
                         "ground_truth.jsonl and report.json; enables the mode")
    gt.add_argument("--out-dir", default="",
                    help="where ttur-useful.tsv + ttur-useful-summary.json go "
                         "(default: the run dir)")
    gt.add_argument("--gt-slices", type=int, default=DEFAULT_GT_SLICES,
                    help=f"created_at slices for the version scan, each with "
                         f"its own {GT_SLICE_TIMEOUT}s bound "
                         f"(default {DEFAULT_GT_SLICES})")
    gt.add_argument("--independent-streams", type=int, default=2,
                    help="minimum DISTINCT evidence modality classes the top "
                         "hypothesis must cover for the sufficient_evidence "
                         "clause (default 2 — the engine's own bar)")
    gt.add_argument("--max-versions", type=int, default=500000,
                    help="refuse to stream more than this many version rows "
                         "into Python (default 500000)")
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
    if args.ground_truth:
        if args.gt_slices < 1 or args.gt_slices > 240:
            die("--gt-slices must be in [1, 240]")
        if args.independent_streams < 1:
            die("--independent-streams must be >= 1")
        if args.max_versions < 1:
            die("--max-versions must be >= 1")
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

    if args.ground_truth:
        return do_ground_truth(ch, args, argv)

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
