"""Snapshot restorability + repository-custody ship contract (2026-09-03).

WHY THIS SUITE EXISTS. The netops-fs OpenSearch snapshot repository was
silently UNRESTORABLE for seven days (2026-08-26 -> 2026-09-03). A manual
`rm -rf .../data/opensearch-snapshots/indices` during the 08-26 disk crunch
deleted the repository's blob tree while the repository stayed registered;
OpenSearch re-created the empty directory at 2026-08-27T01:30:46Z (the instant
the next scheduled snapshot started) and from then on every shard failed with
`java.nio.file.NoSuchFileException: .../snapshots/indices/<id>/0/index-<gen>`
out of BlobStoreRepository.buildBlobStoreIndexShardSnapshots. Nothing alerted:
the SM policy kept "succeeding" into PARTIAL, `_cat/snapshots` kept listing
rows, and every control measured that a snapshot HAPPENED rather than that one
could be RESTORED.

A second, independent defect was proven live the same day at 11:47Z:
`apply-ism.sh` PUT the netops-daily SM policy with no `enabled` field, and
OpenSearch defaults a missing `enabled` to true — so a schedule an operator had
deliberately stopped from the GUI was silently RE-ENABLED by the next
`docker compose up`.

Executed-function tests (fake `curl` on PATH, real script runs -- never
grep-only where execution is possible) pinning:

  * apply-ism.sh, SM policy `enabled` custody: an UPDATE echoes the LIVE flag
    back (true stays true, false stays false and is announced on stderr with
    its consequence), only a CREATE may set enabled true, and an existing
    policy whose flag cannot be parsed is NOT written at all (preserve, loudly)
    -- because a write without the flag defaults to true and would clobber a
    deliberate stop;
  * apply-ism.sh, SINGLE-WRITER guard: a foreign repository name already
    pointing at the same `location` blocks the netops-fs registration with a
    loud refusal (two names over one blob tree = two deleters = the documented
    corruption hazard), while the ordinary single-repository case registers
    normally and an unreadable `_snapshot/_all` registers but says the guard
    did not run;
  * stack-watchdog.sh, tracker 225(b): a PARTIAL snapshot now carries the first
    shard-failure REASON, picked from the NEWEST partial snapshot, single-line
    and bounded -- and says "reason unavailable" rather than implying there is
    none. The stable half of the message is longer than the 160 characters
    problem_key hashes, so a run-varying reason cannot mint a new problem class
    (and a new phone push) every minute;
  * stack-watchdog.sh, the new SNAPSHOT_RESTORABLE_CHECK problem class: present,
    opt-out documented in stack-watchdog.env.example, absence handled as
    UNPROVEN rather than healthy;
  * host-hygiene.sh, the flood-stage healer: it spoke plain HTTP to a TLS
    listener, so `heal_opensearch` reported 0 blocked indices for every secured
    install and the healing this script exists for had NEVER run (verified live
    2026-09-03: curl rc=52 "Empty reply from server" -> old code counted 0).
    Pinned here: https-with-CA-and-admin-cert first, plaintext only as a
    fallback, `--resolve` rather than `-k`, and a failed probe reported as a
    NAMED WARN carrying curl's error -- never as 0;
  * every touched script stays `bash -n`/`sh -n` clean and shellcheck clean.
"""

import os
import re
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
WATCHDOG = SCRIPTS / "stack-watchdog.sh"
HYGIENE = SCRIPTS / "host-hygiene.sh"
ENV_EXAMPLE = SCRIPTS / "stack-watchdog.env.example"
APPLY_ISM = ROOT / "deployment" / "docker" / "opensearch" / "apply-ism.sh"
SNAP_README = ROOT / "deployment" / "docker" / "opensearch" / "SNAPSHOTS-DO-NOT-DELETE-README.txt"
RULES_SLO = ROOT / "src" / "config" / "rules-scale-slo.yaml"
RULES_TEST = ROOT / "src" / "config" / "rules-tests" / "snapshot-restorability.test.yaml"


def _write_exec(path: Path, content: str) -> None:
    path.write_text(content)
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def _extract(script: Path, name: str) -> str:
    """Pull one shell function out of a script for standalone execution."""
    r = subprocess.run(
        ["sed", "-n", f"/^{name}() {{/,/^}}/p", str(script)],
        capture_output=True, text=True, check=True)
    assert r.stdout.strip(), f"{name}() not found in {script.name}"
    return r.stdout


# ===========================================================================
# apply-ism.sh — executed end to end with a fake curl
# ===========================================================================

# The fake curl answers by URL and records METHOD + URL + stdin body, so the
# tests assert on what actually crossed the process boundary rather than on
# what the source looks like. Responses are canned per test via env vars.
FAKE_CURL = r"""#!/bin/sh
# Parse enough of curl's argv to know the method, the URL and whether a body
# arrives on stdin (`-d @-`). Everything else is ignored on purpose.
method=GET
url=
stdin_body=
while [ $# -gt 0 ]; do
  case "$1" in
    -X) method="$2"; shift 2 ;;
    -H) shift 2 ;;
    -d) if [ "$2" = "@-" ]; then stdin_body=$(cat); else stdin_body="$2"; fi; shift 2 ;;
    -o) shift 2 ;;
    -m) shift 2 ;;
    -s|-f|-sf|-fsS|-sS) shift ;;
    -*) shift ;;
    *) url="$1"; shift ;;
  esac
done
# One record per call, single-line: a multi-line JSON body would otherwise
# split into records the reader cannot reassemble.
printf '%s\t%s\t%s\n' "$method" "$url" "$(printf '%s' "$stdin_body" | tr '\n' ' ')" >> "$CURL_LOG"
case "$url" in
  */_cluster/health*)  printf '{"status":"green","number_of_data_nodes":1}' ;;
  */_cluster/settings*) printf '{"acknowledged":true}' ;;
  */_snapshot/_all*)   printf '%s' "$FAKE_REPOS" ;;
  */_snapshot/netops-fs) printf '%s' "${FAKE_REPO_PUT:-{\"acknowledged\":true\}}" ;;
  */_plugins/_sm/policies/netops-daily*)
      case "$method" in
        GET) printf '%s' "$FAKE_SM_GET" ;;
        *)   printf '{"_id":"netops-daily-sm-policy","sm_policy":{"name":"netops-daily"}}' ;;
      esac ;;
  */_plugins/_ism/*)   printf '{"_id":"netops-retention","_seq_no":1,"_primary_term":1}' ;;
  *)                   printf '{"acknowledged":true}' ;;
esac
exit 0
"""

SM_GET_404 = '{"error":{"root_cause":[{"type":"status_exception","reason":"policy not found"}]},"status":404}'


def _sm_get(enabled: str | None) -> str:
    """A realistic _sm/policies GET body (shape copied from the live cluster,
    2026-09-03), optionally with the `enabled` field removed."""
    en = "" if enabled is None else f'"enabled":{enabled},'
    return (
        '{"_id":"netops-daily-sm-policy","_version":18,"_seq_no":544423,'
        '"_primary_term":8,"sm_policy":{"name":"netops-daily",'
        '"description":"Daily snapshot of netops-* to the netops-fs repository (F-59).",'
        '"schema_version":21,'
        '"creation":{"schedule":{"cron":{"expression":"30 1 * * *","timezone":"UTC"}},"time_limit":"2h"},'
        '"deletion":{"schedule":{"cron":{"expression":"0 3 * * *","timezone":"UTC"}},'
        '"condition":{"min_count":1,"max_count":14}},'
        '"snapshot_config":{"indices":"netops-*","ignore_unavailable":true,'
        '"include_global_state":false,"repository":"netops-fs"},'
        '"schedule":{"interval":{"start_time":1788436012037,"period":1,"unit":"Minutes"}},'
        f'{en}"last_updated_time":1788436031931,"enabled_time":null}}}}'
    )


ONLY_OURS = ('{"netops-fs":{"type":"fs","settings":{"compress":"true",'
             '"location":"/usr/share/opensearch/snapshots"}}}')
FOREIGN_SAME_LOCATION = (
    '{"netops-fs":{"type":"fs","settings":{"compress":"true",'
    '"location":"/usr/share/opensearch/snapshots"}},'
    '"legacy-fs":{"type":"fs","settings":{"location":"/usr/share/opensearch/snapshots"}}}')
FOREIGN_OTHER_LOCATION = (
    '{"netops-fs":{"type":"fs","settings":{"location":"/usr/share/opensearch/snapshots"}},'
    '"offsite":{"type":"fs","settings":{"location":"/mnt/elsewhere"}}}')


def _run_apply_ism(tmp_path: Path, sm_get: str, repos: str = ONLY_OURS):
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    _write_exec(bindir / "curl", FAKE_CURL)
    # `sleep` is only reached if the health wait loop fails; make it a no-op so
    # a regression there fails fast instead of hanging the suite.
    _write_exec(bindir / "sleep", "#!/bin/sh\nexit 0\n")
    log = tmp_path / "curl.log"
    env = os.environ.copy()
    env["PATH"] = f"{bindir}:{env['PATH']}"
    env["CURL_LOG"] = str(log)
    env["FAKE_SM_GET"] = sm_get
    env["FAKE_REPOS"] = repos
    r = subprocess.run(["sh", str(APPLY_ISM)], env=env,
                       capture_output=True, text=True, timeout=60)
    calls = []
    if log.exists():
        for line in log.read_text().splitlines():
            parts = line.split("\t")
            if len(parts) == 3:
                calls.append(tuple(parts))
    return r, calls


def _sm_writes(calls):
    return [c for c in calls
            if "/_plugins/_sm/policies/netops-daily" in c[1] and c[0] != "GET"]


def _repo_puts(calls):
    return [c for c in calls
            if c[1].endswith("/_snapshot/netops-fs") and c[0] == "PUT"]


def test_sm_update_preserves_a_disabled_schedule(tmp_path):
    """THE 11:47Z DEFECT. An operator stopped the schedule; the bootstrap must
    echo enabled=false back, not omit the field (which defaults to true)."""
    r, calls = _run_apply_ism(tmp_path, _sm_get("false"))
    writes = _sm_writes(calls)
    assert len(writes) == 1, f"exactly one SM write expected: {writes}"
    method, url, body = writes[0]
    assert method == "PUT" and "if_seq_no=544423" in url, (method, url)
    assert '"enabled": false' in body, (
        "an UPDATE must carry the LIVE enabled flag — omitting it lets "
        f"OpenSearch default it to true and re-enable a stopped schedule: {body}")
    assert "DISABLED by operator intent" in r.stderr, r.stderr
    assert "no new restore points are being created" in r.stderr, (
        "the notice must state the CONSEQUENCE, not just the fact")


def test_sm_update_preserves_an_enabled_schedule(tmp_path):
    r, calls = _run_apply_ism(tmp_path, _sm_get("true"))
    writes = _sm_writes(calls)
    assert len(writes) == 1
    method, url, body = writes[0]
    assert method == "PUT" and "if_primary_term=8" in url
    assert '"enabled": true' in body, body
    assert "DISABLED by operator intent" not in r.stderr


def test_sm_create_sets_enabled_true(tmp_path):
    """Only a CREATE may turn the schedule on — that is the product default."""
    r, calls = _run_apply_ism(tmp_path, SM_GET_404)
    writes = _sm_writes(calls)
    assert len(writes) == 1
    method, url, body = writes[0]
    assert method == "POST", "SM create is POST; a seq_no-less PUT is rejected"
    assert "if_seq_no" not in url
    assert '"enabled": true' in body, body


def test_sm_unparsable_enabled_refuses_to_write(tmp_path):
    """§16.1. The policy exists but its flag did not parse. Writing without the
    flag would default it to true, so the ONLY safe move is not to write —
    loudly, naming what was therefore not applied."""
    r, calls = _run_apply_ism(tmp_path, _sm_get(None))
    assert _sm_writes(calls) == [], (
        "an existing policy with an unreadable enabled flag must NOT be written")
    assert "could not be read" in r.stderr and "REFUSING to update" in r.stderr, r.stderr
    assert "has NOT been applied" in r.stderr, (
        "the operator must be told the policy definition was left stale")


def test_single_writer_guard_blocks_a_second_repository_name(tmp_path):
    """Two repository names over one filesystem location is the documented
    OpenSearch corruption hazard — two deleters, one blob tree."""
    r, calls = _run_apply_ism(tmp_path, _sm_get("true"), repos=FOREIGN_SAME_LOCATION)
    assert _repo_puts(calls) == [], (
        "netops-fs must NOT be registered while another name claims the same location")
    assert "REFUSING to register netops-fs" in r.stderr, r.stderr
    assert "legacy-fs" in r.stderr, "the refusal must NAME the conflicting repository"
    # Non-fatal: retention still has to be applied.
    assert _sm_writes(calls), "the guard must not abort the rest of the bootstrap"


def test_single_writer_guard_allows_the_normal_case(tmp_path):
    r, calls = _run_apply_ism(tmp_path, _sm_get("true"), repos=ONLY_OURS)
    assert len(_repo_puts(calls)) == 1, "the ordinary single-repository case must register"
    assert "REFUSING" not in r.stderr


def test_single_writer_guard_ignores_a_repository_elsewhere(tmp_path):
    """A second repository at a DIFFERENT location is fine and must not block —
    a guard that cries wolf gets routed around."""
    r, calls = _run_apply_ism(tmp_path, _sm_get("true"), repos=FOREIGN_OTHER_LOCATION)
    assert len(_repo_puts(calls)) == 1
    assert "REFUSING" not in r.stderr


def test_single_writer_guard_unreadable_is_named_not_assumed(tmp_path):
    """An unreadable guard is not a passed guard (§16.1). We still register —
    refusing on an unproven conflict would leave a fresh stack with no backup —
    but the ambiguity is stated."""
    r, calls = _run_apply_ism(tmp_path, _sm_get("true"), repos="")
    assert len(_repo_puts(calls)) == 1
    assert "single-writer check did NOT run" in r.stderr, r.stderr


def test_do_not_delete_notice_is_versioned_in_the_repo():
    """data/ is gitignored, so the SOURCE of the operator notice must live in
    the repo — a warning that exists only on one host is a one-host artefact."""
    assert SNAP_README.is_file(), f"{SNAP_README} missing"
    text = SNAP_README.read_text(encoding="utf-8")
    for needle in ("LIVE OPENSEARCH SNAPSHOT REPOSITORY",
                   "unregister FIRST",
                   "A BACKUP THAT HAS NEVER BEEN RESTORED IS NOT A BACKUP."):
        assert needle in text, f"notice lost its {needle!r} clause"
    install = (SCRIPTS / "install.py").read_text(encoding="utf-8")
    assert "SNAPSHOTS-DO-NOT-DELETE-README.txt" in install, (
        "scripts/install.py must place the notice — the opensearch-init "
        "container has no mount of the repository and cannot")


# ===========================================================================
# stack-watchdog.sh — PARTIAL diagnosis (tracker 225(b))
# ===========================================================================

def _partial_harness(snap_json: str, detail: str | None) -> tuple[str, str]:
    """Run the newest-PARTIAL selection + reason extraction exactly as the
    watchdog does, with os_fetch stubbed to return `detail`."""
    src = WATCHDOG.read_text()
    m = re.search(r"( *)# Newest PARTIAL snapshot by end_epoch\.(.*?)\n( *)# The stable sentence comes FIRST",
                  src, re.S)
    assert m, "the PARTIAL diagnosis block moved — re-point this harness"
    block = m.group(0).rsplit("# The stable sentence", 1)[0]
    stub = (
        'OS_API_PW=""; OS_MON_PW=""\n'
        'os_fetch() { printf "%s" "${FAKE_DETAIL:-}"; }\n'
        f'snap_json={_shq(snap_json)}\n'
    )
    tail = 'printf "ID=%s\\nREASON=%s\\n" "${snap_p_id:-}" "$snap_reason"\n'
    env = os.environ.copy()
    if detail is not None:
        env["FAKE_DETAIL"] = detail
    r = subprocess.run(["bash", "-c", stub + block + tail],
                       env=env, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    out = dict(line.split("=", 1) for line in r.stdout.splitlines() if "=" in line)
    return out.get("ID", ""), out.get("REASON", "")


def _shq(s: str) -> str:
    return "'" + s.replace("'", "'\\''") + "'"


NOSUCHFILE = ("java.nio.file.NoSuchFileException: "
              "/usr/share/opensearch/snapshots/indices/xY9/0/index-14")

DETAIL_WITH_FAILURES = (
    '{"snapshots":[{"snapshot":"netops-daily-c","state":"PARTIAL",'
    '"shards":{"total":40,"failed":40,"successful":0},"failures":['
    f'{{"index":"netops-flows-2026.09.01","index_uuid":"AbC","shard_id":0,'
    f'"reason":"{NOSUCHFILE}","node_id":"n1","status":"INTERNAL_SERVER_ERROR"}},'
    '{"index":"netops-syslog-2026.09.01","reason":"second failure"}]}]}')

CAT_TWO_PARTIALS = (
    '[{"id":"netops-daily-a","status":"SUCCESS","end_epoch":"1756000000"},'
    '{"id":"netops-daily-b","status":"PARTIAL","end_epoch":"1756100000"},'
    '{"id":"netops-daily-c","status":"PARTIAL","end_epoch":"1756200000"}]')


def test_partial_reports_the_newest_partial_and_its_reason():
    """The whole point of 225(b): the next occurrence must be self-describing."""
    sid, reason = _partial_harness(CAT_TWO_PARTIALS, DETAIL_WITH_FAILURES)
    assert sid == "netops-daily-c", "must pick the NEWEST partial by end_epoch"
    assert reason == NOSUCHFILE, reason
    assert "\n" not in reason and "\t" not in reason, "must be a single line"


def test_partial_reason_unavailable_when_the_detail_cannot_be_fetched():
    """Never imply there is no reason when we simply could not read one."""
    _, reason = _partial_harness(CAT_TWO_PARTIALS, "")
    assert reason == "reason unavailable", reason
    _, reason = _partial_harness(CAT_TWO_PARTIALS,
                                 '{"snapshots":[{"state":"PARTIAL"}]}')
    assert reason == "reason unavailable", reason


def test_partial_reason_is_bounded_and_single_line():
    long_reason = "x" * 400 + "\nsecond line"
    detail = '{"snapshots":[{"failures":[{"reason":"%s"}]}]}' % long_reason.replace("\n", " ")
    _, reason = _partial_harness(CAT_TWO_PARTIALS, detail)
    assert len(reason) <= 200, f"reason must be truncated, got {len(reason)}"


def test_partial_stable_prefix_outlives_problem_key_hash():
    """problem_key hashes the FIRST 160 characters. The run-varying reason must
    sit past that, or a changing shard/generation mints a brand-new problem
    class — and a brand-new phone push — every single minute."""
    src = WATCHDOG.read_text()
    m = re.search(r'problems\+=\("(OpenSearch snapshot is PARTIAL[^"]*)"\)', src)
    assert m, "the PARTIAL problem message moved"
    msg = m.group(1)
    idx = msg.find("${snap_p_id")
    assert idx > 160, (
        f"the first run-varying token starts at char {idx}; it must be past the "
        "160 characters problem_key hashes")


def test_partial_reason_fetch_is_bounded():
    """§16.3: every external call bounded. The detail fetch rides os_fetch,
    whose curl config carries max-time."""
    src = WATCHDOG.read_text()
    assert 'os_fetch svc_api "$OS_API_PW" "/_snapshot/netops-fs/${snap_p_id}"' in src
    assert '"max-time = 8"' in src, "os_fetch lost its bound"


# ===========================================================================
# stack-watchdog.sh — the new restorability problem class
# ===========================================================================

def test_restorability_problem_class_exists_and_is_opt_outable():
    src = WATCHDOG.read_text()
    assert 'if [ "${SNAPSHOT_RESTORABLE_CHECK:-1}" = "1" ]; then' in src, (
        "the restorability probe must carry an ENGINE_CONSUMER_CHECK-style opt-out")
    assert "SNAPSHOT_NOT_RESTORABLE:" in src
    assert "SNAPSHOT_RESTORABILITY_UNPROVEN:" in src, (
        "an ABSENT metric must be its own named problem — blind is not fresh")
    assert "netops_opensearch_snapshot_restorable" in src
    assert "storage-and-volume-operations.md#managing-snapshots" in src, (
        "every problem must carry its runbook")


def test_restorability_is_advisory_not_a_watchdog_critical():
    """DELIBERATE, and pinned so a future edit is a decision rather than a slip.

    problem_is_critical() decides which problems become an URGENT phone push.
    An unrestorable backup is a latent recovery risk, not a live outage, and the
    owner approved exactly four page-worthy conditions (2026-09-02) — none of
    them this. It still pushes on transition as an ADVISORY, which is the same
    tier the stale-backup problem has always had, and matches the tier: warning
    the vmalert rules carry. Promoting it means changing both sides together."""
    src = WATCHDOG.read_text()
    crit = src[src.index("problem_is_critical() {"):]
    crit = crit[:crit.index("\n}\n")]
    assert "SNAPSHOT_NOT_RESTORABLE" not in crit
    assert "SNAPSHOT_RESTORABILITY_UNPROVEN" not in crit
    # ...and the standing precedent it is modelled on is still advisory too.
    assert "backup STALE" not in crit


def test_restorability_opt_out_is_documented():
    text = ENV_EXAMPLE.read_text()
    assert "SNAPSHOT_RESTORABLE_CHECK" in text
    assert "SNAPSHOT_MAX_AGE_H" in text
    # Documented BESIDE the freshness knob, because the whole lesson is that
    # the two are different questions.
    assert abs(text.index("SNAPSHOT_RESTORABLE_CHECK")
               - text.index("SNAPSHOT_MAX_AGE_H")) < 1200


def test_restorability_reuses_the_shared_vm_query_seam():
    """One eng_query definition, used by both probes — two copies is how one of
    them quietly grows a `|| true`."""
    src = WATCHDOG.read_text()
    assert src.count("eng_query() {") == 1, "eng_query must be defined exactly once"
    assert src.index("eng_query() {") < src.index(
        'if [ "${SNAPSHOT_RESTORABLE_CHECK:-1}" = "1" ]; then'), (
        "the shared seam must be defined before the probes that use it")


def _restorable_block() -> str:
    """The SNAPSHOT_RESTORABLE_CHECK block, lifted for standalone execution.

    The end sentinel is the NEXT probe gate, not the F-16 banner further down.
    That distinction is load-bearing: on 2026-09-05 the pipeline debugger added
    two more probes (DEBUG_LEVEL_CHECK and, inside it, the parse-marker follow)
    between this block and F-16, so slicing to F-16 silently swallowed them —
    every assertion here that counts `problems` then saw three probes' output
    and this suite failed while the watchdog was perfectly correct. The
    assertions below make a wrong slice fail LOUDLY as a wrong slice rather
    than as a fake defect in the block under test."""
    src = WATCHDOG.read_text()
    start = src.index('if [ "${SNAPSHOT_RESTORABLE_CHECK:-1}" = "1" ]; then')
    end = src.index('if [ "${DEBUG_LEVEL_CHECK:-1}" = "1" ]; then', start)
    block = src[start:end]
    # Trim the trailing comment banner that belongs to the NEXT section.
    block = block[:block.rindex("\nfi\n") + 4]
    # Anti-vacuity + anti-overreach: this is THE restorability probe, all of it
    # and nothing else. A restructured watchdog must fail here, with a message
    # that says the slice is wrong.
    assert "netops_opensearch_snapshot_restorable" in block, (
        "the extracted block is not the restorability probe — the watchdog was "
        "restructured and this extractor's start sentinel is stale")
    for foreign in ("DEBUG_LEVEL_CHECK", "netops_debug_level_active",
                    "netops_debug_parse_marker_active"):
        assert foreign not in block, (
            f"the extracted block has swallowed {foreign} — another probe now "
            f"sits between the start and end sentinels, so every `problems` "
            f"count in this file would be measuring two probes at once")
    return block


def _run_restorable(tmp_path: Path, *, restorable=None, verified=None,
                    api_up=None, query_err="", no_victoria=False,
                    enabled_env="1"):
    """Execute the block with eng_query stubbed. Values are the raw strings the
    real eng_query would print; None means "no series" (empty output)."""
    def val(x):
        return "" if x is None else str(x)
    stub = (
        "problems=()\n"
        'logerr() { printf "LOG %s\\n" "$*"; }\n'
        f'eng_cid={"" if no_victoria else "victoria-cid"}\n'
        'eng_err=""\n'
        # Mirrors the REAL contract: the value comes back in eng_val, the
        # diagnostic in eng_err, and neither travels through a subshell.
        'eng_val=""\n'
        'eng_query() {\n'
        '  eng_err="$QUERY_ERR"; eng_val=""\n'
        '  [ -n "$QUERY_ERR" ] && return 1\n'
        '  case "$1" in\n'
        '    *restorable_verified_timestamp*) eng_val="$V_VERIFIED" ;;\n'
        '    *up%7Bjob*)                      eng_val="$V_APIUP" ;;\n'
        '    *snapshot_restorable*)           eng_val="$V_RESTORABLE" ;;\n'
        '  esac\n'
        '  return 0\n'
        '}\n'
        'PROJECT=netops\n'
    )
    tail = 'printf "PROBLEM %s\\n" "${problems[@]}"\n'
    env = os.environ.copy()
    env.update(SNAPSHOT_RESTORABLE_CHECK=enabled_env, QUERY_ERR=query_err,
               V_RESTORABLE=val(restorable), V_VERIFIED=val(verified),
               V_APIUP=val(api_up))
    r = subprocess.run(["bash", "-c", stub + _restorable_block() + tail],
                       env=env, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    problems = [ln[len("PROBLEM "):] for ln in r.stdout.splitlines()
                if ln.startswith("PROBLEM ") and ln.strip() != "PROBLEM"]
    logs = [ln for ln in r.stdout.splitlines() if ln.startswith("LOG ")]
    return problems, logs


def test_restorable_zero_is_a_problem_naming_the_probed_and_failed_case():
    problems, _ = _run_restorable(Path("."), restorable="0", verified="1756000000")
    assert len(problems) == 1, problems
    assert problems[0].startswith("SNAPSHOT_NOT_RESTORABLE:")
    assert "the probe RAN and the restore FAILED" in problems[0], problems[0]


def test_restorable_zero_with_never_probed_says_unproven_not_proven_bad():
    """The two halves of `restorable == 0` need different first responses."""
    problems, _ = _run_restorable(Path("."), restorable="0", verified="0")
    assert len(problems) == 1
    assert "NEVER returned a verdict" in problems[0], problems[0]


def test_restorable_one_is_silent():
    problems, _ = _run_restorable(Path("."), restorable="1", verified="1756000000")
    assert problems == [], problems


def test_restorable_absent_while_api_is_up_is_a_named_problem():
    """blind != fresh. The api is scraped and exports nothing -> UNPROVEN."""
    problems, _ = _run_restorable(Path("."), restorable=None, api_up="1")
    assert len(problems) == 1
    assert problems[0].startswith("SNAPSHOT_RESTORABILITY_UNPROVEN:"), problems[0]


def test_restorable_absent_while_api_is_down_defers_to_the_service_loop():
    """A down api is ALREADY a critical elsewhere; a second push for one fault
    is the noise that gets a pager muted."""
    problems, logs = _run_restorable(Path("."), restorable=None, api_up="0")
    assert problems == [], problems
    assert any("api scrape target is DOWN" in l for l in logs), logs


def test_restorable_query_failure_is_a_named_skip_not_a_pass():
    problems, _ = _run_restorable(Path("."), query_err="victoria query failed (rc=1): boom")
    assert len(problems) == 1
    assert problems[0].startswith("snapshot-restorability probe SKIPPED:")
    assert "boom" in problems[0]


def test_restorable_non_numeric_value_is_unknown_not_healthy():
    problems, _ = _run_restorable(Path("."), restorable="NaN", verified="0")
    assert len(problems) == 1
    assert "not a number" in problems[0] and "UNKNOWN, not as healthy" in problems[0]


def test_restorable_no_victoria_container_is_reported_not_silent():
    problems, _ = _run_restorable(Path("."), no_victoria=True)
    assert len(problems) == 1
    assert "no running victoria container" in problems[0]


def test_restorable_opt_out_runs_nothing():
    problems, logs = _run_restorable(Path("."), restorable="0", verified="0",
                                     enabled_env="0")
    assert problems == [] and logs == []


def test_eng_query_returns_its_value_in_a_global_not_on_stdout():
    """REGRESSION GUARD for a swallow found on 2026-09-03.

    eng_query used to PRINT the value, and every caller wrote
    `v=$(eng_query ...)`. Command substitution runs the function in a SUBSHELL,
    so the eng_err it set died there and no caller's `if [ -n "$eng_err" ]`
    branch could ever be taken — a failed or refused VictoriaMetrics query fell
    through to the "no series at all" branch and became a quiet logerr instead
    of a reported problem. A broken probe read as a quiet stack, which is the
    exact failure this section exists to make impossible. Restoring the
    command-substitution shape re-opens it, so pin BOTH halves."""
    src = WATCHDOG.read_text()
    assert "eng_val=$(printf" in src, "eng_query must assign eng_val, not print it"
    # Comment lines are exempt — the block above quotes the broken form on
    # purpose so the next reader knows what not to write.
    offenders = [ln for ln in src.splitlines()
                 if "=$(eng_query " in ln and not ln.lstrip().startswith("#")]
    assert not offenders, (
        "no caller may wrap eng_query in a command substitution — the subshell "
        f"discards eng_err and the failure becomes silence: {offenders}")
    # Every consumer reads the global. The count is DERIVED from the call sites
    # rather than pinned to a literal: this guard is about the shape of the
    # contract, and a literal turns "someone added a probe" into a failure of
    # this test — which trains the next reader to bump the number, the exact
    # habit that would let a real unread call through. Anti-vacuity floor below
    # keeps it from passing on an empty scan.
    calls = [ln for ln in src.splitlines()
             if re.match(r"\s*eng_query\s+'", ln) and not ln.lstrip().startswith("#")]
    reads = src.count('="$eng_val"')
    assert len(calls) >= 7, (
        f"only {len(calls)} eng_query call sites found — this guard is not "
        f"reading the watchdog any more")
    assert reads == len(calls), (
        f"{len(calls)} eng_query call sites but {reads} reads of eng_val: each "
        f"call must be followed by a read of the global, because the value no "
        f"longer travels on stdout")


def test_restorability_stable_prefix_outlives_problem_key_hash():
    src = WATCHDOG.read_text()
    m = re.search(r'problems\+=\("(SNAPSHOT_NOT_RESTORABLE:[^"]*)"\)', src)
    assert m, "the SNAPSHOT_NOT_RESTORABLE message moved"
    msg = m.group(1)
    idx = msg.find("${snap_when")
    assert idx > 160, f"run-varying detail starts at char {idx}, inside the hashed prefix"


# ===========================================================================
# host-hygiene.sh — the healer that never healed
# ===========================================================================

def _hygiene_probe(tmp_path: Path, *, https_ok: bool, http_ok: bool,
                   tls_material: bool = True):
    """Execute os_probe_setup with a fake curl whose success depends on the
    scheme, and report which endpoint it settled on."""
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    _write_exec(bindir / "curl", (
        "#!/bin/sh\n"
        'for a in "$@"; do case "$a" in\n'
        '  https://*) [ -n "${HTTPS_OK:-}" ] && { echo \'{"status":"green"}\'; exit 0; }\n'
        "             echo 'curl: (60) SSL certificate problem' >&2; exit 60 ;;\n"
        '  http://*)  [ -n "${HTTP_OK:-}" ] && { echo \'{"status":"green"}\'; exit 0; }\n'
        "             echo 'curl: (52) Empty reply from server' >&2; exit 52 ;;\n"
        "esac; done\n"
        "exit 0\n"
    ))
    tls = tmp_path / "tls"
    if tls_material:
        (tls / "admin").mkdir(parents=True, exist_ok=True)
        (tls / "ca.pem").write_text("ca")
        (tls / "admin" / "admin.crt").write_text("crt")
        (tls / "admin" / "admin.key").write_text("key")
    env = os.environ.copy()
    env["PATH"] = f"{bindir}:{env['PATH']}"
    if https_ok:
        env["HTTPS_OK"] = "1"
    if http_ok:
        env["HTTP_OK"] = "1"
    stub = f'SCRIPT_DIR="{tmp_path}"\nOS_TLS_DIR="{tls}"\n'
    body = _extract(HYGIENE, "os_probe_setup")
    tail = ('if os_probe_setup 172.18.0.15; then printf "URL=%s\\n" "$OS_URL";'
            ' else printf "ERR=%s\\n" "$OS_PROBE_ERR"; fi\n')
    return subprocess.run(["bash", "-c", stub + body + tail],
                          env=env, capture_output=True, text=True)


def test_hygiene_prefers_https_with_ca_and_admin_cert(tmp_path):
    r = _hygiene_probe(tmp_path, https_ok=True, http_ok=True)
    assert r.returncode == 0, r.stderr
    assert "URL=https://opensearch:9200" in r.stdout, r.stdout


def test_hygiene_falls_back_to_http_on_a_plaintext_install(tmp_path):
    r = _hygiene_probe(tmp_path, https_ok=False, http_ok=True)
    assert "URL=http://172.18.0.15:9200" in r.stdout, r.stdout


def test_hygiene_probe_failure_is_named_with_both_curl_errors(tmp_path):
    """THE REGRESSION THAT MATTERS. Neither scheme answered: the script must
    say so with curl's own errors, not proceed as if all was well."""
    r = _hygiene_probe(tmp_path, https_ok=False, http_ok=False)
    assert "ERR=" in r.stdout, r.stdout
    assert "curl rc=60" in r.stdout and "curl rc=52" in r.stdout, r.stdout


def test_hygiene_reports_missing_tls_material_by_name(tmp_path):
    r = _hygiene_probe(tmp_path, https_ok=True, http_ok=False, tls_material=False)
    assert "https not attempted" in r.stdout, r.stdout
    assert "TLS material unreadable" in r.stdout


def _hygiene_blocked(tmp_path: Path, body: str, rc: int = 0):
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    _write_exec(bindir / "curl",
                "#!/bin/sh\n"
                f'printf "%s" "$FAKE_BODY"\nexit {rc}\n')
    env = os.environ.copy()
    env["PATH"] = f"{bindir}:{env['PATH']}"
    env["FAKE_BODY"] = body
    # NOTE the call shape: os_blocked_count must NOT be invoked in a command
    # substitution. A subshell cannot export OS_BLOCKED_ERR back to its caller,
    # which would silently restore the very "failure reads as no blocks"
    # behaviour this fix removes — so the function returns its result in a
    # GLOBAL and the caller reads it after the call.
    stub = 'OS_URL="https://opensearch:9200"\nOS_CURL_ARGS=()\n'
    fn = _extract(HYGIENE, "os_blocked_count")
    tail = ('if os_blocked_count; then printf "COUNT=%s\\n" "$OS_BLOCKED";'
            ' else printf "ERR=%s\\n" "$OS_BLOCKED_ERR"; fi\n')
    return subprocess.run(["bash", "-c", stub + fn + tail],
                          env=env, capture_output=True, text=True)


def test_hygiene_blocked_count_counts_real_blocks(tmp_path):
    body = ('{"netops-applogs-2026.09.01":{"settings":{"index":{"blocks":'
            '{"read_only_allow_delete":"true"}}}},'
            '"netops-flows-2026.09.01":{"settings":{"index":{"blocks":'
            '{"read_only_allow_delete":"true"}}}}}')
    r = _hygiene_blocked(tmp_path, body)
    assert "COUNT=2" in r.stdout, r.stdout


def test_hygiene_blocked_count_never_reports_zero_for_a_failed_probe(tmp_path):
    """The live bug, exactly: curl failed and `| grep -o | wc -l` said 0, so
    heal_opensearch returned early and the healing never ran."""
    r = _hygiene_blocked(tmp_path, "curl: (52) Empty reply from server", rc=52)
    assert "COUNT=" not in r.stdout, "a failed probe must not yield a count"
    assert "ERR=" in r.stdout and "curl rc=52" in r.stdout, r.stdout


def test_hygiene_blocked_count_rejects_a_200_shaped_refusal(tmp_path):
    """curl exits 0, the body is an auth error, `grep -o` finds nothing — the
    old code called that '0 blocked'."""
    r = _hygiene_blocked(
        tmp_path,
        '{"error":{"root_cause":[{"type":"security_exception","reason":"no permissions"}]},"status":403}')
    assert "COUNT=" not in r.stdout
    assert "ERR=" in r.stdout and "refused" in r.stdout, r.stdout


def test_hygiene_never_uses_insecure_curl():
    """-k would turn a real MITM or a misissued cert into a silent pass — the
    same swallow this fix exists to remove, in a different costume."""
    text = HYGIENE.read_text()
    assert "--resolve" in text, "hostname pinning is how https://<ip> is made verifiable"
    assert not re.search(r"curl[^\n]*\s(-k|--insecure)\b", text), \
        "host-hygiene.sh must never disable certificate verification"


def test_hygiene_heal_counts_a_blind_probe_as_a_reclaim_failure():
    """A hygiene job that cannot do its job must be as loud as the condition it
    maintains against — non-zero exit plus the existing degraded push."""
    text = HYGIENE.read_text()
    heal = text[text.index("heal_opensearch() {"):]
    heal = heal[:heal.index("\n}\n") + 3]
    assert "OPENSEARCH_PROBE_FAILED" in heal
    assert "OPENSEARCH_BLOCK_QUERY_FAILED" in heal
    assert heal.count("RECLAIM_FAILURES=$((RECLAIM_FAILURES + 1))") == 2, (
        "both blind paths must count as reclaim failures")
    assert "UNKNOWN" in heal, "blind must be reported as UNKNOWN, never as zero"


# ===========================================================================
# Alert rules
# ===========================================================================

def test_snapshot_rules_are_all_warning_tier():
    """The owner approved exactly FOUR page conditions (2026-09-02) and an
    unrestorable backup is not one of them. A fifth page here dilutes the four."""
    text = RULES_SLO.read_text()
    block = text[text.index("SNAPSHOT RESTORABILITY  (2026-09-03)"):]
    alerts = re.findall(r"- alert: (OpenSearchSnapshot\w+)", block)
    assert set(alerts) == {"OpenSearchSnapshotNotRestorable",
                           "OpenSearchSnapshotRestorabilityStale",
                           "OpenSearchSnapshotProbeDisabled"}, alerts
    for label in re.findall(r"labels: \{([^}]*)\}", block):
        assert "tier: warning" in label and "severity: warning" in label, label
        assert "tier: page" not in label
    assert block.count(
        'runbook: "docs/runbooks/storage-and-volume-operations.md#managing-snapshots"') == 3


def test_snapshot_rule_unit_tests_exist_and_cover_every_rule():
    text = RULES_TEST.read_text()
    assert "rules-scale-slo.yaml" in text, "the test must target the right rule file"
    for name in ("OpenSearchSnapshotNotRestorable",
                 "OpenSearchSnapshotRestorabilityStale",
                 "OpenSearchSnapshotProbeDisabled"):
        assert f"alertname: {name}" in text, f"{name} is untested"
    # Both halves: firing AND silent. A test that only proves firing cannot
    # catch a rule that fires always.
    assert text.count("exp_alerts: []") >= 6, "each rule needs its all-clear case"


# ===========================================================================
# Floor: the scripts still parse and lint
# ===========================================================================

@pytest.mark.parametrize("script,shell", [
    (WATCHDOG, "bash"), (HYGIENE, "bash"), (APPLY_ISM, "sh"),
])
def test_scripts_parse(script, shell):
    r = subprocess.run([shell, "-n", str(script)], capture_output=True, text=True)
    assert r.returncode == 0, f"{shell} -n {script.name}: {r.stderr}"


@pytest.mark.skipif(shutil.which("shellcheck") is None, reason="shellcheck not installed")
@pytest.mark.parametrize("script", [WATCHDOG, HYGIENE, APPLY_ISM])
def test_scripts_are_shellcheck_clean(script):
    r = subprocess.run(["shellcheck", str(script)], capture_output=True, text=True)
    assert r.returncode == 0, f"shellcheck {script.name}:\n{r.stdout}{r.stderr}"
