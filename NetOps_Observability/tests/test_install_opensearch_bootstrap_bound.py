# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""apply-ism.sh waits for OpenSearch within a budget, and says why (FMEA row 9).

FMEA 2026-09-15 §2 row 9 / §3.8 O1. The opensearch-init one-shot opened with

    until curl -sf "$OS/_cluster/health" >/dev/null 2>&1; do sleep 5; done

— an unbounded loop that discards every reason it is looping. Under TLS a
wrong bootstrap credential answers 401 forever while the TLS healthcheck counts
401 as healthy, so the one-shot never exits, never fails, and nothing names the
problem. The rules pinned here:

  * the wait is bounded by OPENSEARCH_WAIT_BUDGET_S (clamped) with a growing,
    capped backoff;
  * every failure class is NAMED: connection refused, 401, 403, 5xx;
  * budget exhaustion exits NON-ZERO (the install's stability gate then names
    the one-shot) — never a silent hang, never a pass;
  * the credential in OPENSEARCH_URL never reaches the output.

Executed end to end under `sh` (dash) with a fake curl and a fake sleep.

Run:  python3 -m pytest tests/test_install_opensearch_bootstrap_bound.py -v
"""

from __future__ import annotations

import stat
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
APPLY_ISM = ROOT / "deployment" / "docker" / "opensearch" / "apply-ism.sh"

# Health answers come from $FAKE_HEALTH: a space-separated script consumed one
# token per health call (last token repeats). A token is `refused`, `dns`, or
# an HTTP code. Every other URL answers a benign JSON body.
FAKE_CURL = r"""#!/bin/sh
url=; wfmt=
while [ $# -gt 0 ]; do
  case "$1" in
    -w) wfmt="$2"; shift 2 ;;
    -X|-H|-d|-o|-m|--connect-timeout|--max-time) shift 2 ;;
    -*) shift ;;
    *) url="$1"; shift ;;
  esac
done
printf '%s\n' "$url" >> "$CURL_LOG"
case "$url" in
  */_cluster/health*)
    n=$(grep -c '_cluster/health' "$CURL_LOG")
    tok=$(printf '%s\n' $FAKE_HEALTH | sed -n "${n}p")
    [ -n "$tok" ] || tok=$(printf '%s\n' $FAKE_HEALTH | tail -1)
    case "$tok" in
      refused) echo "curl: (7) Failed to connect to opensearch port 9200: Connection refused" >&2; exit 7 ;;
      dns)     echo "curl: (6) Could not resolve host: opensearch" >&2; exit 6 ;;
    esac
    [ -n "$wfmt" ] && printf '%s' "$tok" || printf '{"status":"green"}'
    exit 0 ;;
  */_snapshot/_all*) printf '{}' ;;
  */_plugins/_sm/policies/*) printf '{"status":404}' ;;
  *) printf '{"acknowledged":true}' ;;
esac
exit 0
"""

FAKE_SLEEP = "#!/bin/sh\necho \"$1\" >> \"$SLEEP_LOG\"\nexec /bin/sleep 0.05\n"


def _write_exec(path: Path, body: str) -> None:
    path.write_text(body)
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def _run(tmp_path: Path, health: str, budget: str = "2", url: str | None = None,
         timeout: int = 60):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    _write_exec(bindir / "curl", FAKE_CURL)
    _write_exec(bindir / "sleep", FAKE_SLEEP)
    env = {
        "PATH": f"{bindir}:/usr/bin:/bin",
        "CURL_LOG": str(tmp_path / "curl.log"),
        "SLEEP_LOG": str(tmp_path / "sleep.log"),
        "FAKE_HEALTH": health,
        "OPENSEARCH_WAIT_BUDGET_S": budget,
        "OPENSEARCH_SNAPSHOT_KEEP": "0",
    }
    if url:
        env["OPENSEARCH_URL"] = url
    r = subprocess.run(["sh", str(APPLY_ISM)], capture_output=True, text=True,
                       timeout=timeout, env=env, check=False)
    sleeps = (tmp_path / "sleep.log").read_text().split() if (tmp_path / "sleep.log").exists() else []
    calls = (tmp_path / "curl.log").read_text().splitlines() if (tmp_path / "curl.log").exists() else []
    return r, sleeps, calls


@pytest.mark.parametrize("token,words", [
    ("refused", ("refused",)),
    ("401", ("401", "credential")),
    ("403", ("403", "forbidden")),
    ("503", ("503", "not serving")),
])
def test_a_cluster_that_never_answers_exhausts_the_budget_and_names_why(
        tmp_path: Path, token: str, words: tuple[str, ...]) -> None:
    try:
        r, _, calls = _run(tmp_path, token)
    except subprocess.TimeoutExpired:
        pytest.fail("apply-ism.sh is still waiting forever for OpenSearch")
    out = (r.stdout + r.stderr).lower()
    assert r.returncode != 0, "budget exhaustion must fail the one-shot, not pass it"
    for w in words:
        assert w in out, f"{w!r} missing from:\n{r.stdout}{r.stderr}"
    assert "budget" in out or "gave up" in out, out
    assert not any("_plugins/_ism" in c for c in calls), (
        "nothing may be applied against a cluster that never became ready")


def test_a_cluster_that_recovers_inside_the_budget_is_used(tmp_path: Path) -> None:
    r, sleeps, calls = _run(tmp_path, "refused 503 200", budget="60")
    assert any("_plugins/_ism/policies/netops-retention" in c for c in calls), (
        r.stdout + r.stderr)
    assert len(sleeps) == 2, sleeps


def test_the_backoff_grows_and_is_capped(tmp_path: Path) -> None:
    health = " ".join(["refused"] * 12 + ["200"])
    r, sleeps, _ = _run(tmp_path, health, budget="3600")
    nums = [int(float(s)) for s in sleeps]
    assert len(nums) == 12, (nums, r.stdout, r.stderr)
    assert nums[1] >= nums[0] and nums[4] > nums[0], nums
    assert max(nums) <= 32, f"backoff must be capped (≈30 s + jitter): {nums}"


def test_the_bootstrap_credential_never_reaches_the_output(tmp_path: Path) -> None:
    r, _, _ = _run(tmp_path, "401",
                   url="https://svc_bootstrap:S3cretBootstrapPw@opensearch:9200")
    assert r.returncode != 0
    assert "S3cretBootstrapPw" not in r.stdout + r.stderr


def test_a_nonsense_budget_is_clamped_not_trusted(tmp_path: Path) -> None:
    src = APPLY_ISM.read_text()
    assert "OPENSEARCH_WAIT_BUDGET_S" in src
    code = "\n".join(ln for ln in src.splitlines() if not ln.lstrip().startswith("#"))
    assert "until curl" not in code, "the unbounded wait loop is still there"
    r, _, _ = _run(tmp_path, "200", budget="not-a-number")
    assert r.returncode == 0, r.stdout + r.stderr
