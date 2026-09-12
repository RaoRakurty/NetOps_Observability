# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""correlix-debug against the RUNNING lab stack (W1 integration test).

docs/design/PIPELINE_DEBUGGER_2026-09-04.md §6 W1: "an integration test against
the lab (tests/test_correlix_debug_lab.py, skipped without the stack)".

WHAT IT PROVES that the unit tests cannot: that a real record, injected through
the real ingress, is actually followed hop by hop — i.e. that the tap component
ids, the OpenSearch index pattern, the marker's analyser behaviour and the
session layout all match the deployed pipeline rather than a fixture of it.

It asserts:
  * the session directory has EVERY module file the design's §3 layout lists,
    and none of them is empty (an unobserved module says why, in one line);
  * the timeline reaches AT LEAST the opensearch stage — the record crossed
    syslog-ng, the aggregator, Kafka and the router and was indexed;
  * every stage carries one of the three honest verdicts, and every non-`seen`
    verdict carries a reason;
  * the injected record is tagged synthetic.

IT SKIPS (never silently passes) when: docker or go is missing, the stack is not
up, the admin credentials are unreadable, or the api build in front of it does
not serve /api/debug/* yet (a stack deployed before this feature). Point
CORRELIX_DEBUG_API at another base URL to test a candidate build.

Run:  python3 -m pytest tests/test_correlix_debug_lab.py -v
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import urllib.error
import urllib.request

import pytest

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
BACKEND = os.path.join(ROOT, "src", "backend")
ENV_PATH = os.path.join(ROOT, "deployment", "docker", ".env")

# The §3 layout — one file per module, plus the three session artefacts.
MODULE_FILES = [
    "ingress.log", "parser.log", "kafka.log", "router.log",
    "opensearch.log", "victoria.log", "clickhouse.log",
    "correlation.log", "api.log", "ui.log",
]
SESSION_FILES = ["manifest.json", "summary.txt", "timeline.json"]

VERDICTS = {"seen", "not_seen", "not_observable"}


def read_env() -> dict:
    out = {}
    try:
        with open(ENV_PATH) as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                out[k.strip()] = v
    except OSError:
        pass
    return out


def api_base(env: dict) -> str:
    if override := os.environ.get("CORRELIX_DEBUG_API"):
        return override.rstrip("/")
    return "http://localhost:" + env.get("BASE_PORT", "8000")


def post_json(url: str, body: dict, token: str = "", timeout: int = 20):
    data = json.dumps(body).encode()
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(url, data=data, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:   # nosec B310 — localhost stack URL
        return json.load(resp)


def login(base: str, env: dict) -> str:
    """Platform-admin token, or "" when the CLI can log in on its own."""
    if tok := os.environ.get("CORRELIX_TOKEN"):
        return tok
    user, pw = env.get("ADMIN_USERNAME", ""), env.get("ADMIN_INITIAL_PASSWORD", "")
    if not user or not pw:
        pytest.skip("no admin credentials in deployment/docker/.env")
    try:
        return post_json(base + "/api/auth/login", {"username": user, "password": pw}).get("token", "")
    except Exception as exc:                                     # noqa: BLE001
        pytest.skip(f"cannot log in to the lab api: {exc}")


@pytest.fixture(scope="module")
def lab():
    """Resolve the stack, the credentials, a traceable device — or SKIP."""
    for tool in ("docker", "go"):
        if shutil.which(tool) is None:
            pytest.skip(f"{tool} is not installed")
    env = read_env()
    base = api_base(env)
    token = login(base, env)

    # The debug routes must be SERVED. A stack deployed before this feature
    # answers 404, which is a skip, not a failure.
    try:
        req = urllib.request.Request(base + "/api/debug/trace", data=b"{}",
                                     headers={"Content-Type": "application/json",
                                              "Authorization": "Bearer " + token})
        urllib.request.urlopen(req, timeout=10)                  # nosec B310 — localhost stack URL
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            pytest.skip("this api build does not serve /api/debug/* yet — deploy it, or set CORRELIX_DEBUG_API")
        if exc.code in (401, 403):
            pytest.skip("the token is not a platform admin; /api/debug/* is platform-admin only")
        # 400 is the EXPECTED answer to an empty body: the routes are live.
        if exc.code != 400:
            pytest.skip(f"/api/debug/trace answered {exc.code}")
    except Exception as exc:                                     # noqa: BLE001
        pytest.skip(f"the lab stack is not reachable at {base}: {exc}")

    device, tenant = lab_device(base, token)
    return {"base": base, "token": token, "device": device, "tenant": tenant}


def lab_device(base: str, token: str):
    """A device the pipeline actually knows, so the tenant stamp is exercised."""
    if dev := os.environ.get("CORRELIX_DEBUG_DEVICE"):
        return dev, os.environ.get("CORRELIX_DEBUG_TENANT", "")
    try:
        req = urllib.request.Request(base + "/api/devices",
                                     headers={"Authorization": "Bearer " + token})
        with urllib.request.urlopen(req, timeout=15) as resp:     # nosec B310 — localhost stack URL
            devices = json.load(resp)
    except Exception as exc:                                      # noqa: BLE001
        pytest.skip(f"cannot read the device inventory: {exc}")
    if isinstance(devices, dict):
        devices = devices.get("devices", [])
    if not devices:
        pytest.skip("the lab inventory is empty — a trace needs a device to attribute the record to")
    d = devices[0]
    return d.get("id") or d.get("name"), d.get("tenant_id", "")


@pytest.fixture(scope="module")
def binary(tmp_path_factory):
    out = str(tmp_path_factory.mktemp("bin") / "correlix-debug")
    proc = subprocess.run(                                        # nosec B603 — fixed argv, no shell
        ["go", "build", "-o", out, "./cmd/correlix-debug"],
        cwd=BACKEND, capture_output=True, text=True, timeout=600)
    if proc.returncode != 0:
        pytest.fail(f"building correlix-debug failed:\n{proc.stderr}")
    return out


@pytest.fixture(scope="module")
def traced(lab, binary):
    """Run ONE real trace and return (exit code, stdout, session directory)."""
    root = tempfile.mkdtemp(prefix="correlix-debug-lab-")
    argv = [binary, "trace", "--kind", "syslog",
            "--device", lab["device"], "--ttl", "45s",
            "--api", lab["base"], "--token", lab["token"], "--root", root]
    if lab["tenant"]:
        argv += ["--tenant", lab["tenant"]]
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=300)  # nosec B603 — fixed argv, no shell
    debug_root = os.path.join(root, "data", "debug")
    sessions = sorted(os.listdir(debug_root)) if os.path.isdir(debug_root) else []
    if not sessions:
        pytest.fail(f"the trace created no session directory\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}")
    return proc, os.path.join(debug_root, sessions[-1])


# ── the §3 session layout ───────────────────────────────────────────────────

def test_session_has_one_log_file_per_module(traced):
    _proc, session = traced
    for name in MODULE_FILES + SESSION_FILES:
        path = os.path.join(session, name)
        assert os.path.isfile(path), f"{name} is missing from the session directory"


def test_no_module_file_is_empty(traced):
    """An unobserved module writes ONE line saying why — never an empty file
    that looks like 'nothing happened'."""
    _proc, session = traced
    for name in MODULE_FILES:
        with open(os.path.join(session, name)) as fh:
            body = fh.read().strip()
        assert body, f"{name} is EMPTY — an unobserved module must say why"
        for line in body.splitlines():
            json.loads(line)          # line-oriented JSON so jq/grep work


def test_session_directory_is_operator_private(traced):
    _proc, session = traced
    assert oct(os.stat(session).st_mode & 0o777) == "0o700"


# ── the timeline ────────────────────────────────────────────────────────────

def test_timeline_reaches_at_least_the_opensearch_stage(traced):
    """THE end-to-end assertion: the record crossed syslog-ng, the aggregator,
    Kafka and the router, and was indexed."""
    _proc, session = traced
    with open(os.path.join(session, "timeline.json")) as fh:
        timeline = json.load(fh)
    stages = {e["stage"]: e for e in timeline["entries"]}
    assert "opensearch" in stages, f"no opensearch stage in the timeline: {list(stages)}"
    os_stage = stages["opensearch"]
    assert os_stage["verdict"] == "seen", (
        "the injected record never reached OpenSearch: "
        f"{os_stage['verdict']} — {os_stage.get('reason', '')}")
    assert os_stage.get("evidence_ref"), "the opensearch stage names no document"


def test_every_stage_carries_an_honest_verdict(traced):
    _proc, session = traced
    with open(os.path.join(session, "timeline.json")) as fh:
        timeline = json.load(fh)
    for entry in timeline["entries"]:
        assert entry["verdict"] in VERDICTS, entry
        if entry["verdict"] != "seen":
            assert entry.get("reason"), (
                f"stage {entry['stage']} is {entry['verdict']} with NO reason — "
                "'we could not look' must never be indistinguishable from 'it was not there'")
        assert entry.get("query"), f"stage {entry['stage']} does not record the query it used"


def test_marker_is_ulid_shaped_and_the_record_is_tagged_synthetic(traced):
    _proc, session = traced
    with open(os.path.join(session, "manifest.json")) as fh:
        manifest = json.load(fh)
    marker = manifest["marker"]
    assert len(marker) == 26 and marker == marker.lower(), marker
    with open(os.path.join(session, "summary.txt")) as fh:
        summary = fh.read()
    assert marker in summary
    with open(os.path.join(session, "ingress.log")) as fh:
        ingress = fh.read()
    if '"verdict": "not_observable"' not in ingress and "not_observable" not in ingress:
        assert "cx_synthetic=true" in ingress, (
            "the record that entered the pipeline is not tagged synthetic — it would "
            "appear in a customer's log search as device traffic")


def test_exit_code_matches_the_verdict(traced):
    """Exit 0 ONLY if the record reached the UI-facing api (design §1)."""
    proc, session = traced
    with open(os.path.join(session, "timeline.json")) as fh:
        timeline = json.load(fh)
    reached = any(e["stage"] == "api" and e["verdict"] == "seen" for e in timeline["entries"])
    assert (proc.returncode == 0) == reached, (
        f"exit {proc.returncode} but api-reached={reached}\n{proc.stdout}")


def test_summary_is_printed_and_names_every_stage(traced):
    proc, session = traced
    with open(os.path.join(session, "summary.txt")) as fh:
        summary = fh.read()
    for stage in ("ingress", "parser", "kafka", "router", "opensearch",
                  "victoria", "clickhouse", "correlation", "api", "ui"):
        assert stage in summary, f"summary.txt does not mention the {stage} stage"
    assert summary.strip() in proc.stdout, "the summary was not printed to the operator"


# ── bundle ──────────────────────────────────────────────────────────────────

def test_bundle_packages_the_session_with_checksums(traced, binary):
    proc, session = traced
    debug_root = os.path.dirname(session)              # .../data/debug
    root = os.path.dirname(os.path.dirname(debug_root))
    out = subprocess.run(                                # nosec B603 — fixed argv, no shell
        [binary, "bundle", "--session", session, "--root", root],
        capture_output=True, text=True, timeout=300)
    assert out.returncode == 0, out.stderr
    assert "sha256 :" in out.stdout and "sessions: 1" in out.stdout, out.stdout
    artefacts = [f for f in os.listdir(debug_root) if f.startswith("correlix-debug-")]
    assert any(f.endswith((".tar.zst", ".tar.gz")) for f in artefacts), artefacts
    assert any(f.endswith(".sha256") for f in artefacts), artefacts
