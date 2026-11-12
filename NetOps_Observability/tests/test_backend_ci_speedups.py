# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix
"""Guards for the CI speed-ups of the 2026-11-12 audit (C2–C6).

Each speed-up removes work from a gate, so each carries the property that makes
the removal safe, asserted here so a later edit cannot quietly turn "faster"
into "checks less":

  C2  the -race run is split, not shrunk: test-race-pkgs + test-race-root cover
      every package exactly once (the shard regexes themselves are proved in
      tests/test_go_shard.py; the matrix/gate wiring in tests/test_test_plan.py).
  C3  pg-integration runs only the packages that need the database — and the
      selection provably includes every build-tagged AND every env-gated file.
  C4  the Go build cache is real (explicit, refreshed per main commit) and the
      offline vendor build stays cold.
  C5  a diagnostics upload can never fail a green install leg.
  C6  the install legs cache npm downloads for both lockfiles they install.
"""
from __future__ import annotations

import importlib.util
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
REPO = ROOT.parent
BACKEND = ROOT / "src" / "backend"
WORKFLOWS = REPO / ".github" / "workflows"
PG_SELECT = ROOT / "scripts" / "ci" / "go-pg-packages.py"

_spec = importlib.util.spec_from_file_location("go_pg_packages", PG_SELECT)
pgsel = importlib.util.module_from_spec(_spec)
sys.modules["go_pg_packages"] = pgsel
_spec.loader.exec_module(pgsel)

CACHE_SHA = "0057852bfaa89a56745cba8c7296529d2fc39830"
CACHE_KEY = ("gocache-${{ github.job }}-${{ runner.os }}-${{ hashFiles("
             "'NetOps_Observability/src/backend/**/*.go', "
             "'NetOps_Observability/src/backend/go.sum') }}")
CACHE_RESTORE_PREFIX = "gocache-${{ github.job }}-${{ runner.os }}-"
SAVE_ON_MAIN = "github.event_name == 'push' && github.ref == 'refs/heads/main'"


def _wf(name: str) -> dict:
    return yaml.safe_load((WORKFLOWS / name).read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def backend() -> dict:
    return _wf("backend-ci.yml")["jobs"]


@pytest.fixture(scope="module")
def install() -> dict:
    return _wf("fresh-install-integrity.yml")["jobs"]


def _steps_using(job: dict, action: str) -> list[dict]:
    return [s for s in job.get("steps", []) if str(s.get("uses", "")).startswith(action + "@")]


def _run(job: dict, name_part: str) -> str:
    steps = [s for s in job["steps"] if name_part in str(s.get("name", ""))]
    assert len(steps) == 1, f"expected one step named like {name_part!r}, found {len(steps)}"
    return steps[0]["run"]


# ── C2: the -race run is split, never shrunk ─────────────────────────────────

def test_race_pkgs_excludes_exactly_the_root_and_nothing_else(backend):
    run = _run(backend["test-race-pkgs"], "go test -race")
    assert "set -euo pipefail" in run
    assert "go list ./... | grep -vx 'netops/backend'" in run
    assert re.search(r"^\s*go test -race -timeout 60m \$pkgs$", run, re.MULTILINE)
    assert "-run" not in run and "-short" not in run
    # an empty list is a failure, not a no-op run
    assert '[ -z "$pkgs" ]' in run and "exit 1" in run


def test_root_import_path_is_what_the_exclusion_names():
    first = (BACKEND / "go.mod").read_text(encoding="utf-8").splitlines()[0]
    assert first == "module netops/backend"


def test_the_cheap_checks_stayed_in_the_gate(backend):
    names = [s.get("name", "") for s in backend["test-race-pkgs"]["steps"]]
    for want in ("gofmt (blocking, both Go modules)", "go build", "go vet",
                 "go vet -tags=pgintegration"):
        assert want in names, want


def test_the_root_package_is_only_run_by_the_shards(backend):
    """`go test -race` over the root package happens in test-race-root and
    nowhere else in the race lane — no double run, no gap."""
    root_runs = "\n".join(s.get("run", "") for s in backend["test-race-root"]["steps"])
    assert "-run \"$(cat \"$RUNNER_TEMP/root-shard.re\")\" ." in root_runs
    assert "./..." not in root_runs


# ── C3: pg-integration runs exactly the packages that need the database ──────

@pytest.fixture(scope="module")
def pg_step(backend) -> dict:
    steps = [s for s in backend["pg-integration"]["steps"]
             if "go test -tags=pgintegration" in str(s.get("name", ""))]
    assert len(steps) == 1
    return steps[0]


def test_pg_step_keeps_its_flags_and_has_no_run_filter(pg_step):
    run = pg_step["run"]
    test_line = next(ln for ln in run.splitlines() if ln.strip().startswith("go test"))
    assert "-tags=pgintegration" in test_line
    assert "-count=1" in test_line
    assert re.search(r"(^|\s)-p 1(\s|$)", test_line)
    assert "-run" not in test_line, "H8: a -run filter silently dropped the RLS corpus once"
    assert "./..." not in test_line
    assert "$pkgs" in test_line
    assert "scripts/ci/go-pg-packages.py" in run and "set -euo pipefail" in run


def test_the_selector_knows_every_dsn_the_job_exports(pg_step):
    """Adding a DSN to the job without teaching the selector must fail here."""
    dsn_keys = {k for k in pg_step["env"] if "DSN" in k or "DATABASE_URL" in k}
    assert dsn_keys == set(pgsel.ENV_VARS)


def test_the_repo_wide_tagged_compile_guard_remains(backend):
    names = [s.get("name", "") for s in backend["test-race-pkgs"]["steps"]]
    assert "go vet -tags=pgintegration" in names
    step = next(s for s in backend["test-race-pkgs"]["steps"]
                if s.get("name") == "go vet -tags=pgintegration")
    assert step["run"].strip() == "go vet -tags=pgintegration ./..."


def _pg_needing_files() -> list[Path]:
    """Independent of the selector's walk: every first-party .go file that is
    build-tagged pgintegration or names a DSN env var."""
    out = []
    for path in BACKEND.rglob("*.go"):
        rel = path.relative_to(BACKEND)
        if any(part in ("vendor", "testdata") or part.startswith((".", "_"))
               for part in rel.parts[:-1]):
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if re.search(r"^//go:build.*pgintegration", text, re.MULTILINE) or any(
                v in text for v in pgsel.ENV_VARS):
            out.append(rel)
    return out


def test_every_tagged_and_env_gated_file_is_in_a_selected_package():
    selected = set(pgsel.select(BACKEND))
    files = _pg_needing_files()
    assert files, "found no pg file at all — this guard is aimed at the wrong tree"
    tagged = [f for f in files
              if "pgintegration" in (BACKEND / f).read_text(encoding="utf-8")]
    assert tagged, "no //go:build pgintegration file found"
    for f in files:
        pkg = "." if f.parent == Path(".") else f"./{f.parent.as_posix()}"
        assert pkg in selected, f"{f} needs Postgres but {pkg} is not selected"


def test_env_gated_packages_without_a_build_tag_are_selected():
    """The trap a tag-only selection falls into, pinned with real packages."""
    selected = set(pgsel.select(BACKEND))
    for pkg in ("./internal/metering", "./internal/users", "."):
        assert pkg in selected, pkg


def test_selection_is_a_real_narrowing_and_cli_fails_closed(tmp_path):
    selected = pgsel.select(BACKEND)
    assert 1 < len(selected) < 60, selected
    proc = subprocess.run([sys.executable, "-I", str(PG_SELECT)], cwd=BACKEND,
                          capture_output=True, text=True, check=False)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.split() == selected

    (tmp_path / "go.mod").write_text("module x\n", encoding="utf-8")
    (tmp_path / "a.go").write_text("package x\n", encoding="utf-8")
    proc = subprocess.run([sys.executable, "-I", str(PG_SELECT), "--root", str(tmp_path)],
                          capture_output=True, text=True, check=False)
    assert proc.returncode == 1 and "FAIL" in proc.stderr


def test_selector_walk_rules(tmp_path):
    (tmp_path / "go.mod").write_text("module x\n", encoding="utf-8")
    tag = "//go:build pgintegration\n\npackage p\n"
    env = 'package p\n\nvar _ = "DATABASE_URL_TEST"\n'
    layout = {
        "root_test.go": env,                      # module root -> "."
        "a/b/x_test.go": tag,                     # nested package
        "c/y_test.go": "//go:build linux && pgintegration\n\npackage c\n",
        "vendor/v/z.go": tag,                     # vendor: never
        "d/testdata/t.go": tag,                   # testdata: never
        ".hidden/h.go": tag, "_skip/s.go": tag,   # go ignores these
        "nested/go.mod": "module y\n", "nested/n.go": tag,  # another module
        "e/plain_test.go": "package e\n",         # unrelated
    }
    for rel, text in layout.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    assert pgsel.select(tmp_path) == [".", "./a/b", "./c"]


# ── C4: a real Go build cache; the offline build stays cold ──────────────────

GO_JOBS_WITH_CACHE = ("test-race-pkgs", "test-race-root", "test-plain", "pg-integration",
                      "vuln", "security-lint", "full-lint", "iris-gates")


def test_no_backend_setup_go_keeps_its_own_cache(backend):
    seen = 0
    for jid, job in backend.items():
        for step in _steps_using(job, "actions/setup-go"):
            seen += 1
            assert step["with"].get("cache") is False, f"{jid}: setup-go must set cache: false"
            assert "cache-dependency-path" not in step["with"], jid
    assert seen >= len(GO_JOBS_WITH_CACHE) + 1


@pytest.mark.parametrize("jid", GO_JOBS_WITH_CACHE)
def test_every_go_job_restores_and_main_saves_the_build_cache(backend, jid):
    job = backend[jid]
    restores = _steps_using(job, "actions/cache/restore")
    saves = _steps_using(job, "actions/cache/save")
    assert len(restores) == 1 and len(saves) == 1, jid
    r, s = restores[0], saves[0]
    assert r["uses"] == f"actions/cache/restore@{CACHE_SHA}"
    assert s["uses"] == f"actions/cache/save@{CACHE_SHA}"
    for step in (r, s):
        paths = step["with"]["path"].split()
        assert "~/.cache/go-build" in paths, jid
        assert step["with"]["key"] == CACHE_KEY, jid
    assert r["with"]["restore-keys"].strip() == CACHE_RESTORE_PREFIX
    # restore before any go command, save last
    steps = job["steps"]
    assert steps.index(r) < min(i for i, st in enumerate(steps)
                                if re.search(r"\bgo (test|build|vet|install|list)\b",
                                             str(st.get("run", "")))
                                or "golangci" in str(st.get("uses", "")))
    assert steps.index(s) == len(steps) - 1, jid
    # only a push to main writes a cache (PRs restore main's)
    assert SAVE_ON_MAIN in s["if"], jid


def test_shards_share_one_cache_and_only_shard_0_saves(backend):
    job = backend["test-race-root"]
    save = _steps_using(job, "actions/cache/save")[0]
    assert "matrix.shard == 0" in save["if"]
    assert "matrix" not in save["with"]["key"]


def test_the_offline_vendor_build_stays_cold(backend):
    job = backend["offline-build"]
    assert not _steps_using(job, "actions/cache/restore")
    assert not _steps_using(job, "actions/cache")
    (setup,) = _steps_using(job, "actions/setup-go")
    assert setup["with"]["cache"] is False


def test_cached_test_results_cannot_stand_in_where_a_real_run_is_required(backend):
    """With a warm GOCACHE, go test reuses results for unchanged inputs. The
    jobs whose whole point is a fresh run must defeat that."""
    pg = next(s for s in backend["pg-integration"]["steps"]
              if "go test -tags=pgintegration" in str(s.get("name", "")))
    assert "-count=1" in pg["run"]
    shard = _run(backend["test-race-root"], "-shuffle=on")
    assert "-shuffle=on" in shard          # not a cacheable flag: always executes
    # iris-gates' scorers must rewrite their reports on every run
    iris = [ln for s in backend["iris-gates"]["steps"]
            for ln in str(s.get("run", "")).splitlines() if ln.strip().startswith("go test")]
    assert iris
    for line in iris:
        assert "-count=1" in line, line


# ── C5 / C6: fresh-install-integrity ─────────────────────────────────────────

def test_artifact_uploads_never_decide_an_install_leg(install):
    uploads = [(jid, s) for jid, job in install.items()
               for s in _steps_using(job, "actions/upload-artifact")]
    assert uploads, "no upload-artifact step found — guard aimed at nothing"
    for jid, step in uploads:
        assert step.get("continue-on-error") is True, f"{jid}: {step.get('name')}"


def test_install_legs_cache_npm_for_both_lockfiles(install):
    nodes = [(jid, s) for jid, job in install.items()
             for s in _steps_using(job, "actions/setup-node")]
    assert len(nodes) == 3, f"expected the three install legs, found {len(nodes)}"
    for jid, step in nodes:
        w = step["with"]
        assert w.get("cache") == "npm", jid
        deps = set(w["cache-dependency-path"].split())
        assert deps == {"NetOps_Observability/src/frontend/package-lock.json",
                        "NetOps_Observability/docs-portal/package-lock.json"}, jid
        for dep in deps:
            assert (REPO / dep).is_file(), dep
