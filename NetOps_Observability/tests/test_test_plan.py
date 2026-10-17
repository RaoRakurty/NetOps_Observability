# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix
"""scripts/test-plan.py sizes local test effort to the risk of a diff.

The property that matters most: it can make the LOCAL plan smaller, but it must
never classify a risky change as low-risk, and its fast checks must catch the
generated-artifact class that kept PR #22 red for a week (2026-10-10 → 17).
"""
import importlib.util
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_spec = importlib.util.spec_from_file_location("test_plan", os.path.join(ROOT, "scripts", "test-plan.py"))
tp = importlib.util.module_from_spec(_spec)
sys.modules["test_plan"] = tp  # dataclasses resolve the module by name
_spec.loader.exec_module(tp)

P = "NetOps_Observability/"


def test_docs_only_needs_no_code_gate():
    plan = tp.classify([P + "docs/TRACKER.md", P + "docs/runbooks/x.md", P + "README.md"])
    assert plan.tier == "docs"
    assert not plan.artifact_checks
    assert any("nothing" in c for c in plan.local)


def test_markdown_under_src_is_code_not_docs():
    # Skill/prompt files the product loads are behaviour, not prose.
    plan = tp.classify([P + "src/backend/ai/skills/explain/kpi.md"])
    assert plan.tier == "high-risk"


def test_frontend_only_runs_build_and_scoped_e2e():
    plan = tp.classify([P + "src/frontend/src/iris/Panel.tsx"])
    assert plan.tier == "frontend"
    assert any("vite build" in c for c in plan.local)
    assert any("Playwright" in c for c in plan.local)


def test_one_go_package_runs_that_package_and_leaves_race_to_ci():
    plan = tp.classify([P + "src/backend/collectors/vrf.go"])
    assert plan.tier == "code"
    assert any("go test -timeout 60m ./collectors" in c for c in plan.local)
    assert any("-race" in c for c in plan.ci_only)


def test_root_package_points_at_a_scoped_run_and_names_the_full_run_as_ci():
    plan = tp.classify([P + "src/backend/main.go"])
    assert any("-run" in c and c.endswith(" .)") for c in plan.local)
    assert any("root package full run" in c for c in plan.ci_only)


def test_vendor_changes_are_not_listed_as_packages_to_test():
    assert tp._go_packages(["src/backend/vendor/golang.org/x/net/a.go"]) == []


def test_high_risk_paths_win_regardless_of_diff_size():
    for path in ("src/backend/migrations/0060_add.sql",
                 "src/backend/tlsconfig/config.go",
                 "src/backend/sealing/seal.go",
                 "src/backend/tenant_scope.go",
                 "src/backend/auth_oidc.go",
                 "src/backend/copilot.go",
                 "src/backend/go.mod",
                 "src/frontend/package-lock.json",
                 "deployment/docker/Dockerfile.backend"):
        plan = tp.classify([P + "docs/TRACKER.md", P + path])
        assert plan.tier == "high-risk", path
        assert any("pgintegration" in c for c in plan.local), path


def test_workflow_edits_are_high_risk():
    assert tp.classify([".github/workflows/backend-ci.yml"]).tier == "high-risk"


def test_unknown_paths_fall_to_code_not_docs():
    # Fail-safe: a path no rule names is never treated as prose.
    assert tp.classify([P + "some/new/thing.bin"]).tier == "code"


def test_every_input_of_the_pr22_failures_triggers_the_artifact_checks():
    for path in ("src/backend/go.mod", "src/backend/vendor/modules.txt",
                 "scripts/installer-gui/go.mod", "src/frontend/package-lock.json",
                 "docs-portal/package-lock.json", "src/correlation/requirements.txt",
                 "deployment/docker/Dockerfile.backend"):
        assert tp.classify([P + path]).artifact_checks, path


def test_fast_checks_pass_on_the_committed_tree():
    # The tree CI tests must be current; if this fails the tree is red anyway.
    assert tp.run_fast_checks() == []


def test_run_fast_skips_when_no_artifact_input_changed():
    assert tp.main(["--run-fast", P + "docs/TRACKER.md"]) == 0


def test_unreadable_diff_is_treated_as_strictest(monkeypatch, capsys):
    def boom(_base):
        raise RuntimeError("bad revision")
    monkeypatch.setattr(tp, "changed_paths", boom)
    assert tp.main(["--base", "nope"]) == 0
    out = capsys.readouterr()
    assert "tier: high-risk" in out.out
    assert "strictest" in out.out + out.err


def test_cli_prints_a_plan():
    res = subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "test-plan.py"),
                          P + "src/backend/collectors/vrf.go"],
                         capture_output=True, text=True, timeout=60, check=False)
    assert res.returncode == 0, res.stderr
    assert "tier: code" in res.stdout


# ── CI job selection (--ci-groups) ──────────────────────────────────────────
import json

import pytest
import yaml

REPO = os.path.dirname(ROOT)
WIRED = ("backend-ci", "correlation-ci", "frontend-ci", "fresh-install-integrity")
NEVER_SKIPPED = ("supply-chain", "ingest-contract-ci", "tracker-ci", "telemetry-catalog-ci")


def _on(paths, event="pull_request"):
    return {g for g, v in tp.ci_groups(paths, event)["groups"].items() if v}


ALL = set(tp.CI_GROUPS)


@pytest.mark.parametrize("paths,expected", [
    # documentation only → the always-run jobs alone
    ([P + "docs/TRACKER.md", P + "README.md", "CLAUDE.md"], set()),
    ([P + "docs/runbooks/x.md", P + "tests/test_x.py"], set()),
    # backend source: a sub-package needs backend; the root package boots the stack
    ([P + "src/backend/collectors/vrf.go"], {"backend"}),
    ([P + "src/backend/main.go"], {"backend", "install-boot"}),
    ([P + "src/backend/migrations/0060_x.sql"], {"backend", "install-boot"}),
    ([P + "src/backend/tlsconfig/config.go"], {"backend", "install-boot"}),
    # Go dependency changes
    ([P + "src/backend/go.mod", P + "src/backend/go.sum"], {"backend", "install-boot"}),
    ([P + "src/backend/vendor/golang.org/x/net/a.go"], {"backend", "install-boot"}),
    # lockfiles
    ([P + "src/frontend/package-lock.json"], {"frontend", "install-boot"}),
    ([P + "docs-portal/package-lock.json"], {"frontend", "install-boot"}),
    ([P + "src/correlation/requirements.txt"], {"correlation", "install-boot"}),
    # Dockerfiles → their component + install-boot
    ([P + "deployment/docker/Dockerfile.backend"], {"backend", "install-boot"}),
    ([P + "deployment/docker/Dockerfile.correlation"], {"correlation", "install-boot"}),
    ([P + "deployment/docker/Dockerfile.frontend"], {"frontend", "install-boot"}),
    ([P + "deployment/docker/docker-compose.yml"], {"install-boot"}),
    # install / startup scripts
    ([P + "scripts/install.py"], {"install-boot"}),
    ([P + "scripts/install-correlix.sh"], {"install-boot"}),
    # frontend / correlation / catalogue
    ([P + "src/frontend/src/iris/Panel.tsx"], {"frontend"}),
    ([P + "src/correlation/engine.py"], {"correlation"}),
    ([P + "telemetry-catalog/events.yaml"], {"correlation"}),
    ([P + "src/config/rules.yaml"], {"backend", "install-boot"}),
    # an .md the product loads is code, not prose
    ([P + "src/backend/ai/skills/explain/kpi.md"], {"backend"}),
])
def test_ci_groups_per_category(paths, expected):
    plan = tp.ci_groups(paths)
    assert plan["mode"] == "selective"
    assert _on(paths) == expected


@pytest.mark.parametrize("paths", [
    [".github/workflows/backend-ci.yml"],                 # CI workflow change
    [".github/actions/ci-plan/action.yml"],
    [P + "scripts/test-plan.py"],                         # planner change
    [P + "scripts/ci/ci_gate.py"],
    [P + "Makefile"],
    [P + "some/new/top-level/thing.bin"],                 # unknown critical path
    [P + "docs/x.md", P + "unknown.cfg"],                 # one unknown is enough
])
def test_ci_changes_and_unknown_paths_are_full(paths):
    plan = tp.ci_groups(paths)
    assert plan["mode"] == "full" and _on(paths) == ALL


@pytest.mark.parametrize("event", ["push", "workflow_call", "workflow_dispatch", "merge_group", "schedule", ""])
def test_non_pr_events_are_full(event):
    assert _on([P + "docs/x.md"], event) == ALL


def test_empty_diff_is_full():
    assert tp.ci_groups([])["mode"] == "full"


def test_rules_only_add_groups():
    # A docs path alongside a backend path never removes backend.
    assert _on([P + "docs/x.md", P + "src/backend/a/b.go"]) == {"backend"}


def test_unreadable_git_diff_is_full(monkeypatch):
    def boom(_b, _h="HEAD"):
        raise RuntimeError("bad object")
    monkeypatch.setattr(tp, "changed_paths", boom)
    plan = tp.ci_plan_from_git("pull_request", ["deadbeef"], "HEAD")
    assert plan["mode"] == "full" and all(plan["groups"].values())


def test_stacked_pr_unions_both_bases(monkeypatch):
    # The parent branch's diff alone is the top layer; main's adds what is below.
    diffs = {"parent": [P + "docs/x.md"], "origin/main": [P + "docs/x.md", P + "src/frontend/a.tsx"]}
    monkeypatch.setattr(tp, "changed_paths", lambda b, h="HEAD": diffs[b])
    plan = tp.ci_plan_from_git("pull_request", ["parent", "origin/main"], "HEAD")
    assert plan["groups"]["frontend"] is True


def test_changed_paths_reports_both_sides_of_a_rename(tmp_path):
    def git(*a):
        subprocess.run(["git", *a], cwd=tmp_path, check=True, capture_output=True, timeout=30)
    git("init", "-q"); git("config", "user.email", "t@t"); git("config", "user.name", "t")
    (tmp_path / "auth_x.go").write_text("package x\n" * 50)
    git("add", "."); git("commit", "-qm", "a")
    git("mv", "auth_x.go", "plain.go"); git("commit", "-qm", "b")
    monkey = tp.PROJECT
    try:
        tp.PROJECT = str(tmp_path)
        assert set(tp.changed_paths("HEAD~1")) == {"auth_x.go", "plain.go"}
    finally:
        tp.PROJECT = monkey


def test_github_output_format(tmp_path):
    out = tmp_path / "out"
    tp.write_github_output(tp.ci_groups([P + "src/frontend/a.tsx"]), str(out))
    lines = out.read_text().splitlines()
    assert "frontend=true" in lines and "backend=false" in lines and "install-boot=false" in lines
    plan = json.loads(next(ln for ln in lines if ln.startswith("plan="))[5:])
    assert plan["schema"] == 1 and plan["groups"]["frontend"] is True


def test_cli_ci_groups_json():
    res = subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "test-plan.py"), "--ci-groups",
                          P + "docs/x.md"], capture_output=True, text=True, timeout=60, check=False)
    assert res.returncode == 0, res.stderr
    assert json.loads(res.stdout)["mode"] == "selective"


# PR #22 (2026-10-10): red for a week on four stale generated artifacts. Those
# checks live in workflows the planner can never skip, and its diff selects the
# backend and install-boot groups as well — the historical result is 4/4.
PR22_PATHS = [P + "src/backend/go.mod", P + "src/backend/go.sum", P + "src/backend/vendor/modules.txt",
              P + "deployment/docker/Dockerfile.backend", P + "src/frontend/package-lock.json",
              P + "docs-portal/package-lock.json", ".github/workflows/backend-ci.yml"]
PR22_FAILURES = ("tests/test_sbom.py", "tests/test_license_audit.py",
                 "tests/test_oci_digest_lock.py", "tests/test_toolchain_pin.py")


def test_pr22_failures_stay_detectable():
    assert tp.classify(PR22_PATHS).artifact_checks            # pre-push --run-fast fires
    assert _on(PR22_PATHS) == ALL                             # workflow edit → full
    assert _on([p for p in PR22_PATHS if ".github" not in p]) >= {"backend", "install-boot"}
    # the four failing tests run in ingest-contract-ci's tests/ suite, which is never skipped
    with open(os.path.join(REPO, ".github", "workflows", "ingest-contract-ci.yml"), encoding="utf-8") as fh:
        ingest = fh.read()
    assert "pytest" in ingest and "tests" in ingest
    for f in PR22_FAILURES:
        assert os.path.isfile(os.path.join(ROOT, f)), f


def _wf(name):
    with open(os.path.join(REPO, ".github", "workflows", f"{name}.yml"), encoding="utf-8") as fh:
        return yaml.safe_load(fh)


@pytest.mark.parametrize("name", WIRED)
def test_wired_workflow_shape(name):
    jobs = _wf(name)["jobs"]
    assert "plan" in jobs and "ci-gate" in jobs
    plan_outputs = set(jobs["plan"]["outputs"]) - {"plan"}
    assert plan_outputs == set(tp.CI_GROUPS)
    gate = jobs["ci-gate"]
    assert gate["if"] == "always()"                            # a cancelled run fails, never skips
    others = set(jobs) - {"plan", "ci-gate"}
    assert set(gate["needs"]) == others | {"plan"}             # the gate sees every job
    step = next(s for s in gate["steps"] if s.get("uses") == "./.github/actions/ci-gate")
    mapping = dict(pair.split("=") for pair in step["with"]["jobs"].split())
    assert set(mapping) == others                              # and knows every job's group
    for jid in others:
        cond = str(jobs[jid].get("if", ""))
        if mapping[jid] == "always":
            assert "needs.plan" not in cond, jid
            continue
        assert mapping[jid] in tp.CI_GROUPS
        assert jobs[jid]["needs"] == "plan", jid
        # skip ONLY on an explicit 'false' from a plan that ran — never on failure
        assert "!cancelled()" in cond and f"needs.plan.outputs.{mapping[jid]} != 'false'" in cond, jid


@pytest.mark.parametrize("name", NEVER_SKIPPED)
def test_security_and_contract_workflows_are_never_planned_away(name):
    with open(os.path.join(REPO, ".github", "workflows", f"{name}.yml"), encoding="utf-8") as fh:
        text = fh.read()
    assert "needs.plan" not in text and "ci-plan" not in text


def test_push_runs_only_on_main_for_pr_workflows():
    for name in WIRED + NEVER_SKIPPED:
        on = _wf(name).get(True) or _wf(name).get("on")     # PyYAML reads `on:` as True
        assert on["push"]["branches"] == ["main"], name
        assert "pull_request" in on, name
