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
