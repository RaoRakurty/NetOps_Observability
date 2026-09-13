# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Guard: the ONE fail-closed release gate actually fails closed.

WHY THIS EXISTS. `scripts/release-gate.py` is the entry point the RC1 governance
directive (Decision 8) asks for: one command that says whether this commit is
releasable. A gate like that has exactly two ways to be worthless, and both are
invisible when you run it on a clean tree:

  1. it passes something it did not prove — a missing scanner read as a skip, a
     human blocker read as "not applicable", a filtered run read as a verdict;
  2. it quietly shrinks — an item of Decision 8 stops being checked and nothing
     notices, because the report only lists the checks that still exist.

So every check is driven here through a STUB command that passes, fails, or is
missing, and the resulting table is asserted: any FAIL is non-zero, a
BLOCKED-HUMAN row is non-zero AND labelled, a missing tool is a FAIL rather than
a skip, and a partial run can never return the GO exit code. The list of checks
is held against the directive's own Decision-8 sentence, parsed out of the
document, so the aggregate cannot silently lose an item.

Nothing here runs a real command: `run_process` is replaced wholesale. The suite
is therefore offline, second-scale, and safe in CI.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path

import pytest

PROJ = Path(__file__).resolve().parents[1]
REPO = PROJ.parent
SCRIPT = PROJ / "scripts" / "release-gate.py"
DIRECTIVE = PROJ / "docs" / "release" / "RC1_GOVERNANCE_DIRECTIVE_2026-09-13.md"
MAKEFILE = PROJ / "Makefile"
CHECKLIST = PROJ / "docs" / "RELEASE_CHECKLIST.md"
RC1_PROCEDURE = PROJ / "docs" / "runbooks" / "rc1-release-procedure.md"
WORKFLOWS = REPO / ".github" / "workflows"

HEAD_SHA = "0123456789abcdef0123456789abcdef01234567"


def load_module():
    """Import the gate. The filename carries a dash (it is a command first), so it
    is loaded by path the same way tests/test_licensing_consistency.py loads its
    subject."""
    spec = importlib.util.spec_from_file_location("correlix_release_gate", SCRIPT)
    assert spec and spec.loader, f"cannot load {SCRIPT}"
    module = importlib.util.module_from_spec(spec)
    # Registered BEFORE exec: @dataclass resolves its annotations through
    # sys.modules[cls.__module__], which is None for a module that was never
    # registered (a hard AttributeError on 3.10, not a warning).
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


mod = load_module()


# ── the stub ─────────────────────────────────────────────────────────────────
class StubRunner:
    """Stands in for `run_process`: every mapped check's command comes through here.

    `mode` is "pass", "fail" or "missing". In "pass" mode the stub answers the few
    commands whose OUTPUT the gate parses (git, gpg, licensing-gate --json) with a
    plausible shape; everything else just succeeds. Every call is recorded so the
    tests can assert what was invoked and that it was bounded.
    """

    def __init__(self, mode: str = "pass", blockers: list[dict] | None = None,
                 tag: str = "v0.9.0-rc1", have_key: bool = True,
                 gosec_files: int = 42):
        self.mode = mode
        self.gosec_files = gosec_files
        self.blockers = blockers or []
        self.tag = tag
        self.have_key = have_key
        self.calls: list[tuple[tuple[str, ...], str, float]] = []
        self.envs: list[dict[str, str]] = []

    def __call__(self, argv, cwd, timeout, env_overrides=None):
        self.calls.append((tuple(argv), str(cwd), timeout))
        self.envs.append(dict(env_overrides or {}))
        # CLAUDE.md §9: all IO has a timeout. A check that forgot one would hang a
        # release gate forever, so the stub refuses to answer an unbounded call.
        assert isinstance(timeout, (int, float)) and 0 < timeout < 86_400, (
            f"unbounded or absurd timeout {timeout!r} for {argv}"
        )
        joined = " ".join(str(a) for a in argv)

        if "rev-parse" in joined:
            return mod.Proc(rc=0, out=HEAD_SHA + "\n")
        if "--list-secret-keys" in joined:
            if not self.have_key:
                return mod.Proc(rc=2, err="gpg: error reading key")
            return mod.Proc(rc=0, out="sec:u:::::::::\nfpr:::::::::DEADBEEFCAFE1234:\n")
        if "licensing-gate.py" in joined and "--json" in joined:
            payload = {"ok": not self.blockers, "failures": self.blockers}
            return mod.Proc(rc=1 if self.blockers else 0, out=json.dumps(payload))

        if self.mode == "missing":
            return mod.Proc(rc=127, err=f"{argv[0]}: not found (No such file)",
                            missing=True)
        if self.mode == "fail":
            return mod.Proc(rc=1, err="stub: the check failed")

        if "gosec" in joined:
            # gosec's summary is parsed, because `gosec -quiet` exits 0 after
            # analysing NOTHING (see check_security_gosec).
            return mod.Proc(rc=0, out=f"Summary:\n  Files  : {self.gosec_files}\n"
                                      f"  Issues : 0\n")
        if "describe" in joined:
            if not self.tag:
                return mod.Proc(rc=128, err="fatal: no tag exactly matches")
            return mod.Proc(rc=0, out=self.tag + "\n")
        if "verify-tag" in joined:
            return mod.Proc(rc=0, err="gpg: Good signature from \"Correlix Release\"")
        if "status" in joined and "--porcelain" in joined:
            return mod.Proc(rc=0, out="")
        return mod.Proc(rc=0, out="stub: ok")


ENTERPRISE_BLOCKER = {
    "check": "RELEASE",
    "where": "LICENSES/LicenseRef-Correlix-Enterprise.txt",
    "message": ("LICENSES/LicenseRef-Correlix-Enterprise.txt still contains the marker "
                "CORRELIX-ENTERPRISE-TEXT-PLACEHOLDER. OWNER ACTION: counsel."),
}
CLA_BLOCKER = {
    "check": "RELEASE",
    "where": "CONTRIBUTING.md",
    "message": "CONTRIBUTING.md states the CLA requirement but names no process.",
}


def write_bundle(root: Path, git_sha: str = HEAD_SHA[:8], signed: bool = True,
                 extra_uncovered: bool = False, corrupt: bool = False) -> Path:
    """A minimal but STRUCTURALLY REAL bundle: MANIFEST, payload files, a
    SHA256SUMS that covers them, and (optionally) a detached signature."""
    bundle = root / "dist" / f"correlix-2026.09.13-g{git_sha}"
    bundle.mkdir(parents=True)
    (bundle / "install-correlix.sh").write_text("#!/bin/sh\nexit 0\n")
    (bundle / "LICENSE").write_text("Apache-2.0\n")
    manifest = [
        "product:  Correlix (NetOps Observability)",
        "version:  2026.09.13-g" + git_sha,
        f"git_sha:  {git_sha}",
        "profile:  full",
        "built:    2026-09-13T00:00:00+00:00",
        "images:",
        "  - netops-api",
    ]
    if signed:
        manifest.append("signing-key DEADBEEFCAFE1234")
    (bundle / "MANIFEST").write_text("\n".join(manifest) + "\n")
    lines = []
    for name in ("install-correlix.sh", "LICENSE", "MANIFEST"):
        digest = hashlib.sha256((bundle / name).read_bytes()).hexdigest()
        lines.append(f"{digest}  ./{name}")
    (bundle / "SHA256SUMS").write_text("\n".join(lines) + "\n")
    if corrupt:
        (bundle / "LICENSE").write_text("Apache-2.0 but tampered\n")
    if extra_uncovered:
        (bundle / "surprise.tar.zst").write_bytes(b"payload nobody listed")
    if signed:
        (bundle / "SHA256SUMS.asc").write_text("-----BEGIN PGP SIGNATURE-----\n")
    return bundle


def ctx_for(bundle: Path | None = None, *, key: str | None = "DEADBEEFCAFE1234",
            tag: str = "v0.9.0-rc1", run_tests: bool = False) -> object:
    return mod.Ctx(
        bundle=str(bundle) if bundle else None,
        bundle_why="" if bundle else "no dist/correlix-*/ bundle with a MANIFEST",
        run_tests=run_tests,
        signing_fpr=key,
        signing_why="" if key else "CORRELIX_SIGNING_KEY is unset on this host",
        head=HEAD_SHA,
        tag=tag,
    )


def run_all(monkeypatch, runner: StubRunner, ctx, only: str = ""):
    monkeypatch.setattr(mod, "run_process", runner)
    return mod.run_checks(ctx, only)


# ── the Decision-8 contract ──────────────────────────────────────────────────
def decision8_items_from_directive() -> list[str]:
    """Parse the items out of Decision 8 itself.

    The directive is the authority; a list retyped into the script is a copy that
    can drift. This reads the sentence, so dropping an item from the aggregate
    fails here instead of shipping a gate that checks fourteen things.
    """
    text = DIRECTIVE.read_text(encoding="utf-8")
    match = re.search(
        r"8\.\s+\*\*Fail-closed release gate\.\*\*(.+?)Any failure", text, re.DOTALL,
    )
    assert match, "Decision 8 is not in the directive in the expected shape"
    body = re.sub(r"\s+", " ", match.group(1))
    assert "aggregating:" in body, body
    listed = body.split("aggregating:", 1)[1].split(".")[0]
    return [part.strip() for part in listed.split(",") if part.strip()]


def test_the_script_items_are_exactly_the_directives_items():
    assert list(mod.DECISION8_ITEMS) == decision8_items_from_directive()


def test_every_decision8_item_has_at_least_one_check():
    covered = {item for _cid, item, _fn in mod.CHECKS}
    missing = [item for item in mod.DECISION8_ITEMS if item not in covered]
    assert not missing, f"Decision-8 items with no check: {missing}"


def test_no_check_claims_an_item_the_directive_does_not_name():
    stray = {item for _cid, item, _fn in mod.CHECKS} - set(mod.DECISION8_ITEMS)
    assert not stray, f"checks filed under non-directive items: {stray}"


def test_check_ids_are_unique_and_stable_keys():
    ids = [cid for cid, _item, _fn in mod.CHECKS]
    assert len(ids) == len(set(ids)), "duplicate check id"
    for cid in ids:
        assert re.fullmatch(r"[a-z0-9-]+\.[a-z0-9-]+", cid), cid


def test_the_registry_matches_the_results_it_produces(monkeypatch):
    report = run_all(monkeypatch, StubRunner("pass"), ctx_for())
    assert [r.check for r in report.results] == [c[0] for c in mod.CHECKS]
    for result in report.results:
        assert result.status in mod.STATUSES
        assert result.evidence, f"{result.check} produced no evidence line"
        assert result.command, f"{result.check} produced no command"
        assert result.title, f"{result.check} produced no title"


# ── fail closed ──────────────────────────────────────────────────────────────
def test_any_fail_makes_the_exit_code_non_zero(monkeypatch, tmp_path):
    bundle = write_bundle(tmp_path)
    report = run_all(monkeypatch, StubRunner("fail"), ctx_for(bundle))
    assert report.counts[mod.FAIL] > 0
    assert report.exit_code == 1
    assert report.verdict == "NO-GO"


def test_a_missing_tool_is_a_fail_not_a_skip(monkeypatch, tmp_path):
    """The defect scripts/CLAUDE.md §16.1 exists to kill: "command not found"
    reported as anything other than a failure."""
    bundle = write_bundle(tmp_path)
    report = run_all(monkeypatch, StubRunner("missing"), ctx_for(bundle))
    by_id = {r.check: r for r in report.results}
    for cid in ("security.secrets-history", "security.go-vuln", "spdx.headers",
                "copyleft.third-party", "sbom.committed", "build.go"):
        assert by_id[cid].status == mod.FAIL, f"{cid} did not fail on a missing tool"
        assert "not found" in by_id[cid].evidence
    assert "SKIP" not in {r.status for r in report.results}
    assert report.exit_code == 1


def test_blocked_human_rows_are_labelled_and_still_fail(monkeypatch):
    """The four human-controlled inputs: counsel's licence text, the CLA
    mechanism, the distribution signing key, the owner's tag signature."""
    runner = StubRunner("pass", blockers=[ENTERPRISE_BLOCKER, CLA_BLOCKER], tag="",
                        have_key=False)
    report = run_all(monkeypatch, runner, ctx_for(None, key=None, tag=""))
    blocked = {r.check: r for r in report.results if r.status == mod.BLOCKED}
    for cid in ("enterprise-licence.text", "enterprise-licence.cla",
                "signature.bundle", "source-tag.exact-tag", "source-tag.signed-tag"):
        assert cid in blocked, f"{cid} should be BLOCKED-HUMAN, not FAIL or PASS"
        label = blocked[cid].human_action
        # The label is what separates "engineering has a bug" from "a human owes an
        # input", so it must SAY so — either as an action or as the directive's own
        # BLOCKED sentence.
        assert re.search(r"HUMAN ACTION|BLOCKED:", label), f"{cid} is unlabelled: {label}"
    assert report.exit_code == 1, "a human blocker must fail the release, not warn"
    assert report.verdict == "NO-GO"


def test_a_cleared_blocker_stops_being_blocked(monkeypatch):
    """Proof the BLOCKED-HUMAN rows are driven by evidence and not hard-coded: with
    no release blocker reported, both licence rows pass."""
    report = run_all(monkeypatch, StubRunner("pass", blockers=[]), ctx_for())
    by_id = {r.check: r for r in report.results}
    assert by_id["enterprise-licence.text"].status == mod.PASS
    assert by_id["enterprise-licence.cla"].status == mod.PASS


def test_only_one_of_the_two_licence_blockers_open(monkeypatch):
    report = run_all(monkeypatch, StubRunner("pass", blockers=[CLA_BLOCKER]), ctx_for())
    by_id = {r.check: r for r in report.results}
    assert by_id["enterprise-licence.cla"].status == mod.BLOCKED
    assert by_id["enterprise-licence.text"].status == mod.PASS


def test_ci_only_is_never_counted_as_a_pass(monkeypatch, tmp_path):
    bundle = write_bundle(tmp_path)
    report = run_all(monkeypatch, StubRunner("pass"), ctx_for(bundle))
    assert report.counts[mod.CI_ONLY] > 0
    assert report.counts[mod.FAIL] == 0 and report.counts[mod.BLOCKED] == 0
    # Nothing is wrong here, and it is still not a GO: the CI-only legs are
    # unverified on this host.
    assert report.exit_code == 3
    assert report.verdict == "NO-GO"
    for result in report.results:
        if result.status == mod.CI_ONLY:
            assert result.workflow and result.job


def test_every_ci_only_row_names_a_job_that_exists(monkeypatch):
    """A CI-ONLY row is a promise that something else checks it. A promise naming a
    workflow job that does not exist is worse than no row at all."""
    report = run_all(monkeypatch, StubRunner("pass"), ctx_for())
    seen = 0
    for result in report.results:
        if result.status != mod.CI_ONLY:
            continue
        path = WORKFLOWS / result.workflow
        assert path.is_file(), f"{result.check} names missing workflow {result.workflow}"
        body = path.read_text(encoding="utf-8")
        named = f"name: {result.job}" in body
        as_job_id = re.search(rf"(?m)^  {re.escape(result.job)}:\s*$", body) is not None
        assert named or as_job_id, (
            f"{result.check}: {result.workflow} has no job '{result.job}'"
        )
        seen += 1
    assert seen >= 5


def test_gosec_that_analysed_nothing_is_a_fail(monkeypatch):
    """The real trap this gate hit on day one: `gosec -quiet` exits 0 after
    failing to load every package. Exit 0 is not evidence of a scan."""
    monkeypatch.setattr(mod, "run_process", StubRunner("pass", gosec_files=0))
    result = mod.check_security_gosec(ctx_for())
    assert result.status == mod.FAIL
    assert "analysed 0 files" in result.evidence
    monkeypatch.setattr(mod, "run_process", StubRunner("pass", gosec_files=17))
    ok = mod.check_security_gosec(ctx_for())
    assert ok.status == mod.PASS
    assert "17 file(s)" in ok.evidence
    assert "-quiet" not in ok.command, (
        "the -quiet flag suppresses the very summary this check reads"
    )


def test_a_ci_only_row_whose_job_vanished_becomes_a_fail(monkeypatch, tmp_path):
    """A CI-ONLY row is a promise that another gate covers this. If the promise is
    void — the workflow or the job was renamed away — the row must fail, not point
    reassuringly at a job that no longer exists."""
    (tmp_path / "supply-chain.yml").write_text("jobs:\n  something-else:\n")
    monkeypatch.setattr(mod, "WORKFLOWS", str(tmp_path))
    result = mod.ci_only("x.y", "SBOM", "t", "supply-chain.yml", "SBOM (CycloneDX)", "w")
    assert result.status == mod.FAIL
    assert "no longer exists" in result.evidence
    # ... and the real job in the real workflow still resolves.
    assert mod.workflow_job_exists.__doc__
    monkeypatch.undo()
    assert mod.ci_only("x.y", "SBOM", "t", "supply-chain.yml", "SBOM (CycloneDX)",
                       "w").status == mod.CI_ONLY


def test_an_all_pass_report_is_the_only_exit_zero():
    """Exit 0 is reserved for a report with nothing unproven in it.

    Asserted on the report object rather than through the registry, because the
    registry always carries CI-ONLY rows — which is exactly why `make release-check`
    on a developer host tops out at exit 3.
    """
    good = mod.Report(results=[
        mod.Result("a.b", "tests", "t", mod.PASS, "e", "c"),
        mod.Result("c.d", "build", "t", mod.PASS, "e", "c"),
    ])
    assert good.exit_code == 0
    assert good.verdict == "GO"
    for status in (mod.FAIL, mod.BLOCKED, mod.CI_ONLY):
        mixed = mod.Report(results=[
            mod.Result("a.b", "tests", "t", mod.PASS, "e", "c"),
            mod.Result("c.d", "build", "t", status, "e", "c"),
        ])
        assert mixed.exit_code != 0, f"{status} must not yield exit 0"
        assert mixed.verdict == "NO-GO"


def test_a_partial_run_is_never_a_verdict(monkeypatch):
    report = run_all(monkeypatch, StubRunner("pass"), ctx_for(), only="spdx")
    assert [r.check for r in report.results] == ["spdx.headers", "spdx.boundary"]
    assert all(r.status == mod.PASS for r in report.results)
    assert report.filtered is True
    assert report.exit_code == 3, "a filtered run must not be able to return GO"
    assert report.verdict == "NO-GO"


def test_an_unknown_status_degrades_to_fail(monkeypatch):
    """A gate defect must not read as a pass."""
    def broken(_ctx):
        return mod.Result("x.y", "tests", "t", "PROBABLY FINE", "e", "c")

    monkeypatch.setattr(mod, "CHECKS", (("x.y", "tests", broken),))
    report = run_all(monkeypatch, StubRunner("pass"), ctx_for())
    assert report.results[0].status == mod.FAIL
    assert "PROBABLY FINE" in report.results[0].evidence
    assert report.exit_code == 1


def test_a_check_that_raises_becomes_a_fail_and_the_rest_still_run(monkeypatch):
    def explodes(_ctx):
        raise RuntimeError("the check itself is broken")

    def fine(_ctx):
        return mod.Result("ok.row", "build", "t", mod.PASS, "e", "c")

    monkeypatch.setattr(mod, "CHECKS", (
        ("boom.row", "tests", explodes), ("ok.row", "build", fine),
    ))
    report = run_all(monkeypatch, StubRunner("pass"), ctx_for())
    assert [r.status for r in report.results] == [mod.FAIL, mod.PASS]
    assert "RuntimeError" in report.results[0].evidence
    assert report.exit_code == 1


def test_the_item_rollup_reports_the_worst_status_per_item(monkeypatch):
    report = mod.Report(results=[
        mod.Result("a.b", "tests", "t", mod.PASS, "e", "c"),
        mod.Result("a.c", "tests", "t", mod.CI_ONLY, "e", "c"),
        mod.Result("d.e", "build", "t", mod.PASS, "e", "c"),
        mod.Result("f.g", "SBOM", "t", mod.BLOCKED, "e", "c"),
        mod.Result("h.i", "checksums", "t", mod.FAIL, "e", "c"),
    ])
    rollup = report.item_rollup
    assert rollup["tests"] == mod.CI_ONLY
    assert rollup["build"] == mod.PASS
    assert rollup["SBOM"] == mod.BLOCKED
    assert rollup["checksums"] == mod.FAIL
    assert rollup["signature"] == "NOT CHECKED"


# ── the JSON report ──────────────────────────────────────────────────────────
def test_json_shape(monkeypatch, tmp_path, capsys):
    bundle = write_bundle(tmp_path)
    monkeypatch.setattr(mod, "run_process", StubRunner("pass"))
    monkeypatch.setattr(mod, "find_bundle", lambda explicit: (str(bundle), ""))
    monkeypatch.setattr(mod, "signing_key", lambda: ("DEADBEEFCAFE1234", ""))
    rc = mod.main(["--json"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["schema"] == "correlix.release-gate/1"
    assert payload["exit_code"] == rc
    assert payload["verdict"] in ("GO", "NO-GO")
    assert payload["commit"] == HEAD_SHA
    assert payload["partial_run"] is False
    assert set(payload["counts"]) == set(mod.STATUSES)
    assert sum(payload["counts"].values()) == len(payload["checks"])
    assert list(payload["decision8_items"]) == list(mod.DECISION8_ITEMS)
    for entry in payload["checks"]:
        assert set(entry) >= {"check", "item", "title", "status", "evidence",
                              "command", "seconds"}
        assert entry["status"] in mod.STATUSES
        assert entry["item"] in mod.DECISION8_ITEMS
        if entry["status"] == mod.CI_ONLY:
            assert entry["workflow"] and entry["job"]
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", payload["generated"])


def test_the_table_prints_every_row_and_the_verdict(monkeypatch, tmp_path, capsys):
    bundle = write_bundle(tmp_path)
    monkeypatch.setattr(mod, "run_process", StubRunner("fail"))
    monkeypatch.setattr(mod, "find_bundle", lambda explicit: (str(bundle), ""))
    monkeypatch.setattr(mod, "signing_key", lambda: (None, "unset"))
    rc = mod.main([])
    out = capsys.readouterr().out
    assert rc == 1
    for cid, _item, _fn in mod.CHECKS:
        assert cid in out, f"{cid} is missing from the table"
    for item in mod.DECISION8_ITEMS:
        assert item in out
    assert "VERDICT: NO-GO" in out
    assert "Human blockers" in out and "Engineering failures" in out


def test_only_matching_nothing_is_a_usage_error(monkeypatch, capsys):
    monkeypatch.setattr(mod, "run_process", StubRunner("pass"))
    assert mod.main(["--only", "no-such-check"]) == 2
    assert "matched no check" in capsys.readouterr().err


def test_list_prints_the_registry_and_runs_nothing(monkeypatch, capsys):
    def refuse(*_a, **_k):
        raise AssertionError("--list must not execute anything")

    monkeypatch.setattr(mod, "run_process", refuse)
    assert mod.main(["--list"]) == 0
    out = capsys.readouterr().out
    assert len(out.strip().splitlines()) == len(mod.CHECKS)


# ── the artifact checks ──────────────────────────────────────────────────────
def test_a_signed_and_consistent_bundle_passes(monkeypatch, tmp_path):
    bundle = write_bundle(tmp_path)
    report = run_all(monkeypatch, StubRunner("pass"), ctx_for(bundle))
    by_id = {r.check: r for r in report.results}
    for cid in ("checksums.bundle", "signature.bundle", "signature.verify",
                "release-metadata.manifest", "source-tag.bundle-commit"):
        assert by_id[cid].status == mod.PASS, f"{cid}: {by_id[cid].evidence}"


def test_a_file_outside_sha256sums_fails_the_checksum_check(monkeypatch, tmp_path):
    """A signature over a partial manifest says nothing about the file somebody
    added afterwards — make-installer.sh refuses to sign that, and so does this."""
    bundle = write_bundle(tmp_path, extra_uncovered=True)
    report = run_all(monkeypatch, StubRunner("pass"), ctx_for(bundle))
    row = {r.check: r for r in report.results}["checksums.bundle"]
    assert row.status == mod.FAIL
    assert "surprise.tar.zst" in row.evidence


def test_a_tampered_file_fails_the_checksum_check(monkeypatch, tmp_path):
    bundle = write_bundle(tmp_path, corrupt=True)
    report = run_all(monkeypatch, StubRunner("pass"), ctx_for(bundle))
    row = {r.check: r for r in report.results}["checksums.bundle"]
    assert row.status == mod.FAIL
    assert "mismatch" in row.evidence


def test_an_unsigned_bundle_with_a_key_present_is_an_engineering_fail(monkeypatch,
                                                                     tmp_path):
    """With the key in hand, an unsigned bundle is a build defect, not a blocker."""
    bundle = write_bundle(tmp_path, signed=False)
    report = run_all(monkeypatch, StubRunner("pass"), ctx_for(bundle))
    by_id = {r.check: r for r in report.results}
    assert by_id["signature.bundle"].status == mod.FAIL
    assert by_id["signature.verify"].status == mod.FAIL
    assert by_id["release-metadata.manifest"].status == mod.FAIL


def test_an_unsigned_bundle_with_no_key_is_a_human_blocker(monkeypatch, tmp_path):
    bundle = write_bundle(tmp_path, signed=False)
    report = run_all(monkeypatch, StubRunner("pass", have_key=False),
                     ctx_for(bundle, key=None))
    by_id = {r.check: r for r in report.results}
    assert by_id["signature.bundle"].status == mod.BLOCKED
    assert by_id["signature.verify"].status == mod.BLOCKED


def test_a_bundle_from_another_commit_fails(monkeypatch, tmp_path):
    bundle = write_bundle(tmp_path, git_sha="deadbee1")
    report = run_all(monkeypatch, StubRunner("pass"), ctx_for(bundle))
    row = {r.check: r for r in report.results}["source-tag.bundle-commit"]
    assert row.status == mod.FAIL
    assert "deadbee1" in row.evidence


def test_no_bundle_is_a_fail_with_the_command_that_fixes_it(monkeypatch):
    report = run_all(monkeypatch, StubRunner("pass"), ctx_for(None))
    by_id = {r.check: r for r in report.results}
    for cid in ("checksums.bundle", "release-metadata.manifest",
                "source-tag.bundle-commit"):
        assert by_id[cid].status == mod.FAIL
        assert "make bundle" in by_id[cid].command


def test_a_non_release_tag_is_not_accepted_as_one(monkeypatch):
    report = run_all(monkeypatch, StubRunner("pass", tag="review/0d1dae06"),
                     ctx_for(tag="review/0d1dae06"))
    row = {r.check: r for r in report.results}["source-tag.exact-tag"]
    assert row.status == mod.BLOCKED
    assert "review/0d1dae06" in row.evidence


def test_find_bundle_rejects_a_directory_that_is_not_a_bundle(tmp_path):
    (tmp_path / "empty").mkdir()
    found, why = mod.find_bundle(str(tmp_path / "empty"))
    assert found is None and "MANIFEST" in why
    found, why = mod.find_bundle(str(tmp_path / "nope"))
    assert found is None and "not a directory" in why


# ── the pure-python checks ───────────────────────────────────────────────────
def write_go_module(root: Path, gomod: str, modules_txt: str) -> None:
    backend = root / "src" / "backend" / "vendor"
    backend.mkdir(parents=True)
    (root / "src" / "backend" / "go.mod").write_text(gomod)
    (backend / "modules.txt").write_text(modules_txt)


GOOD_GOMOD = """module netops/backend

go 1.26.0

require (
\tgithub.com/jackc/pgx/v5 v5.9.2
)

require (
\tgolang.org/x/text v0.41.0 // indirect
)
"""
GOOD_MODULES = """# github.com/jackc/pgx/v5 v5.9.2
## explicit; go 1.25.0
github.com/jackc/pgx/v5
# golang.org/x/text v0.41.0
## explicit; go 1.24.0
golang.org/x/text/unicode
"""


@pytest.mark.parametrize(
    ("modules_txt", "needle"),
    [
        (GOOD_MODULES.replace("v5.9.2", "v5.9.1"), "go.mod v5.9.2 vs vendor v5.9.1"),
        (GOOD_MODULES.split("# golang.org")[0], "vendored"),
        (GOOD_MODULES + "# example.com/ghost v1.0.0\n## explicit\nexample.com/ghost\n",
         "absent from go.mod"),
    ],
)
def test_vendor_drift_fails_the_dependency_lock(monkeypatch, tmp_path, modules_txt,
                                                needle):
    """A `go get` with no follow-up `go mod vendor` builds on a warm cache and
    fails on an air-gapped host. The lock is the two files agreeing."""
    write_go_module(tmp_path, GOOD_GOMOD, modules_txt)
    monkeypatch.setattr(mod, "BACKEND", str(tmp_path / "src" / "backend"))
    result = mod.check_dependency_lock_vendor(ctx_for())
    assert result.status == mod.FAIL
    assert needle in result.evidence


def test_a_consistent_vendor_tree_passes(monkeypatch, tmp_path):
    write_go_module(tmp_path, GOOD_GOMOD, GOOD_MODULES)
    monkeypatch.setattr(mod, "BACKEND", str(tmp_path / "src" / "backend"))
    assert mod.check_dependency_lock_vendor(ctx_for()).status == mod.PASS


ALLOWLIST_DOC = """## 6. DEPENDENCY RULES

### Allowlist (the ONLY third-party modules permitted)

| Module | Purpose | Notes |
|--------|---------|-------|
| `github.com/jackc/pgx` (or `lib/pq`) | PostgreSQL driver | required |
| `sqlc` (build-time, not a runtime import) | codegen | build-time |
| `golang.org/x/crypto/ssh` | SSH client | vendored |

Anything not in this table is **forbidden without first amending this table.**
"""


def test_the_allowlist_is_read_from_claude_md(tmp_path):
    (tmp_path / "CLAUDE.md").write_text(ALLOWLIST_DOC)
    allowed = mod.parse_dependency_allowlist(str(tmp_path / "CLAUDE.md"))
    assert allowed == ["github.com/jackc/pgx", "golang.org/x/crypto/ssh"]
    assert "sqlc" not in allowed, "a build-time tool is not a runtime import"


def test_a_dependency_off_the_allowlist_fails(monkeypatch, tmp_path):
    (tmp_path / "CLAUDE.md").write_text(ALLOWLIST_DOC)
    write_go_module(
        tmp_path,
        GOOD_GOMOD.replace("github.com/jackc/pgx/v5 v5.9.2",
                           "github.com/gin-gonic/gin v1.10.0"),
        GOOD_MODULES,
    )
    monkeypatch.setattr(mod, "REPO", str(tmp_path))
    monkeypatch.setattr(mod, "BACKEND", str(tmp_path / "src" / "backend"))
    result = mod.check_dependency_lock_allowlist(ctx_for())
    assert result.status == mod.FAIL
    assert "github.com/gin-gonic/gin" in result.evidence
    assert "CLAUDE.md §6" in result.evidence


def test_an_allowlisted_subpackage_covers_its_module(monkeypatch, tmp_path):
    """CLAUDE.md §6 names `golang.org/x/crypto/ssh`; go.mod requires
    `golang.org/x/crypto`. That is the same permission, not a violation."""
    (tmp_path / "CLAUDE.md").write_text(ALLOWLIST_DOC)
    write_go_module(
        tmp_path,
        GOOD_GOMOD.replace("github.com/jackc/pgx/v5 v5.9.2",
                           "golang.org/x/crypto v0.56.0"),
        GOOD_MODULES.replace("github.com/jackc/pgx/v5 v5.9.2",
                             "golang.org/x/crypto v0.56.0")
                    .replace("github.com/jackc/pgx/v5\n", "golang.org/x/crypto/ssh\n"),
    )
    monkeypatch.setattr(mod, "REPO", str(tmp_path))
    monkeypatch.setattr(mod, "BACKEND", str(tmp_path / "src" / "backend"))
    assert mod.check_dependency_lock_allowlist(ctx_for()).status == mod.PASS


def test_an_empty_allowlist_table_fails_rather_than_passing_by_accident(monkeypatch,
                                                                       tmp_path):
    (tmp_path / "CLAUDE.md").write_text("# no allowlist here\n")
    write_go_module(tmp_path, GOOD_GOMOD, GOOD_MODULES)
    monkeypatch.setattr(mod, "REPO", str(tmp_path))
    monkeypatch.setattr(mod, "BACKEND", str(tmp_path / "src" / "backend"))
    result = mod.check_dependency_lock_allowlist(ctx_for())
    assert result.status == mod.FAIL
    assert "empty" in result.evidence


def test_an_unhashed_pip_pin_fails(monkeypatch, tmp_path):
    (tmp_path / "src" / "correlation").mkdir(parents=True)
    (tmp_path / "src" / "correlation" / "requirements.txt").write_text(
        "# generated\nconfluent-kafka==2.5.0 \\\n    --hash=sha256:aaaa\n"
        "requests==2.32.3\n",
    )
    monkeypatch.setattr(mod, "PROJ", str(tmp_path))
    result = mod.check_dependency_lock_pip(ctx_for())
    assert result.status == mod.FAIL
    assert "requests" in result.evidence


def test_a_lockfile_entry_with_no_resolved_url_fails(monkeypatch, tmp_path):
    for rel in ("src/frontend", "docs-portal"):
        (tmp_path / rel).mkdir(parents=True)
        (tmp_path / rel / "package-lock.json").write_text(json.dumps({
            "lockfileVersion": 3,
            "packages": {"node_modules/left-pad": {"version": "1.3.0",
                                                   "resolved": "https://x/left-pad"}},
        }))
    monkeypatch.setattr(mod, "PROJ", str(tmp_path))
    assert mod.check_dependency_lock_npm(ctx_for()).status == mod.PASS
    (tmp_path / "src" / "frontend" / "package-lock.json").write_text(json.dumps({
        "lockfileVersion": 3,
        "packages": {"node_modules/left-pad": {"version": "1.3.0"}},
    }))
    result = mod.check_dependency_lock_npm(ctx_for())
    assert result.status == mod.FAIL
    assert "resolved URL" in result.evidence


def test_a_dirty_worktree_fails_generated_code_cleanliness(monkeypatch):
    class Dirty(StubRunner):
        def __call__(self, argv, cwd, timeout, env_overrides=None):
            if "--porcelain" in " ".join(argv):
                return mod.Proc(rc=0, out=" M src/backend/generated.go\n?? stray.py\n")
            return super().__call__(argv, cwd, timeout, env_overrides)

    monkeypatch.setattr(mod, "run_process", Dirty("pass"))
    result = mod.check_generated_worktree_clean(ctx_for())
    assert result.status == mod.FAIL
    assert "2 path(s)" in result.evidence


# ── the Go rows use this host's real toolchain selection ─────────────────────
def test_no_check_pins_gotoolchain(monkeypatch):
    """Standing rule on the build hosts: `go` on PATH can be older than go.mod's
    `go` directive, and go.mod's `toolchain` line is what resolves the real
    compiler (from the module cache). Pinning GOTOOLCHAIN=local made every Go row
    fail on a fact about the host's PATH rather than about the release.
    GOTOOLCHAIN=local belongs to the docker lint container, not here."""
    runner = StubRunner("pass")
    run_all(monkeypatch, runner, ctx_for())
    offenders = [env for env in runner.envs if "GOTOOLCHAIN" in env]
    assert not offenders, f"a check pinned GOTOOLCHAIN: {offenders}"
    # …and the name appears nowhere in the script's CODE, so a check added later
    # cannot reintroduce it on a path this stub does not reach. Comments are
    # exempt: the one that explains why it is absent is the point.
    code = "\n".join(line for line in SCRIPT.read_text(encoding="utf-8").splitlines()
                     if not line.lstrip().startswith("#"))
    assert "GOTOOLCHAIN" not in code


def test_the_offline_row_still_forbids_the_network():
    """Dropping GOTOOLCHAIN must not have dropped the offline invariant with it."""
    assert mod.GO_OFFLINE_ENV == {"GOFLAGS": "-mod=vendor", "GOPROXY": "off"}


def test_an_uncached_toolchain_fails_the_offline_row_and_says_so(monkeypatch):
    """A clean offline build implies a cached toolchain. If the compiler itself
    would have to be downloaded, that is a FAIL — and the row must distinguish it
    from an incomplete vendor/, because the two have different fixes."""
    class NoToolchain(StubRunner):
        def __call__(self, argv, cwd, timeout, env_overrides=None):
            if "build" in argv:
                return mod.Proc(rc=1, err="go: downloading go1.26.8: module lookup "
                                          "disabled by GOPROXY=off")
            return super().__call__(argv, cwd, timeout, env_overrides)

    monkeypatch.setattr(mod, "run_process", NoToolchain("pass"))
    result = mod.check_offline_build(ctx_for())
    assert result.status == mod.FAIL
    assert "TOOLCHAIN itself is not in the module cache" in result.evidence
    assert "GOFLAGS=-mod=vendor GOPROXY=off" in result.command


def test_a_vendor_gap_is_not_reported_as_a_toolchain_problem(monkeypatch):
    class VendorGap(StubRunner):
        def __call__(self, argv, cwd, timeout, env_overrides=None):
            if "build" in argv:
                return mod.Proc(rc=1, err="netops/backend/foo: cannot find module "
                                          "providing package example.com/bar")
            return super().__call__(argv, cwd, timeout, env_overrides)

    monkeypatch.setattr(mod, "run_process", VendorGap("pass"))
    result = mod.check_offline_build(ctx_for())
    assert result.status == mod.FAIL
    assert "TOOLCHAIN" not in result.evidence
    assert "cannot find module" in result.evidence


def test_the_gate_tools_are_found_off_the_default_path(monkeypatch, tmp_path):
    """staticcheck/gosec/govulncheck/gitleaks are `go install`ed into GOBIN or
    $GOPATH/bin, which is on no default and no cron PATH (scripts/CLAUDE.md
    §16.2). A gate that reported them 'not installed' would answer the wrong
    question."""
    gobin = tmp_path / "gobin"
    gobin.mkdir()
    fake = gobin / "staticcheck"
    fake.write_text("#!/bin/sh\nexit 0\n")
    fake.chmod(0o755)
    monkeypatch.setenv("GOBIN", str(gobin))
    monkeypatch.setattr("shutil.which", lambda _name: None)
    assert mod.resolve_tool("staticcheck") == str(fake)
    assert mod.resolve_tool("definitely-not-a-real-tool") is None


def test_the_row_names_the_binary_it_used(monkeypatch):
    """Two versions of a linter can be installed; "staticcheck passed" and "THIS
    staticcheck passed" are different claims."""
    report = run_all(monkeypatch, StubRunner("pass"), ctx_for())
    by_id = {r.check: r for r in report.results}
    for cid in ("security.staticcheck", "security.go-vuln", "security.gosec",
                "security.secrets-history"):
        assert "via " in by_id[cid].evidence, (
            f"{cid} does not say which binary it ran: {by_id[cid].evidence}"
        )


# ── evidence hygiene ─────────────────────────────────────────────────────────
def test_one_line_strips_ansi_and_control_characters():
    noisy = "progress\r\x1b[32mINF\x1b[0m gitleaks FAIL: 3 leaks\x07\n"
    line = mod.one_line(noisy)
    assert "\x1b" not in line and "\x07" not in line and "\r" not in line
    assert "gitleaks FAIL: 3 leaks" in line


def test_the_evidence_line_prefers_the_verdict_over_a_progress_log():
    """Real shape: gosec ends stderr with a timestamped "Import directory: …" while
    the cause sits on stdout. A row whose evidence is a path explains nothing."""
    proc = mod.Proc(
        rc=1,
        out=('Golang errors in file: [sealing]:\n'
             '  > loading files from package "sealing": err: exit status 1: '
             'stderr: go: go.mod requires go >= 1.26.0\n'),
        err="[gosec] 2026/09/13 09:09:14 Import directory: /src/backend/internalca\n",
    )
    assert "err: exit status 1" in proc.tail
    assert "Import directory" not in proc.tail
    # With nothing verdict-shaped anywhere, the last line is still reported — an
    # empty evidence cell would be worse than a vague one.
    assert mod.Proc(rc=1, err="doing a thing\nstill doing it\n").tail == "still doing it"


def test_one_line_is_bounded():
    assert len(mod.one_line("x" * 5000)) <= 220


def test_the_displayed_command_is_retypable(monkeypatch):
    report = run_all(monkeypatch, StubRunner("pass"), ctx_for())
    for result in report.results:
        assert mod.PY not in result.command or mod.PY == "python3", (
            f"{result.check} shows the interpreter's absolute path: {result.command}"
        )
        assert "\n" not in result.command


def test_no_row_leaks_key_material(monkeypatch, tmp_path):
    """§8 / Decision 10: only fingerprints, never key bytes."""
    bundle = write_bundle(tmp_path)
    monkeypatch.setenv("CORRELIX_SIGNING_KEY", "DEADBEEFCAFE1234")
    report = run_all(monkeypatch, StubRunner("pass"), ctx_for(bundle))
    for result in report.results:
        blob = f"{result.evidence} {result.command} {result.human_action}"
        assert "BEGIN PGP PRIVATE" not in blob
        assert "-----BEGIN" not in blob


# ── the entry point is wired up ──────────────────────────────────────────────
def test_the_makefile_exposes_release_check():
    body = MAKEFILE.read_text(encoding="utf-8")
    assert re.search(r"(?m)^release-check:\n\tpython3 scripts/release-gate\.py$", body)
    assert re.search(r"(?m)^release-check-json:\n\tpython3 scripts/release-gate\.py "
                     r"--json$", body)
    assert re.search(r"(?m)^\.PHONY:.*release-check", body, re.DOTALL)


def test_the_storm_slo_release_gate_target_is_not_repurposed():
    """`make release-gate` is the #101 storm-SLO lane contract and is referenced
    elsewhere; the new gate took a new name precisely so this stays true."""
    body = MAKEFILE.read_text(encoding="utf-8")
    recipe = body.split("\nrelease-gate:\n", 1)[1].split("\n\n", 1)[0]
    assert "test_storm_release_gate.py" in recipe
    assert "release-gate.py" not in recipe


def test_the_docs_name_the_one_command_and_the_distinction():
    checklist = CHECKLIST.read_text(encoding="utf-8")
    assert "make release-check" in checklist
    assert "scripts/release-gate.py" in checklist
    # The near-identical names are the trap; the checklist must disarm it.
    assert "release-gate" in checklist and "#101" in checklist
    procedure = RC1_PROCEDURE.read_text(encoding="utf-8")
    assert "make release-check" in procedure
