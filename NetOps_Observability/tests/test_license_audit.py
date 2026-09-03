"""Licence-compliance gate — fail CI when a dependency's licence is unreviewed.

CLAUDE.md §6 puts zero trust on dependencies. That rule has always covered the
Go module allowlist; these tests extend the same bar to every OTHER thing we
distribute — npm packages linked into the SPA, Python packages baked into the
correlation image, container images in the compose bundle, and third-party
content copied into the tree by hand (MIB modules, icon path data, marks).

The gate is deliberately narrow: it fails on a NEW component whose licence
nobody has reviewed, and on any strong-copyleft component that would be linked
into one of our own artifacts. Pre-existing findings that the owner has yet to
rule on are recorded as reviewed exceptions with `status: OPEN` — they are
printed loudly by every run (and listed in docs/security/LICENSE_AUDIT_2026-09-03.md)
rather than blocking merges, because a gate that is red on day one is a gate
people learn to switch off.

Run:  python3 -m pytest tests/test_license_audit.py -v
"""
import json
import os
import subprocess
import sys

import pytest

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
SCRIPT = os.path.join(ROOT, "scripts", "license-audit.py")
DATA = os.path.join(ROOT, "scripts", "license-data.json")
NOTICES = os.path.join(ROOT, "docs", "THIRD_PARTY_LICENSES.md")

sys.path.insert(0, os.path.join(ROOT, "scripts"))
import importlib.util

_spec = importlib.util.spec_from_file_location("license_audit", SCRIPT)
assert _spec and _spec.loader
license_audit = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(license_audit)


def run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, SCRIPT, *args],
        cwd=ROOT, capture_output=True, text=True, timeout=180, check=False,
    )


@pytest.fixture(scope="module")
def inventory():
    data = license_audit.load_data()
    return data, license_audit.build_inventory(data)


# ── the gate itself ──────────────────────────────────────────────────────────

def test_license_audit_passes():
    """The whole-tree licence gate must be green.

    A failure here means a dependency arrived whose licence is outside the
    allowlist, or has no resolvable licence at all. Read the reported lines:
    either the licence is fine and belongs in scripts/license-data.json, or the
    dependency does not belong in the product."""
    proc = run("--check")
    assert proc.returncode != 2, (
        f"the licence audit could not run at all:\n{proc.stderr}")
    assert proc.returncode == 0, (
        f"licence gate FAILED:\n{proc.stdout}\n{proc.stderr}")


def test_audit_covers_every_ecosystem(inventory):
    """A silently-empty source would turn the gate into a rubber stamp."""
    _data, comps = inventory
    found = {c.ecosystem for c in comps}
    for eco in ("go", "npm", "pypi", "image", "vendored"):
        assert eco in found, f"no {eco} components discovered — the collector is broken"


# ── the invariants the gate exists to protect ────────────────────────────────

def test_nothing_copyleft_is_linked_into_our_binaries(inventory):
    """Strong copyleft linked into our own artifact would relicense our code.

    This is the one rule with no exception path: GPL/AGPL may run beside us as
    a separate container, never inside our binary or our JS bundle."""
    _data, comps = inventory
    bad = [f"{c.name}@{c.version} ({c.license}, {c.usage})"
           for c in comps
           if c.klass == "SEPARATE_PROCESS" and c.usage in ("linked", "bundled-runtime")]
    assert not bad, ("strong copyleft linked into a Correlix artifact: "
                     + "; ".join(bad))


def test_no_source_available_licences_anywhere(inventory):
    """SSPL / BUSL / Elastic / RSAL are not open source and must never appear.

    Redis and Redpanda were removed for exactly this reason (#97); this test
    keeps them, and anything like them, from coming back."""
    _data, comps = inventory
    banned = {"SSPL-1.0", "BUSL-1.1", "BSL-1.1", "Elastic-2.0", "ELv2", "RSAL-2.0",
              "Commons-Clause"}
    bad = [f"{c.name}@{c.version} ({c.license})" for c in comps if c.license in banned]
    assert not bad, "source-available (non-OSS) component present: " + "; ".join(bad)


def test_removed_components_have_not_returned(inventory):
    """Redis, Redpanda and Prometheus were removed on licensing/architecture
    grounds. make-installer.sh guards the bundle; this guards the whole tree."""
    _data, comps = inventory
    bad = [c.name for c in comps
           if any(t in c.name.lower() for t in ("redpanda", "/redis", "redis:"))
           or c.name.lower() in ("redis", "prom/prometheus")]
    assert not bad, f"removed component reappeared: {bad}"


def test_every_exception_is_reasoned(inventory):
    """An exception without a stated posture and obligation is a rubber stamp."""
    data, comps = inventory
    present = {c.name for c in comps} | {c.key for c in comps}
    for name, exc in data.get("exceptions", {}).items():
        if name not in present:
            continue
        for field in ("license", "posture", "obligation", "owner_decision"):
            assert exc.get(field), (
                f"exception '{name}' is missing `{field}` — every exception must "
                f"say what the component is, how we use it, what we owe, and "
                f"whether the owner still has to decide something")


def test_weak_copyleft_components_are_all_reviewed(inventory):
    """MPL/EPL/LGPL are fine unmodified, but each needs a recorded posture so a
    later change ('let's patch Vector') meets the obligation knowingly."""
    data, comps = inventory
    exceptions = data.get("exceptions", {})
    unreviewed = [f"{c.name} ({c.license})" for c in comps
                  if c.klass == "REVIEW_REQUIRED"
                  and not (exceptions.get(c.name) or exceptions.get(c.key))]
    assert not unreviewed, ("weak-copyleft component with no reviewed exception: "
                            + "; ".join(unreviewed))


# ── the notices file must stay in step with the inventory ────────────────────

def test_notices_file_is_current():
    """docs/THIRD_PARTY_LICENSES.md is GENERATED. If it drifts from the tree we
    are shipping attribution for the wrong set of components — which is the
    exact failure mode the hand-maintained bundle LICENSES.md had."""
    assert os.path.isfile(NOTICES), (
        "docs/THIRD_PARTY_LICENSES.md missing — run "
        "`python3 scripts/license-audit.py --notices`")
    data = license_audit.load_data()
    comps = license_audit.build_inventory(data)
    expected = license_audit.render_notices(comps, data)
    with open(NOTICES, encoding="utf-8") as fh:
        actual = fh.read()
    assert actual == expected, (
        "docs/THIRD_PARTY_LICENSES.md is stale — regenerate it with "
        "`python3 scripts/license-audit.py --notices`")


def test_every_distributed_attribution_component_is_in_the_notices():
    """Every shipped component whose licence demands attribution must actually
    appear in the file we ship. OFL fonts, EPL/MPL libraries and the copied
    Feather/Lucide icon data are the ones that were missing before this audit."""
    data = license_audit.load_data()
    comps = license_audit.build_inventory(data)
    with open(NOTICES, encoding="utf-8") as fh:
        text = fh.read()
    must_appear = [c for c in comps
                   if c.usage in ("linked", "bundled-runtime", "separate-container")
                   and not c.unit.startswith(("NOT SHIPPED", "NOT REFERENCED"))
                   and c.klass in ("NOTICE_REQUIRED", "REVIEW_REQUIRED",
                                   "SEPARATE_PROCESS")]
    assert must_appear, "no attribution-bearing shipped components found — check the fixture"
    missing = [c.name for c in must_appear if c.name not in text]
    assert not missing, ("shipped component with an attribution obligation is "
                         f"absent from THIRD_PARTY_LICENSES.md: {missing}")


def test_source_offer_covers_every_copyleft_component():
    """GPL/AGPL/MPL/EPL all require telling recipients how to get the source.
    The written offer must name each such component we actually ship."""
    with open(NOTICES, encoding="utf-8") as fh:
        text = fh.read()
    for component in ("syslog-ng", "Grafana", "Vector", "elkjs", "certifi"):
        assert component in text, (
            f"{component} carries a source-availability obligation but is not "
            f"named in the written offer in THIRD_PARTY_LICENSES.md")


# ── the data file must stay honest ───────────────────────────────────────────

def test_declared_vendored_paths_all_exist():
    """Attribution must track the content it covers. A moved or deleted file
    whose entry stays behind means we credit something we no longer ship — or,
    worse, ship something we no longer credit."""
    data = license_audit.load_data()
    for name, fact in data.get("vendored", {}).items():
        for rel in fact.get("paths", []):
            assert os.path.exists(os.path.join(ROOT, rel)), (
                f"vendored entry '{name}' points at missing path {rel}")


def test_license_data_is_valid_json_and_sorted():
    with open(DATA, encoding="utf-8") as fh:
        raw = fh.read()
    data = json.loads(raw)
    for section in ("npm", "python", "images", "exceptions", "vendored"):
        assert section in data, f"license-data.json is missing the `{section}` section"


def test_classifier_resolves_dual_licences_to_the_permissive_branch():
    """`BSD-3-Clause OR GPL-2.0` is ours to take under BSD. The classifier must
    not read a disjunction as copyleft and block a merge for no reason."""
    assert license_audit.classify("BSD-3-Clause OR GPL-2.0-or-later") == "PERMISSIVE"
    assert license_audit.classify("MIT OR CC0-1.0") == "PERMISSIVE"
    assert license_audit.classify("AGPL-3.0-only") == "SEPARATE_PROCESS"
    assert license_audit.classify("MPL-2.0") == "REVIEW_REQUIRED"
    assert license_audit.classify("SSPL-1.0") == "FORBIDDEN"
    assert license_audit.classify("") == "FORBIDDEN"


def test_gate_rejects_an_unreviewed_copyleft_arrival():
    """The gate must actually bite. Inject a synthetic SSPL dependency and a
    synthetic AGPL library linked into the SPA, and assert both are caught."""
    data = license_audit.load_data()
    sspl = license_audit.Component(
        key="npm:test:evil", name="evil-db-driver", version="1.0.0",
        license="SSPL-1.0", ecosystem="npm", usage="bundled-runtime",
        unit="frontend image", source="test")
    agpl = license_audit.Component(
        key="npm:test:agpl", name="agpl-lib", version="1.0.0",
        license="AGPL-3.0-only", ecosystem="npm", usage="bundled-runtime",
        unit="frontend image", source="test")
    unknown = license_audit.Component(
        key="npm:test:unknown", name="mystery-pkg", version="1.0.0",
        license="UNKNOWN", ecosystem="npm", usage="bundled-runtime",
        unit="frontend image", source="unresolved")
    violations = license_audit.gate([sspl, agpl, unknown], data)
    assert len(violations) == 3, f"gate let something through: {violations}"
    assert any("evil-db-driver" in v and "non-OSS" in v for v in violations)
    assert any("agpl-lib" in v and "never allowed" in v.lower() for v in violations)
    assert any("mystery-pkg" in v for v in violations)
