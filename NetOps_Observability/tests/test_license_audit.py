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
import re
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


# ── the notices must SHIP, not just exist in the repo ────────────────────────
# The 2026-09-03 audit's five attribution failures were all failures of
# DISTRIBUTION, not of knowledge: the facts were in the tree, and none of them
# reached the customer. These tests assert the notices are inside each
# distribution unit — the frontend image's served files, the correlation
# image's /app/licenses, and the installer bundle's LICENSES.md.

FRONTEND = os.path.join(ROOT, "src", "frontend")
PUBLIC_LICENSES = os.path.join(FRONTEND, "public", "licenses")
NOTICE_FILE = os.path.join(ROOT, "NOTICE")
ICON_TSX = os.path.join(FRONTEND, "src", "components", "Icon.tsx")
INSTALLER = os.path.join(ROOT, "scripts", "make-installer.sh")

# path under public/licenses/  ->  a string the real licence text must contain
SHIPPED_LICENCE_FILES = {
    "index.html": "Third-party licences",
    "THIRD_PARTY_LICENSES.md": "Correlix — Third-party licences",
    "elkjs/LICENSE-EPL-2.0.txt": "Eclipse Public License - v 2.0",
    "elkjs/SOURCE.txt": "github.com/kieler/elkjs",
    "fonts/NOTICE.txt": "SIL Open Font License",
    "fonts/inter-OFL-1.1.txt": "SIL OPEN FONT LICENSE",
    "fonts/ibm-plex-mono-OFL-1.1.txt": "SIL OPEN FONT LICENSE",
    "fonts/space-grotesk-OFL-1.1.txt": "SIL OPEN FONT LICENSE",
    "fonts/manrope-OFL-1.1.txt": "SIL OPEN FONT LICENSE",
    "icons/feather-lucide-NOTICE.txt": "Cole Bemis",
}


def read(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def test_frontend_source_tree_carries_every_shipped_licence_text():
    """Dockerfile.frontend COPYs src/frontend/dist, and Vite copies public/
    verbatim into dist/ — so a licence text that is absent from
    public/licenses/ is a licence text the customer never receives.

    Regenerate with: cd src/frontend && node scripts/gen-licenses.mjs
    (it also runs automatically as npm's `prebuild`)."""
    for rel, needle in SHIPPED_LICENCE_FILES.items():
        path = os.path.join(PUBLIC_LICENSES, rel)
        assert os.path.isfile(path), (
            f"src/frontend/public/licenses/{rel} is missing — the frontend image "
            f"would ship without it. Run `node scripts/gen-licenses.mjs` in src/frontend.")
        body = read(path)
        assert needle in body, (
            f"public/licenses/{rel} does not contain {needle!r} — it is not the "
            f"licence text it claims to be")
        assert len(body) > 200, f"public/licenses/{rel} is suspiciously short"


def test_shipped_notices_match_the_generated_inventory():
    """The copy served at /licenses/ must be the SAME file the audit generates.
    A stale copy is attribution for a component set we no longer ship."""
    assert read(os.path.join(PUBLIC_LICENSES, "THIRD_PARTY_LICENSES.md")) == read(NOTICES), (
        "src/frontend/public/licenses/THIRD_PARTY_LICENSES.md has drifted from "
        "docs/THIRD_PARTY_LICENSES.md — re-run `node scripts/gen-licenses.mjs`")


def test_licence_page_links_to_every_licence_text():
    """/licenses/ is the page a customer actually opens; every text we ship
    must be reachable from it (and the page must stay CSP-safe: the SPA's
    Content-Security-Policy is `script-src 'self'` with no inline allowance)."""
    page = read(os.path.join(PUBLIC_LICENSES, "index.html"))
    for rel in SHIPPED_LICENCE_FILES:
        if rel == "index.html":
            continue
        assert f'href="{rel}"' in page, f"/licenses/ does not link to {rel}"
    assert "<script" not in page.lower(), (
        "the licences page must contain no script — the SPA CSP would block it")


def test_frontend_build_cannot_skip_the_notice_generation():
    """A notice that only ships when someone remembers to regenerate it is the
    failure mode this closes. `prebuild` runs on every `npm run build`."""
    pkg = json.loads(read(os.path.join(FRONTEND, "package.json")))
    assert pkg["scripts"].get("prebuild") == "node scripts/gen-licenses.mjs", (
        "src/frontend/package.json must run scripts/gen-licenses.mjs as `prebuild` "
        "so the shipped notices are regenerated by every build")


def test_frontend_dist_carries_the_notices_when_it_has_been_built():
    """dist/ is gitignored, so this only runs where a build has happened — but
    where it has, the built output is what the image bakes, so it must carry
    the notices Vite was supposed to copy across."""
    dist = os.path.join(FRONTEND, "dist")
    if not os.path.isdir(dist):
        pytest.skip("src/frontend/dist not built in this checkout")
    for rel in SHIPPED_LICENCE_FILES:
        assert os.path.isfile(os.path.join(dist, "licenses", rel)), (
            f"dist/licenses/{rel} missing from a built frontend — rebuild with "
            f"`npm run build` (its prebuild step generates them)")


def test_the_ui_offers_a_way_to_reach_the_notices():
    """Shipping the files is half the obligation; a recipient has to be able to
    find them. Both account menus (v1 topbar, v2 rail) link to the page."""
    for rel in ("src/components/TopBar.tsx", "src/components/IconRail.tsx"):
        body = read(os.path.join(FRONTEND, rel))
        assert 'href="/licenses/"' in body and "Third-party licences" in body, (
            f"{rel} has no 'Third-party licences' link — the notices ship but "
            f"nothing in the product points at them")


def test_frontend_nginx_actually_serves_the_notices():
    """Shipping the files into the image is not enough: the SPA's history
    fallback (`try_files $uri /index.html`, no `$uri/` branch) cannot resolve a
    directory request, so /licenses/ needs its own location — placed BEFORE
    `location /`, since the longer prefix wins."""
    conf = read(os.path.join(ROOT, "deployment", "docker", "frontend", "default.conf"))
    assert "location /licenses/ {" in conf, (
        "the SPA nginx has no /licenses/ location — the notices would be shipped "
        "but unreachable")
    assert conf.index("location /licenses/ {") < conf.index("location / {"), (
        "location /licenses/ must precede the SPA fallback location")
    assert "default_type text/plain" in conf, (
        "the .md/.txt licence texts need a readable content type; nginx would "
        "otherwise offer .md as a binary download")


def test_correlation_image_ships_its_python_notices():
    """certifi is MPL-2.0 (audit §2.4): the image's recipient must get the
    notice and the source pointer."""
    body = read(os.path.join(ROOT, "deployment", "docker", "Dockerfile.correlation"))
    assert "/app/licenses/" in body and "THIRD_PARTY_LICENSES.md" in body, (
        "Dockerfile.correlation must COPY the generated notices into /app/licenses")


def test_frontend_image_ships_the_generated_notices_even_with_a_stale_dist():
    body = read(os.path.join(ROOT, "deployment", "docker", "Dockerfile.frontend"))
    assert "docs/THIRD_PARTY_LICENSES.md" in body and "/licenses/" in body, (
        "Dockerfile.frontend must COPY docs/THIRD_PARTY_LICENSES.md into the "
        "served /licenses/ path")


# ── the installer bundle ─────────────────────────────────────────────────────

def test_installer_no_longer_hand_writes_the_bundle_notice():
    """The heredoc that used to build LICENSES.md listed zero libraries and
    misstated syslog-ng as GPL-3.0 (audit §2.5). It must stay gone."""
    body = read(INSTALLER)
    assert "syslog-ng | syslog receiver | GPL-3.0" not in body, (
        "the hand-written LICENSES.md heredoc is back — it misstates syslog-ng "
        "(LGPL-2.1-or-later core / GPL-2.0-or-later modules, no OpenSSL exception)")
    assert "license-audit.py\" --notices" in body and "license-audit.py\" --check" in body, (
        "make-installer.sh must regenerate the notices AND gate them before "
        "writing the bundle's LICENSES.md")


def test_installer_licences_dry_run_produces_a_complete_notice(tmp_path):
    """`make-installer.sh --licenses-only` is the dry run: it regenerates the
    notices, fails if the licence gate is not green, and writes the bundle's
    LICENSES.md — no Docker, no npm, no archives. Everything the old
    hand-written file got wrong or omitted must appear in the result."""
    before = read(NOTICES)
    proc = subprocess.run(
        ["bash", INSTALLER, "--licenses-only", "--out", str(tmp_path)],
        cwd=ROOT, capture_output=True, text=True, timeout=300, check=False,
    )
    assert proc.returncode == 0, f"--licenses-only failed:\n{proc.stdout}\n{proc.stderr}"
    assert read(NOTICES) == before, (
        "the dry run changed docs/THIRD_PARTY_LICENSES.md — the checked-in "
        "notices file was stale; regenerate and commit it")

    bundles = list(tmp_path.glob("correlix-*/LICENSES.md"))
    assert len(bundles) == 1, f"expected one bundle LICENSES.md, got {bundles}"
    text = bundles[0].read_text(encoding="utf-8")

    # Libraries — the whole category the old file omitted.
    for library in ("elkjs", "certifi", "@fontsource/inter", "github.com/jackc/pgx",
                    "golang.org/x/crypto", "react"):
        assert library in text, f"bundle LICENSES.md omits {library}"
    # Images the old file forgot, now that `sso` is in BASE_PROFILES.
    for image in ("keycloak", "kafka-exporter", "curl"):
        assert image in text.lower(), f"bundle LICENSES.md omits {image}"
    # syslog-ng stated correctly, and the source offer that GPL/AGPL/MPL/EPL need.
    assert "LGPL-2.1-or-later" in text and "GPL-2.0-or-later" in text, (
        "bundle LICENSES.md must state syslog-ng's real split licence")
    assert "NO OpenSSL linking exception" in text, (
        "bundle LICENSES.md must record that syslog-ng has no OpenSSL exception")
    assert "Written offer for Corresponding Source" in text
    # The removed components must still be declared removed.
    for gone in ("Redis", "Redpanda", "Prometheus"):
        assert gone in text


# ── NOTICE, Icon.tsx and the facts file ──────────────────────────────────────

def test_notice_carries_the_four_missing_attributions():
    """audit §2: elkjs, the OFL fonts, Feather/Lucide and certifi were all
    absent from NOTICE."""
    text = read(NOTICE_FILE)
    for name in ("elkjs", "Feather", "Lucide", "certifi"):
        assert name in text, f"NOTICE does not attribute {name}"
    for font in ("Inter", "IBM Plex Mono", "Space Grotesk", "Manrope"):
        assert font in text, f"NOTICE does not attribute the {font} font"
    for licence in ("Eclipse Public License", "SIL Open Font License",
                    "MIT License", "ISC License", "Mozilla Public License"):
        assert licence in text, f"NOTICE does not name {licence}"


def test_notice_points_at_the_file_that_actually_exists():
    """The NetClaw attribution referenced src/backend/verify_modules.go, which
    moved during package decomposition. Attribution that points at a missing
    file is attribution nobody can check."""
    text = read(NOTICE_FILE)
    assert "src/backend/verify_modules.go" not in text, "stale pre-decomposition path"
    assert "src/backend/internal/verify/modules.go" in text
    assert os.path.isfile(os.path.join(ROOT, "src/backend/internal/verify/modules.go"))


def test_icon_component_carries_its_feather_and_lucide_notices():
    """Icon.tsx is minified into the shipped bundle, so MIT/ISC notice
    retention applies to it directly (audit §2.3)."""
    text = read(ICON_TSX)
    for needed in ("Cole Bemis", "MIT License", "ISC License",
                   "feathericons/feather", "lucide-icons/lucide",
                   "Permission is hereby granted",
                   "Permission to use, copy, modify, and/or distribute"):
        assert needed in text, f"Icon.tsx header is missing {needed!r}"
    # Per-icon provenance for the glyphs the audit verified as verbatim.
    assert text.count("upstream:") >= 15, (
        "Icon.tsx should record per-icon provenance for the ~20 glyphs the audit "
        "identified as verbatim Feather/Lucide path data")
    # `Feather \`activity\`` is deliberately NOT in this list. It was the
    # provenance of the unused `logo` entry, which nothing rendered (the top bar
    # shows the BLOGO5 artwork and the favicon is the original network-eye SVG);
    # the entry was deleted on 2026-09-04, so requiring its attribution would be
    # requiring credit for path data we no longer ship. See the correction note
    # at the top of docs/security/LICENSE_AUDIT_2026-09-03.md.
    assert "Feather `activity`" not in text, (
        "the `logo`/activity path data is back in Icon.tsx — if that is "
        "deliberate, restore its provenance comment and re-add it here")
    for glyph in ("Feather `shield`", "Feather `compass`", "Feather `sliders`",
                  "Feather `log-out`", "Lucide `check`", "Lucide `mail`"):
        assert glyph in text, f"Icon.tsx does not record provenance for {glyph}"


def test_unreferenced_vendor_marks_were_deleted():
    """audit housekeeping: the Jira/ServiceNow marks had no terms recorded and
    zero references, and still shipped in the source tarball."""
    for rel in ("src/frontend/src/assets/connectors/jira.svg",
                "src/frontend/src/assets/connectors/servicenow.svg"):
        assert not os.path.exists(os.path.join(ROOT, rel)), f"{rel} is back"
    data = license_audit.load_data()
    assert "connector-marks" not in data["vendored"], (
        "the connector-marks vendored entry must go with the files it tracked")


def test_closed_findings_record_their_evidence():
    """A finding flipped to FIXED or DECIDED without evidence is a finding
    nobody can re-verify. OPEN ones still need an owner decision and are printed
    by every audit run instead."""
    data = license_audit.load_data()
    for name, exc in data.get("exceptions", {}).items():
        status = str(exc.get("status", "")).upper()
        if status == "FIXED":
            assert exc.get("evidence"), (
                f"exception '{name}' is FIXED but records no evidence path")
        elif status == "DECIDED":
            for field in ("decided", "rationale", "evidence"):
                assert exc.get(field), (
                    f"exception '{name}' is DECIDED but records no `{field}`. An "
                    f"owner decision that does not say WHAT was decided, WHY, and "
                    f"WHERE to check it is indistinguishable from a rubber stamp.")
            assert "DECIDED" in str(exc.get("owner_decision", "")), (
                f"exception '{name}' has status DECIDED but its owner_decision "
                f"text still reads as pending")
            assert "REQUIRED" not in str(exc.get("owner_decision", "")).split(".")[0], (
                f"exception '{name}' is DECIDED but its owner_decision still "
                f"opens by demanding a decision")
        elif status.startswith("OPEN"):
            assert "REQUIRED" in str(exc.get("owner_decision", "")), (
                f"exception '{name}' is OPEN but names no owner decision")


def test_an_open_finding_is_printed_even_when_it_matches_nothing():
    """The silence bug, guarded.

    `open_findings()` used to skip any exception whose name matched no
    inventoried component. `busybox` is exactly that shape — the inventory is
    built from image REFERENCES in compose files and Dockerfiles, and busybox is
    a base LAYER inside other images, so it never appeared. Combined with its
    missing `status`, an OPEN owner question was invisible for months. An
    unmatched OPEN finding must now print, labelled."""
    data = license_audit.load_data()
    comps = license_audit.build_inventory(data)
    present = {c.name for c in comps} | {c.key for c in comps}
    unmatched_open = [n for n, e in data.get("exceptions", {}).items()
                      if str(e.get("status", "")).upper().startswith("OPEN")
                      and n not in present]
    findings = license_audit.open_findings(comps, data)
    for name in unmatched_open:
        assert any(name in f for f in findings), (
            f"OPEN exception '{name}' matches no inventoried component and is "
            f"not printed — it is invisible, which is how it rotted before")
        assert any(name in f and "NOT MATCHED" in f for f in findings), (
            f"'{name}' is printed but not labelled as unmatched; a reader must "
            f"be able to tell 'we ship this and it is unresolved' from 'the "
            f"inventory cannot see this at all'")


def test_every_exception_declares_a_status():
    """A missing `status` is invisible, not benign.

    open_findings() only prints entries whose status starts with OPEN, so an
    exception with NO status at all is neither closed nor reported — which is
    how `busybox` sat with an owner_decision reading 'REQUIRED' that no audit
    run ever printed. Every exception must say where it stands."""
    data = license_audit.load_data()
    comps = license_audit.build_inventory(data)
    present = {c.name for c in comps} | {c.key for c in comps}
    allowed = {"OPEN", "FIXED", "DECIDED", "ACCEPTED"}
    for name, exc in data.get("exceptions", {}).items():
        if name not in present:
            continue
        status = str(exc.get("status", "")).upper()
        assert status in allowed, (
            f"exception '{name}' has status {status!r}; expected one of "
            f"{sorted(allowed)}. An exception with no status is never printed "
            f"by the audit and never counted as closed.")


# ── the six owner decisions of 2026-09-04 (audit §4 D1–D6) ──────────────────

def test_the_six_owner_decisions_are_recorded():
    """D1–D6 were the audit's open owner calls. Each is now DECIDED, and this
    asserts the record exists rather than that someone remembers making it."""
    data = license_audit.load_data()
    exc = data["exceptions"]
    expected = {
        "grafana/grafana": "keep",                     # D1
        "balabit/syslog-ng": "mirror-source-per-release",  # D2
        "cisco-mib-extracts": "replace-with-ietf-rfc",  # D3
        "arista-mibs": "fetch-at-build-time",           # D4
        "cloud-vendor-marks": "replace-with-original-glyphs",  # D5
        "quay.io/keycloak/keycloak": "accept-ubi-eula",  # D6
        "gotenberg/gotenberg": "never-ship",            # D6, second half
    }
    for name, decided in expected.items():
        assert name in exc, f"exception '{name}' has disappeared from license-data.json"
        assert str(exc[name].get("status", "")).upper() == "DECIDED", (
            f"'{name}' is one of the 2026-09-04 owner decisions and must be DECIDED, "
            f"not {exc[name].get('status')!r}")
        assert exc[name].get("decided") == decided, (
            f"'{name}' records decided={exc[name].get('decided')!r}, expected {decided!r}")


def test_grafana_ui_is_not_rewritten_by_the_proxy():
    """D1 keeps Grafana on the express basis that it ships UNMODIFIED. The nginx
    /grafana/ route used to `sub_filter` a stylesheet into Grafana's HTML that
    repainted it AND hid the Grafana logo. Injecting markup into the bytes an
    AGPL program serves to a network user is exactly what the 'unmodified'
    claim cannot survive, and stripping the mark is independently contrary to
    Grafana Labs' trademark policy. If this test fails, either the injection is
    back or D1 has to be re-decided."""
    for conf in ("default.conf", "default-mtls.conf"):
        body = read(os.path.join(ROOT, "deployment", "docker", "nginx", conf))
        start = body.index("location /grafana/ {")
        end = body.index("location ", start + 1)
        # Comments in this block deliberately NAME sub_filter (the do-not-
        # reintroduce note); only live directives count.
        live = "\n".join(ln for ln in body[start:end].splitlines()
                         if not ln.lstrip().startswith("#"))
        for banned, why in (
            ("sub_filter", "rewrites Grafana's response body"),
            ("grafana_typelogo", "hides Grafana's branding"),
            ("sidemenu__logo", "hides Grafana's branding"),
            ('Accept-Encoding ""',
             ("strips upstream compression, which is only ever needed in order "
              "to rewrite the body")),
        ):
            assert banned not in live, (
                f"nginx/{conf} {why} again ({banned!r} is a live directive in the "
                f"/grafana/ block) — that breaks the 'unmodified' basis of "
                f"licence-audit decision D1")


def test_grafana_ships_only_in_the_optional_addon_pack():
    """The other half of D1: 'optional' has to be true of the build, not just of
    the prose. Grafana must be profile-gated and its profile must not be in the
    base bundle's profile set."""
    compose = read(os.path.join(ROOT, "deployment", "docker", "docker-compose.yml"))
    idx = compose.index("\n  grafana:\n")
    block = compose[idx:idx + 2000]
    assert 'profiles: ["self-monitoring"]' in block, (
        "the grafana service is no longer gated behind the self-monitoring profile")
    installer = read(INSTALLER)
    base = next(ln for ln in installer.splitlines() if ln.startswith("BASE_PROFILES="))
    assert "self-monitoring" not in base, (
        "self-monitoring joined BASE_PROFILES — Grafana (AGPL-3.0) would ship in "
        "the CORE bundle, which is not what decision D1 ratified")


def test_no_correlix_image_is_built_from_grafana_or_syslog_ng():
    """'Unmodified upstream container' means no Dockerfile of ours uses one as a
    base. A patched image would move both D1 and D2 onto entirely different
    ground."""
    hits = []
    for base, dirs, files in os.walk(ROOT):
        dirs[:] = [d for d in dirs if d not in
                   ("node_modules", ".git", "data", "dist", "vendor", "build")]
        for fn in files:
            if not fn.startswith("Dockerfile"):
                continue
            path = os.path.join(base, fn)
            for line in read(path).splitlines():
                if line.strip().upper().startswith("FROM") and (
                        "grafana" in line.lower() or "syslog-ng" in line.lower()):
                    hits.append(f"{os.path.relpath(path, ROOT)}: {line.strip()}")
    assert not hits, ("a Correlix image is built FROM a copyleft upstream image, "
                      "which would make it a modified version: " + "; ".join(hits))


def test_gotenberg_can_no_longer_reach_a_bundle():
    """D6's second half. This was a written rule; a rule that is not a build
    failure is a rule that lasts until the next person adds a profile."""
    body = read(INSTALLER)
    assert body.count("gotenberg") >= 2, (
        "make-installer.sh has no gotenberg guard — the pdf profile bundles "
        "PDFtk (GPL-2.0+), a proprietary Microsoft font EULA and Google Chrome")
    base = next(ln for ln in body.splitlines() if ln.startswith("BASE_PROFILES="))
    assert "pdf" not in base
    addons = next(ln for ln in body.splitlines() if ln.startswith("ADDONS="))
    assert "pdf" not in addons


def test_notices_state_the_agpl_and_ubi_postures():
    """D1 and D6 are discharged by what the customer RECEIVES, not by what the
    data file says. Both must reach the generated notices."""
    text = read(NOTICES)
    assert "Affero" in text and "AGPL-3.0" in text, (
        "the notices do not state Grafana's AGPL posture")
    assert "add-on" in text.lower() and "unmodified" in text.lower()
    assert "Universal Base Image" in text and "EULA" in text, (
        "the notices do not state the Red Hat UBI EULA that Keycloak ships under")
    assert "ACCEPTS" in text, (
        "the UBI section must state the acceptance, not merely link the terms")


def test_notice_file_states_the_agpl_and_ubi_postures():
    """NOTICE travels with the source tarball, which is a distribution unit of
    its own."""
    text = read(NOTICE_FILE)
    for needed in ("Affero", "Universal Base Image", "source-offer/syslog-ng"):
        assert needed in text, f"NOTICE does not record {needed!r}"


def test_the_five_attribution_findings_are_closed():
    """The audit's five attribution obligations (§2) are fixes, not decisions.
    Each is recorded FIXED with where the notice now ships."""
    data = license_audit.load_data()
    exc = data["exceptions"]
    for name in ("elkjs", "certifi", "@fontsource/inter", "@fontsource/ibm-plex-mono",
                 "@fontsource/space-grotesk", "@fontsource-variable/manrope",
                 "connector-marks"):
        assert str(exc[name].get("status", "")).upper() == "FIXED", (
            f"'{name}' is one of the audit's attribution findings and should be FIXED")


def test_go_module_allowlist_version_matches_go_mod():
    """CLAUDE.md §6 is the dependency allowlist; a version recorded there that
    go.mod contradicts is exactly the drift the audit flagged."""
    claude_md = os.path.join(os.path.dirname(ROOT), "CLAUDE.md")
    if not os.path.isfile(claude_md):
        pytest.skip("CLAUDE.md not present beside the project directory")
    guidance = read(claude_md)
    gomod = read(os.path.join(ROOT, "src", "backend", "go.mod"))
    for module in ("golang.org/x/crypto", "golang.org/x/net"):
        pinned = [ln.split()[1] for ln in gomod.splitlines()
                  if ln.strip().startswith(module + " ")]
        assert pinned, f"{module} not found in go.mod"
        assert f"`{pinned[0]}` in `go.mod`" in guidance, (
            f"CLAUDE.md §6 does not record {module} as pinned {pinned[0]}, which "
            f"is what go.mod says")


# ── the two mechanisms that made a finding invisible, guarded synthetically ──
#
# Both tests below inject their own condition instead of asserting over whatever
# license-data.json happens to hold today. That distinction is the whole point:
# a test that reads the real data passes VACUOUSLY the day the real data no
# longer exercises the mechanism, which is precisely how `busybox` sat OPEN and
# unprinted for months. These fail if the mechanism regresses, whatever the data
# says.

def test_audit_hard_fails_on_a_vendored_path_that_no_longer_exists():
    """Attribution must track the content it covers, and the AUDIT — not just a
    test — has to be the thing that notices.

    `collect_vendored()` existence-checks every declared path. If that check
    were ever relaxed, a deleted or relocated file would take its attribution
    with it silently: we would either credit something we no longer ship, or
    (worse) ship something we no longer credit. This injects a vendored entry
    pointing at a path that cannot exist and asserts the audit refuses to build
    an inventory at all, naming the offending path."""
    data = license_audit.load_data()
    poisoned = dict(data)
    poisoned["vendored"] = dict(data.get("vendored", {}))
    poisoned["vendored"]["ghost-marks"] = {
        "license": "MIT",
        "paths": ["src/frontend/src/assets/cloud/aws.svg"],  # deleted under D5
        "usage": "bundled-runtime",
        "unit": "frontend image (netops-frontend) — SPA bundle",
        "version": "in-tree",
    }
    with pytest.raises(license_audit.AuditError) as excinfo:
        license_audit.collect_vendored(poisoned)
    message = str(excinfo.value)
    assert "ghost-marks" in message, "the failure does not name the entry at fault"
    assert "src/frontend/src/assets/cloud/aws.svg" in message, (
        "the failure does not name the missing path, so nobody can fix it")

    # And the same failure must reach the command line as a non-zero exit, not
    # be caught and downgraded to a warning somewhere up the call stack.
    assert license_audit.AuditError is not Exception
    with pytest.raises(license_audit.AuditError):
        license_audit.build_inventory(poisoned)


def test_no_stale_cloud_asset_path_is_declared_anywhere():
    """D5 deleted `src/frontend/src/assets/cloud/*.svg`. A leftover reference to
    one in a `paths` list would hard-fail the audit (the test above proves it
    would); this asserts the data file is clean of them, so the gate stays green
    for the right reason rather than by luck."""
    data = license_audit.load_data()
    for section in ("vendored", "exceptions"):
        for name, entry in data.get(section, {}).items():
            for key in ("paths", "files"):
                for rel in entry.get(key, []) or []:
                    assert not rel.startswith("src/frontend/src/assets/cloud/"), (
                        f"{section} entry '{name}' still declares {rel}, which D5 "
                        f"deleted — the audit would hard-fail on it")


def test_open_findings_prints_an_unmatched_exception_it_was_handed():
    """The silence bug, guarded by injection rather than by observation.

    `test_an_open_finding_is_printed_even_when_it_matches_nothing` asserts over
    the REAL exception register, so it only bites while some real OPEN exception
    happens to match nothing. The day `busybox` is decided, that test goes green
    without testing anything. This one hands `open_findings()` a synthetic
    unmatched OPEN exception and demands it be printed and labelled — so a
    regression to the old `if name not in present: continue` behaviour fails
    here regardless of what the register holds."""
    comps = [license_audit.Component(
        key="npm:test:real", name="a-real-component", version="1.0.0",
        license="MIT", ecosystem="npm", usage="bundled-runtime",
        unit="frontend image", source="test")]
    data = {"exceptions": {
        "phantom-layer": {
            "license": "GPL-2.0-only",
            "status": "OPEN",
            "owner_decision": "REQUIRED — synthetic finding for the regression test",
        },
        "a-real-component": {
            "license": "MIT",
            "status": "OPEN",
            "owner_decision": "REQUIRED — synthetic matched finding",
        },
        "already-settled": {
            "license": "MIT",
            "status": "DECIDED",
            "owner_decision": "DECIDED — must not be printed",
        },
    }}
    findings = license_audit.open_findings(comps, data)

    unmatched = [f for f in findings if f.startswith("phantom-layer")]
    assert unmatched, (
        "an OPEN exception matching no inventoried component was NOT printed — "
        "this is the exact regression that hid `busybox` for months")
    assert "NOT MATCHED by any inventoried component" in unmatched[0], (
        "the unmatched finding is printed but not labelled; a reader cannot "
        "tell 'we ship this and it is unresolved' from 'the inventory cannot "
        "see this at all'")

    matched = [f for f in findings if f.startswith("a-real-component")]
    assert matched, "a matched OPEN exception must still be printed"
    assert "NOT MATCHED" not in matched[0], (
        "a finding that DOES match an inventoried component must not be "
        "labelled unmatched — the label would then mean nothing")

    assert not any(f.startswith("already-settled") for f in findings), (
        "a DECIDED exception must not be printed as awaiting a decision")


def test_the_only_open_findings_are_the_two_tracker_rowed_owner_decisions():
    """The acknowledged list is a queue, not a wastebasket.

    Every entry on it must be a question only the owner can answer, and must be
    tracked somewhere a human actually looks. Today that is exactly two:
    `busybox` (tracker 238) and `connector-vendor-marks` (tracker 239). If this
    fails because a THIRD entry appeared, the entry is either an engineering fix
    someone deferred by labelling it a decision, or a real new owner question
    that needs a tracker row and a §4a paragraph — not a silent addition."""
    data = license_audit.load_data()
    open_names = sorted(n for n, e in data.get("exceptions", {}).items()
                        if str(e.get("status", "")).upper().startswith("OPEN"))
    assert open_names == ["busybox", "connector-vendor-marks"], (
        f"the acknowledged-findings queue is {open_names}, expected "
        f"['busybox', 'connector-vendor-marks']. Add the tracker row and the "
        f"§4a entry, or close the finding — do not just extend this list.")

    audit_doc = read(os.path.join(ROOT, "docs", "security",
                                  "LICENSE_AUDIT_2026-09-03.md"))
    for name in open_names:
        assert name in audit_doc, (
            f"the audit prints '{name}' and points the reader at "
            f"docs/security/LICENSE_AUDIT_2026-09-03.md, which does not mention "
            f"it — the pointer leads nowhere")
    tracker = read(os.path.join(ROOT, "docs", "TRACKER.md"))
    for row in ("| 238 |", "| 239 |"):
        assert row in tracker, (
            f"tracker row {row.strip('| ')} is gone but its licence finding is "
            f"still OPEN — an owner decision with no tracker row is invisible")


# ── D6: the UBI EULA has to reach the customer, not just the data file ───────

UBI_EULA_URL = ("https://www.redhat.com/licenses/"
                "EULA_Red_Hat_Universal_Base_Image_English_20190422.pdf")


def test_the_ubi_eula_reaches_every_ship_set_surface():
    """D6 is discharged by DOCUMENTATION — it is the one decision with no code
    to it — so the documentation is the whole deliverable. Every surface a
    customer or their counsel could reasonably read must carry both halves: the
    pointer to the terms, and our explicit acceptance of them. A page that
    accepts without linking leaves the reader unable to check what was accepted;
    a page that links without accepting states an obligation and not its
    discharge."""
    surfaces = {
        "docs/THIRD_PARTY_LICENSES.md": NOTICES,
        "NOTICE": NOTICE_FILE,
        "docs-portal/docs/deploy/third-party-components.md": os.path.join(
            ROOT, "docs-portal", "docs", "deploy", "third-party-components.md"),
        "docs/RELEASE_NOTES_v0.9.0-rc1.md": os.path.join(
            ROOT, "docs", "RELEASE_NOTES_v0.9.0-rc1.md"),
        "docs/RELEASE_CHECKLIST.md": os.path.join(ROOT, "docs", "RELEASE_CHECKLIST.md"),
    }
    for label, path in surfaces.items():
        assert os.path.isfile(path), f"{label} is missing"
        text = read(path)
        assert "Universal Base Image" in text, (
            f"{label} does not name the Red Hat Universal Base Image that "
            f"Keycloak ships on")
        assert ("redhat.com/licenses/EULA_Red_Hat_Universal_Base_Image" in text
                or "red-hat-end-user-license-agreements" in text), (
            f"{label} states the UBI posture but carries no pointer to the "
            f"terms — a reader cannot check what was accepted")
        lowered = text.lower()
        assert "accept" in lowered, (
            f"{label} links the UBI EULA but never states that Correlix "
            f"ACCEPTS it — an obligation named is not an obligation discharged")


def test_the_ubi_eula_url_is_the_canonical_one_in_the_binding_surfaces():
    """The notices and NOTICE travel with the artifact and are the ones a
    dispute would be read against. They must carry the exact agreement URL, not
    a landing page that could later reorganise."""
    for label, path in (("docs/THIRD_PARTY_LICENSES.md", NOTICES),
                        ("NOTICE", NOTICE_FILE),
                        ("docs/RELEASE_NOTES_v0.9.0-rc1.md",
                         os.path.join(ROOT, "docs", "RELEASE_NOTES_v0.9.0-rc1.md"))):
        assert UBI_EULA_URL in read(path), (
            f"{label} does not carry the canonical UBI EULA URL {UBI_EULA_URL}")


def test_the_ubi_acceptance_is_generated_from_the_data_file():
    """The notices are GENERATED. If the acceptance lived only in the checked-in
    Markdown, the next `--notices` run would delete it."""
    data = license_audit.load_data()
    exc = data["exceptions"]["quay.io/keycloak/keycloak"]
    assert UBI_EULA_URL in str(exc.get("obligation", "")), (
        "the keycloak exception does not record the EULA URL, so the generated "
        "notices cannot be traced back to a reviewed fact")
    assert "ACCEPT" in str(exc.get("owner_decision", "")).upper()

    texts = json.dumps(data.get("license_texts", data))
    assert UBI_EULA_URL in texts, (
        "the UBI EULA URL is not anywhere in license-data.json, so the section "
        "in docs/THIRD_PARTY_LICENSES.md is hand-written and will be lost the "
        "next time the notices are regenerated")


# ── D1: the AGPL add-on posture must be stated where it is received ──────────

def test_the_agpl_addon_posture_is_complete_in_the_notices():
    """D1's ratification rests on four claims, and a customer's counsel will
    look for all four in one place: WHICH licence, WHERE to read it, that the
    binary is UNMODIFIED, and that it is an OPTIONAL ADD-ON rather than part of
    the appliance. Any one of them missing turns a defensible posture into an
    assertion."""
    text = read(NOTICES)
    section = text[text.index("### GNU Affero General Public License 3.0"):]
    section = section[:section.index("\n### ", 1)]
    assert "AGPL-3.0-only" in section
    assert "https://www.gnu.org/licenses/agpl-3.0.html" in section, (
        "the notices do not say where the full AGPL-3.0 text is")
    assert "https://github.com/grafana/grafana" in section and "v11.2.0" in section, (
        "the notices do not point at the corresponding source for the version "
        "shipped")
    assert "UNMODIFIED" in section.upper()
    assert "add-on" in section.lower() and "optional" in section.lower(), (
        "the notices do not state that Grafana reaches a deployment only "
        "through the optional self-monitoring add-on pack")
    assert "self-monitoring" in section, (
        "the notices do not name the profile an operator must enable")


def test_the_copyleft_images_are_pinned_by_digest():
    """`test_no_correlix_image_is_built_from_grafana_or_syslog_ng` proves we do
    not REBUILD them; this proves we can prove WHICH bytes we shipped.

    'The stock upstream image' and 'the corresponding source for the exact
    version shipped' are both claims about a specific artifact. A floating tag
    can be re-pushed under the same name, at which point neither claim is
    checkable — and for syslog-ng it would silently invalidate the mirrored
    tarball, which is a compliance failure that looks like compliance."""
    compose = read(os.path.join(ROOT, "deployment", "docker", "docker-compose.yml"))
    for image, decision in (("grafana/grafana", "D1 (AGPL, unmodified)"),
                            ("balabit/syslog-ng", "D2 (GPL corresponding source)")):
        m = re.search(rf"image:\s*({re.escape(image)}:[^\s]+)", compose)
        assert m, f"no pinned {image} image found in docker-compose.yml"
        assert "@sha256:" in m.group(1), (
            f"{image} is pinned as {m.group(1)} with no digest — {decision} "
            f"rests on being able to say exactly which image was distributed")


def test_the_self_monitoring_addon_is_cut_as_its_own_separate_archive():
    """D1's 'optional add-on pack' has to be a real, separate artifact.

    `test_grafana_ships_only_in_the_optional_addon_pack` proves the profile is
    not in BASE_PROFILES. This proves the other half: the pack is actually cut,
    and its image list is the profile's images MINUS the base set — so Grafana
    lands in `correlix-addon-self-monitoring-*.tar.zst` and in nothing else. If
    the subtraction ever went away the AGPL image would be duplicated into the
    core archive while the prose still called it optional."""
    installer = read(INSTALLER)
    addons = next(ln for ln in installer.splitlines() if ln.startswith("ADDONS="))
    assert "self-monitoring:self-monitoring" in addons, (
        "the self-monitoring add-on pack is no longer cut — Grafana would either "
        "vanish from the ship set or fall back into the core bundle")
    assert "correlix-addon-$name-$VERSION.tar.zst" in installer, (
        "add-on packs are no longer written as their own image archive")
    assert "comm -13" in installer, (
        "the add-on pack no longer subtracts the base image set, so an add-on "
        "image could also be baked into the core archive")
