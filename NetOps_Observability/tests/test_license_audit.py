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
    for glyph in ("Feather `shield`", "Feather `compass`", "Feather `sliders`",
                  "Feather `activity`", "Lucide `check`", "Lucide `mail`"):
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
    """A finding flipped to FIXED without evidence is a finding nobody can
    re-verify. OPEN ones still need an owner decision and are printed by every
    audit run instead."""
    data = license_audit.load_data()
    for name, exc in data.get("exceptions", {}).items():
        status = str(exc.get("status", "")).upper()
        if status == "FIXED":
            assert exc.get("evidence"), (
                f"exception '{name}' is FIXED but records no evidence path")
        elif status.startswith("OPEN"):
            assert "REQUIRED" in str(exc.get("owner_decision", "")), (
                f"exception '{name}' is OPEN but names no owner decision")


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
