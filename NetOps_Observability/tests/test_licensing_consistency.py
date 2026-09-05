"""Licensing consistency — the gate that stops the open-core story from drifting.

Correlix adopted Apache-2.0 open core with separately licensed commercial add-ons
on 2026-09-04. That decision is stated in nine places: two LICENSE files, two
generated directory maps, the README, the NOTICE, the licences page the product
serves at /licenses/, the customer documentation, and the header of the generated
third-party notices. It is also encoded in every container image's OCI metadata
and in the installer bundle.

Nine copies of one fact drift. When they do, the failure is not cosmetic: a
customer reads one of them and relies on it. This file asserts that they all say
the SAME thing, and that the machine-readable policy behind them still describes
the tree as it actually is.

The load-bearing assertion is the directory table. The real top-level directory
list is computed FROM THE FILESYSTEM at test time and compared against the map.
A directory that nobody classified fails this test. That is the point: the
failure mode being prevented is somebody adding a feature area and nobody ever
deciding whether it is open or commercial.

What is NOT asserted here, and why:

  * The Correlix Enterprise License TEXT. It does not exist yet
    (`LICENSES/Correlix-Enterprise.txt` is a placeholder). One test asserts the
    placeholder is still a placeholder, so that landing the real text fails
    loudly and forces this file to be updated rather than silently passing.
  * `docs/THIRD_PARTY_LICENSES.md` itself. It is generated on a different cadence
    from this change, so the assertion runs `render_notices()` and reads what the
    generator produces. A stale checked-in file is a regeneration problem, not a
    licensing-drift problem, and conflating them would make this suite lie.
  * Nothing about the bundle is skipped any more. `scripts/make-installer.sh`'s
    LICENSES.md footer stated the project's own code was "proprietary to
    Correlix"; under the open-core decision that was false, and it was false in
    the single most damaging place — the licence statement a paying customer
    receives with the artifact. It now carries the canonical sentence, and the
    bundle ships the texts that sentence points at (LICENSE, LICENSING.md,
    LICENSES/), which is asserted below rather than assumed.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

PROJ = Path(__file__).resolve().parents[1]
REPO = PROJ.parent
POLICY_PATH = PROJ / "licensing-policy.json"

# ── the canonical Apache-2.0 text ────────────────────────────────────────────
# sha256 of the UNMODIFIED canonical licence text, fetched 2026-09-04 from
#   https://www.apache.org/licenses/LICENSE-2.0.txt
# 11358 bytes, 202 lines, no trailing whitespace on any line, one terminating
# newline. It is the well-known digest of that document and is pinned here so a
# silent edit to our copy — a reflowed paragraph, a "helpfully" filled-in
# copyright placeholder, a CRLF conversion — fails instead of shipping.
#
# NORMALISATION: trailing whitespace is stripped per line and the file is forced
# to exactly one terminating newline before hashing. Nothing else is touched.
# The upstream text already satisfies both, so on an unmodified copy the
# normalisation is a no-op; it exists only so an editor that trims whitespace on
# save cannot fail this test for a reason that is not a licence change.
APACHE_2_0_SHA256 = "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30"

# The one sentence every surface must state, verbatim. Duplicated from
# licensing-policy.json on purpose: a test that reads its expectation from the
# thing under test asserts nothing.
CANONICAL_SENTENCE = (
    "Correlix core is licensed under the Apache License, Version 2.0. "
    "Commercial add-on modules are licensed under the Correlix Enterprise "
    "License (LicenseRef-Correlix-Enterprise) — see LICENSING.md."
)

CORE_ID = "Apache-2.0"
COMMERCIAL_ID = "LicenseRef-Correlix-Enterprise"


def normalise(text: str) -> str:
    """Strip per-line trailing whitespace; end with exactly one newline."""
    return "\n".join(line.rstrip() for line in text.split("\n")).rstrip("\n") + "\n"


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@pytest.fixture(scope="module")
def policy() -> dict:
    return json.loads(POLICY_PATH.read_text(encoding="utf-8"))


# ─────────────────────────────────────────────────────────────────────────────
# (a) the licence texts
# ─────────────────────────────────────────────────────────────────────────────

def test_apache_text_present_at_both_roots_and_matches_upstream():
    """LICENSES/Apache-2.0.txt is the real Apache-2.0, unmodified, at both roots.

    Unmodified matters. The appendix's `Copyright [yyyy] [name of copyright
    owner]` placeholder is part of the licence text; filling it in there is a
    common and wrong instinct. The copyright line belongs in LICENSE and NOTICE,
    which is where this repository puts it.
    """
    paths = [REPO / "LICENSES" / "Apache-2.0.txt", PROJ / "LICENSES" / "Apache-2.0.txt"]
    for path in paths:
        assert path.is_file(), f"{path} is missing"

    bodies = [p.read_text(encoding="utf-8") for p in paths]
    assert bodies[0] == bodies[1], (
        "the two copies of the Apache-2.0 text differ; they must be byte-identical"
    )
    digest = sha256(normalise(bodies[0]))
    assert digest == APACHE_2_0_SHA256, (
        f"LICENSES/Apache-2.0.txt does not match the canonical Apache-2.0 text\n"
        f"  expected sha256 {APACHE_2_0_SHA256}\n"
        f"  actual   sha256 {digest}\n"
        f"Restore it from https://www.apache.org/licenses/LICENSE-2.0.txt verbatim."
    )


def test_licence_notice_is_identical_at_both_roots_and_states_the_sentence():
    paths = [REPO / "LICENSE", PROJ / "LICENSE"]
    for path in paths:
        assert path.is_file(), f"{path} is missing"
    bodies = [p.read_text(encoding="utf-8") for p in paths]
    assert bodies[0] == bodies[1], "the two LICENSE files differ"
    assert CANONICAL_SENTENCE in bodies[0]
    # The default must be stated, and stated as OPEN. A reader who finds no
    # marking on a file has to be told what that means.
    assert "Apache-2.0" in bodies[0] and COMMERCIAL_ID in bodies[0]
    assert "LICENSES/Apache-2.0.txt" in bodies[0]
    assert "LICENSES/Correlix-Enterprise.txt" in bodies[0]


def test_enterprise_licence_text_is_still_an_undrafted_placeholder(policy):
    """A tripwire in both directions.

    Today `LICENSES/Correlix-Enterprise.txt` has no terms in it, and files are
    already marked with the identifier. That is a real, recorded release blocker,
    not an oversight. When counsel delivers the text, this test fails — which is
    exactly what should happen, because whoever lands it must then also flip the
    release gate expectation and re-read what this suite asserts.
    """
    blocker = next(b for b in policy["release_blockers"]["entries"]
                   if b["id"] == "enterprise-text-placeholder")
    for root in (REPO, PROJ):
        body = (root / blocker["file"]).read_text(encoding="utf-8")
        assert blocker["marker"] in body, (
            f"{blocker['file']} no longer carries the placeholder marker. If the real "
            f"Correlix Enterprise License has landed: delete this test, remove the "
            f"blocker from licensing-policy.json, and re-run "
            f"`python3 scripts/licensing-gate.py --release`."
        )
        # Line wrapping must not decide whether this passes, so compare on
        # whitespace-collapsed text.
        flat = " ".join(body.lower().split())
        assert ("not licensed to anyone" in flat
                or "no grant is made" in flat
                or "no licence is granted" in flat), (
            "the placeholder must say plainly that it grants nothing"
        )


# ─────────────────────────────────────────────────────────────────────────────
# (b) the directory map
# ─────────────────────────────────────────────────────────────────────────────

def excluded_names(policy: dict) -> set[str]:
    """Directory names never classified, derived from the policy.

    Each carries its own `why` in licensing-policy.json, so the exclusion list is
    self-documenting and reviewable rather than a bare tuple in a test file. Every
    entry is one of: generated output, third-party code under its own licence, or
    per-developer local state — never Correlix source.
    """
    entries = policy["excluded_paths"]["entries"]
    for entry in entries:
        assert entry.get("why", "").strip(), (
            f"exclusion {entry['name']!r} has no reason; every exclusion must justify itself"
        )
    return {e["name"] for e in entries}


def real_top_level_dirs(policy: dict) -> set[str]:
    skip = excluded_names(policy)
    return {p.name for p in PROJ.iterdir() if p.is_dir() and p.name not in skip}


def map_table_dirs(body: str) -> list[str]:
    """Directory names in the map's tables.

    Directories are written with a trailing slash inside backticks (`docs/`),
    files and identifiers are not, so this cannot accidentally collect a filename
    or an SPDX id. Only the FIRST column of a row is considered.
    """
    found = []
    for line in body.split("\n"):
        if not line.startswith("| `"):
            continue
        first = line.split("|")[1].strip()
        m = re.fullmatch(r"`([A-Za-z0-9_.\-]+)/`", first)
        if m:
            found.append(m.group(1))
    return found


def test_map_is_identical_at_both_roots():
    paths = [REPO / "LICENSING.md", PROJ / "LICENSING.md"]
    for path in paths:
        assert path.is_file(), f"{path} is missing"
    bodies = [p.read_text(encoding="utf-8") for p in paths]
    assert bodies[0] == bodies[1], "the two LICENSING.md files differ"
    assert CANONICAL_SENTENCE in bodies[0]


def test_map_lists_every_top_level_directory_exactly_once(policy):
    """The whole point of this suite.

    A new top-level directory that nobody classified must fail here, so that the
    open-or-commercial decision is made deliberately when the directory is
    created rather than assumed years later.
    """
    body = (PROJ / "LICENSING.md").read_text(encoding="utf-8")
    listed = map_table_dirs(body)
    # Only the project's own top-level table uses bare names; nested paths carry
    # slashes and are filtered out by the regex above.
    listed_top = [d for d in listed]
    real = real_top_level_dirs(policy)

    dupes = sorted({d for d in listed_top if listed_top.count(d) > 1})
    assert not dupes, f"LICENSING.md lists these directories more than once: {dupes}"

    missing = sorted(real - set(listed_top))
    assert not missing, (
        f"top-level directories with no entry in LICENSING.md: {missing}\n"
        f"Classify each in licensing-policy.json (project_top_level), then run:\n"
        f"  python3 scripts/gen-licensing-map.py --write"
    )

    extra = sorted(set(listed_top) - real)
    assert not extra, (
        f"LICENSING.md classifies directories that do not exist: {extra}\n"
        f"Remove them from licensing-policy.json and regenerate."
    )


def test_map_is_not_stale():
    """LICENSING.md is generated. A hand edit changes nothing that is enforced."""
    result = subprocess.run(
        [sys.executable, str(PROJ / "scripts" / "gen-licensing-map.py"), "--check"],
        capture_output=True, text=True, cwd=PROJ, check=False,
    )
    assert result.returncode == 0, (
        f"LICENSING.md is stale relative to licensing-policy.json\n"
        f"{result.stdout}\n{result.stderr}"
    )


def test_still_mixed_directories_are_named_with_their_tracker_row(policy):
    """Honesty requirement: a directory that mixes core and commercial code says so."""
    body = (PROJ / "LICENSING.md").read_text(encoding="utf-8")
    assert "## Still mixed" in body
    mixed = policy["mixed_directories"]
    assert mixed["entries"], "the mixed list is empty; if that is true, delete the section"
    for entry in mixed["entries"]:
        assert f"`{entry['path']}/`" in body, f"{entry['path']} is not named in the map"
        assert (PROJ / entry["path"]).is_dir(), f"{entry['path']} is not a directory"
    assert f"row {mixed['tracker_row']}" in body, (
        "the mixed section must point at the tracker row that owns the extraction"
    )


def test_nothing_is_gated_outside_the_owners_locked_commercial_set(policy):
    """No capability becomes commercial without an owner decision behind it."""
    locked = {
        ent["id"]
        for tier, ents in policy["locked_commercial_set"].items()
        if not tier.startswith("_")
        for ent in ents
    }
    for group in ("commercial_paths", "mixed_directories"):
        for entry in policy[group]["entries"]:
            assert entry["entitlement"] in locked, (
                f"{entry['path']} is gated on {entry['entitlement']!r}, which the owner "
                f"has not locked as commercial. Locked set: {sorted(locked)}"
            )


def test_isolation_is_never_commercial(policy):
    """A standing guarantee, asserted so a future change cannot quietly reverse it."""
    items = " ".join(policy["core_is_never_commercial"]["items"]).lower()
    assert "isolation" in items
    body = (PROJ / "LICENSING.md").read_text(encoding="utf-8")
    assert "Isolation is core and is never a paywall" in body
    # The isolation code itself must not be marked commercial anywhere.
    commercial = [e["path"] for e in policy["commercial_paths"]["entries"]]
    for path in commercial:
        assert "tenant" not in path.lower(), (
            f"{path} is marked commercial and looks like isolation code; isolation is a "
            f"safety property and stays Apache-2.0 in every edition"
        )


# ─────────────────────────────────────────────────────────────────────────────
# (c) NOTICE
# ─────────────────────────────────────────────────────────────────────────────

def test_notice_states_the_project_licence_and_points_at_the_map():
    body = (PROJ / "NOTICE").read_text(encoding="utf-8")
    assert CANONICAL_SENTENCE in body
    assert "LICENSING.md" in body
    assert "Apache-2.0" in body
    # The project-licence block must come BEFORE the third-party sections, so a
    # reader is not left inferring the product's own licence from its absence.
    licence_at = body.index(CANONICAL_SENTENCE)
    third_party_at = body.index("SNMP vendor device-profiles")
    assert licence_at < third_party_at, (
        "the project-licence block must be at the TOP of NOTICE, above the "
        "third-party attribution sections"
    )


# ─────────────────────────────────────────────────────────────────────────────
# (d) container images
# ─────────────────────────────────────────────────────────────────────────────

def discovered_dockerfiles(policy: dict) -> set[str]:
    skip = excluded_names(policy)
    found = set()
    for path in PROJ.rglob("Dockerfile*"):
        if any(part in skip for part in path.relative_to(PROJ).parts):
            continue
        if path.is_file():
            found.add(str(path.relative_to(PROJ)))
    return found


def test_every_dockerfile_is_classified(policy):
    """Discovery, not a hand-list: a new Dockerfile nobody classified fails."""
    ci = policy["container_images"]
    classified = {e["path"] for e in ci["ours"]} | {e["path"] for e in ci["third_party_repackage"]}
    found = discovered_dockerfiles(policy)
    unclassified = sorted(found - classified)
    assert not unclassified, (
        f"Dockerfiles not classified in licensing-policy.json: {unclassified}\n"
        f"Add each to container_images.ours (it builds a Correlix image) or "
        f"container_images.third_party_repackage (it only repackages upstream)."
    )
    ghosts = sorted(classified - found)
    assert not ghosts, f"classified Dockerfiles that do not exist: {ghosts}"


def test_correlix_images_declare_their_licence(policy):
    """Only OUR images. A third-party base image we merely FROM is not ours to
    label; stamping the Correlix licence onto a repackaged OpenSearch or Vector
    image would be a false claim about somebody else's software."""
    label = "org.opencontainers.image.licenses"
    for entry in policy["container_images"]["ours"]:
        body = (PROJ / entry["path"]).read_text(encoding="utf-8")
        expected = f'{label}="{entry["licence"]}"'
        assert expected in body, (
            f"{entry['path']} builds a Correlix image but does not set {expected}"
        )


def test_repackaged_images_are_not_falsely_labelled(policy):
    label = "org.opencontainers.image.licenses"
    for entry in policy["container_images"]["third_party_repackage"]:
        path = PROJ / entry["path"]
        if not path.is_file():
            continue
        assert label not in path.read_text(encoding="utf-8"), (
            f"{entry['path']} only repackages a third-party image; labelling it with a "
            f"Correlix licence would misstate the licence of software we did not write"
        )


# ─────────────────────────────────────────────────────────────────────────────
# (e) the licences page the product serves
# ─────────────────────────────────────────────────────────────────────────────

LICENCES_PAGE = PROJ / "src" / "frontend" / "public" / "licenses" / "index.html"
LICENCES_GENERATOR = PROJ / "src" / "frontend" / "scripts" / "gen-licenses.mjs"


def test_served_licences_page_states_the_project_licence():
    """/licenses/ answers "what may I do with Correlix itself", not only with its
    dependencies. The page is GENERATED: fix gen-licenses.mjs and re-run it,
    never the .html."""
    assert LICENCES_PAGE.is_file(), f"{LICENCES_PAGE} is missing — run gen-licenses.mjs"
    body = LICENCES_PAGE.read_text(encoding="utf-8")
    assert CANONICAL_SENTENCE in body, (
        "the served licences page does not state the project licence. Update "
        "src/frontend/scripts/gen-licenses.mjs, then run `node scripts/gen-licenses.mjs` "
        "in src/frontend. Do not hand-edit the generated HTML."
    )
    assert "GENERATED by src/frontend/scripts/gen-licenses.mjs" in body


def test_licences_page_generator_owns_the_sentence():
    """The sentence must come from the generator, not be inherited from the
    third-party markdown — otherwise the page loses it whenever the notices are
    regenerated from a source that does not carry it."""
    body = LICENCES_GENERATOR.read_text(encoding="utf-8")
    assert "PROJECT_LICENCE_SENTENCE" in body
    assert "Correlix core is licensed under the Apache License" in body


# ─────────────────────────────────────────────────────────────────────────────
# (f) README
# ─────────────────────────────────────────────────────────────────────────────

def test_readme_licence_section_states_the_sentence():
    body = (PROJ / "README.md").read_text(encoding="utf-8")
    assert "## License" in body
    assert CANONICAL_SENTENCE in body
    assert "Internal project — license not specified" not in body, (
        "the README still carries the pre-decision placeholder"
    )


# ─────────────────────────────────────────────────────────────────────────────
# (g) the generated third-party notices header
# ─────────────────────────────────────────────────────────────────────────────

def test_render_notices_emits_the_project_licence():
    """Asserted against the GENERATOR'S OUTPUT, not the checked-in markdown.

    `docs/THIRD_PARTY_LICENSES.md` is regenerated on its own cadence by another
    workstream. Grepping the file would fail on staleness — a regeneration
    problem — and report it as licensing drift, which is a different thing. What
    must be true is that the generator emits the sentence, so that is what is
    checked.
    """
    spec = importlib.util.spec_from_file_location(
        "_license_audit", PROJ / "scripts" / "license-audit.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    header = module.render_notices([], {})
    assert CANONICAL_SENTENCE in header, (
        "render_notices() in scripts/license-audit.py does not state the project "
        "licence in the generated header"
    )
    assert header.index(CANONICAL_SENTENCE) < header.index("Third-party components"), (
        "the project licence must precede the third-party inventory"
    )


# ─────────────────────────────────────────────────────────────────────────────
# (h) the installer bundle
# ─────────────────────────────────────────────────────────────────────────────

MAKE_INSTALLER = PROJ / "scripts" / "make-installer.sh"

# The bundle's LICENSES.md footer used to state that "Correlix application code
# and this bundle's install tooling are proprietary to Correlix." Under the
# 2026-09-04 open-core decision that is FALSE, and it was false in the single
# most damaging place: the licence statement a paying customer receives with the
# artifact. The footer now carries CANONICAL_SENTENCE verbatim.
#
# Verbatim matters. The sentence names a file (LICENSING.md) and a licence id
# (LicenseRef-Correlix-Enterprise) that other consumers grep for; a bundle-local
# paraphrase is how nine copies of one fact become nine different facts.
BUNDLE_FOOTER_FALSEHOOD = "proprietary to\nCorrelix"


def test_installer_bundle_states_the_project_licence():
    body = MAKE_INSTALLER.read_text(encoding="utf-8")
    assert BUNDLE_FOOTER_FALSEHOOD not in body, (
        "make-installer.sh still tells the customer Correlix's own code is proprietary"
    )
    assert CANONICAL_SENTENCE in body, (
        "the installer bundle's LICENSES.md footer must state the project licence, "
        "verbatim — see CANONICAL_SENTENCE at the top of this file"
    )


def test_bundle_ships_the_licence_texts_its_footer_points_at():
    """A licence notice that names a file the customer did not receive is worse
    than no notice: it reads as a deliberate omission. The footer points at
    LICENSE, LICENSING.md and LICENSES/, so the build must copy all three — and
    must FAIL rather than ship a dangling reference if a source file is gone."""
    body = MAKE_INSTALLER.read_text(encoding="utf-8")
    assert re.search(r'for f in LICENSE LICENSING\.md; do', body), (
        "make-installer.sh must copy LICENSE and LICENSING.md into the bundle"
    )
    assert re.search(r'cp -R "\$ROOT/LICENSES" "\$BUNDLE_DIR/LICENSES"', body), (
        "make-installer.sh must copy the LICENSES/ SPDX texts into the bundle"
    )
    # A missing source file is a FATAL, never a silently thinner bundle (§16.1).
    for missing in ("$ROOT/$f is missing", "$ROOT/LICENSES/ is missing"):
        assert missing in body, (
            f"a missing {missing!r} must stop the build — a bundle whose licence "
            f"notice points at nothing is a release-integrity failure"
        )
    # And both texts must be non-empty in the bundle, by SPDX id.
    assert 'for t in Apache-2.0 Correlix-Enterprise; do' in body, (
        "the build must prove BOTH licence texts landed, by SPDX id"
    )


# ─────────────────────────────────────────────────────────────────────────────
# (i) the licence tool ships with the bundle
# ─────────────────────────────────────────────────────────────────────────────
#
# The product is licence-gated: a ceiling refusal is an HTTP 402 an operator may
# first meet at 02:00, possibly while the api is the thing that is down. "Is this
# licence file valid, and what does it grant?" has to be answerable ON the
# customer's host, from the file alone — which is what `correlix-licence verify`
# and `show` do, over the same internal/licence code the api verifies with.
#
# These mirror the correlix-debug ship contract in tests/test_pipeline_debug_ship.py
# one for one, because the reasoning is the same and a second convention for a
# third shipped binary is how one of them ends up unverified.

LICENCE_CMD_DIR = PROJ / "src" / "backend" / "cmd" / "correlix-licence"


def _installer_src() -> str:
    return MAKE_INSTALLER.read_text(encoding="utf-8")


def test_licence_tool_entrypoint_still_exists():
    assert (LICENCE_CMD_DIR / "main.go").is_file(), (
        "src/backend/cmd/correlix-licence/main.go is gone but make-installer.sh "
        "still builds it — the bundle build would fail at release time."
    )


def test_make_installer_builds_the_licence_tool():
    src = _installer_src()
    assert re.search(
        r'go build .*-o "\$BUNDLE_DIR/correlix-licence" \./cmd/correlix-licence', src), (
        "make-installer.sh must build correlix-licence into the bundle"
    )
    m = re.search(r'(CGO_ENABLED=0 go build [^\n]*"\$BUNDLE_DIR/correlix-licence")', src)
    assert m, "correlix-licence is not built with CGO_ENABLED=0 (static, no glibc dependency)"
    assert "-trimpath" in m.group(1), "correlix-licence build lost -trimpath"
    assert not re.search(r'correlix-licence[^\n]*\|\| true', src), (
        "the correlix-licence build must never be `|| true`'d (§16.1)"
    )


def test_licence_tool_is_smoke_tested_on_the_build_host():
    src = _installer_src()
    assert re.search(
        r'"\$BUNDLE_DIR/correlix-licence" --help >/dev/null\s*\\?\s*\n?\s*\|\| \{[^}]*FATAL', src), (
        "the --help smoke test must prove the binary RUNS and hard-fail the build "
        "(§16.1) — a 0-byte artifact must fail here, not on the customer's host"
    )


def test_sha256sums_covers_the_licence_tool_and_the_licence_texts():
    src = _installer_src()
    m = re.search(r'^\(cd "\$BUNDLE_DIR" && sha256sum (.+) > SHA256SUMS\)$', src, re.M)
    assert m, "make-installer.sh lost its SHA256SUMS line"
    listed = m.group(1)
    for want in ("correlix-licence", "LICENSE", "./LICENSES/*.txt"):
        assert want in listed, (
            f"{want} must be covered by SHA256SUMS — an artifact outside the "
            f"integrity manifest is unverifiable on the customer host"
        )


def test_licence_tool_is_a_customer_artifact_not_operator_only():
    """LAB_PATHS is the operator-only exclude list. The tool grants no authority
    (it embeds the PUBLIC verification key; keygen/sign are useless without the
    private signing key, which never enters a bundle), so it is not excluded."""
    m = re.search(r"^LAB_PATHS='([^']+)'", _installer_src(), re.M)
    assert m, "LAB_PATHS definition not found in make-installer.sh"
    for token in ("correlix-licence", "internal/licence"):
        assert token not in m.group(1), (
            f"{token} is excluded by LAB_PATHS but the bundle ships the licence tool"
        )


def test_shipped_licence_tool_sources_carry_no_lab_markers():
    m = re.search(r"^LAB_MARKERS='([^']+)'", _installer_src(), re.M)
    assert m, "LAB_MARKERS definition not found in make-installer.sh"
    for f in sorted(LICENCE_CMD_DIR.glob("*.go")):
        hit = re.search(m.group(1), f.read_text(encoding="utf-8"))
        assert hit is None, f"lab marker {hit.group(0)!r} in shipped file {f}"


def test_licence_tool_source_ships_in_the_source_archive():
    """An export-ignored command would leave customers a binary they cannot
    rebuild or audit."""
    paths = ["src/backend/cmd/correlix-licence/main.go",
             "src/backend/internal/licence/verify.go"]
    out = subprocess.run(
        ["git", "check-attr", "export-ignore", "--", *paths],
        cwd=PROJ, check=True, capture_output=True, text=True,
    ).stdout
    for line in out.strip().splitlines():
        path, _, value = line.rpartition(": export-ignore: ")
        assert value == "unspecified", f"{path} is export-ignored — it would not ship"


def test_bundle_docs_tell_the_customer_the_licence_tool_exists():
    """A binary at the bundle root that no bundle document mentions is a mystery
    file, not a tool."""
    src = _installer_src()
    advanced = src.split('cat > "$BUNDLE_DIR/ADVANCED.md" <<EOF', 1)
    assert len(advanced) == 2, "ADVANCED.md heredoc not found in make-installer.sh"
    body = advanced[1].split("\nEOF\n", 1)[0]
    assert "correlix-licence" in body, (
        "the bundle's ADVANCED.md must document correlix-licence"
    )
    for verb in ("verify", "show"):
        assert f"correlix-licence {verb}" in body, (
            f"ADVANCED.md must show the `{verb}` invocation — the two subcommands "
            f"a customer actually runs"
        )


def test_the_licence_tool_actually_runs_and_never_prints_private_key_material():
    """Executed, not grepped: build it and run --help, the same proof the bundle
    build performs. The usage text must not tempt an operator into printing a
    private key, and `verify`/`show` must both be offered."""
    out = subprocess.run(
        ["go", "run", "./cmd/correlix-licence", "--help"],
        cwd=PROJ / "src" / "backend", capture_output=True, text=True, check=False,
    )
    assert out.returncode == 0, f"correlix-licence --help failed:\n{out.stderr}"
    text = out.stdout
    for verb in ("verify", "show"):
        assert verb in text, f"correlix-licence --help does not mention `{verb}`"
    assert "never printed" in text or "never prints" in text, (
        "the usage text must state that the private key is never printed"
    )


# ─────────────────────────────────────────────────────────────────────────────
# the gate itself
# ─────────────────────────────────────────────────────────────────────────────

def test_licensing_gate_passes():
    """The eight boundary checks. Run here so a `pytest` run catches a policy
    violation even when nobody invokes the gate directly."""
    result = subprocess.run(
        [sys.executable, str(PROJ / "scripts" / "licensing-gate.py")],
        capture_output=True, text=True, cwd=PROJ, check=False,
    )
    assert result.returncode == 0, (
        f"scripts/licensing-gate.py failed\n{result.stdout}\n{result.stderr}"
    )


def test_release_blockers_are_recorded_and_still_open(policy):
    """The release gate must FAIL today, for exactly the two recorded reasons.

    An empty release-blocker list would mean the placeholder licence and the
    undefined CLA process had been quietly forgotten rather than resolved.
    """
    result = subprocess.run(
        [sys.executable, str(PROJ / "scripts" / "licensing-gate.py"), "--release", "--json"],
        capture_output=True, text=True, cwd=PROJ, check=False,
    )
    report = json.loads(result.stdout)
    assert not report["ok"], (
        "the release gate passes, which means the Enterprise licence text and the CLA "
        "process are both resolved. Update licensing-policy.json and this test."
    )
    ids = {b["id"] for b in policy["release_blockers"]["entries"]}
    assert ids == {"enterprise-text-placeholder", "cla-process-undefined"}
    assert all(f["check"] == "RELEASE" for f in report["failures"]), (
        "the default gate must be green; only release blockers may fail"
    )


def test_contributing_requires_a_cla():
    """Open core cannot work without relicensing rights, so the CLA requirement is
    not optional. The process being undecided is recorded honestly rather than
    invented."""
    body = (REPO / "CONTRIBUTING.md").read_text(encoding="utf-8")
    assert "Contributor License Agreement" in body
    assert "relicense" in body.lower()
    assert "CLA-PROCESS-TBD" in body, (
        "if the CLA signing process has been chosen, remove the marker, drop the "
        "blocker from licensing-policy.json, and update this test"
    )


# ─────────────────────────────────────────────────────────────────────────────
# SPDX marking
# ─────────────────────────────────────────────────────────────────────────────

def test_commercial_directories_are_marked(policy):
    for entry in policy["commercial_paths"]["entries"]:
        directory = PROJ / entry["path"]
        notice = PROJ / entry["notice_file"]
        assert notice.is_file(), f"{entry['notice_file']} is missing"
        assert COMMERCIAL_ID in notice.read_text(encoding="utf-8")
        sources = [p for p in directory.iterdir()
                   if p.is_file() and p.suffix in {".go", ".py", ".ts", ".tsx"}]
        assert sources, f"{entry['path']} has no source files; is it still a package?"
        for src in sources:
            head = src.read_text(encoding="utf-8")[:4096]
            assert f"SPDX-License-Identifier: {COMMERCIAL_ID}" in head, (
                f"{src.relative_to(PROJ)} is in a commercial directory but is not marked"
            )


def test_commercial_marking_never_escapes_its_directory(policy):
    """The dangerous direction. A stray commercial header on a core file would
    quietly restrict code the project promised was Apache-2.0."""
    commercial = [e["path"] for e in policy["commercial_paths"]["entries"]]
    skip = excluded_names(policy)
    offenders = []
    for path in PROJ.rglob("*"):
        if not path.is_file() or path.suffix not in {".go", ".py", ".ts", ".tsx", ".mjs"}:
            continue
        rel = path.relative_to(PROJ)
        if any(part in skip for part in rel.parts):
            continue
        if any(str(rel) == d or str(rel).startswith(d + "/") for d in commercial):
            continue
        try:
            head = path.read_text(encoding="utf-8")[:4096]
        except UnicodeDecodeError:
            continue
        if f"SPDX-License-Identifier: {COMMERCIAL_ID}" in head:
            offenders.append(str(rel))
    assert not offenders, (
        f"files marked commercial outside a commercial directory: {sorted(offenders)}"
    )
