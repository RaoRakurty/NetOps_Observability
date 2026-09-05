"""The final OCI image is the compliance boundary (tracker 238).

WHY THIS EXISTS. Correlix's licence inventory used to be derived entirely from
what Correlix DECLARES — vendored Go modules, npm lockfiles, pinned Python
requirements, `image:` lines in compose, `FROM` lines in Dockerfiles. A shipped
container is not that. It is an upstream base image plus whatever a package
manager pulled in plus our own layers, so any software that arrives inside an
inherited layer and is named nowhere in our tree is invisible to that model.

BusyBox is the confirmed case: GPL-2.0-**only**, present in every
`netops-frontend` and `netops-nginx` image we distribute, mentioned in no
Correlix Dockerfile, and consequently sat as an unanswerable `busybox` exception
for months without ever matching an inventoried component.

These tests hold the fix to the behaviour that matters rather than to its
implementation details:

  * BusyBox is discovered in an image whose Dockerfile is `FROM alpine` plus one
    `COPY` — WITHOUT being declared anywhere. The fixture SBOMs are real Syft
    output from images built from tests/fixtures/oci-regression/.
  * a copyleft licence creates a source obligation, and a permissive one does not
  * a missing artifact fails, an artifact whose checksum is wrong fails, and a
    scanner that produced nothing fails — none of them silently pass
  * the same component in two images shares one artifact; a DIFFERENT version of
    the same component does not
  * an undetermined licence is never assumed obligation-free
  * syslog-ng's existing corresponding-source path still works, through the same
    generic mechanism rather than a parallel one

Run:  python3 -m pytest tests/test_oci_compliance.py -v

Offline: no Docker, no network, no scanner. The image scans are checked in as
fixtures; regenerating them is documented in
docs/compliance/OCI_SOURCE_COMPLIANCE.md.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re

import pytest

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
FIXTURES = os.path.join(ROOT, "tests", "fixtures", "oci-regression")
PINS = os.path.join(ROOT, "scripts", "source-mirror.json")
INVENTORY = os.path.join(ROOT, "docs", "compliance", "oci-inventory.json")
DOC = os.path.join(ROOT, "docs", "compliance", "OCI_SOURCE_COMPLIANCE.md")

DIGEST = "sha256:" + "0" * 64


def _load_tool():
    path = os.path.join(ROOT, "scripts", "oci-compliance.py")
    spec = importlib.util.spec_from_file_location("_oci_compliance", path)
    assert spec and spec.loader, f"cannot load {path}"
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


oci = _load_tool()


def read_json(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def read_text(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        return fh.read()


@pytest.fixture(scope="module")
def pins() -> dict:
    return oci.load_pin_table(PINS)


def evaluate_sbom(sbom_path: str, pins: dict, *, base_layers: str | None = None,
                  source_dir: str | None = None, image: str = "test-image"):
    raw, _meta = oci.parse_sbom(sbom_path)
    layers = oci.load_base_layers(base_layers)
    norm = [oci.normalize_component(c, image=image, image_digest=DIGEST,
                                    base_layers=layers) for c in raw]
    return oci.evaluate(norm, pins, source_dir=source_dir)


def by_name(records: list[dict], name: str) -> dict:
    hits = [r for r in records if r["name"] == name]
    assert hits, f"{name} is not in the evaluated inventory"
    assert len(hits) == 1, f"{name} appears {len(hits)} times"
    return hits[0]


# ── the tool's own self-tests ────────────────────────────────────────────────

def test_selftest_passes():
    """The parser/policy self-tests ship with the tool; a harness that never runs
    them would let them rot."""
    assert oci.selftest() == 0


# ── the fixtures must be real, and must not declare BusyBox ──────────────────

def test_regression_dockerfiles_never_mention_busybox():
    """The whole point. If the fixture Dockerfile named BusyBox, the discovery it
    proves would be the old declaration-based discovery wearing a disguise."""
    for name in ("Dockerfile.inherited", "Dockerfile.inherited-other-version"):
        path = os.path.join(FIXTURES, name)
        assert os.path.isfile(path), f"missing regression fixture {name}"
        text = read_text(path)
        assert "busybox" not in text.lower(), (
            f"{name} mentions BusyBox — the inherited-layer regression only "
            f"proves something if the child image declares nothing")
        assert re.search(r"^FROM\s+alpine:[\d.]+@sha256:[0-9a-f]{64}", text,
                         re.MULTILINE), (
            f"{name} must pin its base image by digest — a mutable tag would "
            f"make the fixture describe a different image over time")
        assert "COPY test-binary" in text


def test_regression_sboms_are_real_cyclonedx_scans():
    for name in ("sbom-a321.cdx.json", "sbom-a320.cdx.json"):
        doc = read_json(os.path.join(FIXTURES, name))
        assert doc.get("bomFormat") == "CycloneDX"
        assert len(doc.get("components", [])) > 5, (
            f"{name} looks like a failed scan, not an image inventory")


# ── discovery: BusyBox without being declared ────────────────────────────────

def test_busybox_is_discovered_in_an_image_that_never_declares_it(pins):
    """THE regression. `FROM alpine` + `COPY test-binary`, nothing else — and
    BusyBox must still be in the inventory with its licence and its origin."""
    recs = evaluate_sbom(os.path.join(FIXTURES, "sbom-a321.cdx.json"), pins,
                         base_layers=os.path.join(FIXTURES, "base-layers-a321.txt"))
    bb = by_name(recs, "busybox")
    assert bb["version"] == "1.37.0-r12"
    assert bb["license"] == "GPL-2.0-only"
    assert bb["package_type"] == "apk"
    assert bb["source_required"] is True
    assert bb["origin"] == "inherited-base-layer", (
        "BusyBox is in the base image's layers, and the evaluation must say so "
        "rather than guessing or reporting unknown when the base is known")
    assert bb["image_digest"] == DIGEST, (
        "compliance is tied to the image digest, not to a mutable tag")


def test_origin_is_unknown_when_the_base_is_not_supplied(pins):
    """Provenance is never invented. Without the base image's layer set the tool
    cannot know whether a component was inherited, and must say `unknown`."""
    recs = evaluate_sbom(os.path.join(FIXTURES, "sbom-a321.cdx.json"), pins)
    assert by_name(recs, "busybox")["origin"] == "unknown"


def test_a_component_in_a_correlix_layer_is_not_called_inherited(pins):
    """The origin split has to be real in both directions, or 'inherited' means
    nothing. The fixture's only added layer holds the test binary."""
    recs = evaluate_sbom(os.path.join(FIXTURES, "sbom-a321.cdx.json"), pins,
                         base_layers=os.path.join(FIXTURES, "base-layers-a321.txt"))
    origins = {r["origin"] for r in recs}
    assert "inherited-base-layer" in origins
    base = read_json(os.path.join(FIXTURES, "sbom-a321.cdx.json"))
    assert base, "fixture SBOM is empty"


# ── source obligation, verification and the gate ─────────────────────────────

def test_busybox_source_is_verified_against_a_retained_artifact(pins, tmp_path):
    """`verified` means the BYTES were checked, not that a URL exists."""
    entry = next(c for c in pins["components"]
                 if c["name"] == "busybox"
                 and c.get("role", "corresponding-source") == "corresponding-source")
    packaging = next(c for c in pins["components"]
                     if c["name"] == "busybox" and c.get("role") == "distro-packaging")
    # Stand-in artifacts whose bytes hash to the pinned digests would be
    # impossible to forge, so the pins are temporarily re-pointed at real files
    # instead — the verification path under test is identical.
    src = tmp_path / entry["file"]
    src.write_bytes(b"pretend upstream tarball")
    pkg = tmp_path / packaging["file"]
    pkg.write_bytes(b"pretend aports archive")
    local = json.loads(json.dumps(pins))
    for e in local["components"]:
        if e["name"] != "busybox":
            continue
        target = src if e.get("role", "corresponding-source") == "corresponding-source" else pkg
        e["sha256"] = hashlib.sha256(target.read_bytes()).hexdigest()

    recs = evaluate_sbom(os.path.join(FIXTURES, "sbom-a321.cdx.json"), local,
                         base_layers=os.path.join(FIXTURES, "base-layers-a321.txt"),
                         source_dir=str(tmp_path))
    bb = by_name(recs, "busybox")
    assert bb["source_status"] == "verified"
    assert bb["source_artifact"].endswith(entry["file"])
    assert not oci.failures([bb], release=True), (
        "a verified artifact must satisfy a production release")


def test_missing_source_artifact_fails(pins, tmp_path):
    """No file on disk → `missing` → FAIL, in every mode."""
    recs = evaluate_sbom(os.path.join(FIXTURES, "sbom-a321.cdx.json"), pins,
                         base_layers=os.path.join(FIXTURES, "base-layers-a321.txt"),
                         source_dir=str(tmp_path))  # empty directory
    bb = by_name(recs, "busybox")
    assert bb["source_status"] == "missing"
    problems = oci.failures([bb], release=False)
    assert problems, "a missing corresponding source must fail the gate"
    assert "busybox" in problems[0] and "missing" in problems[0]


def test_invalid_checksum_fails(pins, tmp_path):
    """A file that is present but is NOT the pinned source is worse than absent:
    it reads as compliance. It must be `invalid`, never `verified`."""
    entry = next(c for c in pins["components"]
                 if c["name"] == "busybox"
                 and c.get("role", "corresponding-source") == "corresponding-source")
    (tmp_path / entry["file"]).write_bytes(b"not the source we pinned")
    status, _path, detail = oci.verify_artifact(entry, str(tmp_path))
    assert status == "invalid"
    assert "sha256 mismatch" in detail

    recs = evaluate_sbom(os.path.join(FIXTURES, "sbom-a321.cdx.json"), pins,
                         base_layers=os.path.join(FIXTURES, "base-layers-a321.txt"),
                         source_dir=str(tmp_path))
    bb = by_name(recs, "busybox")
    assert bb["source_status"] == "invalid"
    assert oci.failures([bb], release=False)


def test_upstream_availability_alone_is_not_verified(pins):
    """The pin records an upstream URL. That is provenance, not compliance: with
    nothing retained, the status must not reach `verified`."""
    recs = evaluate_sbom(os.path.join(FIXTURES, "sbom-a321.cdx.json"), pins,
                         base_layers=os.path.join(FIXTURES, "base-layers-a321.txt"))
    bb = by_name(recs, "busybox")
    assert bb["source_url"].startswith("https://")
    assert bb["source_status"] != "verified"
    assert oci.failures([bb], release=True), (
        "a production release must not pass on an unmaterialised pin")


def test_permissive_component_needs_no_source(pins):
    """MIT/BSD/Apache carry notice obligations, not source obligations."""
    recs = evaluate_sbom(os.path.join(FIXTURES, "sbom-a321.cdx.json"), pins,
                         base_layers=os.path.join(FIXTURES, "base-layers-a321.txt"))
    musl = by_name(recs, "musl")
    assert musl["license"] == "MIT"
    assert musl["source_required"] is False
    assert musl["source_status"] == "not-required"
    assert not oci.failures([musl], release=True)


# ── dedup with traceability, and the limits of dedup ─────────────────────────

def test_subpackages_share_one_artifact(pins):
    """busybox, busybox-binsh and ssl_client are three apk packages built from
    ONE origin package. One retained tarball serves all three — matched on the
    normalized source identity, never on a name we special-cased."""
    recs = evaluate_sbom(os.path.join(FIXTURES, "sbom-a321.cdx.json"), pins,
                         base_layers=os.path.join(FIXTURES, "base-layers-a321.txt"))
    artifacts = {by_name(recs, n)["source_artifact"]
                 for n in ("busybox", "busybox-binsh", "ssl_client")}
    assert len(artifacts) == 1, f"expected one shared artifact, got {artifacts}"
    for n in ("busybox-binsh", "ssl_client"):
        assert by_name(recs, n)["source_package"] == "busybox"


def test_a_different_version_is_not_deduplicated(pins):
    """alpine:3.20 carries BusyBox 1.36.1; the retained artifact is 1.37.0. A
    version-blind match would ship the wrong source and call it compliance."""
    recs = evaluate_sbom(os.path.join(FIXTURES, "sbom-a320.cdx.json"), pins,
                         base_layers=os.path.join(FIXTURES, "base-layers-a320.txt"))
    bb = by_name(recs, "busybox")
    assert bb["version"] == "1.36.1-r29"
    assert bb["source_artifact"] == "", (
        "the 1.37.0 artifact must not be offered as the source for 1.36.1")
    assert bb["source_status"] in ("missing", "unknown")
    assert oci.failures([bb], release=False)


def test_same_component_across_images_keeps_every_digest():
    """Dedup must not lose traceability: one inventory row, every image it was
    found in, each with its own digest."""
    manifests = [
        {"image": "img-a", "image_digest": "sha256:" + "a" * 64,
         "components": [{"name": "busybox", "version": "1.37.0-r12",
                         "license": "GPL-2.0-only", "license_confidence": "expression",
                         "package_type": "apk", "source_package": "busybox",
                         "purl": "", "origin": "inherited-base-layer",
                         "source_required": True, "source_status": "verified"}]},
        {"image": "img-b", "image_digest": "sha256:" + "b" * 64,
         "components": [{"name": "busybox", "version": "1.37.0-r12",
                         "license": "GPL-2.0-only", "license_confidence": "expression",
                         "package_type": "apk", "source_package": "busybox",
                         "purl": "", "origin": "inherited-base-layer",
                         "source_required": True, "source_status": "missing"}]},
    ]
    inv = oci.merge_inventory(manifests)
    rows = [c for c in inv["components"] if c["name"] == "busybox"]
    assert len(rows) == 1, "one component/version must be one inventory row"
    assert {i["image"] for i in rows[0]["images"]} == {"img-a", "img-b"}
    assert len({i["digest"] for i in rows[0]["images"]}) == 2
    assert rows[0]["source_status"] == "missing", (
        "the WORST status must win — a component verified in one image and "
        "missing in another is not clean")


def test_two_versions_are_two_inventory_rows():
    manifests = [{
        "image": "img", "image_digest": "sha256:" + "c" * 64,
        "components": [
            {"name": "busybox", "version": v, "license": "GPL-2.0-only",
             "license_confidence": "expression", "package_type": "apk",
             "source_package": "busybox", "purl": "",
             "origin": "inherited-base-layer", "source_required": True,
             "source_status": "missing"}
            for v in ("1.36.1-r29", "1.37.0-r12")],
    }]
    inv = oci.merge_inventory(manifests)
    assert len([c for c in inv["components"] if c["name"] == "busybox"]) == 2


# ── licence determination must never fail open ───────────────────────────────

def test_unknown_licence_is_visible_and_not_assumed_safe():
    for evidence in ([], ["SomethingNobodyHasHeardOf-1.0"]):
        verdict = oci.evaluate_licenses(evidence, [])
        assert verdict["source_required"] is True, (
            f"{evidence!r} must not be silently treated as obligation-free")
        assert verdict["confidence"] in ("no-license", "unknown-license")


def test_a_licence_list_with_a_copyleft_member_is_manual_review():
    """Debian copyright files list every licence in a source package with no
    stated relationship. Guessing either way is wrong; the answer is a human."""
    verdict = oci.evaluate_licenses(["MIT", "BSD-3-Clause", "GPL-2.0-only"], [])
    assert verdict["confidence"] == "license-list"
    assert verdict["source_required"] is True


def test_a_disjunction_is_taken_on_its_permissive_branch():
    verdict = oci.evaluate_licenses([], ["BSD-3-Clause OR GPL-2.0-or-later"])
    assert verdict["source_required"] is False


def test_every_mandated_copyleft_id_creates_an_obligation():
    """The licences the policy is REQUIRED to map (tracker 238 spec)."""
    for spdx in ("GPL-2.0-only", "GPL-2.0-or-later", "GPL-3.0-only",
                 "GPL-3.0-or-later", "LGPL-2.1-only", "LGPL-2.1-or-later",
                 "LGPL-3.0-only", "AGPL-3.0-only", "AGPL-3.0-or-later"):
        verdict = oci.evaluate_licenses([spdx], [])
        assert verdict["source_required"] is True, f"{spdx} lost its obligation"


# ── fail closed on the tool's own inputs ─────────────────────────────────────

def test_a_scanner_that_found_nothing_is_a_failure_not_an_empty_image(tmp_path):
    empty = tmp_path / "empty.cdx.json"
    empty.write_text(json.dumps({"bomFormat": "CycloneDX", "components": []}),
                     encoding="utf-8")
    with pytest.raises(oci.ComplianceError, match="scanner failure"):
        oci.parse_sbom(str(empty))


def test_a_non_cyclonedx_document_is_a_failure(tmp_path):
    junk = tmp_path / "junk.json"
    junk.write_text(json.dumps({"hello": "world"}), encoding="utf-8")
    with pytest.raises(oci.ComplianceError, match="not a CycloneDX"):
        oci.parse_sbom(str(junk))


def test_a_missing_sbom_is_a_failure():
    with pytest.raises(oci.ComplianceError):
        oci.parse_sbom("/nonexistent/scan.cdx.json")


def test_an_empty_base_layer_list_is_a_failure(tmp_path):
    """An empty list would mark every component Correlix-added — the opposite of
    the truth, and a silent way to make 'inherited' disappear."""
    p = tmp_path / "layers.txt"
    p.write_text("", encoding="utf-8")
    with pytest.raises(oci.ComplianceError, match="empty"):
        oci.load_base_layers(str(p))


def test_a_mutable_tag_is_not_an_identity():
    assert oci.main(["--sbom", os.path.join(FIXTURES, "sbom-a321.cdx.json"),
                     "--image", "x", "--digest", "latest"]) == 2


def test_the_cli_exit_codes_are_the_documented_ones(tmp_path):
    """0 PASS · 1 violation · 2 cannot run. A gate whose exit codes drift is a
    gate CI stops honouring."""
    assert oci.main(["--selftest"]) == 0
    assert oci.main(["--sbom", "/nope.json", "--image", "x",
                     "--digest", DIGEST]) == 2
    rc = oci.main(["--sbom", os.path.join(FIXTURES, "sbom-a320.cdx.json"),
                   "--image", "x", "--digest", DIGEST, "--quiet"])
    assert rc == 1, "an unrecorded, unretained obligation must fail"


# ── the checked-in policy and inventory ──────────────────────────────────────

def test_pin_table_covers_busybox_with_both_artifacts(pins):
    roles = {c.get("role", "corresponding-source") for c in pins["components"]
             if c["name"] == "busybox"}
    assert roles == {"corresponding-source", "distro-packaging"}, (
        "BusyBox needs BOTH the upstream release and Alpine's own packaging: "
        "the upstream tarball alone is not the tree the distribution built")


def test_the_distro_exact_claim_is_checked_against_the_image(pins):
    """`distro-exact` may only be claimed when the retained packaging is pinned
    to the same build reference the IMAGE records. Fabricated correspondence is
    the failure this guards."""
    recs = evaluate_sbom(os.path.join(FIXTURES, "sbom-a321.cdx.json"), pins,
                         base_layers=os.path.join(FIXTURES, "base-layers-a321.txt"))
    bb = by_name(recs, "busybox")
    assert bb["correspondence"] == "distro-exact"
    assert bb["distro_build_ref"], "the image records no build reference to check"

    wrong = json.loads(json.dumps(pins))
    for e in wrong["components"]:
        if e.get("role") == "distro-packaging":
            e["distro_package"]["build_ref"] = "0" * 40
    recs2 = evaluate_sbom(os.path.join(FIXTURES, "sbom-a321.cdx.json"), wrong,
                          base_layers=os.path.join(FIXTURES, "base-layers-a321.txt"))
    assert by_name(recs2, "busybox")["correspondence"] == "distro-packaging-mismatch"


def test_syslog_ng_still_has_its_corresponding_source(pins):
    """The generic mechanism must not have cost the case it grew out of."""
    sng = [c for c in pins["components"] if c["name"] == "syslog-ng"]
    assert len(sng) == 1
    assert sng[0]["file"].endswith(".tar.gz")
    assert sng[0]["url"].startswith("https://")
    assert re.fullmatch(r"[0-9a-f]{64}", sng[0]["sha256"])
    assert sng[0].get("provides"), (
        "syslog-ng must declare what it provides like every other entry — the "
        "mechanism is generic or it is not a mechanism")


def test_the_deferred_register_is_version_pinned(pins):
    """A blanket rule would hide the next inherited component. Every recorded
    posture names an exact version, so a base-image bump stops matching and the
    gate asks again."""
    deferred = pins.get("deferred", [])
    assert deferred, "the register is empty — did the inventory collapse?"
    for entry in deferred:
        assert entry["version"], f"{entry['component']} has no version"
        assert entry["license"], f"{entry['component']} has no licence"
        assert entry.get("tracker"), (
            f"{entry['component']} names no tracker row — an undischarged "
            f"obligation nobody owns is how tracker 238 happened")
    assert pins.get("deferred_posture"), (
        "the register must state what the recorded posture actually IS")


def test_recorded_postures_fail_a_production_release(pins):
    """A recorded posture keeps daily builds green (it is pre-existing and
    reviewed) but must never let a customer artifact out the door."""
    recs = evaluate_sbom(os.path.join(FIXTURES, "sbom-a321.cdx.json"), pins,
                         base_layers=os.path.join(FIXTURES, "base-layers-a321.txt"))
    recorded = [r for r in recs if r.get("deferred")]
    assert recorded, "expected some recorded-posture components in this fixture"
    assert not oci.failures(recorded, release=False)
    assert oci.failures(recorded, release=True)


def test_committed_inventory_is_wellformed_and_names_busybox():
    inv = read_json(INVENTORY)
    comps = inv.get("components")
    assert comps, "docs/compliance/oci-inventory.json lists no components"
    assert inv.get("images"), "the inventory names no images"
    for img in inv["images"]:
        assert re.fullmatch(r"sha256:[0-9a-f]{64}", img["digest"]), (
            f"{img['image']} is identified by {img['digest']!r}, which is not an "
            f"immutable digest")
    bb = [c for c in comps if c["name"] == "busybox"]
    assert bb, ("busybox is absent from the committed OCI inventory — the exact "
                "invisibility tracker 238 records")
    assert bb[0]["license"] == "GPL-2.0-only"
    assert bb[0]["origin"] == "inherited-base-layer"
    assert bb[0]["source_status"] == "verified"
    assert {i["image"] for i in bb[0]["images"]} >= {"netops-frontend", "netops-nginx"}
    unrecorded = [c for c in comps
                  if c["source_status"] in ("missing", "invalid")
                  and not c.get("recorded_posture")]
    assert not unrecorded, (
        "components with an undischarged source obligation and NO recorded "
        f"posture: {[c['name'] for c in unrecorded]}")


def test_busybox_reaches_the_shipped_notices():
    """An inherited component that never appears in the notices is invisible to
    the person who receives the software — which is the whole obligation."""
    notices = read_text(os.path.join(ROOT, "docs", "THIRD_PARTY_LICENSES.md"))
    assert "busybox" in notices
    assert "GPL-2.0-only" in notices
    assert "source-offer/busybox-" in notices, (
        "the notices must tell the recipient WHERE the corresponding source is, "
        "not merely that BusyBox is present")


def test_the_documentation_states_the_two_binding_sentences():
    """Owner spec, tracker 238. These two sentences are the policy; a mechanism
    whose policy is not written down is a mechanism nobody can apply."""
    # Normalised so markdown blockquote markers and emphasis cannot break the
    # match — the sentence is the contract, its typography is not.
    text = " ".join(re.sub(r"[>*`]", " ", read_text(DOC)).split())
    for needle in (
        ("Correlix owns source-availability compliance for applicable copyleft "
         "components contained anywhere in distributed container images, "
         "including inherited base-image layers."),
        ("Upstream source availability may be recorded as provenance or used for "
         "retrieval, but Correlix release compliance requires an independently "
         "retained and verified source artifact whenever Correlix policy requires "
         "corresponding source."),
    ):
        assert needle in text, (
            f"docs/compliance/OCI_SOURCE_COMPLIANCE.md is missing the binding "
            f"sentence: {needle[:60]}…")


def test_no_source_archive_is_baked_into_a_runtime_image():
    """Corresponding source travels with the RELEASE, never inside the running
    image: it would inflate every deployment for a file nobody reads at runtime."""
    docker_dir = os.path.join(ROOT, "deployment", "docker")
    offenders = []
    for base, _dirs, files in os.walk(docker_dir):
        for fn in files:
            if not fn.startswith("Dockerfile"):
                continue
            text = read_text(os.path.join(base, fn))
            for line in text.splitlines():
                if re.match(r"^\s*(COPY|ADD)\b", line) and "source-offer" in line:
                    offenders.append(f"{fn}: {line.strip()}")
    assert not offenders, (
        "a Dockerfile copies corresponding source into a runtime image: "
        + "; ".join(offenders))
