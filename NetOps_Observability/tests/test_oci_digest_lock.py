# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""The base-image digest lock — a re-pin without a re-scan is a CI failure.

WHY THIS EXISTS. `docs/compliance/oci-inventory.json` is not a description of
"our images" in the abstract. Every statement in it — which packages are
present, which licences they carry, which retained corresponding source matches
which binary — is a statement about SPECIFIC BYTES: the base images the build
pinned by digest at the moment the scan ran.

Bump one `FROM …@sha256:` and all of it silently becomes a claim about an image
nobody ships any more. That is exactly the shape of the defect tracker 238
records (software Correlix distributes that no Correlix inventory can see), one
step downstream: an inventory that still looks complete while describing
something else.

So the digests are LOCKED. `scripts/oci-compliance.py --emit-inventory` writes
every digest the build definitions pin into the inventory it generates, and this
test compares the tree against that record. They can only diverge one way: a
digest moved without the compliance evaluation being re-run.

THE FIX WHEN THIS FAILS IS NEVER TO EDIT THE INVENTORY BY HAND. Re-scan the
images, regenerate the inventory and re-review the register — the pinned package
versions will have moved with the base image, so `deferred` rows stop matching
and the obligations have to be looked at again. The procedure is
docs/compliance/OCI_SOURCE_COMPLIANCE.md §13.

Offline: reads two files in the repository. No Docker, no network, no scanner.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re

import pytest

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
INVENTORY = os.path.join(ROOT, "docs", "compliance", "oci-inventory.json")
DOC = os.path.join(ROOT, "docs", "compliance", "OCI_SOURCE_COMPLIANCE.md")


def _load_tool():
    path = os.path.join(ROOT, "scripts", "oci-compliance.py")
    spec = importlib.util.spec_from_file_location("_oci_compliance_lock", path)
    assert spec and spec.loader, f"cannot load {path}"
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


oci = _load_tool()

REGENERATE = (
    "\n\nA pinned image digest changed without a fresh compliance evaluation.\n"
    "Re-scan the images and regenerate the inventory (do NOT hand-edit it):\n"
    "  docs/compliance/OCI_SOURCE_COMPLIANCE.md §13 — 'Bumping a base image'\n"
)


@pytest.fixture(scope="module")
def inventory() -> dict:
    with open(INVENTORY, encoding="utf-8") as fh:
        return json.load(fh)


@pytest.fixture(scope="module")
def pinned_in_tree() -> list[dict]:
    return oci.scan_pinned_images(ROOT)


def test_the_tree_pins_images_by_digest_at_all(pinned_in_tree):
    """A scan that finds nothing would make every assertion below vacuous."""
    assert pinned_in_tree, (
        "no `FROM …@sha256:` or `image: …@sha256:` pin was found under "
        "deployment/docker — either the pinning convention was abandoned or the "
        "scanner stopped matching. Both make the digest lock meaningless.")
    for entry in pinned_in_tree:
        assert re.fullmatch(r"sha256:[0-9a-f]{64}", entry["digest"]), entry
        assert entry["pinned_in"], entry


def test_the_inventory_records_the_digest_lock(inventory):
    locked = inventory.get("pinned_base_images")
    assert locked, (
        "docs/compliance/oci-inventory.json carries no `pinned_base_images` "
        "section, so nothing constrains a base-image bump." + REGENERATE)


def test_no_pinned_image_digest_changed_without_a_fresh_compliance_evaluation(
        inventory, pinned_in_tree):
    """THE TEST. The tree and the last compliance evaluation must agree."""
    locked = {(e["image"], e["digest"]) for e in inventory["pinned_base_images"]}
    current = {(e["image"], e["digest"]) for e in pinned_in_tree}
    where = {(e["image"], e["digest"]): e["pinned_in"] for e in pinned_in_tree}

    bumped = sorted(current - locked)
    stale = sorted(locked - current)

    problems = []
    for image, digest in bumped:
        was = sorted(d for i, d in locked if i == image)
        problems.append(
            f"  {image} is pinned to {digest}\n"
            f"    in {', '.join(where[(image, digest)])}\n"
            f"    but the compliance inventory was taken against "
            f"{was or ['(this image was not evaluated at all)']}")
    for image, digest in stale:
        if image not in {i for i, _ in current}:
            problems.append(
                f"  {image}@{digest} was evaluated for compliance but is no "
                f"longer pinned anywhere in deployment/docker")

    assert not problems, (
        "base-image digests disagree with the recorded compliance evaluation:\n"
        + "\n".join(problems) + REGENERATE)


def test_the_images_that_were_scanned_are_still_the_ones_we_build(inventory):
    """The evaluated images are named by immutable digest, not by tag."""
    assert inventory.get("images"), "the inventory names no scanned images"
    for img in inventory["images"]:
        assert re.fullmatch(r"sha256:[0-9a-f]{64}", img["digest"]), img


def test_the_bump_procedure_is_written_down():
    """A gate whose fix is not documented is a gate people switch off."""
    with open(DOC, encoding="utf-8") as fh:
        doc = fh.read()
    assert "pinned_base_images" in doc, (
        "OCI_SOURCE_COMPLIANCE.md does not mention the digest lock")
    assert "tests/test_oci_digest_lock.py" in doc, (
        "OCI_SOURCE_COMPLIANCE.md does not tell the reader which test enforces it")
