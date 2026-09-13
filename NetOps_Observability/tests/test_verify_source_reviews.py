# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""A licence review is only worth its evidence (tracker 238(a)).

WHY THIS EXISTS. `scripts/source-review.json` is the written answer to every
licence question an image scan could not resolve, and `owner_signoff: true` is
what lets `oci-compliance.py --release` rest on one. The owner's 2026-09-13
decision approved that signature SUBJECT TO a mechanical verification of seven
conditions per entry, so the signature can never mean "a first pass wrote a
convincing paragraph".

`scripts/verify-source-reviews.py` is that verification. These tests hold the
behaviour that matters — that EACH of the seven conditions actually fails an
entry that violates it, that a complete entry passes, and that `--sign` can
only ever flip a boolean:

  1 evidence that cannot be fetched, and an APKBUILD cited at a commit the
    image's own apk database does not record
  2 a missing sha256 and a sha256 that does not match the fetched bytes
  3 an empty `governing_licences`, and a `source_required` that is neither a
    boolean nor "unclear"
  4 a rationale that argues about the source package and never about the
    shipped artifact
  5 a placeholder anywhere in the entry
  6 a version the image's own package database does not record, and one the
    committed OCI inventory contradicts
  7 a copyleft record with a `source_required: false` conclusion, a copyleft
    term narrowed away without being named, and a free-text licence claim the
    evidence text does not support

Offline: no docker, no network, no scanner. Evidence comes from MappingFetcher,
the dict-backed transport the tool injects for exactly this reason.

Run:  python3 -m pytest tests/test_verify_source_reviews.py -v
"""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import subprocess
import sys

import pytest

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
TOOL = os.path.join(ROOT, "scripts", "verify-source-reviews.py")
REVIEWS = os.path.join(ROOT, "scripts", "source-review.json")


def _load(path: str, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader, f"cannot load {path}"
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


vsr = _load(TOOL, "_verify_source_reviews")
oci = _load(os.path.join(ROOT, "scripts", "oci-compliance.py"), "_oci_for_verify_tests")


# ── fixtures: one image, one apk database, one complete review ───────────────
IMAGE = "netops-test"

APK_DB = (
    "C:Q1aa=\n"
    "P:xz-libs\n"
    "V:5.8.3-r0\n"
    "L:GPL-2.0-or-later AND 0BSD AND Public-Domain AND LGPL-2.1-or-later\n"
    "o:xz\n"
    "c:ce9944f1daadb681dd6f0f81a06e9cce97127377\n"
    "R:liblzma.so.5\n"
    "R:liblzma.so.5.8.3\n"
    "\n"
    "C:Q1bb=\n"
    "P:readline\n"
    "V:8.3.3-r1\n"
    "L:GPL-3.0-or-later\n"
    "o:readline\n"
    "c:a854c03acdac188901fb012f7acbee70a36e8041\n"
    "R:libreadline.so.8\n"
)
APK_DB_SHA = hashlib.sha256(APK_DB.encode()).hexdigest()

APKBUILD = (
    "pkgname=readline\n"
    "pkgver=8.3.3\n"
    "pkgrel=1\n"
    'license="GPL-3.0-or-later"\n'
    'subpackages="$pkgname-dev"\n'
)
APKBUILD_SHA = hashlib.sha256(APKBUILD.encode()).hexdigest()
APKBUILD_COMMIT = "a854c03acdac188901fb012f7acbee70a36e8041"

COPYRIGHT = (
    "This is the Debian prepackaged version of the thing.\n\n"
    "This program is free software; you can redistribute it and/or modify\n"
    "it under the terms of the GNU General Public License as published by\n"
    "the Free Software Foundation; either version 2 of the License, or\n"
    "(at your option) any later version.\n"
)
COPYRIGHT_SHA = hashlib.sha256(COPYRIGHT.encode()).hexdigest()
DPKG_STATUS = "Package: base-things\nVersion: 1.2-3\nArchitecture: amd64\n"

INVENTORY = {"components": [
    {"name": "xz-libs", "version": "5.8.3-r0", "package_type": "apk"},
    {"name": "readline", "version": "8.3.3-r1", "package_type": "apk"},
    {"name": "base-things", "version": "1.2-3", "package_type": "deb"},
]}


def fetcher(**extra) -> object:
    files = {
        (IMAGE, vsr.APK_DB_PATH): APK_DB.encode(),
        (IMAGE, "/usr/share/doc/base-things/copyright"): COPYRIGHT.encode(),
        (IMAGE, "/var/lib/dpkg/status.d/base-things"): DPKG_STATUS.encode(),
    }
    files.update(extra.pop("files", {}))
    return vsr.MappingFetcher(
        aports={("main", "readline", APKBUILD_COMMIT): APKBUILD.encode()},
        files=files, **extra)


def verifier(fetch=None, inventory=None) -> object:
    return vsr.Verifier(fetch or fetcher(), oci,
                        inventory=INVENTORY if inventory is None else inventory)


def apkbuild_review() -> dict:
    """A complete review: the APKBUILD at the commit the image records, the
    right sha, an explicit copyleft conclusion, a rationale about the artifact."""
    return {
        "component": "readline", "version": "8.3.3-r1", "package_type": "apk",
        "images": [IMAGE],
        "evidence": {"kind": vsr.KIND_APKBUILD, "image": IMAGE,
                     "path": f"aports main/readline/APKBUILD @ {APKBUILD_COMMIT}",
                     "sha256": APKBUILD_SHA},
        "governing_licences": ["GPL-3.0-or-later"],
        "source_required": True, "needs_human": False,
        "rationale": ("Alpine records GPL-3.0-or-later for this package in the apk "
                      "database the image itself carries, and the APKBUILD at that "
                      "commit agrees; the obligation stands for the shipped binary "
                      "libreadline.so.8."),
        "reviewer": "test", "reviewed": "2026-09-13", "owner_signoff": False,
    }


def narrowed_review() -> dict:
    """The hard shape: a copyleft LIST narrowed to the licence that governs the
    one library the subpackage ships."""
    return {
        "component": "xz-libs", "version": "5.8.3-r0", "package_type": "apk",
        "images": [IMAGE],
        "evidence": {"kind": vsr.KIND_APK_RECORD_FILE, "image": IMAGE,
                     "path": f"{vsr.APK_DB_PATH} (the P:xz-libs record)",
                     "sha256": APK_DB_SHA},
        "governing_licences": ["0BSD", "Public-Domain"],
        "source_required": False, "needs_human": False,
        "rationale": ("The origin package's licence field is a LIST covering the "
                      "whole source tree — GPL-2.0-or-later AND 0BSD AND "
                      "Public-Domain AND LGPL-2.1-or-later. The package's own file "
                      "list in the image answers what is shipped: xz-libs installs "
                      "R:liblzma.so.5 and R:liblzma.so.5.8.3 and nothing else, and "
                      "liblzma is 0BSD. No copyleft work is distributed by it."),
        "reviewer": "test", "reviewed": "2026-09-13", "owner_signoff": False,
    }


def dpkg_review() -> dict:
    return {
        "component": "base-things", "version": "1.2-3", "package_type": "deb",
        "images": [IMAGE],
        "evidence": {"kind": vsr.KIND_DPKG_COPYRIGHT, "image": IMAGE,
                     "path": "/usr/share/doc/base-things/copyright",
                     "sha256": COPYRIGHT_SHA},
        "governing_licences": ["GPL-2.0-or-later"],
        "source_required": True, "needs_human": False,
        "rationale": ("The package ships no machine-readable copyright; the free-text "
                      "file the image carries states the whole package is distributed "
                      "under the GNU GPL version 2 or later."),
        "reviewer": "test", "reviewed": "2026-09-13", "owner_signoff": False,
    }


def conditions(review: dict, **kw) -> list[int]:
    return verifier(**kw).verify(review).conditions_failed()


def reasons(review: dict, **kw) -> str:
    res = verifier(**kw).verify(review)
    return " | ".join(f"C{f.condition}: {f.reason}" for f in res.findings)


# ── the pass ─────────────────────────────────────────────────────────────────
def test_a_complete_review_passes_all_seven():
    res = verifier().verify(apkbuild_review())
    assert res.findings == [], reasons(apkbuild_review())
    assert res.disposition == vsr.PASS
    assert res.eligible is True


def test_a_narrowed_review_passes_when_it_names_the_copyleft_it_drops():
    """The xz-libs shape: the record lists GPL and LGPL, the subpackage ships
    one 0BSD library, and the rationale says so against the file list."""
    res = verifier().verify(narrowed_review())
    assert res.findings == [], reasons(narrowed_review())
    assert any("narrowing accepted" in n for n in res.notes), res.notes


def test_a_free_text_debian_copyright_review_passes():
    res = verifier().verify(dpkg_review())
    assert res.findings == [], reasons(dpkg_review())


# ── condition 1: the evidence exists ─────────────────────────────────────────
def test_c1_evidence_that_cannot_be_fetched_fails():
    r = apkbuild_review()
    r["evidence"]["path"] = ("aports main/readline/APKBUILD @ "
                             + "0" * 40)
    got = conditions(r)
    assert 1 in got, reasons(r)
    assert "not found" in reasons(r) or "records commit" in reasons(r)


def test_c1_an_apkbuild_cited_at_the_wrong_commit_fails():
    """The condition is the APKBUILD at the commit the IMAGE records, not any
    APKBUILD that happens to exist."""
    other = "b" * 40
    f = vsr.MappingFetcher(
        aports={("main", "readline", other): APKBUILD.encode()},
        files={(IMAGE, vsr.APK_DB_PATH): APK_DB.encode()})
    r = apkbuild_review()
    r["evidence"]["path"] = f"aports main/readline/APKBUILD @ {other}"
    assert 1 in conditions(r, fetch=f), reasons(r, fetch=f)
    assert "records commit" in reasons(r, fetch=f)


def test_c1_an_unparsable_evidence_path_fails():
    r = apkbuild_review()
    r["evidence"]["path"] = "somewhere in aports"
    assert 1 in conditions(r)


def test_c1_a_quoted_apk_record_absent_from_the_image_fails():
    r = {
        "component": "readline", "version": "8.3.3-r1", "package_type": "apk",
        "images": [IMAGE],
        "evidence": {"kind": vsr.KIND_APK_RECORD_QUOTED, "image": IMAGE,
                     "path": vsr.APK_DB_PATH,
                     "record": "P:readline\nV:8.3.3-r1\nL:MIT",
                     "sha256": hashlib.sha256(
                         b"P:readline\nV:8.3.3-r1\nL:MIT").hexdigest()},
        "governing_licences": ["MIT"], "source_required": False,
        "needs_human": False,
        "rationale": ("The record the image itself carries records MIT for the "
                      "shipped binary, a notice-only licence with no copyleft term."),
        "reviewer": "test", "reviewed": "2026-09-13", "owner_signoff": False,
    }
    text = reasons(r)
    assert 1 in conditions(r), text
    assert "does not appear" in text


def test_c1_an_entry_whose_kind_asserts_no_evidence_can_never_be_verified():
    r = apkbuild_review()
    r["evidence"] = {"kind": vsr.KIND_NO_EVIDENCE, "image": IMAGE,
                     "path": "/opt/thing/*.exe", "sha256": ""}
    got = conditions(r)
    assert 1 in got and 2 in got, reasons(r)


# ── condition 2: the sha256 is present and valid ─────────────────────────────
def test_c2_a_missing_sha_fails():
    r = apkbuild_review()
    r["evidence"]["sha256"] = ""
    assert conditions(r) == [2], reasons(r)


def test_c2_a_malformed_sha_fails():
    r = apkbuild_review()
    r["evidence"]["sha256"] = "NOTAHASH"
    assert conditions(r) == [2], reasons(r)


def test_c2_a_sha_that_does_not_match_the_bytes_fails():
    r = apkbuild_review()
    r["evidence"]["sha256"] = "f" * 64
    text = reasons(r)
    assert conditions(r) == [2], text
    assert "recomputed" in text


# ── condition 3: the conclusion is explicit ──────────────────────────────────
def test_c3_an_empty_licence_conclusion_fails():
    r = apkbuild_review()
    r["governing_licences"] = []
    assert 3 in conditions(r), reasons(r)


def test_c3_a_source_required_that_is_neither_bool_nor_unclear_fails():
    r = apkbuild_review()
    r["source_required"] = "probably"
    assert 3 in conditions(r), reasons(r)


def test_c3_unclear_is_a_valid_verdict_but_not_signable():
    r = narrowed_review()
    r["source_required"] = "unclear"
    r["needs_human"] = True
    res = verifier().verify(r)
    assert 3 not in res.conditions_failed()
    assert res.eligible is False
    assert res.disposition == vsr.NEEDS_HUMAN


# ── condition 4: the rationale explains the SHIPPED artifact ──────────────────
def test_c4_a_rationale_about_the_source_tree_only_fails():
    r = apkbuild_review()
    r["rationale"] = ("The upstream source tree is released under the GNU GPL "
                      "version 3 or later according to its own COPYING file.")
    text = reasons(r)
    assert 4 in conditions(r), text
    assert "SHIPPED artifact" in text


def test_c4_an_empty_or_stub_rationale_fails():
    r = apkbuild_review()
    r["rationale"] = "GPL."
    assert 4 in conditions(r), reasons(r)
    r["rationale"] = "   "
    assert 4 in conditions(r), reasons(r)


def test_c4_may_be_satisfied_by_exclusion_only_when_no_copyleft_is_recorded():
    """A record with no copyleft term cannot bind the binary more strictly than
    it binds the tree — but the entry must SAY so, and the pass is reported."""
    db = ("C:Q1cc=\nP:libmd\nV:1.1.0-r0\nL:BSD-3-Clause AND ISC\no:libmd\n"
          "c:73e716067b9edc32c4cc7818cb7d206e57fdde15\nR:libmd.so.0\n")
    f = vsr.MappingFetcher(files={(IMAGE, vsr.APK_DB_PATH): db.encode()})
    r = {
        "component": "libmd", "version": "1.1.0-r0", "package_type": "apk",
        "images": [IMAGE],
        "evidence": {"kind": vsr.KIND_APK_RECORD_FILE, "image": IMAGE,
                     "path": f"{vsr.APK_DB_PATH} (the P:libmd record)",
                     "sha256": hashlib.sha256(db.encode()).hexdigest()},
        "governing_licences": ["BSD-3-Clause", "ISC"], "source_required": False,
        "needs_human": False,
        "rationale": ("Alpine's record states BSD-3-Clause AND ISC — two "
                      "notice-only licences, no copyleft term anywhere in it."),
        "reviewer": "test", "reviewed": "2026-09-13", "owner_signoff": False,
    }
    inv = {"components": [{"name": "libmd", "version": "1.1.0-r0",
                           "package_type": "apk"}]}
    res = vsr.Verifier(f, oci, inventory=inv).verify(r)
    assert res.findings == [], [(x.condition, x.reason) for x in res.findings]
    assert any("by exclusion" in n for n in res.notes), res.notes

    # …and the same prose does NOT excuse a record that does carry copyleft.
    res2 = verifier().verify(dict(apkbuild_review(), rationale=r["rationale"]))
    assert 4 in res2.conditions_failed()


# ── condition 5: no placeholders ─────────────────────────────────────────────
@pytest.mark.parametrize("field,value", [
    ("rationale", ("The shipped binary is covered by TODO: check the copyright "
                   "file before signing this entry off, which nobody did yet.")),
    ("reviewer", "TBD"),
    ("reviewed", "N/A"),
])
def test_c5_a_placeholder_anywhere_in_the_entry_fails(field, value):
    r = apkbuild_review()
    r[field] = value
    assert 5 in conditions(r), reasons(r)


def test_c5_the_word_unclear_is_not_a_placeholder():
    r = narrowed_review()
    r["rationale"] += " The upstream statement is unclear about the tools."
    assert 5 not in conditions(r), reasons(r)


# ── condition 6: the SHIPPED version ─────────────────────────────────────────
def test_c6_a_version_the_image_does_not_record_fails():
    r = apkbuild_review()
    r["version"] = "8.3.2-r0"
    text = reasons(r)
    assert 6 in conditions(r), text
    assert "8.3.3-r1 as the shipped version" in text


def test_c6_a_version_the_committed_inventory_contradicts_fails():
    db = APK_DB.replace("V:8.3.3-r1", "V:9.9.9-r9")
    f = fetcher(files={(IMAGE, vsr.APK_DB_PATH): db.encode()})
    r = apkbuild_review()
    r["version"] = "9.9.9-r9"
    r["evidence"]["sha256"] = APKBUILD_SHA
    text = reasons(r, fetch=f)
    assert 6 in conditions(r, fetch=f), text
    assert "committed OCI inventory records readline 8.3.3-r1" in text


def test_c6_a_component_the_image_does_not_carry_at_all_fails():
    r = apkbuild_review()
    r["component"] = "not-installed"
    assert 6 in conditions(r), reasons(r)


def test_c6_reads_a_debian_version_out_of_the_dpkg_database():
    r = dpkg_review()
    r["version"] = "1.2-4"
    text = reasons(r)
    assert 6 in conditions(r), text
    assert "1.2-3 as the shipped version" in text


def test_c6_reads_the_cpython_version_out_of_patchlevel_h():
    licence = "PYTHON SOFTWARE FOUNDATION LICENSE VERSION 2\n--------\ntext\n"
    header = '#define PY_VERSION "3.12.14"\n'
    f = vsr.MappingFetcher(files={
        (IMAGE, "/usr/local/lib/python3.12/LICENSE.txt"): licence.encode(),
        (IMAGE, "/usr/local/include/python3.12/patchlevel.h"): header.encode(),
    })
    r = {
        "component": "python", "version": "3.12.13", "package_type": "generic",
        "images": [IMAGE],
        "evidence": {"kind": vsr.KIND_IN_IMAGE_LICENCE, "image": IMAGE,
                     "path": "/usr/local/lib/python3.12/LICENSE.txt",
                     "sha256": hashlib.sha256(licence.encode()).hexdigest()},
        "governing_licences": ["PSF-2.0"], "source_required": False,
        "needs_human": False,
        "rationale": ("The image itself carries CPython's licence text, which is the "
                      "Python Software Foundation License version 2 — permissive, "
                      "notice only, for the interpreter this image ships."),
        "reviewer": "test", "reviewed": "2026-09-13", "owner_signoff": False,
    }
    inv = {"components": [{"name": "python", "version": "3.12.13",
                           "package_type": "generic"}]}
    res = vsr.Verifier(f, oci, inventory=inv).verify(r)
    assert 6 in res.conditions_failed(), [(x.condition, x.reason) for x in res.findings]
    assert "3.12.14 as the shipped version" in " ".join(
        x.reason for x in res.findings)
    r["version"] = "3.12.14"
    inv["components"][0]["version"] = "3.12.14"
    res2 = vsr.Verifier(f, oci, inventory=inv).verify(r)
    assert res2.findings == [], [(x.condition, x.reason) for x in res2.findings]


# ── condition 7: evidence must not contradict the conclusion ──────────────────
def test_c7_a_copyleft_record_cannot_conclude_no_obligation():
    r = apkbuild_review()
    r["source_required"] = False
    text = reasons(r)
    assert 7 in conditions(r), text
    assert "source_required=false" in text


def test_c7_a_dropped_copyleft_term_must_be_named():
    r = narrowed_review()
    r["rationale"] = r["rationale"].replace("LGPL-2.1-or-later", "some other term")
    text = reasons(r)
    assert 7 in conditions(r), text
    assert "without ever naming the copyleft term(s) LGPL-2.1-or-later" in text


def test_c7_a_narrowing_needs_the_packages_file_list_not_an_assertion():
    r = narrowed_review()
    r["rationale"] = ("The origin licence field lists GPL-2.0-or-later AND 0BSD AND "
                      "Public-Domain AND LGPL-2.1-or-later, but this image's "
                      "component is obviously permissive and nothing more.")
    text = reasons(r)
    assert 7 in conditions(r), text
    assert "no statement of what the package actually ships" in text


def test_c7_a_licence_the_record_does_not_spell_must_be_read_out_of_free_text():
    """The nginx shape: the record says "2-clause BSD-like license" and the
    review says BSD-2-Clause — allowed, but only if it QUOTES what it read."""
    db = ("C:Q1dd=\nP:nginx\nV:1.27.5-r1\nL:2-clause BSD-like license\no:nginx\nc:\n"
          "R:nginx\n")
    sha = hashlib.sha256(b"P:nginx\nV:1.27.5-r1\nL:2-clause BSD-like license").hexdigest()
    base = {
        "component": "nginx", "version": "1.27.5-r1", "package_type": "apk",
        "images": [IMAGE],
        "evidence": {"kind": vsr.KIND_APK_RECORD_QUOTED, "image": IMAGE,
                     "path": vsr.APK_DB_PATH,
                     "record": "P:nginx\nV:1.27.5-r1\nL:2-clause BSD-like license",
                     "sha256": sha},
        "governing_licences": ["BSD-2-Clause"], "source_required": False,
        "needs_human": False,
        "rationale": ("The image's apk database records the free-text '2-clause "
                      "BSD-like license' for the shipped package, i.e. the two-clause "
                      "BSD licence nginx is released under — notice only."),
        "reviewer": "test", "reviewed": "2026-09-13", "owner_signoff": False,
    }
    inv = {"components": [{"name": "nginx", "version": "1.27.5-r1",
                           "package_type": "apk"}]}
    f = vsr.MappingFetcher(files={(IMAGE, vsr.APK_DB_PATH): db.encode()})
    ok = vsr.Verifier(f, oci, inventory=inv).verify(base)
    assert ok.findings == [], [(x.condition, x.reason) for x in ok.findings]
    assert any("free-text term" in n for n in ok.notes), ok.notes

    unquoted = copy.deepcopy(base)
    unquoted["rationale"] = ("The shipped package is under the two-clause BSD licence "
                             "that nginx is released under, which is notice only.")
    bad = vsr.Verifier(f, oci, inventory=inv).verify(unquoted)
    assert 7 in bad.conditions_failed()
    assert "without quoting them" in " ".join(x.reason for x in bad.findings)


def test_c7_a_free_text_licence_claim_the_evidence_does_not_support_fails():
    r = dpkg_review()
    r["governing_licences"] = ["MIT"]
    r["source_required"] = False
    text = reasons(r)
    assert 7 in conditions(r), text
    assert "does not read like MIT" in text


def test_c7_a_licence_with_no_free_text_marker_fails_closed():
    r = dpkg_review()
    r["governing_licences"] = ["Beerware"]
    r["source_required"] = False
    text = reasons(r)
    assert 7 in conditions(r), text
    assert "no marker pattern" in text


def test_c7_a_copyleft_files_star_stanza_cannot_conclude_no_obligation():
    text = ("Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/\n"
            "\nFiles: *\nCopyright: someone\nLicense: GPL-2.0-or-later\n"
            "\nLicense: GPL-2.0-or-later\n This program is free software; you can\n"
            " redistribute it under the terms of the GNU General Public License,\n"
            " either version 2 of the License, or any later version.\n")
    f = vsr.MappingFetcher(files={
        (IMAGE, "/usr/share/doc/base-things/copyright"): text.encode(),
        (IMAGE, "/var/lib/dpkg/status.d/base-things"): DPKG_STATUS.encode(),
    })
    r = dpkg_review()
    r["evidence"]["sha256"] = hashlib.sha256(text.encode()).hexdigest()
    r["source_required"] = False
    got = reasons(r, fetch=f)
    assert 7 in conditions(r, fetch=f), got
    assert "`Files: *` stanza is GPL-2.0-or-later" in got


# ── --sign: the only change it may make ──────────────────────────────────────
def table_with(reviews: list[dict]) -> dict:
    return {"_comment": ["a table"], "schema_version": 1, "reviewed": "2026-09-13",
            "tracker": "238", "reviews": reviews}


def write_table(path: str, doc: dict) -> str:
    raw = vsr.serialise(doc)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(raw)
    return raw


def test_sign_flips_only_the_booleans_of_passing_entries(tmp_path):
    failing = apkbuild_review()
    failing["version"] = "8.3.2-r0"          # condition 6
    human = narrowed_review()
    human["source_required"] = "unclear"
    human["needs_human"] = True
    doc = table_with([apkbuild_review(), failing, human])
    path = str(tmp_path / "source-review.json")
    before = write_table(path, doc)

    loaded, raw = vsr.read_table(path)
    results = vsr.verify_table(loaded, verifier())
    signed = vsr.sign(loaded, raw, results, path)
    assert [r.component for r in signed] == ["readline"]

    with open(path, encoding="utf-8") as fh:
        after = fh.read()
    diff = [(a, b) for a, b in zip(before.split("\n"), after.split("\n")) if a != b]
    assert len(before.split("\n")) == len(after.split("\n"))
    assert diff == [('      "owner_signoff": false',
                     '      "owner_signoff": true')], diff
    doc_after = json.loads(after)
    assert [e["owner_signoff"] for e in doc_after["reviews"]] == [True, False, False]
    # …and the table the compliance tool consumes still loads.
    assert oci.load_reviews(path, required=True)


def test_sign_is_idempotent(tmp_path):
    path = str(tmp_path / "source-review.json")
    write_table(path, table_with([apkbuild_review()]))
    for expected in ([ "readline" ], []):
        loaded, raw = vsr.read_table(path)
        signed = vsr.sign(loaded, raw, vsr.verify_table(loaded, verifier()), path)
        assert [r.component for r in signed] == expected
    with open(path, encoding="utf-8") as fh:
        assert json.loads(fh.read())["reviews"][0]["owner_signoff"] is True


def test_sign_never_signs_an_entry_that_needs_a_human(tmp_path):
    human = narrowed_review()
    human["needs_human"] = True
    path = str(tmp_path / "source-review.json")
    write_table(path, table_with([human]))
    loaded, raw = vsr.read_table(path)
    assert vsr.sign(loaded, raw, vsr.verify_table(loaded, verifier()), path) == []
    with open(path, encoding="utf-8") as fh:
        assert json.loads(fh.read())["reviews"][0]["owner_signoff"] is False


def test_sign_refuses_a_table_it_cannot_rewrite_byte_for_byte(tmp_path):
    path = str(tmp_path / "source-review.json")
    doc = table_with([apkbuild_review()])
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=4)          # not this file's formatting
    loaded, raw = vsr.read_table(path)
    with pytest.raises(vsr.VerifyError, match="byte for byte"):
        vsr.sign(loaded, raw, vsr.verify_table(loaded, verifier()), path)
    with open(path, encoding="utf-8") as fh:
        assert json.loads(fh.read())["reviews"][0]["owner_signoff"] is False


def test_sign_never_removes_a_signature(tmp_path):
    """Only the owner unsigns. A signed entry that now FAILS is reported, not
    rewritten."""
    signed = apkbuild_review()
    signed["owner_signoff"] = True
    signed["version"] = "8.3.2-r0"           # condition 6 now fails
    path = str(tmp_path / "source-review.json")
    write_table(path, table_with([signed]))
    loaded, raw = vsr.read_table(path)
    results = vsr.verify_table(loaded, verifier())
    assert results[0].disposition == vsr.FAIL
    assert vsr.sign(loaded, raw, results, path) == []
    with open(path, encoding="utf-8") as fh:
        assert json.loads(fh.read())["reviews"][0]["owner_signoff"] is True


# ── the cli contract ─────────────────────────────────────────────────────────
def test_check_exits_one_when_an_eligible_review_fails(tmp_path, monkeypatch, capsys):
    failing = apkbuild_review()
    failing["evidence"]["sha256"] = "a" * 64
    path = str(tmp_path / "source-review.json")
    write_table(path, table_with([apkbuild_review(), failing]))
    inv = str(tmp_path / "inv.json")
    with open(inv, "w", encoding="utf-8") as fh:
        json.dump(INVENTORY, fh)
    monkeypatch.setattr(vsr, "LiveFetcher", lambda **kw: fetcher())
    code = vsr.main(["--check", "--reviews-file", path, "--inventory", inv])
    out = capsys.readouterr()
    assert code == 1, out
    assert "C2" in out.out
    assert "FAILED mechanical verification" in out.err


def test_check_exits_zero_when_every_eligible_review_passes(tmp_path, monkeypatch,
                                                            capsys):
    human = narrowed_review()
    human["source_required"] = "unclear"
    human["needs_human"] = True
    path = str(tmp_path / "source-review.json")
    write_table(path, table_with([apkbuild_review(), human]))
    inv = str(tmp_path / "inv.json")
    with open(inv, "w", encoding="utf-8") as fh:
        json.dump(INVENTORY, fh)
    monkeypatch.setattr(vsr, "LiveFetcher", lambda **kw: fetcher())
    assert vsr.main(["--check", "--reviews-file", path, "--inventory", inv]) == 0
    out = capsys.readouterr().out
    assert "NOT ELIGIBLE FOR SIGN-OFF (1)" in out


def test_an_unreadable_table_is_cannot_run_not_zero(tmp_path, capsys):
    missing = str(tmp_path / "nope.json")
    assert vsr.main(["--check", "--reviews-file", missing]) == 2
    assert "CANNOT RUN" in capsys.readouterr().err


def test_a_transport_failure_is_cannot_run_not_a_condition_failure(tmp_path,
                                                                   monkeypatch,
                                                                   capsys):
    """"I could not look" must never be reported as "the evidence is not there"."""
    class Dead(vsr.Fetcher):
        def aports_apkbuild(self, repo, pkg, commit):
            raise vsr.Unavailable("no route to aports")

        def image_file(self, image, path):
            raise vsr.Unavailable("docker is not on PATH")

        def image_id(self, image):
            return ""

    path = str(tmp_path / "source-review.json")
    write_table(path, table_with([apkbuild_review()]))
    monkeypatch.setattr(vsr, "LiveFetcher", lambda **kw: Dead())
    assert vsr.main(["--check", "--reviews-file", path]) == 2
    assert "CANNOT RUN" in capsys.readouterr().err


def test_the_selftest_passes_in_process_and_as_a_subprocess():
    assert vsr.selftest() == 0
    proc = subprocess.run([sys.executable, TOOL, "--selftest"],
                          capture_output=True, text=True, timeout=120, check=False)
    assert proc.returncode == 0, proc.stderr
    assert "selftest OK" in proc.stdout


# ── the real table, offline ───────────────────────────────────────────────────
@pytest.fixture(scope="module")
def real_table() -> dict:
    doc, _ = vsr.read_table(REVIEWS)
    return doc


def test_every_real_entry_has_a_kind_this_verifier_can_recheck(real_table):
    unknown = [f"{r['component']} {r['version']}: {r['evidence'].get('kind')!r}"
               for r in real_table["reviews"]
               if r.get("evidence", {}).get("kind") not in vsr.KNOWN_KINDS]
    assert not unknown, (
        "the verifier cannot re-check these evidence kinds, so --sign could never "
        f"pass them: {unknown}")


def test_no_real_entry_carries_a_placeholder(real_table):
    """Condition 5 over the committed table — this one needs no network."""
    v = vsr.Verifier(vsr.MappingFetcher(), oci)
    offenders = []
    for review in real_table["reviews"]:
        res = vsr.Result(review)
        v.check_no_placeholders(review, res)
        if res.findings:
            offenders.append(f"{review['component']} {review['version']}: "
                             f"{res.findings[0].reason}")
    assert not offenders, offenders


def test_every_signed_entry_states_an_explicit_conclusion(real_table):
    """A signature may never sit on top of a vague entry. Offline half of the
    seven conditions (3, 4-prose, 5); `--check` does the rest with evidence."""
    v = vsr.Verifier(vsr.MappingFetcher(), oci)
    offenders = []
    for review in real_table["reviews"]:
        if not review.get("owner_signoff"):
            continue
        res = vsr.Result(review)
        v.check_conclusion_is_explicit(review, res)
        v.check_no_placeholders(review, res)
        if not str(review.get("rationale") or "").strip():
            res.fail(4, "no rationale")
        if res.findings:
            offenders.append(f"{review['component']} {review['version']}: "
                             + "; ".join(f"C{f.condition} {f.reason}"
                                         for f in res.findings))
    assert not offenders, offenders


def test_entries_that_need_a_human_are_unsigned_in_the_committed_table(real_table):
    signed_human = [f"{r['component']} {r['version']}" for r in real_table["reviews"]
                    if (r.get("needs_human") or r.get("source_required") == "unclear")
                    and r.get("owner_signoff")]
    assert not signed_human, (
        f"an unresolved review carries a signature: {signed_human}")
