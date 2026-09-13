# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""No Windows PE binaries in a Linux image — tracker 238(b).

`netops-correlation` shipped six Windows PE launcher stubs for months:
`pip/_vendor/distlib/{t32,t64,t64-arm,w32,w64,w64-arm}.exe`, vendored inside pip
by the `python:3.12-alpine` base. Nothing on musl Linux executes them and nothing
links them, but Correlix DISTRIBUTES them and the image carries no licence text
beside them, so Syft recorded them as an undischarged source obligation —
`Simple Launcher 1.1.0.14`, six times, under two different representations
depending on which PE cataloger claimed the file first (`binary` /
`pe-binary-package-cataloger`, or `dotnet` with
`pkg:nuget/Simple%20Launcher@1.1.0.14`).

Owner decision 2026-09-13: delete the bytes rather than infer a licence basis to
silence a scanner. The fix has two halves and this file guards both:

  * `Dockerfile.correlation` strips them in the RUNTIME stage (they arrive from
    the base layer, not from the build stage) and ASSERTS in the same stage that
    no `*.exe` and no `MZ`-magic file survives under /usr/local or /app. The
    build is the check, so a base-image bump that reintroduces them fails.
  * `scripts/check-no-pe-binaries.py` is the repo-side half: the source tree
    carries no PE binary, the Dockerfile still declares strip + assertion, and an
    SBOM of a final image contains no PE component under ANY representation.

Offline: reads files in the repository. No Docker, no network, no scanner.
"""

from __future__ import annotations

import importlib.util
import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DOCKERFILE = ROOT / "deployment" / "docker" / "Dockerfile.correlation"

# The six stubs, by name. Named explicitly so a partial strip is a test failure
# rather than a smaller number nobody notices.
STUBS = ("t32.exe", "t64.exe", "t64-arm.exe", "w32.exe", "w64.exe", "w64-arm.exe")


def _load_tool():
    path = ROOT / "scripts" / "check-no-pe-binaries.py"
    spec = importlib.util.spec_from_file_location("_check_no_pe_binaries", path)
    assert spec and spec.loader, f"cannot load {path}"
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


gate = _load_tool()


# --------------------------------------------------------------------------- #
# The Dockerfile change itself
# --------------------------------------------------------------------------- #
def test_dockerfile_strips_every_named_stub():
    text = DOCKERFILE.read_text(encoding="utf-8")
    missing = [s for s in STUBS
               if f"pip/_vendor/distlib/{s}" not in text]
    assert not missing, (
        f"Dockerfile.correlation no longer removes {missing} — all six PE stubs "
        f"must be deleted by explicit path, not just swept by a glob"
    )


def test_dockerfile_sweeps_and_asserts_in_the_runtime_stage():
    """The strip and the assertion must live AFTER the last FROM.

    A delete in the build stage removes nothing that ships: the build stage
    already drops its own pip copy, and the stubs reach the final image from the
    BASE layer underneath the `COPY --from=build`.
    """
    lines = DOCKERFILE.read_text(encoding="utf-8").splitlines()
    last_from = max(i for i, ln in enumerate(lines)
                    if ln.strip().upper().startswith("FROM "))
    runtime = "\n".join(lines[last_from:])
    assert re.search(r"-name\s+'\*\.exe'\s+-delete", runtime), (
        "the runtime stage no longer sweeps *.exe out of the shipped tree"
    )
    assert 'b"MZ"' in runtime, (
        "the runtime stage no longer asserts on the PE MZ magic — a renamed stub, "
        "or one at a path we did not predict, would ship silently"
    )
    assert "sys.exit(" in runtime, (
        "the PE check does not FAIL the build; a check that only prints is not a gate"
    )
    # Every named stub must also be removed in the runtime stage, not earlier.
    for stub in STUBS:
        assert f"pip/_vendor/distlib/{stub}" in runtime, (
            f"{stub} is removed outside the runtime stage, where it removes nothing"
        )


def test_dockerfile_adds_no_package_and_moves_no_pin():
    """Reproducibility: the fix is `rm` + an assertion, nothing else.

    The runtime stage installs nothing (that is a property tracker 263 paid for),
    and the base image stays digest-pinned at the same digest.
    """
    lines = DOCKERFILE.read_text(encoding="utf-8").splitlines()
    last_from = max(i for i, ln in enumerate(lines)
                    if ln.strip().upper().startswith("FROM "))
    runtime = "\n".join(lines[last_from + 1:])
    assert "apk add" not in runtime, "the runtime stage must install no apk package"
    assert "pip install" not in runtime, "the runtime stage must install no wheel"
    froms = [ln for ln in lines if ln.strip().upper().startswith("FROM ")]
    digests = {re.search(r"@sha256:[0-9a-f]{64}", ln).group(0) for ln in froms
               if re.search(r"@sha256:[0-9a-f]{64}", ln)}
    assert len(digests) == 1 and len(froms) == 2, (
        "both stages must stay pinned to the same base digest"
    )


# --------------------------------------------------------------------------- #
# The repo-side gate
# --------------------------------------------------------------------------- #
def test_gate_selftest_passes():
    assert gate._selftest() == 0


def test_repo_tree_carries_no_pe_binary():
    assert gate.check_tree() == []


def test_owned_dockerfiles_pass_the_gate():
    assert gate.check_dockerfiles() == []


def test_gate_bites_when_the_dockerfile_guard_is_deleted(tmp_path):
    """The regression this whole change exists to prevent: somebody 'tidies away'
    the rm+assert on a pip-bearing base and the stubs come straight back."""
    stripped = tmp_path / "Dockerfile.correlation"
    text = DOCKERFILE.read_text(encoding="utf-8")
    kept = [ln for ln in text.splitlines()
            if "distlib/" not in ln
            and "-name '*.exe' -delete" not in ln
            and 'b"MZ"' not in ln
            and not ln.startswith("RUN rm -f /usr/local")]
    stripped.write_text("\n".join(kept) + "\n", encoding="utf-8")
    problems = gate.check_dockerfiles([stripped])
    assert any("no longer strips" in p for p in problems), problems
    assert any("assertion is gone" in p for p in problems), problems


@pytest.mark.parametrize(
    "label,doc",
    [
        # syft >= 1.19: the PE cataloger claims the file, type `binary`, no purl.
        ("binary", {"artifacts": [{
            "name": "Simple Launcher", "version": "1.1.0.14", "type": "binary",
            "foundBy": "pe-binary-package-cataloger", "purl": "",
            "locations": [{"path": "/usr/local/lib/python3.12/site-packages/pip/"
                                   "_vendor/distlib/w64.exe"}]}]}),
        # syft 1.18.1: the .NET cataloger claims it first, type `dotnet`, nuget purl.
        ("nuget", {"artifacts": [{
            "name": "Simple Launcher", "version": "1.1.0.14", "type": "dotnet",
            "foundBy": "dotnet-portable-executable-cataloger",
            "purl": "pkg:nuget/Simple%20Launcher@1.1.0.14",
            "locations": [{"path": "/usr/local/lib/python3.12/site-packages/pip/"
                                   "_vendor/distlib/w64.exe"}]}]}),
        # The CycloneDX shape the compliance gate actually consumes.
        ("cyclonedx", {"components": [{
            "name": "Simple Launcher", "version": "1.1.0.14", "type": "application",
            "properties": [
                {"name": "syft:package:foundBy", "value": "pe-binary-package-cataloger"},
                {"name": "syft:package:type", "value": "binary"},
                {"name": "syft:location:0:path",
                 "value": "/usr/local/lib/python3.12/site-packages/pip/"
                          "_vendor/distlib/w64.exe"}]}]}),
        # A PE file no cataloger claimed at all: the suffix alone must be enough.
        ("unclaimed-path", {"artifacts": [{
            "name": "something", "version": "0", "type": "unknown",
            "foundBy": "generic-cataloger", "purl": "",
            "locations": [{"path": "/opt/vendor/launcher.exe"}]}]}),
    ],
)
def test_sbom_rule_is_representation_independent(tmp_path, label, doc):
    """Whichever representation the scanner emits, the rule must catch it.

    The 2026-09-05 inventory recorded these as `nuget` and the 2026-09-06 one as
    `binary`. A gate keyed to one spelling would have silently passed the other.
    """
    p = tmp_path / f"{label}.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    assert gate.check_sbom(p), f"the {label} representation slipped through"


def test_sbom_rule_fails_closed(tmp_path):
    """An unreadable, unrecognised or empty SBOM is an error, never a pass
    (scripts/CLAUDE.md §16.1)."""
    empty = tmp_path / "empty.json"
    empty.write_text(json.dumps({"artifacts": []}), encoding="utf-8")
    assert any("ZERO components" in p for p in gate.check_sbom(empty))

    garbage = tmp_path / "garbage.json"
    garbage.write_text("}{", encoding="utf-8")
    assert any("unparsable" in p for p in gate.check_sbom(garbage))

    alien = tmp_path / "alien.json"
    alien.write_text(json.dumps({"spdxVersion": "SPDX-2.3"}), encoding="utf-8")
    assert any("not a recognised SBOM" in p for p in gate.check_sbom(alien))

    assert gate.check_sbom(tmp_path / "absent.json"), "a missing SBOM must fail"


def test_clean_sbom_passes(tmp_path):
    p = tmp_path / "clean.json"
    p.write_text(json.dumps({"artifacts": [{
        "name": "busybox", "version": "1.37.0-r31", "type": "apk",
        "foundBy": "apk-db-cataloger", "purl": "pkg:apk/alpine/busybox@1.37.0-r31",
        "locations": [{"path": "/lib/apk/db/installed"}]}]}), encoding="utf-8")
    assert gate.check_sbom(p) == []


# --------------------------------------------------------------------------- #
# CI wiring — a gate nothing runs is not a gate
# --------------------------------------------------------------------------- #
def test_supply_chain_workflow_runs_the_gate():
    wf = (ROOT.parent / ".github" / "workflows" / "supply-chain.yml").read_text(encoding="utf-8")
    assert "scripts/check-no-pe-binaries.py" in wf, (
        "supply-chain.yml no longer runs the no-PE-binaries gate"
    )
    assert "--selftest" in wf, "the workflow must prove the gate bites before trusting it"
    # It has to run in the job that already has an SBOM of a real final image.
    oci = wf.split("oci-compliance:", 1)
    assert len(oci) == 2 and "check-no-pe-binaries.py" in oci[1], (
        "the gate must be wired into the oci-compliance job, where a Syft SBOM of "
        "a final image exists to feed it"
    )


def test_sbom_rule_catches_cyclonedx_file_entries(tmp_path):
    """Syft's file-level entries carry the path as the component NAME and no
    location property. The file-level evidence must not be quieter than the
    package-level evidence — in the real before-image CycloneDX scan there were
    12 entries for these six stubs (6 packages + 6 files), and a gate that saw
    only 6 of them would pass an image that still shipped the bytes under a
    scanner configuration that emitted files only."""
    p = tmp_path / "files.json"
    p.write_text(json.dumps({"components": [
        {"bom-ref": "a", "type": "file",
         "name": "/usr/local/lib/python3.12/site-packages/pip/_vendor/distlib/t32.exe",
         "hashes": [{"alg": "SHA-256", "content": "0" * 64}]},
        {"bom-ref": "b", "type": "file", "name": "/usr/local/bin/uvicorn"},
    ]}), encoding="utf-8")
    problems = gate.check_sbom(p)
    assert len(problems) == 1 and "t32.exe" in problems[0], problems
