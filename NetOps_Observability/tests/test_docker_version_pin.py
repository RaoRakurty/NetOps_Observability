# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix
"""tracker 373 (option B): Docker Engine is pinned to a Correlix-validated
version, held, and checked by the install doctor.

Docker's own UDP conntrack flush is what keeps device source addresses intact
across a receiver restart; it was broken in 29.5.0 and is port-sensitive later
(moby#53384). So the installer must never install "latest", the pin must be a
version the doctor calls validated, and the doctor must flag known-bad Engines.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import install_doctor as doctor

PREPARE = (ROOT / "scripts" / "prepare-host.sh").read_text(encoding="utf-8")


def pinned_version() -> str:
    m = re.search(r'^DOCKER_CE_VERSION="\$\{DOCKER_CE_VERSION:-([0-9.]+)\}"', PREPARE, re.MULTILINE)
    assert m, "prepare-host.sh must declare DOCKER_CE_VERSION with a default"
    return m.group(1)


def test_the_pin_is_a_validated_version() -> None:
    assert pinned_version() in doctor.VALIDATED_DOCKER_VERSIONS


def test_prepare_host_never_installs_an_unpinned_engine() -> None:
    installs = re.findall(r"apt-get install[^\n]*docker-ce[^\n]*", PREPARE)
    assert installs, "the Docker install line moved — update this test"
    for line in installs:
        assert '"docker-ce=${docker_pkg_ver}"' in line and '"docker-ce-cli=${docker_pkg_ver}"' in line, line
    assert "apt-mark hold docker-ce docker-ce-cli" in PREPARE, "the Engine must be held after install"


def test_a_missing_pinned_version_fails_loudly() -> None:
    i = PREPARE.index('if [ -z "$docker_pkg_ver" ]; then')
    assert "fixfail" in PREPARE[i:i + 400], "an unavailable pin must be a reported failure, never a fallback to latest"


def test_doctor_classifies_engine_versions() -> None:
    cases = {
        pinned_version(): "ok",
        "29.5.0": "problem",       # broken flush (fixed in 29.5.1)
        "22.06.0": "problem",      # pre-23: no flush for published UDP ports
        "20.10.24": "problem",
        "29.9.3": "warn",          # works upstream, not validated
        "24.0.7": "warn",
        "not-a-version": "unknown",
    }
    for version, want in cases.items():
        assert doctor.classify_docker_version(version)[0] == want, version


def test_doctor_problem_and_warn_always_carry_a_remedy() -> None:
    for version in ("29.5.0", "20.10.24", "29.9.3"):
        status, summary, remedy = doctor.classify_docker_version(version)
        assert summary and "validated Docker Engine" in remedy, (version, status)
