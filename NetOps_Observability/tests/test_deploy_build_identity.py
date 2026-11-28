# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix
"""deploy.sh stamps the build identity (GIT_SHA, BUILD_TIME) before building.

2026-11-28: every lab api image reported buildSHA=unknown — compose passes
${GIT_SHA:-unknown} to the Dockerfile but deploy.sh never set it, and the stack
watchdog raised "BUILD UNIDENTIFIED" on each run.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEPLOY = (ROOT / "scripts" / "deploy.sh").read_text()


def test_git_sha_and_build_time_are_exported_before_the_build() -> None:
    build_at = DEPLOY.index('dc build "${SERVICES[@]}"')
    head = DEPLOY[:build_at]
    assert "export GIT_SHA" in head, "GIT_SHA must be exported before the build"
    assert re.search(r"export BUILD_TIME=", head), "BUILD_TIME must be exported before the build"
    assert 'git -C "$ROOT" rev-parse HEAD' in head


def test_an_operator_supplied_sha_wins_and_a_git_failure_is_said() -> None:
    block = DEPLOY[DEPLOY.index("# Build identity"):DEPLOY.index('dc build "${SERVICES[@]}"')]
    assert 'if [ -z "${GIT_SHA:-}" ]' in block, "an explicit GIT_SHA must not be overwritten"
    assert "warn " in block and "GIT_SHA=unknown" in block, "a git failure warns, never silently"


def test_compose_passes_the_identity_to_the_backend_build() -> None:
    compose = (ROOT / "deployment" / "docker" / "docker-compose.yml").read_text()
    assert "GIT_SHA: ${GIT_SHA:-unknown}" in compose
    assert "BUILD_TIME: ${BUILD_TIME:-unknown}" in compose
