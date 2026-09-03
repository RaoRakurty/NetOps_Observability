"""ONE Go toolchain version, pinned in every place that builds Go.

WHY (2026-09-03). The 2026-09-02 raise 1.25.13 -> 1.26.8 (x/crypto v0.56.0 for
GO-2026-6354/6355, x/crypto/ssh DoS) landed in `src/backend/go.mod`, in
`backend-ci.yml`'s `GO_VERSION`, and in `Dockerfile.backend`. It MISSED:

  * `scripts/installer-gui/go.mod`      — still go 1.25.0 / toolchain go1.25.13,
    and this module is compiled into the CUSTOMER BUNDLE by make-installer.sh,
    so a stale pin ships a binary built with an unpatched Go;
  * `deployment/docker/mock-nms/go.mod` and `mock-servicenow/go.mod` — `go 1.25`
    while their Dockerfiles already built on golang:1.26.8-alpine;
  * `.github/workflows/fuzz-nightly.yml` — a HARD-CODED `go-version: '1.26.8'`
    at the step, which happened to be right but is invisible to any sweep that
    looks for `GO_VERSION`.

Every one of those is the same failure mode: the version is written down in N
places and only some of them move. So `src/backend/go.mod` is declared the
SINGLE SOURCE OF TRUTH here and everything else is asserted equal to it.

Two different numbers live in a go.mod and they are not interchangeable:

  go 1.26.0          the LANGUAGE version (minimum toolchain that may build it)
  toolchain go1.26.8 the toolchain actually selected

Both are pinned across modules: a module that declares an older `go` line
compiles under different language semantics than the rest of the tree.

Run:  python3 -m pytest tests/test_toolchain_pin.py -v
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = ROOT.parent  # .github/ lives one level up, beside NetOps_Observability/
BACKEND_GOMOD = ROOT / "src" / "backend" / "go.mod"
WORKFLOWS = REPO_ROOT / ".github" / "workflows"

# Every Go module in the repo. src/backend is the reference; the rest must match.
OTHER_GOMODS = (
    ROOT / "scripts" / "installer-gui" / "go.mod",
    ROOT / "deployment" / "docker" / "mock-nms" / "go.mod",
    ROOT / "deployment" / "docker" / "mock-servicenow" / "go.mod",
)

# Multi-stage builds whose `build` stage compiles this repo's Go.
GO_DOCKERFILES = (
    ROOT / "deployment" / "docker" / "Dockerfile.backend",
    ROOT / "deployment" / "docker" / "mock-nms" / "Dockerfile",
    ROOT / "deployment" / "docker" / "mock-servicenow" / "Dockerfile",
)

_GO_RE = re.compile(r"^go\s+(\d+\.\d+(?:\.\d+)?)\s*$", re.M)
_TOOLCHAIN_RE = re.compile(r"^toolchain\s+go(\d+\.\d+\.\d+)\s*$", re.M)
_FROM_GOLANG_RE = re.compile(r"^FROM\s+golang:(\d+\.\d+\.\d+)-", re.M)
_GO_VERSION_ENV_RE = re.compile(r"^\s*GO_VERSION:\s*'([^']+)'\s*$", re.M)
_GO_VERSION_USE_RE = re.compile(r"^\s*go-version:\s*(.+?)\s*$", re.M)


def _go_directive(path: Path) -> str:
    m = _GO_RE.search(path.read_text())
    assert m, f"{path} has no `go` directive"
    return m.group(1)


def _toolchain(path: Path) -> str:
    m = _TOOLCHAIN_RE.search(path.read_text())
    assert m, (
        f"{path} has no `toolchain` line. Without it the module builds with "
        "whatever Go the host happens to have — the pin is the point."
    )
    return m.group(1)


REF_GO = _go_directive(BACKEND_GOMOD)
REF_TOOLCHAIN = _toolchain(BACKEND_GOMOD)


def test_the_reference_pin_is_a_full_patch_version() -> None:
    """`toolchain go1.26` would float across patch releases — CVEs included."""
    assert re.fullmatch(r"\d+\.\d+\.\d+", REF_TOOLCHAIN), (
        f"src/backend/go.mod toolchain must be a full x.y.z, got {REF_TOOLCHAIN!r}"
    )
    # A toolchain older than the language version cannot build the module.
    ref_go_parts = tuple(int(p) for p in (REF_GO.split(".") + ["0"])[:3])
    tc_parts = tuple(int(p) for p in REF_TOOLCHAIN.split("."))
    assert tc_parts >= ref_go_parts, (
        f"toolchain go{REF_TOOLCHAIN} is older than the `go {REF_GO}` directive"
    )


@pytest.mark.parametrize("path", OTHER_GOMODS, ids=lambda p: str(p.relative_to(ROOT)))
def test_every_module_declares_the_reference_language_version(path: Path) -> None:
    assert path.is_file(), f"{path} is missing — was a module moved?"
    got = _go_directive(path)
    assert got == REF_GO, (
        f"{path.relative_to(ROOT)} declares `go {got}` but src/backend/go.mod "
        f"declares `go {REF_GO}`. A toolchain raise must move every module or "
        "the stragglers compile under different language semantics."
    )


@pytest.mark.parametrize("path", OTHER_GOMODS, ids=lambda p: str(p.relative_to(ROOT)))
def test_every_module_pins_the_reference_toolchain(path: Path) -> None:
    got = _toolchain(path)
    assert got == REF_TOOLCHAIN, (
        f"{path.relative_to(ROOT)} pins toolchain go{got}, src/backend/go.mod "
        f"pins go{REF_TOOLCHAIN}. installer-gui in particular is compiled into "
        "the customer bundle — a stale pin ships an unpatched Go."
    )


@pytest.mark.parametrize("path", GO_DOCKERFILES, ids=lambda p: str(p.relative_to(ROOT)))
def test_go_builder_images_match_the_pinned_toolchain(path: Path) -> None:
    assert path.is_file(), f"{path} is missing"
    tags = _FROM_GOLANG_RE.findall(path.read_text())
    assert tags, f"{path.relative_to(ROOT)} has no `FROM golang:x.y.z-` build stage"
    for tag in tags:
        assert tag == REF_TOOLCHAIN, (
            f"{path.relative_to(ROOT)} builds on golang:{tag} but the module "
            f"pins go{REF_TOOLCHAIN} — prod would ship a different Go than CI "
            "tested."
        )


def _workflows_with_go() -> list[Path]:
    if not WORKFLOWS.is_dir():
        pytest.skip(f"{WORKFLOWS} not present in this checkout")
    return sorted(p for p in WORKFLOWS.glob("*.yml") if "setup-go" in p.read_text())


@pytest.mark.parametrize("path", _workflows_with_go(), ids=lambda p: p.name)
def test_workflows_declare_go_version_once_as_an_env(path: Path) -> None:
    """A literal at the step is what let fuzz-nightly drift out of the sweep."""
    text = path.read_text()
    envs = _GO_VERSION_ENV_RE.findall(text)
    assert envs, (
        f"{path.name} sets up Go but declares no `GO_VERSION:` env — pin it "
        "once at the top like backend-ci.yml so a raise is one edit."
    )
    assert len(set(envs)) == 1, f"{path.name} declares GO_VERSION more than once: {envs}"
    for use in _GO_VERSION_USE_RE.findall(text):
        assert "env.GO_VERSION" in use, (
            f"{path.name} hard-codes `go-version: {use}` at a step instead of "
            "referencing ${{ env.GO_VERSION }} — that is exactly how the "
            "2026-09-02 raise missed this file."
        )


@pytest.mark.parametrize("path", _workflows_with_go(), ids=lambda p: p.name)
def test_workflow_go_version_matches_the_module_toolchain(path: Path) -> None:
    (version,) = set(_GO_VERSION_ENV_RE.findall(path.read_text()))
    assert version == REF_TOOLCHAIN, (
        f"{path.name} pins GO_VERSION {version}, src/backend/go.mod pins "
        f"go{REF_TOOLCHAIN}. CI must test the toolchain prod ships."
    )
