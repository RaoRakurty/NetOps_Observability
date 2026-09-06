"""The root `.dockerignore` must never hide a path a Dockerfile COPYs.

Eight compose services build with `context: ../..`, which resolves to the
project root — so one `.dockerignore` there filters the context of all of them
(tracker #193). That file is the cheapest possible thing to get wrong: an
exclusion that also matches a COPY source does not fail the build loudly at the
line that caused it, it produces an image that is missing a file, or a `COPY`
that fails hundreds of lines later with "not found" and no hint that an ignore
rule ate it. The two most dangerous entries are exactly the ones a reasonable
person would add first — `dist` and `build` — because `src/frontend/dist` and
`docs-portal/build` are BUILD OUTPUT that the frontend image ships.

So this is a static, dockerless contract over the committed files:

  * every non-`--from` COPY source in every root-context Dockerfile survives
    the ignore rules (the source itself AND every one of its parents, which is
    how Docker actually decides);
  * the rules that earn the file its place are present and DO match — data/,
    backups/, .git, the generated `.env`, python caches, stray Go binaries;
  * `src/frontend/dist` and `docs-portal/build` are called out by name, because
    a future "ignore all dist" edit is the specific regression this guards.

The matcher below implements Docker's own semantics (moby/patternmatcher):
`*` does not cross `/`, `**` matches any number of segments, later patterns win,
`!` re-includes, and a path is excluded when it OR ANY PARENT matches.

Run:  python3 -m pytest tests/test_dockerignore_copy_sources.py -v
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
DOCKERIGNORE = ROOT / ".dockerignore"
COMPOSE = ROOT / "deployment" / "docker" / "docker-compose.yml"


# ── Docker's ignore-pattern semantics ────────────────────────────────────────


def _pattern_to_regex(pattern: str) -> re.Pattern[str]:
    """Translate one .dockerignore pattern into a full-match regex.

    Mirrors moby/patternmatcher: `**` spans separators, `*` and `?` do not,
    everything else is literal.
    """
    out = ["^"]
    i = 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "*":
            if pattern.startswith("**", i):
                i += 2
                if pattern.startswith("/", i):  # `**/` may also match nothing
                    i += 1
                    out.append("(?:.*/)?")
                else:
                    out.append(".*")
                continue
            out.append("[^/]*")
        elif ch == "?":
            out.append("[^/]")
        else:
            out.append(re.escape(ch))
        i += 1
    out.append("$")
    return re.compile("".join(out))


class DockerIgnore:
    def __init__(self, text: str) -> None:
        self.rules: list[tuple[bool, str, re.Pattern[str]]] = []
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            negated = line.startswith("!")
            if negated:
                line = line[1:].strip()
            line = line.lstrip("/").rstrip("/")
            if not line or line == ".":
                continue
            self.rules.append((negated, line, _pattern_to_regex(line)))

    def matches(self, path: str) -> bool:
        """True when `path` itself is excluded (last matching rule wins)."""
        excluded = False
        for negated, _, rx in self.rules:
            if rx.match(path):
                excluded = not negated
        return excluded

    def excluded(self, path: str) -> tuple[bool, str]:
        """Docker's real question: is this path, or any parent, excluded?"""
        parts = Path(path).parts
        for i in range(1, len(parts) + 1):
            prefix = "/".join(parts[:i])
            if self.matches(prefix):
                culprit = next(
                    pat for neg, pat, rx in reversed(self.rules) if rx.match(prefix) and not neg
                )
                return True, f"{prefix!r} matched by {culprit!r}"
        return False, ""


@pytest.fixture(scope="module")
def ignore() -> DockerIgnore:
    assert DOCKERIGNORE.is_file(), (
        ".dockerignore is missing from the build-context root — eight services "
        "build with `context: ../..` and would ship the whole tree to the daemon"
    )
    return DockerIgnore(DOCKERIGNORE.read_text())


# ── the Dockerfiles whose context is this directory ──────────────────────────


def root_context_dockerfiles() -> list[tuple[str, Path]]:
    """(service, Dockerfile path) for every compose service built from here."""
    with COMPOSE.open() as fh:
        compose = yaml.safe_load(fh)
    out: list[tuple[str, Path]] = []
    for name, svc in (compose.get("services") or {}).items():
        build = svc.get("build")
        if not isinstance(build, dict) or build.get("context") != "../..":
            continue
        dockerfile = ROOT / build["dockerfile"]
        assert dockerfile.is_file(), f"{name}: {dockerfile} does not exist"
        out.append((name, dockerfile))
    return out


COPY_RE = re.compile(r"^\s*(?:COPY|ADD)\s+(.*)$", re.IGNORECASE)

# COPY sources that are BUILD OUTPUT: present only after `npm run build` /
# the docs build, so a fresh checkout legitimately lacks them. They must still
# never be dockerignored — that is what the dedicated test below asserts.
BUILD_OUTPUT_SOURCES = {"src/frontend/dist", "docs-portal/build"}


def copy_sources(dockerfile: Path) -> list[str]:
    """Context-relative sources of every COPY/ADD that reads the context.

    `COPY --from=<stage>` reads another stage, not the context, so it is skipped.
    """
    sources: list[str] = []
    for line in dockerfile.read_text().splitlines():
        m = COPY_RE.match(line)
        if not m:
            continue
        args = m.group(1)
        flags = re.findall(r"--\S+", args)
        if any(f.startswith("--from=") for f in flags):
            continue
        rest = re.sub(r"--\S+\s*", "", args).strip()
        parts = rest.split()
        if len(parts) < 2:  # malformed / JSON form — nothing to check
            continue
        for src in parts[:-1]:  # the last token is the destination
            sources.append(src.strip('"').lstrip("./").rstrip("/"))
    return sources


def test_eight_services_share_this_context() -> None:
    """The premise of the file: this is not a one-service concern."""
    services = [name for name, _ in root_context_dockerfiles()]
    assert len(services) == 8, f"root-context services changed: {services}"


@pytest.mark.parametrize("service,dockerfile", root_context_dockerfiles(), ids=lambda v: str(v))
def test_no_copy_source_is_ignored(service: str, dockerfile: Path, ignore: DockerIgnore) -> None:
    for src in copy_sources(dockerfile):
        if any(ch in src for ch in "*?["):  # a glob source: check its directory
            src = str(Path(src).parent)
            if src in (".", ""):
                continue
        excluded, why = ignore.excluded(src)
        assert not excluded, (
            f"{service} ({dockerfile.name}) COPYs {src!r}, but .dockerignore "
            f"removes it from the build context: {why}"
        )
        if src not in BUILD_OUTPUT_SOURCES:
            assert (ROOT / src).exists(), (
                f"{service} ({dockerfile.name}) COPYs {src!r}, which is not in "
                "the checkout — a COPY of a path that does not exist"
            )


def test_build_output_the_images_ship_is_never_ignored(ignore: DockerIgnore) -> None:
    """The specific regression: 'ignore dist/build artefacts' eating the SPA.

    Both paths are gitignored build output that the frontend image COPYs, so
    neither may be dockerignored no matter how tempting the pattern looks.
    """
    for path in ("src/frontend/dist", "docs-portal/build"):
        excluded, why = ignore.excluded(path)
        assert not excluded, f"{path} is shipped by the frontend image but ignored: {why}"


def test_the_expensive_and_unsafe_paths_are_ignored(ignore: DockerIgnore) -> None:
    """The file has to actually do its job, not just exist."""
    must_ignore = [
        "data",                              # live OpenSearch/ClickHouse/VM state (double-digit GB)
        "data/opensearch/nodes/0/indices",
        "backups",                           # pre-cutover snapshots — contain live secrets
        ".git",
        ".claude",
        "deployment/docker/.env",            # generated: every stack credential
        "deployment/docker/.env.rotate.bak",
        "src/correlation/__pycache__",       # stale host .pyc shipped into the image
        "src/correlation/__pycache__/main.cpython-312.pyc",
        "src/correlation/.pytest_cache",
        "src/backend/api",                   # stray `go build -o api` output (40+ MB)
        "docs-portal/node_modules",
        "scripts/stack-watchdog.log",
    ]
    for path in must_ignore:
        excluded, _ = ignore.excluded(path)
        assert excluded, f"{path} should never reach the daemon, but .dockerignore lets it through"


def test_vendored_go_modules_stay_in_the_context(ignore: DockerIgnore) -> None:
    """The Go build is offline: `src/backend/vendor` is a build input, not junk."""
    for path in ("src/backend/vendor", "src/backend/vendor/golang.org/x/crypto/ssh"):
        excluded, why = ignore.excluded(path)
        assert not excluded, f"{path} is required for the offline Go build but ignored: {why}"

# ── what the rules remove from INSIDE a copied tree ──────────────────────────
#
# `COPY src/backend/ ./` and `COPY src/correlation/ ./` copy whole trees, so an
# ignore rule that matches a file INSIDE one of them changes what the image
# gets. That is intended for exactly two classes — host caches and build
# artefacts, which are stale or wrong inside a container — and must never reach
# a source file. (Measured when this landed: 497 files / 46.8 MB of Python
# caches left the correlation image, taking its /app from 853 files and 53 MB to
# 356 files and 7 MB, with 441 stale host .pyc files among them; the Go builder
# stopped receiving a 42 MB stray `go build -o api` binary. No source file moved.)

CACHE_DIRS = {"__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".venv", "node_modules", "build"}
BUILD_ARTEFACTS = {"src/backend/api", "src/backend/backend"}
COPIED_TREES = (
    "src/backend",
    "src/correlation",
    "src/frontend/dist",
    "docs-portal/build",
    "deployment/docker/mock-nms",
    "deployment/docker/mock-servicenow",
    "deployment/docker/swtpm-sidecar",
)


@pytest.mark.parametrize("tree", COPIED_TREES)
def test_only_caches_and_artefacts_are_removed_from_copied_trees(tree: str, ignore: DockerIgnore) -> None:
    base = ROOT / tree
    if not base.is_dir():  # docs-portal/build only exists after a docs build
        pytest.skip(f"{tree} not built in this checkout")
    for path in base.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(ROOT).as_posix()
        excluded, why = ignore.excluded(rel)
        if not excluded:
            continue
        parts = set(rel.split("/"))
        assert (parts & CACHE_DIRS) or rel in BUILD_ARTEFACTS or rel.endswith(".test"), (
            f"{rel} is inside a COPY'd tree and would be removed from the image "
            f"({why}) — ignore rules may drop caches and build artefacts, never sources"
        )


def test_go_build_inputs_survive(ignore: DockerIgnore) -> None:
    """The api/prober image compiles offline from src/backend: no input may vanish."""
    backend = ROOT / "src" / "backend"
    for name in ("go.mod", "go.sum", "main.go", "identity_handlers.go", "cmd/api/main.go",
                 "vendor/modules.txt", "internal/apikey/store.go"):
        rel = (backend / name).relative_to(ROOT).as_posix()
        assert (ROOT / rel).exists(), f"{rel} missing from the checkout"
        excluded, why = ignore.excluded(rel)
        assert not excluded, f"{rel} is a Go build input but is dockerignored: {why}"
