"""Feature-to-UI coverage guard — every public API route family must have a UI,
or be declared headless-by-design in a checked-in allowlist.

The failure mode this exists to catch (owner, 2026-09-05): "we are building
features but the UI is missing — in that case we are missing all the work we
have done." A backend capability nobody can reach from the product is invisible
work, and nothing in CI noticed when it happened.

The check is mechanical and fail-closed:

  1. Parse the PUBLIC route surface from `src/backend/main.go`
     (`mux.HandleFunc("...")`) unioned with `internal/openapi/openapi.go`.
     `/api/internal/*` is excluded — that subtree is service-to-service by
     definition (vmalert → api).
  2. Parse every `/api/...` string literal out of the frontend sources
     (`src/frontend/src/**/*.ts{,x}`, excluding `*.test.*` — a test fixture is
     not a user surface).
  3. Group both into ROUTE FAMILIES: the first two path segments after `/api`
     (`/api/bgp/watchlist`, `/api/devices`). A family is the granularity a
     "feature" lives at; per-id leaves ride along with their family.
  4. Every backend family must be referenced by the frontend, OR listed in
     `docs/audit/headless-routes.yaml` with a reason.
  5. The reverse: every frontend route literal must be servable by some
     registered backend route (catches a UI calling a route that does not
     exist, or that was renamed out from under it).

Adding a new public route family therefore forces a decision: build the UI, or
write down why it is headless. Both are fine; silence is not.

Run:  python3 -m pytest tests/test_feature_ui_coverage.py -v
"""
import os
import re

import pytest
import yaml

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))

BACKEND_MAIN = os.path.join(ROOT, "src", "backend", "main.go")
BACKEND_OPENAPI = os.path.join(ROOT, "src", "backend", "internal", "openapi", "openapi.go")
FRONTEND_SRC = os.path.join(ROOT, "src", "frontend", "src")
ALLOWLIST = os.path.join(ROOT, "docs", "audit", "headless-routes.yaml")

# Service-to-service subtree: vmalert POSTs its Alertmanager-v2 payload here
# with a shared secret. Never a browser surface, by construction.
INTERNAL_PREFIX = "/api/internal/"

# Family depth: ["api", "<a>", "<b>"] — two segments after /api.
FAMILY_DEPTH = 3


# ── parsing ──────────────────────────────────────────────────────────────────

def _read(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def backend_routes() -> list[str]:
    """Every public /api route pattern the backend registers or documents."""
    routes: set[str] = set()
    for pat in re.findall(r'HandleFunc\(\s*"([^"]+)"', _read(BACKEND_MAIN)):
        routes.add(pat)
    for pat in re.findall(r'"(/api/[^"]*)"', _read(BACKEND_OPENAPI)):
        routes.add(pat)
    return sorted(
        r for r in routes
        if r.startswith("/api/") and not r.startswith(INTERNAL_PREFIX)
    )


def frontend_literals() -> list[tuple[str, str]]:
    """(file, literal) for every /api string literal in non-test frontend source."""
    out: list[tuple[str, str]] = []
    lit_re = re.compile(r"""["'`](/api/[A-Za-z0-9_./{}$-]*)""")
    for dirpath, dirnames, filenames in os.walk(FRONTEND_SRC):
        dirnames[:] = [d for d in dirnames if d != "node_modules"]
        for name in filenames:
            if not name.endswith((".ts", ".tsx")):
                continue
            if ".test." in name or ".spec." in name:
                continue
            path = os.path.join(dirpath, name)
            for lit in lit_re.findall(_read(path)):
                out.append((os.path.relpath(path, ROOT), lit))
    return out


# ── normalisation ────────────────────────────────────────────────────────────
#
# Both sides are reduced to a segment list with "*" standing for a variable
# segment, so `/api/incidents/{id}/tac` (Go mux wildcard) and
# `/api/incidents/${encodeURIComponent(id)}/tac` (TS template) compare equal.

def backend_segments(pattern: str) -> list[str]:
    return [s for s in re.sub(r"\{[^}]*\}", "*", pattern).split("/") if s]


def frontend_segments(literal: str) -> tuple[list[str], bool]:
    """Segments plus a flag: True when the literal was cut short at a `${…}`
    interpolation, i.e. it is a PREFIX of the real request path."""
    idx = literal.find("${")
    truncated = idx != -1
    head = literal[:idx] if truncated else literal
    head = head.split("?")[0]
    segs = [s for s in head.split("/") if s]
    # `/api/protocols/${proto}/summary` → a whole dynamic segment.
    # `/api/cloud/health${qs}`          → a query suffix; the segment stands.
    if truncated and (head.endswith("/") or not head):
        segs.append("*")
    return segs, truncated


def family(segments: list[str]) -> tuple[str, ...]:
    return tuple(segments[:FAMILY_DEPTH])


def as_path(segments) -> str:
    return "/" + "/".join(segments)


# ── allowlist ────────────────────────────────────────────────────────────────

def load_allowlist() -> dict[tuple[str, ...], dict]:
    """route family → entry. Both `headless` and `dynamic` sections suppress
    the coverage failure; they differ in WHY, and the audit keeps them apart."""
    with open(ALLOWLIST, encoding="utf-8") as fh:
        doc = yaml.safe_load(fh) or {}
    out: dict[tuple[str, ...], dict] = {}
    for section in ("headless", "dynamic", "missing_ui"):
        for entry in doc.get(section) or []:
            assert isinstance(entry, dict), f"{section}: entries must be mappings, got {entry!r}"
            route = entry.get("route")
            assert route, f"{section}: an entry is missing `route`: {entry!r}"
            key = family(backend_segments(route))
            assert key not in out, f"duplicate allowlist entry for {route}"
            entry["_section"] = section
            out[key] = entry
    return out


# ── fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def surface():
    be = backend_routes()
    fe = frontend_literals()
    be_segs = [backend_segments(r) for r in be]
    fe_segs = [(f, lit, *frontend_segments(lit)) for f, lit in fe]
    return {
        "backend_routes": be,
        "backend_segments": be_segs,
        "backend_families": sorted({family(s) for s in be_segs}),
        "frontend": fe_segs,  # (file, literal, segments, truncated)
    }


def _referenced(fam: tuple[str, ...], frontend) -> bool:
    """A family is referenced when some frontend literal starts with it."""
    n = len(fam)
    return any(tuple(segs[:n]) == fam for _, _, segs, _ in frontend)


def _servable(segs: list[str], truncated: bool, backend_routes_, backend_segments_) -> bool:
    """Is this frontend path served by some registered backend route?"""
    def compat(a, b):
        return a == b or a == "*" or b == "*"

    for raw, bs in zip(backend_routes_, backend_segments_):
        if raw.endswith("/"):  # Go mux subtree pattern: matches any deeper path
            if len(segs) >= len(bs) and all(compat(x, y) for x, y in zip(segs, bs)):
                return True
        if truncated:  # the literal is a prefix of the real URL
            if len(segs) <= len(bs) and all(compat(x, y) for x, y in zip(segs, bs)):
                return True
        if len(segs) == len(bs) and all(compat(x, y) for x, y in zip(segs, bs)):
            return True
    return False


# ── the guard ────────────────────────────────────────────────────────────────

def test_backend_surface_is_non_trivial(surface):
    """Guard the guard: a parser that silently matches nothing would pass every
    other assertion here."""
    assert len(surface["backend_routes"]) > 200, surface["backend_routes"][:5]
    assert len(surface["backend_families"]) > 150
    assert len(surface["frontend"]) > 200


def test_every_public_route_family_has_a_ui_or_a_written_reason(surface):
    """FAIL CLOSED: a new public route family with no UI must be declared."""
    allow = load_allowlist()
    orphans = []
    for fam in surface["backend_families"]:
        if _referenced(fam, surface["frontend"]):
            continue
        if fam in allow:
            continue
        orphans.append(as_path(fam))
    assert not orphans, (
        "Backend route families with NO frontend reference and no allowlist "
        "entry — build the UI, or add them to docs/audit/headless-routes.yaml "
        "with a reason:\n  " + "\n  ".join(orphans)
    )


def test_allowlist_entries_all_carry_a_reason():
    for fam, entry in load_allowlist().items():
        reason = (entry.get("reason") or "").strip()
        assert len(reason) >= 20, (
            f"{as_path(fam)}: headless-routes.yaml entries need a real reason, got {reason!r}"
        )


def test_allowlist_has_no_stale_entries(surface):
    """An allowlisted family that has since grown a UI, or been deleted, must be
    removed — otherwise the allowlist rots into a blanket exemption."""
    allow = load_allowlist()
    backend = set(surface["backend_families"])
    stale = []
    for fam, entry in allow.items():
        if fam not in backend:
            stale.append(f"{as_path(fam)} (no such backend route family any more)")
        elif entry["_section"] in ("headless", "missing_ui") and _referenced(fam, surface["frontend"]):
            stale.append(f"{as_path(fam)} (the frontend now calls it — drop the entry)")
    assert not stale, "Stale headless-routes.yaml entries:\n  " + "\n  ".join(stale)


# The debt recorded on 2026-09-05. This number is a RATCHET: building a UI for
# one of these removes its entry and lowers the pin. It must never be raised —
# a new gap belongs in `headless` (with a reason) or in a page.
MISSING_UI_BASELINE = 23


def test_missing_ui_debt_only_shrinks():
    """`missing_ui` records backend capability with no user surface. Shipping a
    page removes an entry and lowers MISSING_UI_BASELINE; nothing may be added."""
    with open(ALLOWLIST, encoding="utf-8") as fh:
        doc = yaml.safe_load(fh) or {}
    count = len(doc.get("missing_ui") or [])
    assert count <= MISSING_UI_BASELINE, (
        f"missing_ui grew to {count} (baseline {MISSING_UI_BASELINE}). A new "
        "backend capability with no UI is the exact regression this guard "
        "exists to stop — build the page, or justify it under `headless`."
    )
    if count < MISSING_UI_BASELINE:
        pytest.fail(
            f"missing_ui is down to {count} — lower MISSING_UI_BASELINE to {count} "
            "so the ratchet keeps holding."
        )


def test_no_frontend_call_to_a_route_the_backend_does_not_serve(surface):
    """The reverse leak: a page wired to a route that does not exist (renamed,
    never built, or a typo) is a dead button."""
    broken = []
    for path, lit, segs, truncated in surface["frontend"]:
        if len(segs) < 2:  # bare "/api" — a base-url constant, not a route
            continue
        if _servable(segs, truncated, surface["backend_routes"], surface["backend_segments"]):
            continue
        broken.append(f"{lit}  ({path})")
    assert not broken, (
        "Frontend route literals with no matching backend route:\n  " + "\n  ".join(sorted(set(broken)))
    )
