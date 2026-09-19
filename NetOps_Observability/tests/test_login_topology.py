# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""The login wallpaper is a drawing with rules, and these are the rules.

Owner, 2026-09-16: "There is topology type of image in the background. Enhance
that topology look, geometry doesnt look right. Build connections like real POPs
in the internet, Make it look for real networks." and "Ensure nothing touches the
Username and password box when you are redrawing the topology."

`scripts/login_topology.py` draws POPs on their own metro rings, a long-haul
backbone between them, peering between neighbouring metros and access spurs off
the ring. It is deterministic — no randomness — so the picture embedded in
`styles.css` can be re-derived here and compared byte for byte. Two failures are
therefore impossible to ship: a geometry regression (something touching the
sign-in panel, a line through a node, two nodes on top of each other), and a
hand-edited data URI that no longer matches the generator.

Run:  python3 -m pytest tests/test_login_topology.py -v
"""

from __future__ import annotations

import base64
import importlib.util
import math
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
GEN = ROOT / "scripts" / "login_topology.py"
CSS = ROOT / "src" / "frontend" / "src" / "styles.css"


def _generator():
    spec = importlib.util.spec_from_file_location("login_topology", GEN)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["login_topology"] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def gen():
    return _generator()


@pytest.fixture(scope="module")
def topo(gen):
    t = gen.build()
    gen.repair(t)
    return t


# ── the geometry contract ────────────────────────────────────────────────────

def test_the_drawing_satisfies_its_own_contract(gen, topo):
    violations = gen.check(topo)
    assert violations == [], "\n".join(violations)


def test_nothing_is_drawn_where_the_sign_in_panel_sits(gen, topo):
    """The owner's hard requirement: nothing touches the username/password box."""
    for i, n in enumerate(topo.nodes):
        inside = (gen.KEEP_X0 <= n.x <= gen.KEEP_X1) and (gen.KEEP_Y0 <= n.y <= gen.KEEP_Y1)
        assert not inside, f"node {i} ({n.kind}) is behind the panel at ({n.x:.0f},{n.y:.0f})"
    for li, ln in enumerate(topo.links):
        for (x, y) in gen.sample(gen.curve(topo, ln)):
            inside = (gen.KEEP_X0 <= x <= gen.KEEP_X1) and (gen.KEEP_Y0 <= y <= gen.KEEP_Y1)
            assert not inside, f"link {li} ({ln.kind}) crosses the panel at ({x:.0f},{y:.0f})"


def test_no_line_touches_a_node_it_does_not_belong_to(gen, topo):
    for li, ln in enumerate(topo.links):
        pts = list(gen.sample(gen.curve(topo, ln)))
        for ni, n in enumerate(topo.nodes):
            if ni in (ln.a, ln.b):
                continue
            closest = min(math.hypot(x - n.x, y - n.y) for (x, y) in pts)
            assert closest >= n.r + gen.CLEAR, (
                f"link {li} passes {closest:.1f}px from node {ni} ({n.kind}); needs {n.r + gen.CLEAR:.1f}px")


def test_every_link_stops_short_of_both_of_its_own_dots(gen, topo):
    for li, ln in enumerate(topo.links):
        x1, y1, _, _, x2, y2 = gen.curve(topo, ln)
        a, b = topo.nodes[ln.a], topo.nodes[ln.b]
        assert math.hypot(x1 - a.x, y1 - a.y) >= a.r + gen.GAP - 0.01, f"link {li} starts inside its own node"
        assert math.hypot(x2 - b.x, y2 - b.y) >= b.r + gen.GAP - 0.01, f"link {li} ends inside its own node"


def test_nodes_keep_their_distance(gen, topo):
    for i in range(len(topo.nodes)):
        for j in range(i + 1, len(topo.nodes)):
            a, b = topo.nodes[i], topo.nodes[j]
            d = math.hypot(a.x - b.x, a.y - b.y)
            assert d >= gen.MIN_SEP, f"nodes {i} and {j} are {d:.1f}px apart"


# ── it is a NETWORK, not a point cloud ───────────────────────────────────────

def test_it_is_shaped_like_a_carrier_network(topo):
    kinds = [n.kind for n in topo.nodes]
    assert kinds.count("pop") >= 8, "a backbone needs POPs"
    assert kinds.count("metro") >= 30, "each POP carries a metro ring"
    assert kinds.count("edge") >= 8, "access sites hang off the rings"
    link_kinds = [l.kind for l in topo.links]
    assert link_kinds.count("backbone") >= 10, "POPs must interconnect, not chain"
    assert link_kinds.count("metro") >= 40

    # Every POP sits ON its ring (not at the centre with spokes — that drew a
    # star, which is what "geometry doesnt look right" was about).
    pops = [i for i, n in enumerate(topo.nodes) if n.kind == "pop"]
    for pid in pops:
        ring = [l for l in topo.links if l.kind == "metro" and pid in (l.a, l.b)]
        assert len(ring) == 2, f"POP {pid} has {len(ring)} metro links; a ring gives exactly two"


def test_the_drawing_is_deterministic(gen):
    a, b = gen.build(), gen.build()
    gen.repair(a); gen.repair(b)
    assert gen.svg(a, "dark") == gen.svg(b, "dark")


# ── what ships is what the generator draws ───────────────────────────────────

def _css_uris() -> list[str]:
    return re.findall(r'data:image/svg\+xml;base64,([A-Za-z0-9+/=]+)', CSS.read_text(encoding="utf-8"))


@pytest.mark.parametrize("palette", ["dark", "light"])
def test_styles_css_embeds_exactly_what_the_generator_draws(gen, topo, palette):
    want = base64.b64encode(gen.svg(topo, palette).encode()).decode()
    assert want in _css_uris(), (
        f"the {palette} login wallpaper in styles.css is not the generator's output — "
        "regenerate with: python3 scripts/login_topology.py")
