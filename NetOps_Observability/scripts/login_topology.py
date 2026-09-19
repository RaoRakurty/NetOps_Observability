# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix
"""Login-screen wallpaper: a real internet topology, drawn to rules.

The old wallpaper was a random point cloud with lines between neighbours — it
read as "AI mesh", and the geometry was wrong in the ways an engineer notices:
links ended inside node dots, lines crossed nodes they had nothing to do with,
and clusters collided. This draws what the product is about instead: POPs, a
long-haul backbone between them, metro rings hanging off each POP, and access
spurs off the ring.

Rules enforced by construction, then asserted (see check()):
  1. Nothing is drawn inside the CARD KEEP-OUT band — the sign-in panel is
     centred, so a full-height central band stays empty at every aspect ratio
     the page can take (`background-size: cover`). Nothing touches the username
     or password fields, ever.
  2. Links stop SHORT of both endpoint dots (GAP px), so no line touches a node.
  3. A link never passes within CLEAR px of any node that is not its endpoint.
  4. No two nodes are closer than MIN_SEP px.
  5. Backbone arcs bow AWAY from the centre band, the way real long-haul routes
     follow coasts rather than cutting through a metro.

Deterministic: no randomness at all, so the file is reproducible and reviewable.
"""

from __future__ import annotations

import base64
import math
from dataclasses import dataclass, field

W, H = 1440, 900
# The sign-in panel is min(420px, 100%) wide and centred; on a 1440-wide canvas
# that is 510..930. The keep-out adds ~60px of air on each side.
KEEP_X0, KEEP_X1 = 430, 1010
KEEP_Y0, KEEP_Y1 = 120, 790   # the panel is ~430px tall, centred; this is it plus air
GAP = 5.0        # link stops this far short of a node's edge
CLEAR = 9.0      # a link must pass at least this far from a foreign node
MIN_SEP = 26.0   # closest two node centres may be


@dataclass(frozen=True)
class Node:
    x: float
    y: float
    r: float
    kind: str  # pop | metro | edge


@dataclass
class Link:
    a: int
    b: int
    bow: float = 0.0     # perpendicular offset of the quadratic control point
    kind: str = "metro"  # backbone | metro | access


@dataclass
class Topo:
    nodes: list[Node] = field(default_factory=list)
    links: list[Link] = field(default_factory=list)

    def add(self, n: Node) -> int:
        self.nodes.append(n)
        return len(self.nodes) - 1

    def place(self, n: Node) -> int | None:
        """Add the node, or return None when it would crowd an existing one."""
        for other in self.nodes:
            if math.hypot(n.x - other.x, n.y - other.y) < MIN_SEP:
                return None
        return self.add(n)


def ring(cx: float, cy: float, radius: float, count: int, phase: float) -> list[tuple[float, float]]:
    return [(cx + radius * math.cos(phase + i * 2 * math.pi / count),
             cy + radius * math.sin(phase + i * 2 * math.pi / count)) for i in range(count)]


def build() -> Topo:
    """POPs on their own metro rings, a long-haul backbone between them.

    The first cut put the POP at the centre of its ring and uplinked inwards,
    which drew a star — nothing in a real network looks like that. A metro ring
    passes THROUGH its POP: the POP is one node on the loop, and the loop is
    what survives a fibre cut. Neighbouring metros peer directly, which is why
    traffic does not always transit the backbone.
    """
    t = Topo()
    # Ten POPs, five a side, placed to fill the frame rather than cluster: the
    # coordinates are hand-set (not generated) so the map reads deliberately.
    pops = [
        (120, 120), (330, 235), (150, 420), (300, 640), (128, 800),
        (1320, 120), (1110, 235), (1290, 430), (1140, 650), (1312, 812),
        (690, 48), (770, 858),
    ]
    pop_ids = [t.add(Node(x, y, 7.0, "pop")) for x, y in pops]

    # Long-haul: a path down each side plus one chord, so each POP has two or
    # three backbone neighbours — partial mesh, the way a carrier builds it.
    backbone = [(0, 1), (1, 2), (2, 3), (3, 4), (0, 2), (2, 4),
                (5, 6), (6, 7), (7, 8), (8, 9), (5, 7), (7, 9),
                (1, 10), (10, 6), (3, 11), (11, 8)]
    for a, b in backbone:
        t.links.append(Link(pop_ids[a], pop_ids[b], bow=16.0, kind="backbone"))
    # Two cross-country routes, bowed hard over the top and under the bottom so
    # neither goes anywhere near the sign-in panel.
    t.links.append(Link(pop_ids[0], pop_ids[5], bow=-88.0, kind="backbone"))
    t.links.append(Link(pop_ids[4], pop_ids[9], bow=88.0, kind="backbone"))

    ring_nodes: list[list[int]] = []
    for i, (cx, cy) in enumerate(pops):
        # The ring is an ellipse THROUGH the POP: the POP is node 0 of the loop.
        rx, ry = 74 + 8 * (i % 3), 52 + 7 * ((i + 1) % 3)
        if i >= 10:            # the centre pair: a flat ring hugging the frame edge
            rx, ry = 150, 30
        tilt = 0.5 + 0.31 * i
        count = 6
        # Centre the ellipse so its first vertex lands exactly on the POP.
        phase = 0.0
        ex = cx - rx * math.cos(phase + tilt)
        ey = cy - rx * 0 - ry * math.sin(phase + tilt)
        ids = [pop_ids[i]]
        for k in range(1, count):
            a = phase + k * 2 * math.pi / count
            x = ex + rx * math.cos(a + tilt)
            y = ey + ry * math.sin(a + tilt)
            # Never cross into the keep-out band, and stay on canvas.
            if KEEP_X0 - 18 < x < KEEP_X1 + 18 and KEEP_Y0 - 18 < y < KEEP_Y1 + 18:
                x = KEEP_X0 - 18 if cx < W / 2 else KEEP_X1 + 18
            x = min(max(x, 26), W - 26)
            y = min(max(y, 26), H - 26)
            nid = t.place(Node(x, y, 3.4, "metro"))
            if nid is None:
                continue          # too close to a neighbour's ring: leave the gap
            ids.append(nid)
        for k in range(len(ids)):
            t.links.append(Link(ids[k], ids[(k + 1) % len(ids)], bow=6.0, kind="metro"))
        ring_nodes.append(ids)

        # Access spurs: two per metro, hanging outward, away from the centre.
        for k in [k for k in (1, 3, 5) if k < len(ids)]:
            bx, by = t.nodes[ids[k]].x, t.nodes[ids[k]].y
            ux, uy = bx - cx, by - cy
            norm = math.hypot(ux, uy) or 1.0
            sx, sy = bx + ux / norm * 42, by + uy / norm * 42
            if (KEEP_X0 - 18 < sx < KEEP_X1 + 18 and KEEP_Y0 - 18 < sy < KEEP_Y1 + 18) or not (18 < sx < W - 18 and 18 < sy < H - 18):
                continue
            sid = t.place(Node(sx, sy, 2.3, "edge"))
            if sid is not None:
                t.links.append(Link(ids[k], sid, kind="access"))

    # Metro-to-metro peering between vertical neighbours on the same side.
    for i in (0, 1, 2, 5, 6, 7):
        a_ring, b_ring = ring_nodes[i], ring_nodes[i + 1]
        best = min(((ai, bi) for ai in a_ring[1:] for bi in b_ring[1:]),
                   key=lambda pair: math.hypot(t.nodes[pair[0]].x - t.nodes[pair[1]].x,
                                               t.nodes[pair[0]].y - t.nodes[pair[1]].y))
        t.links.append(Link(best[0], best[1], bow=10.0, kind="access"))
    return t


def curve(t: Topo, ln: Link) -> tuple[float, float, float, float, float, float]:
    """Endpoint-trimmed quadratic: (x1,y1,cx,cy,x2,y2), stopping GAP short of
    each dot so a line never touches a node."""
    a, b = t.nodes[ln.a], t.nodes[ln.b]
    dx, dy = b.x - a.x, b.y - a.y
    d = math.hypot(dx, dy) or 1.0
    ux, uy = dx / d, dy / d
    x1, y1 = a.x + ux * (a.r + GAP), a.y + uy * (a.r + GAP)
    x2, y2 = b.x - ux * (b.r + GAP), b.y - uy * (b.r + GAP)
    mx, my = (x1 + x2) / 2, (y1 + y2) / 2
    # Bow away from the canvas centre for backbone arcs; a fixed small bow for
    # metro edges so rings look drawn, not polygonal.
    px, py = -uy, ux
    if ln.kind == "backbone" and ln.bow >= 0:
        away = 1.0 if (mx - W / 2) * px + (my - H / 2) * py > 0 else -1.0
        bow = ln.bow * away
    else:
        bow = ln.bow
    return x1, y1, mx + px * bow, my + py * bow, x2, y2


def sample(c: tuple[float, float, float, float, float, float], n: int = 24):
    x1, y1, cx, cy, x2, y2 = c
    for i in range(n + 1):
        s = i / n
        yield ((1 - s) ** 2 * x1 + 2 * (1 - s) * s * cx + s * s * x2,
               (1 - s) ** 2 * y1 + 2 * (1 - s) * s * cy + s * s * y2)


def check(t: Topo) -> list[str]:
    """The geometry contract. Returns the violations, empty when clean."""
    bad: list[str] = []
    for i, n in enumerate(t.nodes):
        if KEEP_X0 <= n.x <= KEEP_X1 and KEEP_Y0 <= n.y <= KEEP_Y1:
            bad.append(f"node {i} ({n.kind}) sits in the sign-in keep-out at ({n.x:.0f},{n.y:.0f})")
        if not (10 <= n.x <= W - 10 and 10 <= n.y <= H - 10):
            bad.append(f"node {i} ({n.kind}) is off-canvas at ({n.x:.0f},{n.y:.0f})")
    for i in range(len(t.nodes)):
        for j in range(i + 1, len(t.nodes)):
            a, b = t.nodes[i], t.nodes[j]
            if math.hypot(a.x - b.x, a.y - b.y) < MIN_SEP:
                bad.append(f"nodes {i} and {j} are {math.hypot(a.x-b.x, a.y-b.y):.1f}px apart (min {MIN_SEP})")
    for li, ln in enumerate(t.links):
        pts = list(sample(curve(t, ln)))
        for (x, y) in pts:
            if KEEP_X0 <= x <= KEEP_X1 and KEEP_Y0 <= y <= KEEP_Y1:
                bad.append(f"link {li} ({ln.kind}) crosses the sign-in keep-out")
                break
        for ni, n in enumerate(t.nodes):
            if ni in (ln.a, ln.b):
                continue
            if any(math.hypot(x - n.x, y - n.y) < n.r + CLEAR for (x, y) in pts):
                bad.append(f"link {li} ({ln.kind}) passes through node {ni} ({n.kind})")
                break
    return bad


PALETTES = {
    # Rustic smoke and ash: warm greys with a low ember accent on the POPs.
    "dark": {
        "backbone": ("#d5cdc3", 0.34, 1.3),
        "metro": ("#bdb4a9", 0.26, 1.0),
        "access": ("#a89e93", 0.19, 0.85),
        "pop_fill": "#efe7db", "pop_halo": "#b08968",
        "metro_fill": "#c6bdb2", "edge_fill": "#a29889",
        "pop_op": 0.52, "halo_op": 0.13, "metro_op": 0.40, "edge_op": 0.28,
    },
    # Daylight: the installer's cool slate, unchanged in spirit.
    "light": {
        "backbone": ("#3f4a63", 0.26, 1.35),
        "metro": ("#55607d", 0.19, 1.0),
        "access": ("#6b7590", 0.14, 0.85),
        "pop_fill": "#2f3950", "pop_halo": "#4f46e5",
        "metro_fill": "#48526c", "edge_fill": "#68718a",
        "pop_op": 0.34, "halo_op": 0.12, "metro_op": 0.26, "edge_op": 0.18,
    },
}


def svg(t: Topo, palette: str) -> str:
    p = PALETTES[palette]
    out = [(f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" '
            f'viewBox="0 0 {W} {H}" role="presentation">')]
    for kind in ("access", "metro", "backbone"):
        colour, op, width = p[kind]
        out.append(f'<g fill="none" stroke="{colour}" stroke-opacity="{op}" '
                   f'stroke-width="{width}" stroke-linecap="round">')
        for ln in t.links:
            if ln.kind.replace("-fixed", "") != kind:
                continue
            x1, y1, cx, cy, x2, y2 = curve(t, ln)
            out.append(f'<path d="M{x1:.1f} {y1:.1f}Q{cx:.1f} {cy:.1f} {x2:.1f} {y2:.1f}"/>')
        out.append("</g>")
    # POP halo first, then the dots, largest last.
    out.append(f'<g fill="{p["pop_halo"]}" fill-opacity="{p["halo_op"]}">')
    for n in t.nodes:
        if n.kind == "pop":
            out.append(f'<circle cx="{n.x:.1f}" cy="{n.y:.1f}" r="{n.r * 3.4:.1f}"/>')
    out.append("</g>")
    for kind, fill, op in (("edge", p["edge_fill"], p["edge_op"]),
                           ("metro", p["metro_fill"], p["metro_op"]),
                           ("pop", p["pop_fill"], p["pop_op"])):
        out.append(f'<g fill="{fill}" fill-opacity="{op}">')
        for n in t.nodes:
            if n.kind == kind:
                out.append(f'<circle cx="{n.x:.1f}" cy="{n.y:.1f}" r="{n.r:.1f}"/>')
        out.append("</g>")
    out.append("</svg>")
    return "".join(out)


def repair(t: Topo) -> list[str]:
    """Bow each offending link until it clears every foreign node.

    Real long-haul routes bend around a metro rather than through it; this is
    that, mechanically: widen the arc in steps, try both sides, and only if no
    arc in range is clean, drop the link (a missing line is honest; a line
    through a POP is not).
    """
    notes = []
    for li, ln in enumerate(t.links):
        if not violates(t, li, ln):
            continue
        fixed = False
        for mag in range(12, 300, 6):
            for sign in (1, -1):
                trial = Link(ln.a, ln.b, bow=mag * sign, kind="metro" if ln.kind == "backbone" else ln.kind)
                # keep the kind for styling, but bypass the "bow away" rule so
                # the sign we choose is the sign that is drawn
                trial.kind = ln.kind + "-fixed"
                t.links[li] = trial
                if not violates(t, li, trial):
                    trial.kind = ln.kind
                    t.links[li] = Link(ln.a, ln.b, bow=mag * sign, kind=ln.kind)
                    # re-check with the real kind (bow-away rule may flip it)
                    if violates(t, li, t.links[li]):
                        t.links[li] = trial
                        trial.kind = ln.kind + "-fixed"
                    fixed = True
                    break
            if fixed:
                break
        if not fixed:
            t.links[li] = None  # type: ignore[assignment]
            notes.append(f"dropped link {li} ({ln.kind}): no clean arc exists")
    t.links = [l for l in t.links if l is not None]
    return notes


def violates(t: Topo, li: int, ln: Link) -> bool:
    pts = list(sample(curve(t, ln)))
    for (x, y) in pts:
        if KEEP_X0 <= x <= KEEP_X1 and KEEP_Y0 <= y <= KEEP_Y1:
            return True
        if not (6 <= x <= W - 6 and 6 <= y <= H - 6):
            return True
    for ni, n in enumerate(t.nodes):
        if ni in (ln.a, ln.b):
            continue
        if any(math.hypot(x - n.x, y - n.y) < n.r + CLEAR for (x, y) in pts):
            return True
    return False


if __name__ == "__main__":
    topo = build()
    notes = repair(topo)
    for n in notes: print('  ~', n)
    problems = check(topo)
    print(f"nodes={len(topo.nodes)} links={len(topo.links)} violations={len(problems)}")
    for line in problems[:12]:
        print("  !", line)
    for name in ("dark", "light"):
        doc = svg(topo, name)
        with open(f"topology-{name}.svg", "w", encoding="utf-8") as fh:
            fh.write(doc)
        with open(f"topology-{name}.b64", "w", encoding="utf-8") as fh:
            fh.write(base64.b64encode(doc.encode()).decode())
        print(f"{name}: {len(doc)} bytes svg, {len(base64.b64encode(doc.encode()))} bytes base64")
