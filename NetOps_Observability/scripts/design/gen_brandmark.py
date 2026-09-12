#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Generate the Correlix eye brand mark.

Geometry (viewBox 0 0 512 512):
  - Almond eye, wide open. Lids stroked with the design-system gradient
    (indigo -> cyan -> emerald), same as the current placeholder.
  - Iris = deep space: radial near-black-indigo backdrop holding a seeded
    constellation of ~140 "device" nodes joined by hairline links, denser
    toward the pupil (galactic core), with 4 bright cyan hub nodes.
  - Pupil = dark core with a thin glowing observation ring + a small glint.
  - 7 tapered lashes radiating off the upper lid, graduated lengths.

Outputs:
  - public/favicon.svg              (standalone, fixed colors)
  - src/components/BrandMark.tsx    (React component, gradient ids via useId)
"""
import math, random, sys

rng = random.Random(20260704)

CX, CY = 256.0, 256.0
# Iris deliberately larger than the palpebral opening: both lids crop it
# (sclera shows only as corner wedges) — the single strongest "real human
# eye" cue from the EYE-CORRELIX reference art.
IRIS_R = 118.0
PUPIL_R = 40.0

# ---- constellation ---------------------------------------------------------
N = 165
nodes = []
attempts = 0
while len(nodes) < N and attempts < 20000:
    attempts += 1
    # bias toward the inner annulus (galactic core near the pupil ring)
    t = rng.random() ** 0.65
    r = PUPIL_R + 8 + t * (IRIS_R - PUPIL_R - 16)
    a = rng.random() * 2 * math.pi
    x = CX + r * math.cos(a)
    y = CY + r * math.sin(a)
    # min spacing so it reads as a starfield, not noise
    if all((x - nx) ** 2 + (y - ny) ** 2 > 81 for nx, ny, *_ in nodes):
        size = rng.choice([1.6, 1.9, 2.2, 2.5, 2.9, 3.3])
        roll = rng.random()
        # mostly starlight + cyan/indigo, with a sprinkle of gold — echoes the
        # amber accent nodes (and the gold X) in the EYE-CORRELIX reference
        color = (
            "#e0e7ff" if roll < 0.55
            else "#67e8f9" if roll < 0.78
            else "#a5b4fc" if roll < 0.92
            else "#fbbf24"
        )
        op = round(rng.uniform(0.35, 0.95), 2)
        nodes.append((x, y, size, color, op))

# hubs: 4 bright, well-separated
hubs = []
for _ in range(400):
    if len(hubs) == 4:
        break
    a = rng.random() * 2 * math.pi
    r = rng.uniform(PUPIL_R + 22, IRIS_R - 28)
    x, y = CX + r * math.cos(a), CY + r * math.sin(a)
    if all((x - hx) ** 2 + (y - hy) ** 2 > 4200 for hx, hy in hubs):
        hubs.append((x, y))

# links: each node -> up to 2 nearest neighbours within reach
links = set()
pts = [(x, y) for x, y, *_ in nodes] + hubs
for i, (x1, y1) in enumerate(pts):
    d = sorted(
        ((math.hypot(x1 - x2, y1 - y2), j) for j, (x2, y2) in enumerate(pts) if j != i),
        key=lambda p: p[0],
    )
    for dist, j in d[:2]:
        if dist < 46:
            links.add((min(i, j), max(i, j)))

link_el = []
for i, j in sorted(links):
    x1, y1 = pts[i]
    x2, y2 = pts[j]
    op = round(rng.uniform(0.10, 0.26), 2)
    link_el.append(
        f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" '
        f'stroke="#7dd3fc" stroke-width="1" opacity="{op}"/>'
    )

node_el = []
for x, y, s, c, op in nodes:
    node_el.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{s}" fill="{c}" opacity="{op}"/>')
for k, (x, y) in enumerate(hubs):
    hc = "#fbbf24" if k == 3 else "#22d3ee"  # one gold hub, per the reference art
    node_el.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="8" fill="{hc}" opacity="0.16"/>')
    node_el.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="3.6" fill="{hc}" opacity="0.95"/>')

# ---- lid geometry -----------------------------------------------------------
# Human almond, not a symmetric lens: the inner canthus (left) sits lower and
# the outer canthus rides higher (positive canthal tilt); the upper-lid peak
# is shifted toward the inner corner while the lower lid runs flatter with its
# depth shifted outward — the asymmetries that make a real eye read as real.
INNER = (34, 272)
OUTER = (478, 234)
UP_C1, UP_C2 = (96, 126), (330, 84)     # upper lid: steep inner rise, long outer descent
LO_C1, LO_C2 = (392, 414), (156, 406)   # lower lid: deepest just outboard of centre
EYE_PATH = (
    f"M{INNER[0]} {INNER[1]} "
    f"C {UP_C1[0]} {UP_C1[1]}, {UP_C2[0]} {UP_C2[1]}, {OUTER[0]} {OUTER[1]} "
    f"C {LO_C1[0]} {LO_C1[1]}, {LO_C2[0]} {LO_C2[1]}, {INNER[0]} {INNER[1]} Z"
)

# ---- lashes -----------------------------------------------------------------
# lash roots ride the upper-lid cubic
P0, P1, P2, P3 = INNER, UP_C1, UP_C2, OUTER


def bez(t):
    mt = 1 - t
    x = mt**3 * P0[0] + 3 * mt**2 * t * P1[0] + 3 * mt * t**2 * P2[0] + t**3 * P3[0]
    y = mt**3 * P0[1] + 3 * mt**2 * t * P1[1] + 3 * mt * t**2 * P2[1] + t**3 * P3[1]
    return x, y


def bez_d(t):
    mt = 1 - t
    x = 3 * mt**2 * (P1[0] - P0[0]) + 6 * mt * t * (P2[0] - P1[0]) + 3 * t**2 * (P3[0] - P2[0])
    y = 3 * mt**2 * (P1[1] - P0[1]) + 6 * mt * t * (P2[1] - P1[1]) + 3 * t**2 * (P3[1] - P2[1])
    return x, y


# Flowing lashes: filled tapered blades on cubic S-swept spines. Each lash
# roots wide on the lid, rises with the lid's normal, then sweeps outward
# and over — a calligraphic flick, not a spike. Lean and sweep grow toward
# the corners; lengths breathe a little so the fan feels organic.
def rot(vx, vy, deg):
    r = math.radians(deg)
    c, s = math.cos(r), math.sin(r)
    return vx * c - vy * s, vx * s + vy * c


lrng = random.Random(7)
lash_el = []
# Beauty-brand lash line: a dense fan of fine lashes with a mascara C-curl —
# each lash rises off the lid, then its tip rolls outward toward horizontal,
# longer through the middle, shorter and more curled at the corners.
LASH_N = 12
LASH_T = [0.055 + i * (0.89 / (LASH_N - 1)) for i in range(LASH_N)]
for t in LASH_T:
    u = (t - 0.5) * 2                     # -1 .. 1 across the lash line
    # Human lash-length distribution: shortest at the inner canthus, peaking
    # just outboard of centre, still long at the outer corner.
    v = max(-1.0, min(1.0, (u - 0.3) / 1.3))
    ln = (46 + 30 * math.cos(v * math.pi / 2)) * lrng.uniform(0.95, 1.06)
    w = 5.2 + 1.6 * math.cos(v * math.pi / 2)
    x, y = bez(t)
    # Fan in ABSOLUTE angles (0 = straight up, positive = away from centre):
    # the centre lashes stand tall, tips fan out to ~62deg at the corners —
    # a mascara curl that never rolls past horizontal. The spine bows through
    # three angles (root -> mid -> tip) for the C-shape.
    a0 = u * 20
    a1 = u * 40
    a2 = u * 62

    def ang(a):
        r = math.radians(a)
        return math.sin(r), -math.cos(r)

    d0x, d0y = ang(a0)
    d1x, d1y = ang(a1)
    d2x, d2y = ang(a2)
    c1x, c1y = x + d0x * ln * 0.40, y + d0y * ln * 0.40
    c2x, c2y = x + d1x * ln * 0.75, y + d1y * ln * 0.75
    tx, ty = x + d2x * ln, y + d2y * ln
    # base edge perpendicular to the root direction; blade tapers to a point
    px, py = -d0y, d0x
    b1x, b1y = x - px * w / 2, y - py * w / 2
    b2x, b2y = x + px * w / 2, y + py * w / 2
    e = w * 0.13  # edge offset at the controls — keeps the taper silky
    lash_el.append(
        f'<path d="M{b1x:.1f} {b1y:.1f} '
        f'C{c1x - px * e:.1f} {c1y - py * e:.1f} {c2x - px * e * 0.5:.1f} {c2y - py * e * 0.5:.1f} {tx:.1f} {ty:.1f} '
        f'C{c2x + px * e * 0.5:.1f} {c2y + py * e * 0.5:.1f} {c1x + px * e:.1f} {c1y + py * e:.1f} {b2x:.1f} {b2y:.1f} Z"/>'
    )

# ---- assemble ---------------------------------------------------------------
def svg(defs_prefix, react=False):
    """defs_prefix: string used to namespace gradient ids."""
    a = "stopColor" if react else "stop-color"
    sw = "strokeWidth" if react else "stroke-width"
    sl = "strokeLinejoin" if react else "stroke-linejoin"
    slc = "strokeLinecap" if react else "stroke-linecap"
    cp = "clipPath" if react else "clip-path"
    lid = f"{defs_prefix}Lid"
    space = f"{defs_prefix}Space"
    clip = f"{defs_prefix}Clip"
    eclip = f"{defs_prefix}Eye"
    lashes = "\n      ".join(lash_el).replace("stroke-linecap", slc) if not react else \
             "\n      ".join(lash_el).replace("stroke-linecap", "strokeLinecap")
    links_s = "\n      ".join(link_el)
    nodes_s = "\n      ".join(node_el)
    if react:
        links_s = links_s.replace("stroke-width", "strokeWidth")
    body = f"""
    <defs>
      <linearGradient id="{lid}" x1="37" y1="146" x2="475" y2="366" gradientUnits="userSpaceOnUse">
        <stop offset="0%" {a}="#818cf8"/>
        <stop offset="50%" {a}="#22d3ee"/>
        <stop offset="100%" {a}="#34d399"/>
      </linearGradient>
      <radialGradient id="{space}" cx="0.5" cy="0.5" r="0.5">
        <stop offset="0%" {a}="#05060f"/>
        <stop offset="45%" {a}="#0b1026"/>
        <stop offset="78%" {a}="#312e81"/>
        <stop offset="92%" {a}="#4338ca"/>
        <stop offset="100%" {a}="#6366f1"/>
      </radialGradient>
      <clipPath id="{clip}"><circle cx="256" cy="256" r="{IRIS_R}"/></clipPath>
      <clipPath id="{eclip}"><path d="{EYE_PATH}"/></clipPath>
    </defs>
    <g fill="url(#{lid})">
      {lashes}
    </g>
    <g {cp}="url(#{eclip})">
      <path d="{EYE_PATH}" fill="#cdd9ee" opacity="0.30"/>
      <circle cx="256" cy="256" r="{IRIS_R}" fill="url(#{space})"/>
      <g {cp}="url(#{clip})">
        {links_s}
        {nodes_s}
      </g>
      <circle cx="256" cy="256" r="{IRIS_R}" fill="none" stroke="#22d3ee" {sw}="4" opacity="0.75"/>
      <circle cx="256" cy="256" r="{PUPIL_R}" fill="#05060f"/>
      <circle cx="256" cy="256" r="{PUPIL_R}" fill="none" stroke="#7dd3fc" {sw}="5" opacity="0.95"/>
      <circle cx="256" cy="256" r="{PUPIL_R - 8}" fill="none" stroke="#22d3ee" {sw}="1.5" opacity="0.3"/>
      <circle cx="273" cy="231" r="16" fill="#e0e7ff" opacity="0.22"/>
      <circle cx="273" cy="231" r="9" fill="#f1f5ff" opacity="0.92"/>
    </g>
    <path d="{EYE_PATH}"
      fill="none" stroke="url(#{lid})" {sw}="20" {sl}="round"/>"""
    return body


standalone = f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" fill="none">{svg('cxFav')}
</svg>
"""

react_body = svg("UID", react=True)
react_body = (
    react_body
    .replace('id="UIDLid"', 'id={uid + "Lid"}')
    .replace('id="UIDSpace"', 'id={uid + "Space"}')
    .replace('id="UIDClip"', 'id={uid + "Clip"}')
    .replace('id="UIDEye"', 'id={uid + "Eye"}')
    .replace('stroke="url(#UIDLid)"', 'stroke={"url(#" + uid + "Lid)"}')
    .replace('fill="url(#UIDLid)"', 'fill={"url(#" + uid + "Lid)"}')
    .replace('fill="url(#UIDSpace)"', 'fill={"url(#" + uid + "Space)"}')
    .replace('clipPath="url(#UIDClip)"', 'clipPath={"url(#" + uid + "Clip)"}')
    .replace('clipPath="url(#UIDEye)"', 'clipPath={"url(#" + uid + "Eye)"}')
)

tsx = f"""import {{ useId }} from "react";

// BrandMark — the Correlix eye. A wide-open almond eye whose iris is deep
// space: a seeded constellation of device nodes joined by hairline links
// (denser toward the pupil, four bright hubs), behind a glowing observation
// ring. Lids + lashes keep the design-system indigo->cyan->emerald sweep.
// Generated by scripts/design/gen_brandmark.py — regenerate there, don't
// hand-edit the constellation.
export default function BrandMark({{ size = 26 }}: {{ size?: number }}) {{
  const uid = useId().replace(/:/g, "");
  return (
    <svg viewBox="0 0 512 512" width={{size}} height={{size}} fill="none" aria-hidden="true">{react_body}
    </svg>
  );
}}
"""

with open(sys.argv[1], "w") as f:
    f.write(standalone)
with open(sys.argv[2], "w") as f:
    f.write(tsx)
print(f"nodes={len(nodes)} hubs={len(hubs)} links={len(links)} lashes={len(lash_el)}")
