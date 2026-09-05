// NmsControllerArt.test.tsx — tracker 251 guard.
//
// Correlix identifies an NMS / controller platform by a GENERIC FUNCTIONAL
// glyph plus the vendor's product name as plain text. The retired
// `NmsVendorArt.tsx` did the opposite: a per-vendor MONOGRAM chip ("MK", "CC",
// "SD", "ND", "VD", "VC", "PI") filled with a gradient of that vendor's own
// palette, and a dashboard-preview scene themed in the same palette under a
// window title that imitated the vendor's console. These tests are what keeps
// that gone.
//
// The assertions are SEMANTIC, not path-data snapshots: what an operator sees
// (the right functional glyph, no brand hue, the name still readable, the a11y
// contract) plus a SOURCE SCAN of the whole `src/` tree, because a render-only
// guard passes the moment someone re-themes a mark in a component this file
// does not render — exactly how the connector marks survived the 2026-09-03
// audit sweep (see ConnectorGlyph.test.tsx).

import { describe, it, expect, afterEach } from "vitest";
import { render, cleanup } from "@testing-library/react";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, extname, join, resolve } from "node:path";
import {
  NmsMark,
  NmsDashArt,
  NMS_CONTROLLER_REGISTRY,
  GENERIC_CONTROLLER,
  SCENE_TITLE,
  controllerIcon,
  controllerPresentation,
} from "./NmsControllerArt";
import Icon from "./Icon";

afterEach(cleanup);

/**
 * The seven controllers tracker 251 is about, with the functional category and
 * glyph each must map to. The glyph is a name in components/Icon.tsx — never a
 * per-vendor drawing.
 */
const RETIRED_MONOGRAM_CONTROLLERS = [
  { id: "meraki", name: "Meraki", category: "Wireless controller", icon: "wireless", scene: "wireless" },
  { id: "catalyst_center", name: "Catalyst Center", category: "Campus assurance", icon: "monitoring", scene: "assurance" },
  { id: "vmanage", name: "SD-WAN Manager", category: "SD-WAN controller", icon: "topology", scene: "overlay" },
  { id: "ndfc", name: "Nexus Dashboard", category: "Fabric controller", icon: "infrastructure", scene: "fabric" },
  { id: "versa_director", name: "Versa Director", category: "Secure edge services", icon: "stack", scene: "services" },
  { id: "versa_concerto", name: "Versa Concerto", category: "Multi-tenant orchestration", icon: "automation", scene: "orchestration" },
  { id: "prime", name: "Prime Infrastructure", category: "NMS", icon: "alerts", scene: "alarms" },
] as const;

/**
 * Every hex the retired `NMS_THEMES` table carried — the seven vendor palettes
 * plus the macOS-style window chrome the preview imitated. None may reappear
 * anywhere in `src/`, in any component, under any name.
 */
const VENDOR_PALETTE_HEXES = [
  // meraki
  "#67b346", "#a3e07c", "#0a1f10", "#12341c",
  // catalyst_center
  "#049fd9", "#67d8f5", "#05202e", "#0a3347",
  // vmanage
  "#2f6ef3", "#22d3ee", "#081733", "#0e2a52",
  // ndfc
  "#3b82f6", "#a5c6ff", "#0a1530", "#122548",
  // versa_director
  "#7c3aed", "#c4b5fd", "#150a2e", "#241347",
  // versa_concerto
  "#d946ef", "#f0abfc", "#23092b", "#3a1245",
  // prime
  "#8aa0b8", "#cfdbe8", "#101826", "#1b2a3f",
  // imitation window chrome (traffic lights)
  "#ff5f57", "#febc2e", "#28c840",
];

/**
 * Four of the retired theme hexes were not distinctive brand colours at all —
 * they are generic Tailwind ramp values (`#3b82f6`, `#7c3aed`, `#22d3ee`,
 * `#d946ef`) that the chart, topology and severity layers use legitimately all
 * over the SPA. Scanning the tree for those would fail on unrelated data-viz
 * code and say nothing about a vendor palette coming back, so the SOURCE scan
 * uses the distinctive remainder. Nothing is lost: the RENDER assertions above
 * still forbid all thirty-one in the controller artwork itself, and the symbol,
 * monogram and console-title scans below catch a reintroduced theme table
 * whatever hues it is filled with.
 */
const GENERIC_VIZ_HEXES = ["#3b82f6", "#7c3aed", "#22d3ee", "#d946ef"];
const SCANNED_PALETTE_HEXES = VENDOR_PALETTE_HEXES.filter((h) => !GENERIC_VIZ_HEXES.includes(h));

/** The retired per-vendor monogram strings — a stylised initial IS a mark. */
const RETIRED_MONOGRAMS = ["MK", "CC", "SD", "ND", "VD", "VC", "PI"];

/** Symbols that no longer exist and must not be resurrected. */
const RETIRED_SYMBOLS = ["NMS_THEMES", "MONOGRAM", "NmsVendorArt", "NmsVendorId", "ART_TITLE"];

/**
 * Window titles that imitated a vendor's own console chrome, a product domain
 * included. The replacements name the CLASS of state instead.
 */
const RETIRED_ART_TITLES = [
  "dashboard.meraki.com",
  "Catalyst Center — assurance",
  "SD-WAN Manager — overlay health",
  "Nexus Dashboard — fabric controller",
  "Versa Director — appliance services",
  "Versa Concerto — orchestration",
  "Prime Infrastructure — alarm browser",
];

// ── source tree access ─────────────────────────────────────────────────────

function repoDir(relative: string): string {
  for (let dir = process.cwd(), i = 0; i < 8; i++, dir = dirname(dir)) {
    const candidate = resolve(dir, relative);
    if (existsSync(candidate)) return candidate;
    if (dir === dirname(dir)) break;
  }
  throw new Error(`cannot locate ${relative} from ${process.cwd()} — the trademark guard would be vacuous`);
}

const SRC_ROOT = repoDir("src/components/NmsControllerArt.tsx").replace(
  /\/components\/NmsControllerArt\.tsx$/,
  "",
);

function walk(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    const p = join(dir, entry);
    if (statSync(p).isDirectory()) walk(p, out);
    else out.push(p);
  }
  return out;
}

const ALL_SRC_FILES = walk(SRC_ROOT);
/** Source we scan — this test file states the retired literals itself. */
const SCANNED = ALL_SRC_FILES.filter(
  (f) => [".ts", ".tsx", ".css", ".svg"].includes(extname(f)) && !f.endsWith("NmsControllerArt.test.tsx"),
);
const rel = (f: string) => f.slice(SRC_ROOT.length + 1);

// ── registry ───────────────────────────────────────────────────────────────

describe("NMS controller registry", () => {
  it.each(RETIRED_MONOGRAM_CONTROLLERS)(
    "$name resolves to the generic $icon glyph in category $category",
    ({ id, name, category, icon, scene }) => {
      const p = controllerPresentation(id);
      expect(p.displayName).toBe(name);
      expect(p.category).toBe(category);
      expect(p.icon).toBe(icon);
      expect(p.scene).toBe(scene);
      expect(controllerIcon(id)).toBe(icon);
    },
  );

  it("is case- and whitespace-tolerant about the controller id", () => {
    expect(controllerPresentation("  MeRaKi ").icon).toBe("wireless");
  });

  it("falls back to the generic controller plug — never a broken tile, never another vendor", () => {
    for (const unknown of [undefined, null, "", "   ", "aruba_central", "mist", "<script>"]) {
      const p = controllerPresentation(unknown);
      expect(p, String(unknown)).toEqual(GENERIC_CONTROLLER);
      expect(p.icon).toBe("plug");
      expect(p.scene).toBe("stream");
    }
  });

  it("names every registered controller, states its capability and its category", () => {
    for (const [id, entry] of Object.entries(NMS_CONTROLLER_REGISTRY)) {
      expect(entry.displayName.trim(), id).not.toBe("");
      expect(entry.capability.trim(), id).not.toBe("");
      expect(entry.icon.trim(), id).not.toBe("");
      expect(entry.category.trim(), id).not.toBe("");
    }
  });

  it("categorises by FUNCTION, never by vendor — no category is a product name", () => {
    const categories = new Set(
      Object.values(NMS_CONTROLLER_REGISTRY).map((e) => e.category.toLowerCase()),
    );
    for (const brand of ["meraki", "catalyst", "versa", "prime", "nexus", "cisco", "vmanage"]) {
      for (const c of categories) expect(c, `category "${c}" names a product`).not.toContain(brand);
    }
  });

  it("names every scene for the state it draws, never for a product", () => {
    for (const [scene, title] of Object.entries(SCENE_TITLE)) {
      for (const brand of ["meraki", "catalyst", "versa", "prime", "nexus", "cisco", ".com"]) {
        expect(title.toLowerCase(), `scene "${scene}" title imitates a vendor console`).not.toContain(brand);
      }
    }
  });
});

// ── render ─────────────────────────────────────────────────────────────────

describe("NmsMark render", () => {
  it.each(RETIRED_MONOGRAM_CONTROLLERS)(
    "$name draws the shared functional glyph, not a monogram chip",
    ({ id, icon }) => {
      const mine = render(<NmsMark vendor={id} size={34} />).container.innerHTML;
      cleanup();
      const shared = render(<Icon name={icon} size={34} />).container.innerHTML;
      // Byte-identical to the design-system glyph: there is no per-controller
      // artwork anywhere, only a registry lookup into components/Icon.tsx.
      expect(mine).toBe(shared);
    },
  );

  it.each(RETIRED_MONOGRAM_CONTROLLERS)("$name renders NO vendor colour and NO monogram", ({ id, name }) => {
    const html = render(<NmsMark vendor={id} size={34} />).container.innerHTML;
    const lower = html.toLowerCase();
    for (const hex of VENDOR_PALETTE_HEXES) expect(lower, `${id} rendered ${hex}`).not.toContain(hex);
    for (const mono of RETIRED_MONOGRAMS) expect(html, `${id} rendered the monogram ${mono}`).not.toContain(`>${mono}<`);
    expect(lower).not.toContain("lineargradient");
    expect(lower).not.toContain("<text");
    expect(lower).not.toContain("<image");
    expect(lower).not.toContain("data:image");
    // Colour comes from the theme only — legible in BOTH light and dark, and a
    // brand hue is impossible.
    expect(lower).toContain('stroke="currentcolor"');
    expect(lower).not.toMatch(/(stroke|fill)="#/);
    expect(name.length).toBeGreaterThan(0);
  });

  it("is decorative by default and labelled only on request (a11y)", () => {
    const plain = render(<NmsMark vendor="meraki" />).container.querySelector("svg")!;
    expect(plain.getAttribute("aria-hidden")).toBe("true");
    expect(plain.getAttribute("role")).toBeNull();
    expect(plain.querySelector("title")).toBeNull();
    cleanup();
    const labelled = render(<NmsMark vendor="meraki" label="Meraki controller" />).container.querySelector("svg")!;
    expect(labelled.getAttribute("role")).toBe("img");
    expect(labelled.getAttribute("aria-hidden")).toBeNull();
    expect(labelled.querySelector("title")?.textContent).toBe("Meraki controller");
  });

  it("honours size and className so the existing tile layout is unchanged", () => {
    const svg = render(<NmsMark vendor="vmanage" size={28} className="nms-glyph" />).container.querySelector("svg")!;
    expect(svg.getAttribute("width")).toBe("28");
    expect(svg.getAttribute("height")).toBe("28");
    expect(svg.getAttribute("viewBox")).toBe("0 0 24 24");
    expect(svg.getAttribute("class")).toBe("nms-glyph");
  });

  it("a controller tile still identifies the platform BY NAME, glyph or no glyph", () => {
    const { getByText, container } = render(
      <span className="nms-tile-head">
        <span className="nms-mark"><NmsMark vendor="meraki" size={20} /></span>
        <span className="nms-tile-name">{controllerPresentation("meraki").displayName}</span>
        <span className="nms-tile-domain">{controllerPresentation("meraki").category}</span>
      </span>,
    );
    expect(getByText("Meraki")).toBeTruthy();
    expect(getByText("Wireless controller")).toBeTruthy();
    // Strip the glyph entirely: the tile is still fully identifiable, which is
    // the accessibility requirement (identity never rests on the artwork).
    container.querySelector("svg")!.remove();
    expect(container.textContent).toContain("Meraki");
  });
});

// ── render: the dashboard preview ──────────────────────────────────────────

describe("NmsDashArt render", () => {
  it.each([...RETIRED_MONOGRAM_CONTROLLERS, { id: "unknown-controller", scene: "stream" } as const])(
    "$id draws a functional scene with no vendor palette and no imitated console title",
    ({ id, scene }) => {
      const html = render(<NmsDashArt vendor={id} />).container.innerHTML;
      const lower = html.toLowerCase();
      for (const hex of VENDOR_PALETTE_HEXES) expect(lower, `${id} rendered ${hex}`).not.toContain(hex);
      for (const t of RETIRED_ART_TITLES) expect(html, `${id} rendered the retired title ${t}`).not.toContain(t);
      expect(html, `${id} lost its scene title`).toContain(SCENE_TITLE[scene as keyof typeof SCENE_TITLE]);
      // Every colour in the scene is a theme token; the only literals allowed
      // are the defensive fallbacks INSIDE a var().
      const outsideVars = lower.replace(/var\([^)]*\)/g, "");
      expect(outsideVars, `${id} paints a raw colour outside a token`).not.toMatch(/#[0-9a-f]{3,8}\b/);
    },
  );

  it("is decorative — the tile's text carries the identity", () => {
    const svg = render(<NmsDashArt vendor="prime" />).container.querySelector("svg")!;
    expect(svg.getAttribute("aria-hidden")).toBe("true");
    expect(svg.getAttribute("class")).toBe("nms-art");
  });
});

// ── source scan: the vendor theming cannot come back anywhere in the SPA ───

describe("source scan — no NMS vendor palette or monogram anywhere in src/", () => {
  it("scans a non-trivial number of files (the guard is not vacuous)", () => {
    expect(SCANNED.length).toBeGreaterThan(100);
    expect(SCANNED.some((f) => f.endsWith("components/NmsControllerArt.tsx"))).toBe(true);
    expect(SCANNED.some((f) => f.endsWith("pages/NmsIntegrations.tsx"))).toBe(true);
    expect(SCANNED.some((f) => f.endsWith("styles.css"))).toBe(true);
  });

  it("no longer ships the retired NmsVendorArt component", () => {
    expect(existsSync(join(SRC_ROOT, "components", "NmsVendorArt.tsx"))).toBe(false);
  });

  it("contains no hex of a retired vendor palette", () => {
    const hits: string[] = [];
    for (const f of SCANNED) {
      const body = readFileSync(f, "utf8").toLowerCase();
      for (const hex of SCANNED_PALETTE_HEXES) if (body.includes(hex)) hits.push(`${rel(f)} :: ${hex}`);
    }
    expect(hits, `NMS vendor palette reintroduced:\n${hits.join("\n")}`).toEqual([]);
  });

  it("declares no retired vendor-theming symbol", () => {
    const hits: string[] = [];
    for (const f of SCANNED) {
      const body = readFileSync(f, "utf8");
      for (const sym of RETIRED_SYMBOLS) if (body.includes(sym)) hits.push(`${rel(f)} :: ${sym}`);
    }
    expect(hits, `retired vendor-theming symbol reintroduced:\n${hits.join("\n")}`).toEqual([]);
  });

  it("imitates no vendor console title", () => {
    const hits: string[] = [];
    for (const f of SCANNED) {
      const body = readFileSync(f, "utf8");
      for (const t of RETIRED_ART_TITLES) if (body.includes(t)) hits.push(`${rel(f)} :: ${t}`);
    }
    expect(hits, `vendor console chrome reintroduced:\n${hits.join("\n")}`).toEqual([]);
  });

  it("routes every controller tile through the registry, drawing no bespoke artwork", () => {
    const page = readFileSync(join(SRC_ROOT, "pages", "NmsIntegrations.tsx"), "utf8");
    expect(page).toContain('from "../components/NmsControllerArt"');
    // every controller is still named in the UI as factual text …
    for (const { id } of RETIRED_MONOGRAM_CONTROLLERS) {
      expect(page.toLowerCase(), `${id} disappeared from the NMS surface`).toContain(id);
    }
    // … and none of them is drawn by a bespoke per-vendor SVG on the page.
    expect(page).not.toMatch(/<svg/);
  });

  it("styles the controller mark chip from tokens only, so dark mode holds", () => {
    const css = readFileSync(join(SRC_ROOT, "styles.css"), "utf8");
    const rules = css.match(/\.nms-mark\b[^}]*\{[^}]*\}/g) ?? [];
    expect(rules.length, ".nms-mark chip style is missing").toBeGreaterThan(0);
    for (const rule of rules) {
      expect(rule, ".nms-mark hardcodes a colour instead of a token").not.toMatch(/#[0-9a-fA-F]{3,8}\b/);
    }
  });
});
