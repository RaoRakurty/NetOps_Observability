// ConnectorGlyph.test.tsx — tracker 239 guard.
//
// Correlix identifies a third-party connector by a GENERIC FUNCTIONAL glyph
// plus the vendor's name as plain text. Six official vendor marks (ServiceNow,
// Jira, Slack, Twilio, PagerDuty, Microsoft Teams) used to be inlined as
// verbatim brand path data in brand colours; they are gone, and these tests are
// what keeps them gone.
//
// Two kinds of assertion, deliberately:
//   • RENDER tests — what an operator actually sees: the right functional
//     glyph, no brand colour, the name still readable, the a11y contract.
//   • SOURCE-SCAN tests — the whole `src/` tree read from disk. A render-only
//     guard passes the moment someone re-inlines a mark in a component this
//     file does not render, which is exactly how the six survived the
//     2026-09-03 audit sweep.

import { describe, it, expect, afterEach } from "vitest";
import { render, cleanup } from "@testing-library/react";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, extname, join, resolve } from "node:path";
import ConnectorGlyph, {
  CONNECTOR_REGISTRY,
  GENERIC_CONNECTOR,
  connectorIcon,
  connectorPresentation,
} from "./ConnectorGlyph";
import Icon from "./Icon";

afterEach(cleanup);

/** The six connectors tracker 239 is about, with the category each must map to. */
const RETIRED_MARK_CONNECTORS = [
  { id: "servicenow", name: "ServiceNow", category: "ITSM", icon: "ticket" },
  { id: "jira", name: "Jira", category: "Issue tracking", icon: "board" },
  { id: "slack", name: "Slack", category: "Chat", icon: "chat" },
  { id: "twilio", name: "Twilio", category: "Messaging", icon: "phone" },
  { id: "pagerduty", name: "PagerDuty", category: "Incident response", icon: "incident" },
  { id: "teams", name: "Microsoft Teams", category: "Collaboration", icon: "users" },
] as const;

/** Every hex the six retired marks carried. */
const BRAND_HEXES = [
  "#81b5a1",
  "#0052cc", "#2684ff",
  "#de1c59", "#35c5f0", "#2eb57d", "#ebb02e",
  "#f22f46",
  "#25c151",
  "#5059c9", "#7b83eb",
];

/** Distinctive geometry from the six retired marks — catches a recoloured trace. */
const BRAND_PATH_FRAGMENTS = [
  "m32.195 3.312",
  "m46.568 31.918",
  "m27.255 80.719",
  "m47.281 27.255",
  "m48 92.309",
  "m6.704 59.217",
  "m11 22h18v4.2",
];

/** Component symbols that no longer exist and must not be resurrected. */
const RETIRED_SYMBOLS = [
  "ServiceNowLogo", "JiraLogo", "SlackLogo", "TwilioLogo", "PagerDutyLogo", "TeamsLogo",
];

/** Asset filenames retired by the 2026-09-03 sweep — none may return. */
const RETIRED_ASSET_NAMES = [
  "servicenow.svg", "jira.svg", "slack.svg", "twilio.svg", "pagerduty.svg",
  "teams.svg", "msteams.svg",
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

const SRC_ROOT = repoDir("src/components/ConnectorGlyph.tsx").replace(/\/components\/ConnectorGlyph\.tsx$/, "");

function walk(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    const p = join(dir, entry);
    if (statSync(p).isDirectory()) walk(p, out);
    else out.push(p);
  }
  return out;
}

const ALL_SRC_FILES = walk(SRC_ROOT);
/** Source we scan for reintroduced marks — this test file states the hexes itself. */
const SCANNED = ALL_SRC_FILES.filter(
  (f) => [".ts", ".tsx", ".css", ".svg"].includes(extname(f)) && !f.endsWith("ConnectorGlyph.test.tsx")
    && !f.endsWith("ConnectorLogos.test.tsx"),
);

const rel = (f: string) => f.slice(SRC_ROOT.length + 1);

// ── registry ───────────────────────────────────────────────────────────────

describe("connector registry", () => {
  it.each(RETIRED_MARK_CONNECTORS)(
    "$name resolves to the generic $icon glyph in category $category",
    ({ id, name, category, icon }) => {
      const p = connectorPresentation(id);
      expect(p.displayName).toBe(name);
      expect(p.category).toBe(category);
      expect(p.icon).toBe(icon);
      expect(connectorIcon(id)).toBe(icon);
    },
  );

  it("is case- and whitespace-tolerant about the connector id", () => {
    expect(connectorPresentation("  SlAcK ").icon).toBe("chat");
  });

  it("falls back to the generic integration plug — never a broken tile, never another vendor", () => {
    for (const unknown of [undefined, null, "", "   ", "opsgenie", "zendesk", "<script>"]) {
      const p = connectorPresentation(unknown);
      expect(p, String(unknown)).toEqual(GENERIC_CONNECTOR);
      expect(p.icon).toBe("plug");
    }
  });

  it("gives the six a DISTINCT glyph each, so identity does not lean on colour", () => {
    const icons = RETIRED_MARK_CONNECTORS.map((c) => connectorIcon(c.id));
    expect(new Set(icons).size).toBe(icons.length);
  });

  it("names every registered connector and states its capability", () => {
    for (const [id, entry] of Object.entries(CONNECTOR_REGISTRY)) {
      expect(entry.displayName.trim(), id).not.toBe("");
      expect(entry.capability.trim(), id).not.toBe("");
      expect(entry.icon.trim(), id).not.toBe("");
    }
  });
});

// ── render ─────────────────────────────────────────────────────────────────

describe("ConnectorGlyph render", () => {
  it.each(RETIRED_MARK_CONNECTORS)(
    "$name draws the shared functional glyph, not a vendor mark",
    ({ id, icon }) => {
      const mine = render(<ConnectorGlyph connector={id} size={40} />).container.innerHTML;
      cleanup();
      const shared = render(<Icon name={icon} size={40} />).container.innerHTML;
      // Byte-identical to the design-system glyph: there is no per-connector
      // artwork anywhere, only a registry lookup into components/Icon.tsx.
      expect(mine).toBe(shared);
    },
  );

  it.each(RETIRED_MARK_CONNECTORS)("$name renders NO brand colour and NO brand geometry", ({ id }) => {
    const html = render(<ConnectorGlyph connector={id} size={40} />).container.innerHTML.toLowerCase();
    for (const hex of BRAND_HEXES) expect(html, `${id} rendered ${hex}`).not.toContain(hex);
    for (const frag of BRAND_PATH_FRAGMENTS) expect(html, `${id} rendered ${frag}`).not.toContain(frag);
    expect(html).not.toContain("lineargradient");
    expect(html).not.toContain("<image");
    expect(html).not.toContain("data:image");
    // Colour comes from the theme only — this is what makes it legible in BOTH
    // light and dark, and what makes a brand hue impossible.
    expect(html).toContain('stroke="currentcolor"');
    expect(html).not.toMatch(/(stroke|fill)="#/);
    expect(html).toContain('fill="none"');
  });

  it("is decorative by default and labelled only on request (a11y)", () => {
    const plain = render(<ConnectorGlyph connector="slack" />).container.querySelector("svg")!;
    expect(plain.getAttribute("aria-hidden")).toBe("true");
    expect(plain.getAttribute("role")).toBeNull();
    expect(plain.querySelector("title")).toBeNull();
    cleanup();
    const labelled = render(<ConnectorGlyph connector="slack" label="Slack connector" />)
      .container.querySelector("svg")!;
    expect(labelled.getAttribute("role")).toBe("img");
    expect(labelled.getAttribute("aria-hidden")).toBeNull();
    expect(labelled.querySelector("title")?.textContent).toBe("Slack connector");
  });

  it("honours size and className so existing chip layout is unchanged", () => {
    const svg = render(<ConnectorGlyph connector="jira" size={28} className="conn-mark" />)
      .container.querySelector("svg")!;
    expect(svg.getAttribute("width")).toBe("28");
    expect(svg.getAttribute("height")).toBe("28");
    expect(svg.getAttribute("viewBox")).toBe("0 0 24 24");
    expect(svg.getAttribute("class")).toBe("conn-mark");
  });

  it("a connector card still identifies the vendor BY NAME, glyph or no glyph", () => {
    const { getByText, container } = render(
      <span className="conn-tile">
        <span className="conn-logo servicenow"><ConnectorGlyph connector="servicenow" size={40} /></span>
        <span className="conn-name">{connectorPresentation("servicenow").displayName}</span>
        <span className="conn-tag">{connectorPresentation("servicenow").category}</span>
      </span>,
    );
    expect(getByText("ServiceNow")).toBeTruthy();
    expect(getByText("ITSM")).toBeTruthy();
    // Strip the glyph entirely: the tile is still fully identifiable, which is
    // the accessibility requirement (identity never rests on the glyph alone).
    container.querySelector("svg")!.remove();
    expect(container.textContent).toContain("ServiceNow");
  });
});

// ── source scan: the marks cannot come back anywhere in the SPA ────────────

describe("source scan — no official connector mark anywhere in src/", () => {
  it("scans a non-trivial number of files (the guard is not vacuous)", () => {
    expect(SCANNED.length).toBeGreaterThan(100);
    expect(SCANNED.some((f) => f.endsWith("components/ConnectorLogos.tsx"))).toBe(true);
    expect(SCANNED.some((f) => f.endsWith("tabs/admin.tsx"))).toBe(true);
    expect(SCANNED.some((f) => f.endsWith("styles.css"))).toBe(true);
  });

  it("contains no brand hex of the six retired marks", () => {
    const hits: string[] = [];
    for (const f of SCANNED) {
      const body = readFileSync(f, "utf8").toLowerCase();
      for (const hex of BRAND_HEXES) if (body.includes(hex)) hits.push(`${rel(f)} :: ${hex}`);
    }
    expect(hits, `vendor brand colour reintroduced:\n${hits.join("\n")}`).toEqual([]);
  });

  it("contains no path geometry of the six retired marks", () => {
    const hits: string[] = [];
    for (const f of SCANNED) {
      const body = readFileSync(f, "utf8").toLowerCase();
      for (const frag of BRAND_PATH_FRAGMENTS) if (body.includes(frag)) hits.push(`${rel(f)} :: ${frag}`);
    }
    expect(hits, `vendor logo geometry reintroduced:\n${hits.join("\n")}`).toEqual([]);
  });

  it("declares no retired vendor-mark component", () => {
    const hits: string[] = [];
    for (const f of SCANNED) {
      const body = readFileSync(f, "utf8");
      for (const sym of RETIRED_SYMBOLS) if (body.includes(sym)) hits.push(`${rel(f)} :: ${sym}`);
    }
    expect(hits, `retired vendor-mark component reintroduced:\n${hits.join("\n")}`).toEqual([]);
  });

  it("ships no vendor logo asset file", () => {
    const hits = ALL_SRC_FILES.filter((f) =>
      RETIRED_ASSET_NAMES.some((n) => f.toLowerCase().endsWith(`/${n}`)),
    );
    expect(hits.map(rel), "vendor logo asset returned to the tree").toEqual([]);
  });

  it("styles no connector chip with a brand tint — tokens only, so dark mode holds", () => {
    const css = readFileSync(join(SRC_ROOT, "styles.css"), "utf8");
    const chip = css.slice(css.indexOf(".conn-logo {"));
    for (const cls of ["servicenow", "jira", "slack", "pagerduty", "teams", "twilio", "sns"]) {
      const m = chip.match(new RegExp(`\\.conn-logo\\.${cls}\\b[^}]*\\{[^}]*\\}`, "g")) ?? [];
      for (const rule of m) {
        expect(rule, `.conn-logo.${cls} hardcodes a colour instead of a token`)
          .not.toMatch(/#[0-9a-fA-F]{3,8}\b/);
      }
    }
  });

  it("routes the admin connector + channel tiles through the registry", () => {
    const admin = readFileSync(join(SRC_ROOT, "tabs", "admin.tsx"), "utf8");
    expect(admin).toContain('import ConnectorGlyph from "../components/ConnectorGlyph"');
    for (const { id } of RETIRED_MARK_CONNECTORS) {
      // every one of the six is still named in the UI as factual text …
      expect(admin.toLowerCase(), `${id} disappeared from the admin surface`).toContain(id);
    }
    // … and none of them is drawn by a bespoke per-connector SVG.
    expect(admin).not.toMatch(/<svg[^>]*viewBox="0 0 (64|128) (64|128)"/);
  });
});
