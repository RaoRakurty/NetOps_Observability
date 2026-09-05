// ConnectorLogos.test.tsx — licence audit D5 (2026-09-04) guard.
//
// The three CLOUD-provider tiles (AWS / Azure / GCP) used to inline the
// providers' official brand marks — full logo path data in brand colours,
// bundled into the shipped SPA. They were replaced by the ORIGINAL Correlix
// cloud glyph. This file is the guard that they cannot come back.
//
// The load-bearing assertion is the FILE-CONTENT one: a render-only test would
// pass again the moment someone re-inlines a brand mark behind a flag or in a
// component this file does not render. Reading the source catches it outright.
//
// SCOPE: every mark this file ever carried. Tracker 239 (2026-09-05) removed
// the six ITSM / notification marks (ServiceNow, Jira, Slack, Twilio,
// PagerDuty, Microsoft Teams) the same way D5 removed the cloud three, so the
// assertions below now guard NINE retired marks, not three. Connector identity
// moved to components/ConnectorGlyph.tsx (generic functional glyph + the
// vendor's name as text) and is guarded by ConnectorGlyph.test.tsx.

import { describe, it, expect, afterEach } from "vitest";
import { render, cleanup } from "@testing-library/react";
import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { AwsLogo, AzureLogo, GcpLogo } from "./ConnectorLogos";

afterEach(cleanup);

/**
 * Read the component's own SOURCE. `import.meta.url` is not a file: URL under
 * this vitest environment, so walk up from the working directory to the tree
 * that holds the file. A miss THROWS rather than skipping — a guard that
 * silently stops reading the file is worse than no guard at all.
 */
function readComponentSource(relative: string): string {
  for (let dir = process.cwd(), i = 0; i < 8; i++, dir = dirname(dir)) {
    const candidate = resolve(dir, relative);
    if (existsSync(candidate)) return readFileSync(candidate, "utf8");
    if (dir === dirname(dir)) break;
  }
  throw new Error(`cannot locate ${relative} from ${process.cwd()} — the trademark guard would be vacuous`);
}

const SOURCE = readComponentSource("src/components/ConnectorLogos.tsx");
const SOURCE_LC = SOURCE.toLowerCase();

/** Every hex the three removed cloud marks carried. */
const CLOUD_BRAND_HEXES = [
  "#ff9900", // AWS Smile orange
  "#0078d4", "#114a8b", "#0669bc", "#3ccbf4", "#2892df", // Azure chevron + gradient stops
  "#ea4335", "#4285f4", "#34a853", "#fbbc05", // Google four-colour
];

/** Distinctive path fragments from the deleted marks — geometry, not colour. */
const CLOUD_LOGO_PATH_FRAGMENTS = [
  "m55.8 43.4c-6.4 4.7", // AWS Smile arrow
  "m58.5 40.3c-.8-1.1",  // AWS Smile tail
  "m23.7 9h11l-11.4",    // Azure chevron
  "m39.6 32.8h22.1",     // Azure fold (prefix guard)
  "m40.3 22.5h1.9",      // Google red arc
  "m55.4 26.6a24.3",     // Google blue arc
  "m23.6 57.4h13.4",     // Google green arc
  "m23.6 22.3a17.6",     // Google yellow arc
];

describe("ConnectorLogos — no cloud-provider trademark remains", () => {
  it("the SOURCE FILE carries no AWS/Azure/GCP brand hex", () => {
    for (const hex of CLOUD_BRAND_HEXES) {
      expect(SOURCE_LC.split(hex).length - 1, `ConnectorLogos.tsx still contains ${hex}`).toBe(0);
    }
  });

  it("the SOURCE FILE carries no cloud-provider logo path data", () => {
    for (const frag of CLOUD_LOGO_PATH_FRAGMENTS) {
      expect(SOURCE_LC, `ConnectorLogos.tsx still contains logo geometry ${frag}`).not.toContain(frag);
    }
    // Every gradient this file ever held belonged to a retired mark (the Azure
    // chevron ramp, the Jira blue ramp). ANY <linearGradient> here now means a
    // brand ramp came back.
    expect(SOURCE_LC.split("<lineargradient").length - 1,
      "no gradient belongs in this file any more").toBe(0);
  });

  it("the cloud tiles RENDER the original glyph — inline svg, currentColor, letter tag", () => {
    for (const [Logo, tag] of [[AwsLogo, "AWS"], [AzureLogo, "AZ"], [GcpLogo, "GCP"]] as const) {
      const { container } = render(<Logo size={44} />);
      const html = container.innerHTML.toLowerCase();
      expect(container.querySelector("svg")?.getAttribute("viewBox"), tag).toBe("0 0 24 24");
      expect(container.querySelector("text")?.textContent, tag).toBe(tag);
      expect(html).toContain("currentcolor");
      expect(html).not.toContain("lineargradient");
      for (const hex of CLOUD_BRAND_HEXES) {
        expect(html, `${tag} rendered ${hex}`).not.toContain(hex);
      }
      cleanup();
    }
  });

  it("keeps the LogoProps contract so call sites do not churn", () => {
    const { container } = render(<AwsLogo size={30} className="ccw-mark" />);
    const svg = container.querySelector("svg")!;
    expect(svg.getAttribute("width")).toBe("30");
    expect(svg.getAttribute("class")).toBe("ccw-mark");
  });

});

// ── Tracker 239: the six ITSM / chat / comms marks are gone too ────────────
//
// The former ServiceNow / Jira / Slack / Twilio / PagerDuty / Teams components
// are asserted GONE three ways, because each one alone is escapable:
//   1. the exported symbol no longer exists (a call site cannot reach it),
//   2. the brand hex no longer appears in the source (no recolour-in-place),
//   3. the distinctive logo GEOMETRY no longer appears (no "same shape, new
//      colour" lookalike, which is the failure mode a colour-only guard misses).

/** Brand palette of the six retired connector marks. */
const CONNECTOR_BRAND_HEXES = [
  "#81b5a1",                                     // ServiceNow green-teal
  "#0052cc", "#2684ff",                          // Atlassian Jira blue ramp
  "#de1c59", "#35c5f0", "#2eb57d", "#ebb02e",    // Slack four-colour
  "#f22f46",                                     // Twilio red
  "#25c151",                                     // PagerDuty green
  "#5059c9", "#7b83eb",                          // Microsoft Teams purple pair
];

/** Distinctive path fragments from the six retired marks — geometry, not colour. */
const CONNECTOR_LOGO_PATH_FRAGMENTS = [
  "m32.195 3.312",   // ServiceNow "Now" roundel
  "m46.568 31.918",  // Jira chevron stack
  "m27.255 80.719",  // Slack lozenge (crimson quadrant)
  "m47.281 27.255",  // Slack lozenge (blue quadrant)
  "m48 92.309",      // Twilio roundel dots
  "m6.704 59.217",   // PagerDuty left bar
  "m44 24h14",       // Teams right silhouette
  "m11 22h18v4.2",   // Teams "T" counter
];

const RETIRED_CONNECTOR_LOGOS = [
  "ServiceNowLogo", "JiraLogo", "SlackLogo", "TwilioLogo", "PagerDutyLogo", "TeamsLogo",
] as const;

describe("ConnectorLogos — no ITSM/chat/comms vendor trademark remains (tracker 239)", () => {
  it("exports none of the six retired vendor mark components", () => {
    for (const name of RETIRED_CONNECTOR_LOGOS) {
      expect(SOURCE, `${name} came back — connectors use ConnectorGlyph, not vendor artwork`)
        .not.toContain(name);
    }
  });

  it("the SOURCE FILE carries no connector brand hex", () => {
    for (const hex of CONNECTOR_BRAND_HEXES) {
      expect(SOURCE_LC, `ConnectorLogos.tsx still contains ${hex}`).not.toContain(hex);
    }
  });

  it("the SOURCE FILE carries no connector logo geometry (no recoloured lookalike)", () => {
    for (const frag of CONNECTOR_LOGO_PATH_FRAGMENTS) {
      expect(SOURCE_LC, `ConnectorLogos.tsx still contains logo geometry ${frag}`).not.toContain(frag);
    }
  });

  it("carries NO raw colour literal at all — every glyph it renders is currentColor", () => {
    expect(SOURCE).not.toMatch(/#[0-9a-fA-F]{3,8}\b/);
    expect(SOURCE_LC).not.toContain("<lineargradient");
  });

  it("renders no vendor brand colour for ANY tile it still owns", () => {
    for (const [Logo, tag] of [[AwsLogo, "AWS"], [AzureLogo, "AZ"], [GcpLogo, "GCP"]] as const) {
      const html = render(<Logo size={40} />).container.innerHTML.toLowerCase();
      for (const hex of [...CLOUD_BRAND_HEXES, ...CONNECTOR_BRAND_HEXES]) {
        expect(html, `${tag} rendered ${hex}`).not.toContain(hex);
      }
      cleanup();
    }
  });
});
