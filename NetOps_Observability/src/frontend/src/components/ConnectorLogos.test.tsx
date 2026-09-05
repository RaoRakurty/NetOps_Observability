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
// SCOPE: cloud marks only. The six ITSM / notification marks (ServiceNow, Jira,
// Slack, Twilio, PagerDuty, Teams) ARE the vendors' official artwork by
// deliberate decision and are asserted to still be present, so a future sweep
// cannot quietly delete them without a matching owner decision.

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
    // The removed marks were the only <linearGradient> users besides Jira; a
    // second gradient block would mean a cloud mark came back with its ramp.
    expect(SOURCE_LC.split("<lineargradient").length - 1,
      "only Jira's three gradients may remain").toBe(3);
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

  // Deliberately still vendor artwork — a separate owner decision, NOT D5's.
  it("leaves the six non-cloud vendor marks in place", () => {
    for (const [name, hex] of [
      ["ServiceNowLogo", "#81b5a1"],
      ["JiraLogo", "#2684ff"],
      ["SlackLogo", "#de1c59"],
      ["TwilioLogo", "#f22f46"],
      ["PagerDutyLogo", "#25c151"],
      ["TeamsLogo", "#5059c9"],
    ] as const) {
      expect(SOURCE, `${name} was removed without an owner decision`).toContain(name);
      expect(SOURCE_LC, `${name} lost its brand colour`).toContain(hex);
    }
  });
});
