// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { describe, expect, it } from "vitest";
import {
  KEY_PLACEHOLDER, applianceOrigin, cspLines, injectionRules, labelledBy, snippetTag, sourcesSummary,
} from "./rumSetup.model";
import type { DemRumSourcesResponse } from "../../services/api";

const ORIGIN = "https://correlix.example.com";

describe("the tag", () => {
  it("names no app, so one tag labels every app by its web address", () => {
    const tag = snippetTag(ORIGIN, "cx_abc");
    expect(tag).toBe("<script src='https://correlix.example.com/correlix-rum.js' data-endpoint='https://correlix.example.com' data-key='cx_abc' defer></script>");
    expect(tag).not.toContain("data-app");
  });

  it("shows a placeholder until a key is generated", () => {
    expect(snippetTag(ORIGIN, "")).toContain(`data-key='${KEY_PLACEHOLDER}'`);
  });

  it("strips anything that could break out of an attribute or a rule's string", () => {
    const tag = snippetTag("https://x.example.com\"><img onerror=1", "k'\"<>;`$");
    // Exactly the three attribute quote pairs, and every value is inert text.
    expect((tag.match(/'/g) ?? []).length).toBe(6);
    const values = [...tag.matchAll(/='([^']*)'/g)].map((m) => m[1]);
    expect(values).toHaveLength(3);
    for (const v of values) expect(v).toMatch(/^[A-Za-z0-9._:/~+=-]*$/);
    expect(tag.startsWith("<script ") && tag.endsWith("></script>")).toBe(true);
    expect(tag.slice("<script ".length, -"></script>".length)).not.toMatch(/[<>"`$;]/);
  });

  it("reads the appliance origin from the page's own address", () => {
    expect(applianceOrigin("https://correlix.example.com/#/operations/digital-experience/data-health")).toBe(ORIGIN);
    expect(applianceOrigin("not a url")).toBe("");
  });
});

describe("injection rules", () => {
  const rules = injectionRules(ORIGIN, "cx_abc");

  it("covers the shared layers a NOC meets, each with where it goes", () => {
    expect(rules.map((r) => r.id)).toEqual(["nginx", "f5", "netscaler", "envoy", "cloudflare", "akamai", "gtm"]);
    for (const r of rules) {
      expect(r.where.length).toBeGreaterThan(10);
      expect(r.code).toContain("cx_abc");
      expect(r.code).toContain(ORIGIN);
    }
  });

  it("every proxy rule targets the page head, and the text rewriters only touch HTML", () => {
    for (const r of rules.filter((x) => x.id !== "gtm")) {
      // Text rewriters insert before </head>; the HTML rewriters (Cloudflare,
      // Akamai) append to the <head> element itself.
      expect(r.code.includes("</head>") || /on(Element)?\(['"]head['"]/.test(r.code)).toBe(true);
    }
    for (const id of ["nginx", "f5", "netscaler", "envoy", "cloudflare"]) {
      expect(rules.find((r) => r.id === id)!.code.toLowerCase()).toContain("text/html");
    }
  });

  it("GTM passes the settings as an object, not as attributes on an injected tag", () => {
    const gtm = rules.find((r) => r.id === "gtm")!;
    expect(gtm.code).toContain("window.CorrelixRUM = { endpoint:");
  });

  it("names no deployment environment variable anywhere", () => {
    expect(JSON.stringify(rules)).not.toMatch(/CORS_ALLOWED_ORIGINS|\.env\b/);
  });
});

describe("csp and the feed summary", () => {
  it("adds the appliance to script-src and connect-src", () => {
    expect(cspLines(ORIGIN)).toEqual([`script-src ${ORIGIN}`, `connect-src ${ORIGIN}`]);
  });

  const base: DemRumSourcesResponse = { status: "ok", window_s: 86400, lookback_s: 604800, reporting: 0, quiet: 0, sources: [], truncated: false };

  it("never reads an unreadable store as 'nothing installed'", () => {
    expect(sourcesSummary({ ...base, status: "unavailable" })).toMatch(/could not be read/);
    expect(sourcesSummary(base)).toBe("No app has sent real-user data in the last 7 days.");
  });

  it("counts sending and quiet apps", () => {
    const s = sourcesSummary({ ...base, reporting: 2, quiet: 1, sources: [{} as never, {} as never, {} as never] });
    expect(s).toBe("2 apps are sending real-user data; 1 went quiet (nothing in the last 24 hours).");
  });

  it("says how an app was named in plain words", () => {
    expect(labelledBy("attribute")).toBe("Named on the page");
    expect(labelledBy("hostname")).toBe("Named by its web address");
    expect(labelledBy("")).toBe("Not stated");
  });
});
