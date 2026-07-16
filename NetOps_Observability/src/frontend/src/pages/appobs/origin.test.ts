// origin.test.ts — Origin (which cloud) + Service identity for an investigation
// (2026-07 owner review #5 + #1).
//
// Acceptance:
//   · the provider column is derived from the object's OWN evidence, and only a
//     cloud actually present there is ever claimed;
//   · an object whose evidence carries no cloud is on-prem (providers []), not a
//     fabricated cloud and not "unknown";
//   · a multi-cloud object lists every cloud, never just the first;
//   · the Service column falls back to the primary affected RESOURCE when the
//     engine named no app, and to an explicit "unattributed" (with a why) when
//     there is nothing at all — never a silent blank.

import { describe, it, expect } from "vitest";
import { providerFrom, evidenceProvider, deriveObjectOrigins, serviceIdentity, EMPTY_ORIGIN } from "./origin";
import type { EvidenceRow } from "./types";

const ev = (over: Partial<EvidenceRow> = {}): EvidenceRow => ({
  time: "2026-07-15T10:00:00.000Z", category: "grounded", signalType: "cloud_health",
  app: "—", resource: "web-1 (i-abc)", source: "aws", confidence: "suspected",
  reason: "cpu high", grounded: true, rcaGroup: "cid-1", evidenceRef: "sig-1",
  ...over,
});

describe("providerFrom", () => {
  it("accepts the three clouds, case-insensitively", () => {
    expect(providerFrom("aws")).toBe("aws");
    expect(providerFrom("AWS")).toBe("aws");
    expect(providerFrom(" Azure ")).toBe("azure");
    expect(providerFrom("gcp")).toBe("gcp");
  });
  it("refuses to promote a non-cloud token to a cloud", () => {
    // the backend degrades an unstamped cloud signal to the generic "cloud", and
    // a gap row's source is the engine itself — neither names a real provider.
    for (const v of ["cloud", "correlation engine", "", "  ", "onprem", undefined, null]) {
      expect(providerFrom(v as string)).toBeNull();
    }
  });
});

describe("evidenceProvider", () => {
  it("prefers the signal's own cloud_ref provider over the projected source", () => {
    const row = ev({
      source: "cloud", // backend's generic fallback
      cloudRef: { provider: "azure", resourceId: "vm-1", account: "sub", region: "eastus", consoleUrl: "", logUrl: "" },
    });
    expect(evidenceProvider(row)).toBe("azure");
  });
  it("falls back to source when there is no cloud_ref", () => {
    expect(evidenceProvider(ev({ source: "gcp", cloudRef: undefined }))).toBe("gcp");
  });
  it("returns null for an engine-authored gap row", () => {
    expect(evidenceProvider(ev({ category: "missing", grounded: false, source: "correlation engine", cloudRef: undefined }))).toBeNull();
  });
});

describe("deriveObjectOrigins", () => {
  it("attributes an object to the cloud its evidence actually came from", () => {
    const origins = deriveObjectOrigins([ev({ rcaGroup: "cid-1", source: "aws" })]);
    expect(origins.get("cid-1")?.providers).toEqual(["aws"]);
  });

  it("lists EVERY cloud of a multi-cloud object, deduped and stably ordered", () => {
    const origins = deriveObjectOrigins([
      ev({ rcaGroup: "cid-1", source: "gcp" }),
      ev({ rcaGroup: "cid-1", source: "aws", evidenceRef: "sig-2" }),
      ev({ rcaGroup: "cid-1", source: "aws", evidenceRef: "sig-3" }),
      ev({ rcaGroup: "cid-1", source: "azure", evidenceRef: "sig-4" }),
    ]);
    // stable catalog order (aws, azure, gcp) — not evidence arrival order
    expect(origins.get("cid-1")?.providers).toEqual(["aws", "azure", "gcp"]);
  });

  it("reports NO provider for an object whose evidence carries no cloud (on-prem)", () => {
    const origins = deriveObjectOrigins([ev({ rcaGroup: "cid-9", source: "cloud", cloudRef: undefined })]);
    expect(origins.get("cid-9")?.providers).toEqual([]);
  });

  it("keeps objects separate and ignores rows with no rca group", () => {
    const origins = deriveObjectOrigins([
      ev({ rcaGroup: "cid-1", source: "aws" }),
      ev({ rcaGroup: "cid-2", source: "azure" }),
      ev({ rcaGroup: "", source: "gcp" }),
    ]);
    expect(origins.get("cid-1")?.providers).toEqual(["aws"]);
    expect(origins.get("cid-2")?.providers).toEqual(["azure"]);
    expect(origins.has("")).toBe(false);
  });

  it("takes the primary resource from a GROUNDED row only — never a declared gap", () => {
    const origins = deriveObjectOrigins([
      // the gap row comes FIRST and must not become the object's identity
      ev({ rcaGroup: "cid-1", category: "missing", grounded: false, resource: "—", source: "correlation engine", cloudRef: undefined }),
      ev({ rcaGroup: "cid-1", grounded: true, resource: "alb-prod (app/alb/0a1)", evidenceRef: "sig-2" }),
    ]);
    expect(origins.get("cid-1")?.primaryResource).toBe("alb-prod (app/alb/0a1)");
  });
});

describe("serviceIdentity", () => {
  it("uses the engine's named service when there is one", () => {
    const id = serviceIdentity(["billing"], EMPTY_ORIGIN);
    expect(id.kind).toBe("service");
    expect(id.label).toBe("billing");
  });

  it("joins every named service of a multi-service object", () => {
    expect(serviceIdentity(["billing", "checkout"], EMPTY_ORIGIN).label).toBe("billing, checkout");
  });

  it("falls back to the primary affected RESOURCE when no service is mapped", () => {
    const id = serviceIdentity([], { providers: ["aws"], primaryResource: "alb-prod (app/alb/0a1)" });
    expect(id.kind).toBe("resource");
    expect(id.label).toBe("alb-prod (app/alb/0a1)");
    expect(id.why).toMatch(/no service is mapped/i); // the cell always explains itself
  });

  it("says 'unattributed' WITH a reason rather than rendering a silent blank", () => {
    const id = serviceIdentity([], EMPTY_ORIGIN);
    expect(id.kind).toBe("unattributed");
    expect(id.label).toBe("unattributed");
    expect(id.why).toBeTruthy();
  });

  it("treats provider-empty app values as absent (no '—' service names)", () => {
    const id = serviceIdentity(["—", ""], { providers: [], primaryResource: "vm-1" });
    expect(id.kind).toBe("resource");
    expect(id.label).toBe("vm-1");
  });
});
