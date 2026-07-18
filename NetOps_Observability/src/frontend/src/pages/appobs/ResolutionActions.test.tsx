// ResolutionActions.test.tsx (Wave 4 #12 slice 2) — the action row derives
// every action from data that exists: console pivots from THIS investigation's
// evidence rows only, runbooks from the exact-name catalog join with the
// https-only gate, ticket state from the real #78 lane; honest empty states.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, cleanup } from "@testing-library/react";
import type { BusinessServiceRow } from "../../services/api";
import type { EvidenceRow } from "./types";

const h = vi.hoisted(() => ({
  api: {
    correlationTickets: vi.fn(async () => ({ status: { state: "not_created" } })),
    correlationTicketCreate: vi.fn(async () => ({})),
    cloudBusinessServices: vi.fn(async () => ({ business_services: [] as BusinessServiceRow[], count: 0 })),
    permissions: vi.fn(async () => ({ permissions: { infrastructure: 3 } })),
  },
  loadEvidence: vi.fn(async () => ({
    objects: [], rows: [], openCount: 0, total: 0, objectsTruncated: false, nextCursor: "",
  })),
}));
vi.mock("../../services/api", () => ({ api: h.api }));
vi.mock("./api", () => ({ loadEvidence: h.loadEvidence }));

import ResolutionActions, { deriveConsoleActions, deriveRunbookActions } from "./ResolutionActions";

const row = (over: Partial<EvidenceRow>): EvidenceRow => ({
  time: "2026-07-18T00:00:00Z", category: "grounded" as EvidenceRow["category"],
  signalType: "cloud_health", app: "store-api", resource: "web01",
  source: "aws", confidence: "confirmed" as EvidenceRow["confidence"],
  reason: "", grounded: true, rcaGroup: "cid-1", evidenceRef: "s1",
  ...over,
});
const svc = (over: Partial<BusinessServiceRow>): BusinessServiceRow => ({
  business_service_id: "b1", tenant_id: "t", name: "store-api", description: "",
  criticality: "critical", owner: "", runbook_url: "", created_by: "u",
  created_at: "", updated_at: "",
  ...over,
});

afterEach(cleanup);
beforeEach(() => {
  h.api.correlationTickets.mockClear();
  h.api.cloudBusinessServices.mockClear();
  h.loadEvidence.mockClear();
});

describe("deriveConsoleActions", () => {
  it("keeps only THIS investigation's rows with a surviving console URL, deduped and capped", () => {
    const rows: EvidenceRow[] = [
      row({ cloudRef: { provider: "aws", resourceId: "i-1", account: "", region: "", consoleUrl: "https://x.console.aws.amazon.com/ec2#i-1", logUrl: "" } }),
      // duplicate URL — deduped
      row({ evidenceRef: "s2", cloudRef: { provider: "aws", resourceId: "i-1", account: "", region: "", consoleUrl: "https://x.console.aws.amazon.com/ec2#i-1", logUrl: "" } }),
      // another investigation's row — never surfaces here
      row({ rcaGroup: "cid-OTHER", cloudRef: { provider: "aws", resourceId: "i-9", account: "", region: "", consoleUrl: "https://x.console.aws.amazon.com/ec2#i-9", logUrl: "" } }),
      // no console URL — nothing to click
      row({ evidenceRef: "s3", cloudRef: undefined }),
    ];
    const acts = deriveConsoleActions(rows, "cid-1");
    expect(acts).toHaveLength(1);
    expect(acts[0].url).toContain("i-1");
    expect(acts.some((a) => a.url.includes("i-9"))).toBe(false);
  });
});

describe("deriveRunbookActions", () => {
  it("joins affected apps to the catalog by exact name and keeps only safe https runbooks", () => {
    const services = [
      svc({ business_service_id: "b1", name: "Store-API", runbook_url: "https://runbooks.example.com/store" }),
      svc({ business_service_id: "b2", name: "billing", runbook_url: "javascript:alert(1)" }), // unsafe → dropped
      svc({ business_service_id: "b3", name: "search", runbook_url: "" }),                     // unset → no action
    ];
    const acts = deriveRunbookActions(["store-api", "billing", "search", "unknown-app"], services);
    expect(acts).toEqual([{ service: "Store-API", url: "https://runbooks.example.com/store" }]);
  });
});

describe("<ResolutionActions/>", () => {
  it("renders honest empty states when nothing exists to act on", async () => {
    render(<ResolutionActions id="cid-1" />);
    expect(await screen.findByText(/no provider console links/)).toBeTruthy();
    expect(await screen.findByText(/no affected services recorded/)).toBeTruthy();
    expect(await screen.findByText("No ticket")).toBeTruthy();
    expect(screen.getByRole("button", { name: "File ticket" })).toBeTruthy();
  });

  it("surfaces console, ticket and runbook actions from real data", async () => {
    h.loadEvidence.mockResolvedValueOnce({
      objects: [{ correlationId: "cid-1", verdictTier: "suspected", confidence: 0.8,
        topHypothesis: "x", signalCount: 2, state: "open", windowStart: "",
        apps: ["store-api"], origin: { providers: [], primaryResource: "" } } as never],
      rows: [row({ cloudRef: { provider: "aws", resourceId: "i-1", account: "", region: "",
        consoleUrl: "https://x.console.aws.amazon.com/ec2#i-1", logUrl: "" } })],
      openCount: 1, total: 1, objectsTruncated: false, nextCursor: "",
    });
    h.api.cloudBusinessServices.mockResolvedValueOnce({
      business_services: [svc({ name: "store-api", runbook_url: "https://runbooks.example.com/store" })],
      count: 1,
    });
    h.api.correlationTickets.mockResolvedValueOnce({
      status: { state: "open", ticket_number: "INC0000001", url: "https://snow.example.com/INC0000001" },
    } as never);
    render(<ResolutionActions id="cid-1" />);
    expect(await screen.findByText(/AWS Console/)).toBeTruthy();
    expect(await screen.findByText(/Open runbook · store-api/)).toBeTruthy();
    expect(await screen.findByText("INC0000001 ↗")).toBeTruthy();
    // an open ticket offers no second File-ticket affordance
    expect(screen.queryByRole("button", { name: "File ticket" })).toBeNull();
  });
});
