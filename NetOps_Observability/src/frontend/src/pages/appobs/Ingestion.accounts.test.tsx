// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Ingestion.accounts.test.tsx — Wave 2 #4: the Accounts sub-tab is CONNECTOR-
// first. A configured account with no telemetry renders as a red attention row
// stating exactly that (never dropped, never green), identity and telemetry are
// separate columns, and discovered-only accounts stay visible as
// platform-managed.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, cleanup } from "@testing-library/react";
import type { CloudConnectorView, CloudResourceRow } from "../../services/api";

const h = vi.hoisted(() => {
  const conn = (over: Partial<CloudConnectorView> = {}): CloudConnectorView => ({
    id: "ccn_dark", provider: "aws", display_name: "Prod payer", auth_method: "cloud_role",
    auth_federated: true, auth_legacy: false, capability_pack: "aws-observer-v1",
    state: "ACTIVE", collecting: true,
    identity: { has_legacy_secret: false },
    scopes: [{ type: "account", ref: "222222222222", regions: ["us-west-2"] }],
    identity_health: { state: "healthy" }, telemetry_health: { state: "unknown" },
    last_validation: { ok: true, findings: [] }, version: 1,
    created_at: "2026-07-01T00:00:00Z", updated_at: "2026-07-15T00:00:00Z",
    ...over,
  } as CloudConnectorView);
  const res = (over: Partial<CloudResourceRow> = {}): CloudResourceRow => ({
    tenant_id: "", cloud_provider: "aws", account_id: "111", region: "us-east-1",
    resource_id: "r1", resource_type: "AWS::EC2::Instance",
    discovered_at: new Date().toISOString(), last_seen_at: new Date().toISOString(),
    source: "cloud_tag", confidence: "confirmed", ...over,
  } as CloudResourceRow);
  return {
    conn, res,
    mock: {
      cloudIngestion: vi.fn(async () => ({ sources: [], providers: {}, generated_at: "" })),
      cloudConnectors: vi.fn(async () => ({ connectors: [conn()] })),
    },
    inv: {
      fetchCloudInventory: vi.fn(async () => ({ resources: [res()] })),
      invalidateCloudInventory: vi.fn(),
    },
  };
});
vi.mock("../../services/api", () => ({ api: h.mock }));
vi.mock("./api", () => h.inv);
// The wizard and the Connections list have their own suites — keep this one
// focused on the merged account rows.
vi.mock("./ConnectorWizard", () => ({ default: () => null }));
vi.mock("./Connections", () => ({ default: () => null }));

import Ingestion from "./Ingestion";

beforeEach(() => {
  h.mock.cloudIngestion.mockClear();
  h.mock.cloudConnectors.mockClear();
  h.inv.fetchCloudInventory.mockClear();
});
afterEach(cleanup);

describe("Accounts — connector-first rows (Wave 2 #4)", () => {
  it("a silent-but-connected account renders red, stating exactly that", async () => {
    render(<Ingestion initialSub="accounts" />);
    // The connector-configured account exists although NO inventory arrived
    // for it — the pre-fix model derived rows from inventory and dropped it.
    expect(await screen.findByText("222222222222")).toBeTruthy();
    expect(screen.getByText("Connected — no data arriving")).toBeTruthy();
    const row = screen.getByText("222222222222").closest(".dtv-row");
    expect(row?.className).toContain("ao-row--attention");
    // Identity split stays visible: the connection itself is fine.
    expect(screen.getByText("Enabled")).toBeTruthy();
  });

  it("discovered-only accounts stay visible as platform-managed and healthy rows are not red", async () => {
    render(<Ingestion initialSub="accounts" />);
    expect(await screen.findByText("111")).toBeTruthy();
    expect(screen.getByText("Discovered")).toBeTruthy();      // no self-service connection owns it…
    expect(screen.getByText("Platform managed")).toBeTruthy(); // …its credentials are deployment-level
    expect(screen.getByText("Healthy")).toBeTruthy();
    const row = screen.getByText("111").closest(".dtv-row");
    expect(row?.className).not.toContain("ao-row--attention");
  });

  it("a broken connection reads broken, not silent", async () => {
    h.mock.cloudConnectors.mockResolvedValueOnce({
      connectors: [h.conn({ state: "REAUTHORIZATION_REQUIRED", collecting: false })],
    });
    render(<Ingestion initialSub="accounts" />);
    expect(await screen.findByText("Connection broken")).toBeTruthy();
    expect(screen.getByText("Needs re-authorization")).toBeTruthy();
  });
});
