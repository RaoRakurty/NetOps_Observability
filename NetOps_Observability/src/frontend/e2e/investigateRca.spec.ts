// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Investigate / RCA-pin flow E2E (gap #2, operator workflow). Proves the anti-
// black-box RCA narrative renders end-to-end on the real canvas: entering
// Investigate auto-pins the most-actionable incident, fetches its RCA fault-path
// overlay, and the verdict banner shows the server-authored verdict + confidence +
// the TWO independent witnesses (never an asserted black-box answer). Backend mocked.

import { test, expect, type Page, type Route } from "@playwright/test";

const ME = { username: "alice", role: "operator", tenant_id: "t_acme", platform_admin: false, accessible_tenants: ["t_acme"], all_tenants: false };

const CORR = {
  correlation_id: "corr-1", version: 3, state: "open",
  window_start: new Date(Date.now() - 15 * 60_000).toISOString(), window_end: new Date().toISOString(),
  top_hypothesis: "sig.ent.wan.dia-egress-degraded", top_confidence: 0.92, verdict_tier: "confirmed",
  hypotheses: "{}", evidence_missing: "[]", affected: JSON.stringify({ devices: ["edge1"] }),
  signal_count: 4, node_count: 2, owner: "wan_provider",
  engine_version: "v1", catalog_version: "c1", created_at: new Date().toISOString(),
};

// The RCA fault-path overlay (GET /api/correlations/corr-1/rca-path-view). Carries the
// grounded verdict + the independent confirming pair the engine actually used.
const OVERLAY = {
  corr_object_id: "corr-1", verdict: "confirmed", confidence: 0.92, internal: false,
  title: "Egress path degraded to Dallas",
  summary: "Loss on the Dallas DIA egress, confirmed by two independent witnesses.",
  recommended_action: "Open ticket · escalate to WAN provider.",
  path: {
    source: "edge1", destination: "dc1",
    nodes: [
      { id: "edge1", type: "device", kind: "router", label: "edge1", status: "confirmed" },
      { id: "dc1", type: "device", kind: "router", label: "dc1", status: "ok" },
    ],
    edges: [{ id: "p1", source: "edge1", target: "dc1", type: "path", state: "down", label: "egress" }],
  },
  annotations: [],
  evidence_summary: {
    confirming_pair: ["probe-dallas", "edge1 syslog"],
    decisive_modalities: ["active_probe", "control_plane"],
    verdict_reason: "Two independent witnesses agree on the egress fault.",
    blast_radius: { devices: 2, paths: 1, interfaces: 0 },
  },
  missing_evidence_summary: [],
};

function exploreView() {
  const node = (id: string) => ({ id, label: id, kind: "router", health: "ok", confidence: 1, metrics: {}, evidence: [{ source: "lldp", confidence: 1 }] });
  return {
    view_id: "v", mode: "investigate", scope: { tenant_id: "t_acme" }, layout_type: "incident",
    generated_at: new Date().toISOString(), nodes: [node("edge1"), node("dc1")],
    edges: [{ id: "e1", source: "edge1", target: "dc1", status: "up", confidence: 1, evidence: [{ source: "lldp", confidence: 1 }] }],
    groups: [], overlays: ["health"],
  };
}

async function openInvestigate(page: Page) {
  await page.addInitScript(() => localStorage.setItem("netops_token", "e2e-fake-token"));
  await page.route(/^https?:\/\/[^/]+\/api\//, async (route: Route) => {
    const url = new URL(route.request().url());
    const json = (b: unknown) => route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(b) });
    const p = url.pathname;
    if (p.includes("/api/auth/me")) return json(ME);
    if (p.includes("/api/scopes")) return json({ scopes: [{ tenant_id: "t_acme", tenant_name: "Acme", org_id: "o", org_name: "Acme", region: "us" }], all_tenants: false });
    if (p.includes("/rca-path-view")) return json(OVERLAY);                 // check BEFORE the list route
    if (p.includes("/api/correlations")) return json({ data: [CORR], meta: [] });
    if (p.includes("/api/topology/view")) return json(exploreView());
    return json({});
  });
  await page.goto("/#/investigate/topology");
  // Scoped to the canvas' Workflow selector: since the 2026-08 nav redesign the
  // RAIL also has a button accessibly named "Investigate" (the section), so a
  // page-wide role query is ambiguous (strict-mode violation).
  await page.getByRole("group", { name: "Workflow" }).getByRole("button", { name: "Investigate" }).click();
}

test("pinning an incident renders its grounded verdict + independent evidence", async ({ page }) => {
  await openInvestigate(page);

  // The verdict banner appears (auto-pinned to the most-actionable incident).
  const banner = page.locator(".topo-rca-banner");
  await expect(banner).toBeVisible();

  // Server-authored verdict + confidence + title — rendered, not re-derived.
  await expect(banner.getByText("Confirmed", { exact: true })).toBeVisible();
  await expect(banner.getByText(/92% confidence/)).toBeVisible();
  await expect(page.getByText("Egress path degraded to Dallas")).toBeVisible();

  // Anti-black-box: the TWO independent witnesses are NAMED, with operator-facing
  // modality labels (no raw backend tokens).
  await expect(page.getByText("Confirmed by", { exact: true })).toBeVisible();
  await expect(page.getByText("probe-dallas")).toBeVisible();
  await expect(page.getByText("edge1 syslog")).toBeVisible();
  await expect(page.getByText("Active probe")).toBeVisible();
  await expect(page.getByText("Control plane")).toBeVisible();
  expect(await page.locator("body").innerText()).not.toContain("active_probe");

  // The recommended next action is surfaced.
  await expect(page.getByText("Open ticket · escalate to WAN provider.")).toBeVisible();
});

test("unpinning the incident clears the verdict banner", async ({ page }) => {
  await openInvestigate(page);
  await expect(page.locator(".topo-rca-banner")).toBeVisible();

  await page.locator(".topo-rca-clear").click(); // the ✕ unpin control
  await expect(page.locator(".topo-rca-banner")).toHaveCount(0);
});
