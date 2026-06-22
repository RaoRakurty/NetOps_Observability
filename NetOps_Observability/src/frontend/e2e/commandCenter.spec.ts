// Command Center operator-flow E2E (gap-report #2). Proves the decision system
// actually works end-to-end in a browser: an authenticated operator loads the
// Command Center, sees ONLY actionable customer-network incidents (single-signal
// noise and internal-stack objects filtered), and can expand a row to its evidence.
// The backend is mocked at the network boundary, so no stack is needed.

import { test, expect, type Page } from "@playwright/test";

const TENANT = "t_acme";

const ME = {
  username: "alice",
  role: "operator",
  tenant_id: TENANT,
  platform_admin: false,
  accessible_tenants: [TENANT],
  all_tenants: false,
};

// One confirmed customer-network incident (must show), one single-signal
// undetermined object (must be filtered), one internal-stack object (must be
// filtered — RCA is scoped to customer networks, decision #76).
const CORRELATIONS = {
  data: [
    {
      correlation_id: "corr-confirmed-1", version: 3, state: "open",
      window_start: new Date(Date.now() - 20 * 60_000).toISOString(),
      window_end: new Date().toISOString(),
      top_hypothesis: "sig.ent.wan.dia-egress-degraded", top_confidence: 0.91,
      verdict_tier: "confirmed", hypotheses: "{}", evidence_missing: "[]",
      affected: JSON.stringify({ devices: ["leaf-1", "spine-2"], sites: ["dallas"] }),
      signal_count: 4, node_count: 3, owner: "isp",
      engine_version: "v1", catalog_version: "c1", created_at: new Date().toISOString(),
    },
    {
      correlation_id: "corr-noise-1", version: 1, state: "open",
      window_start: new Date().toISOString(), window_end: new Date().toISOString(),
      top_hypothesis: "sig.ent.lan.single", top_confidence: 0.2,
      verdict_tier: "undetermined", hypotheses: "{}", evidence_missing: "[]",
      affected: JSON.stringify({ devices: ["edge-9"] }),
      signal_count: 1, node_count: 1, owner: "",
      engine_version: "v1", catalog_version: "c1", created_at: new Date().toISOString(),
    },
    {
      correlation_id: "corr-internal-1", version: 2, state: "open",
      window_start: new Date().toISOString(), window_end: new Date().toISOString(),
      top_hypothesis: "sig.int.stack", top_confidence: 0.95,
      verdict_tier: "confirmed", hypotheses: "{}", evidence_missing: "[]",
      affected: JSON.stringify({ devices: ["clickhouse", "redpanda", "vector"] }),
      signal_count: 6, node_count: 3, owner: "netops",
      engine_version: "v1", catalog_version: "c1", created_at: new Date().toISOString(),
    },
  ],
  meta: [],
};

// Stub the backend at the network boundary + seed an auth token before boot.
async function bootCommandCenter(page: Page) {
  await page.addInitScript(() => {
    localStorage.setItem("netops_token", "e2e-fake-token");
  });
  // Anchor to BACKEND calls only — `/api/` right after the host. (A plain
  // `**/api/**` glob also matches Vite module paths like
  // /src/features/topology/api/topologyApi.ts and would serve them JSON.)
  await page.route(/^https?:\/\/[^/]+\/api\//, async (route) => {
    const url = route.request().url();
    const json = (body: unknown) => route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(body) });
    if (url.includes("/api/auth/me")) return json(ME);
    if (url.includes("/api/scopes")) return json({ scopes: [{ tenant_id: TENANT, tenant_name: "Acme", region: "us" }], all_tenants: false });
    if (url.includes("/api/correlations")) return json(CORRELATIONS);
    if (url.includes("/api/incidents")) return json([]);
    // Everything else the shell pokes at on boot: a benign empty default.
    return json({});
  });
  await page.goto("/#/incident/overview");
  await expect(page.locator(".cc-h1")).toHaveText("Command Center");
}

test("operator sees only actionable customer-network incidents", async ({ page }) => {
  await bootCommandCenter(page);

  // Exactly one row survives the queue filter (noise + internal-stack dropped).
  const rows = page.locator("tr.cc-row");
  await expect(rows).toHaveCount(1);

  // The confirmed incident is the survivor; the filtered objects never appear.
  await expect(page.locator(".cc-kpi-n").first()).toHaveText("1"); // Correlated incidents KPI
  await expect(page.getByText("edge-9")).toHaveCount(0);     // single-signal noise filtered
  await expect(page.getByText("clickhouse")).toHaveCount(0); // internal-stack filtered (#76)

  // The confirmed row carries a Confirmed RCA chip and an ISP fault domain.
  // (exact match disambiguates the fault chip "ISP / Carrier" from the owner
  // recommendation chip "ISP / carrier".)
  await expect(page.locator("tr.cc-row").getByText("Confirmed", { exact: true })).toBeVisible();
  await expect(page.getByText("ISP / Carrier", { exact: true })).toBeVisible();
});

test("expanding an incident reveals its evidence ledger", async ({ page }) => {
  await bootCommandCenter(page);

  await page.locator("tr.cc-row").first().click();
  // The expand panel shows the evidence summary + recommended next action
  // (scope to the panel's section headings, not the table column header).
  await expect(page.locator(".cc-eh", { hasText: "Evidence" })).toBeVisible();
  await expect(page.getByText(/correlated signal/)).toBeVisible();
  await expect(page.locator(".cc-eh", { hasText: "Recommended next action" })).toBeVisible();
});
