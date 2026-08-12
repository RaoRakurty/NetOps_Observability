// Command Center operator-flow E2E (gap-report #2). Proves the decision system
// actually works end-to-end in a browser: an authenticated operator loads the
// Command Center, sees ONLY actionable customer-network incidents (single-signal
// noise and internal-stack objects filtered), and can expand a row to its evidence.
// The backend is mocked at the network boundary, so no stack is needed.

import { test, expect, type Page } from "@playwright/test";

// The Action Queue renders through the shared DataTable primitive (ae0668a):
// data rows are div[role=row].dtv-row inside the grid labelled "Action Queue —
// correlated incidents" — not the old hand-rolled <tr.cc-row> table. Scoping to
// the named grid keeps the locator anchored to the queue (the accessible
// contract), not to whatever other tables the page may grow.
const queueRows = (page: Page) =>
  page.getByRole("grid", { name: "Action Queue — correlated incidents" }).locator(".dtv-row");

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
  await page.goto("/#/overview/home");
  await expect(page.locator(".cc-h1")).toHaveText("Command Center");
}

test("operator sees only actionable customer-network incidents", async ({ page }) => {
  await bootCommandCenter(page);

  // Exactly one row survives the queue filter (noise + internal-stack dropped).
  const rows = queueRows(page);
  await expect(rows).toHaveCount(1);

  // The confirmed incident is the survivor; the filtered objects never appear.
  await expect(page.locator(".cc-kpi-n").first()).toHaveText("1"); // Correlated incidents KPI
  await expect(page.getByText("edge-9")).toHaveCount(0);     // single-signal noise filtered
  await expect(page.getByText("clickhouse")).toHaveCount(0); // internal-stack filtered (#76)

  // The confirmed row carries a Confirmed RCA chip and an ISP fault domain.
  // (exact match disambiguates the fault chip "ISP / Carrier" from the owner
  // recommendation chip "ISP / carrier".)
  await expect(rows.getByText("Confirmed", { exact: true })).toBeVisible();
  // Scope to the row — the filter bar's fault-domain dropdown also lists "ISP / Carrier".
  await expect(rows.getByText("ISP / Carrier", { exact: true })).toBeVisible();
});

test("expanding an incident reveals its evidence ledger", async ({ page }) => {
  await bootCommandCenter(page);

  await queueRows(page).first().click();
  // The expand panel shows the evidence summary + recommended next action
  // (scope to the panel's section headings, not the table column header).
  await expect(page.locator(".cc-eh", { hasText: "Evidence" })).toBeVisible();
  await expect(page.getByText(/correlated signal/)).toBeVisible();
  await expect(page.locator(".cc-eh", { hasText: "Recommended next action" })).toBeVisible();
});

test("the filter bar narrows the queue without a refetch", async ({ page }) => {
  await bootCommandCenter(page); // one survivor: confirmed, fault domain "ISP / Carrier"

  await expect(queueRows(page)).toHaveCount(1);
  // Filtering to a domain the row isn't in empties the table (no match state).
  // Locate the select through its .cc-filter label wrapper — a bare
  // getByLabel("Fault domain") is ambiguous now that the sortable header's
  // resize grip carries the aria-label "Resize Fault domain column".
  await page
    .locator(".cc-filter", { hasText: "Fault domain" })
    .locator("select")
    .selectOption("SD-WAN");
  await expect(queueRows(page)).toHaveCount(0);
  await expect(page.getByText(/No incidents match the current filters/)).toBeVisible();
  // Clearing brings it back.
  await page.getByRole("button", { name: /Clear/ }).first().click();
  await expect(queueRows(page)).toHaveCount(1);
});
