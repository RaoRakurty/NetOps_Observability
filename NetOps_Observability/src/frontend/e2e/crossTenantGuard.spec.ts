// Cross-tenant UI guard E2E (gap-report #2, the most important SaaS/security
// promise): one tenant must NEVER see another tenant's objects, evidence, blast
// radius, incidents or ledger details. The mock backend models a CORRECTLY isolated
// API — it keys every response on the caller's tenant (X-Acting-Tenant header, else
// the authenticated token's tenant) — and these prove the SPA, given that backend:
//   (a) renders only the caller-tenant's data, symmetrically (A sees only A; B only B);
//   (b) offers a non-platform tenant NO UI path to pivot to another tenant
//       (the scope control is a static chip, never a switcher);
//   (c) never even REQUESTS another tenant's data.

import { test, expect, type Page, type Route } from "@playwright/test";

// The Action Queue renders through the shared DataTable primitive (ae0668a):
// data rows are div[role=row].dtv-row inside the grid labelled "Action Queue —
// correlated incidents" — not the old hand-rolled <tr.cc-row> table.
const queueRows = (page: Page) =>
  page.getByRole("grid", { name: "Action Queue — correlated incidents" }).locator(".dtv-row");

// Two tenants, each with one confirmed incident touching a tenant-unique device.
const DB: Record<string, { device: string; corrId: string; objects: unknown[] }> = {
  t_acme: {
    device: "acme-edge-1", corrId: "corr-acme-1",
    objects: [obj("corr-acme-1", "acme-edge-1", "sig.ent.wan.dia-egress-degraded")],
  },
  t_globex: {
    device: "globex-core-7", corrId: "corr-globex-1",
    objects: [obj("corr-globex-1", "globex-core-7", "sig.ent.dc.fabric-uplink-down")],
  },
};

function obj(corrId: string, device: string, hyp: string) {
  return {
    correlation_id: corrId, version: 2, state: "open",
    window_start: new Date(Date.now() - 15 * 60_000).toISOString(),
    window_end: new Date().toISOString(),
    top_hypothesis: hyp, top_confidence: 0.9, verdict_tier: "confirmed",
    hypotheses: "{}", evidence_missing: "[]",
    affected: JSON.stringify({ devices: [device], sites: ["site-1"] }),
    signal_count: 4, node_count: 3, owner: "netops",
    engine_version: "v1", catalog_version: "c1", created_at: new Date().toISOString(),
  };
}

function me(tenant: string) {
  return {
    username: `user-${tenant}`, role: "operator", tenant_id: tenant,
    platform_admin: false, accessible_tenants: [tenant], all_tenants: false,
    org_id: `org-${tenant}`,
  };
}

// Boot the Command Center authenticated as `tenant`, against a tenant-isolated
// mock backend. Records every correlations request's acting tenant for assertions.
async function bootAs(page: Page, tenant: string) {
  const correlationRequests: string[] = [];
  await page.addInitScript(() => localStorage.setItem("netops_token", "e2e-fake-token"));
  await page.route(/^https?:\/\/[^/]+\/api\//, async (route: Route) => {
    const req = route.request();
    const url = req.url();
    const json = (body: unknown, status = 200) =>
      route.fulfill({ status, contentType: "application/json", body: JSON.stringify(body) });

    // The authenticated tenant is fixed by the token; a correct backend derives the
    // acting tenant from it (or an explicit X-Acting-Tenant) and REFUSES a tenant the
    // caller can't reach.
    const asked = req.headers()["x-acting-tenant"] || tenant;

    if (url.includes("/api/auth/me")) return json(me(tenant));
    if (url.includes("/api/scopes"))
      return json({ scopes: [{ tenant_id: tenant, tenant_name: tenant, org_id: `org-${tenant}`, org_name: tenant, region: "us" }], all_tenants: false });
    if (url.includes("/api/correlations")) {
      correlationRequests.push(asked);
      if (asked !== tenant) return json({ error: "cross-tenant denied" }, 403); // backend isolation
      return json({ data: DB[tenant].objects, meta: [] });
    }
    if (url.includes("/api/incidents")) return json([]);
    return json({});
  });
  await page.goto("/#/incident/overview");
  await expect(page.locator(".cc-h1")).toHaveText("Command Center");
  return { correlationRequests };
}

test("tenant A sees ONLY tenant A's incident — never tenant B's", async ({ page }) => {
  await bootAs(page, "t_acme");

  await expect(queueRows(page)).toHaveCount(1);
  await queueRows(page).first().click(); // expand → blast radius + evidence

  // A's own device is shown in the expanded blast radius…
  await expect(page.getByText("acme-edge-1")).toBeVisible();
  // …and NOTHING belonging to tenant B is anywhere on the page.
  const body = await page.locator("body").innerText();
  expect(body).not.toContain("globex-core-7");
  expect(body).not.toContain("corr-globex-1");
});

test("tenant B sees ONLY tenant B's incident — symmetric isolation", async ({ page }) => {
  await bootAs(page, "t_globex");

  await expect(queueRows(page)).toHaveCount(1);
  await queueRows(page).first().click();

  await expect(page.getByText("globex-core-7")).toBeVisible();
  const body = await page.locator("body").innerText();
  expect(body).not.toContain("acme-edge-1");
  expect(body).not.toContain("corr-acme-1");
});

test("a tenant-scoped operator has NO UI path to another tenant", async ({ page }) => {
  await bootAs(page, "t_acme");

  // The scope control is a STATIC chip — there is no tenant switcher to pivot with.
  await expect(page.locator(".scope-chip")).toBeVisible();
  await expect(page.locator(".scope-btn")).toHaveCount(0);
  await expect(page.locator(".scope-sel")).toHaveCount(0);
});

test("the SPA never even requests another tenant's data", async ({ page }) => {
  const { correlationRequests } = await bootAs(page, "t_acme");
  // Let the 30s auto-refresh poll fire at least once more would be slow; one load
  // is enough to prove scoping. Every correlations fetch acted AS t_acme.
  await page.waitForTimeout(500);
  expect(correlationRequests.length).toBeGreaterThan(0);
  expect(correlationRequests.every((t) => t === "t_acme")).toBe(true);
  expect(correlationRequests).not.toContain("t_globex");
});
