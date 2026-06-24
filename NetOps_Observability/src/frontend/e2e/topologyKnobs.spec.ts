// Topology canvas KNOBS verification — every toolbar control must produce a
// VISIBLE, design-matching change (the "Exec vs Operator showed the same" + greyed
// dead-tab defects). Backend mocked with a fixture that has metrics + a trouble node
// so the density ramp actually has something to express. Screenshots land in
// test-results/ for eyeballing; the assertions are the regression gate.

import { test, expect, type Page, type Route } from "@playwright/test";

const ME = { username: "alice", role: "operator", tenant_id: "t_acme", platform_admin: false, accessible_tenants: ["t_acme"], all_tenants: false };

// Two nodes: one calm (named only at operator+), one in trouble (named at every
// density). Both carry CPU/MEM so the engineer metric strip has data.
function node(id: string, label: string, health: string) {
  return {
    id, label, kind: "router", health, confidence: 1, resolved: true,
    metrics: { cpu_pct: 42, mem_pct: 61 },
    evidence: [{ source: "lldp", confidence: 1 }],
  };
}

function topoView(mode: string) {
  const base = { view_id: "v", mode, scope: { tenant_id: "t_acme" }, layout_type: "spine_leaf", generated_at: new Date().toISOString(), groups: [] };
  if (mode === "dependency") {
    // No flow attribution → zero nodes. Must show an honest empty state, not a blank canvas.
    return { ...base, layout_type: "dependency", nodes: [], edges: [], overlays: ["flow"] };
  }
  if (mode === "capacity") {
    // A near-idle link (raw VM ratio) must render "<0.1%", never the 20-digit float.
    return {
      ...base,
      nodes: [node("calm-sw", "calm-sw", "ok"), node("sick-rtr", "sick-rtr", "critical")],
      edges: [{
        id: "e1", source: "calm-sw", target: "sick-rtr", status: "up", confidence: 1,
        utilization_pct: 0.00003984453955175126, source_port: "Gi0/1", target_port: "Eth1",
        evidence: [{ source: "lldp", confidence: 1 }],
      }],
      overlays: ["health", "utilization"],
    };
  }
  return {
    ...base,
    nodes: [node("calm-sw", "calm-sw", "ok"), node("sick-rtr", "sick-rtr", "critical")],
    edges: [{ id: "e1", source: "calm-sw", target: "sick-rtr", status: "up", confidence: 1, evidence: [{ source: "lldp", confidence: 1 }] }],
    overlays: ["health"],
  };
}

async function openCanvas(page: Page) {
  await page.addInitScript(() => localStorage.setItem("netops_token", "e2e-fake-token"));
  await page.route(/^https?:\/\/[^/]+\/api\//, async (route: Route) => {
    const url = new URL(route.request().url());
    const json = (b: unknown) => route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(b) });
    const p = url.pathname;
    if (p.includes("/api/auth/me")) return json(ME);
    if (p.includes("/api/scopes")) return json({ scopes: [{ tenant_id: "t_acme", tenant_name: "Acme", org_id: "o", org_name: "Acme", region: "us" }], all_tenants: false });
    if (p.includes("/api/topology/view")) return json(topoView(url.searchParams.get("mode") || "explore"));
    if (p.includes("/api/topology/graph")) return json({ ...topoView("explore"), stale: false });
    return json({});
  });
  await page.goto("/#/infrastructure/topology-canvas");
  await expect(page.getByText("sick-rtr")).toBeVisible(); // canvas rendered
}

const name = (page: Page, t: string) => page.locator("span", { hasText: t }).first();

test("density is a visible ramp: Exec hides calm names, Operator names all, Engineer adds metrics", async ({ page }) => {
  await openCanvas(page);

  // Default = Operator: every node is named.
  await expect(name(page, "calm-sw")).toBeVisible();
  await page.screenshot({ path: "test-results/knob-density-operator.png" });

  // Executive (wallboard): the calm node's name is suppressed; the troublemaker stays named.
  await page.getByRole("button", { name: "Exec", exact: true }).click();
  await expect(name(page, "calm-sw")).toBeHidden();
  await expect(name(page, "sick-rtr")).toBeVisible();
  await page.screenshot({ path: "test-results/knob-density-exec.png" });

  // Engineer: calm node named AGAIN and the inline metric strip appears.
  await page.getByRole("button", { name: "Engineer", exact: true }).click();
  await expect(name(page, "calm-sw")).toBeVisible();
  await expect(page.getByText(/CPU/i).first()).toBeVisible();
  await page.screenshot({ path: "test-results/knob-density-engineer.png" });

  // Incident: distinct again (calm dimmed, trouble lifted) — the troublemaker stays named.
  await page.getByRole("button", { name: "Incident", exact: true }).click();
  await expect(name(page, "sick-rtr")).toBeVisible();
  await page.screenshot({ path: "test-results/knob-density-incident.png" });
});

test("no dead tabs: only implemented workflows are offered (no greyed do-nothing tabs)", async ({ page }) => {
  await openCanvas(page);

  // Implemented modes are present and clickable.
  for (const m of ["Explore", "Investigate", "Path Trace", "Capacity", "Dependency"]) {
    await expect(page.getByRole("button", { name: m, exact: true })).toBeVisible();
  }
  // The placeholder modes are NOT rendered (they were greyed + did nothing).
  await expect(page.getByRole("button", { name: "Change Review", exact: true })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Executive / Geo", exact: true })).toHaveCount(0);
});

test("Capacity utilization is operator-readable (no 20-digit float)", async ({ page }) => {
  await openCanvas(page);
  await page.getByRole("button", { name: "Capacity", exact: true }).click();
  // The near-idle link reads "<0.1%", never the raw 0.0000398… float.
  await expect(page.getByText("<0.1%").first()).toBeVisible();
  await expect(page.getByText(/0\.0000398/)).toHaveCount(0);
});

test("empty real view shows an honest empty state — never fabricated demo data", async ({ page }) => {
  await openCanvas(page);
  await page.getByRole("button", { name: "Dependency", exact: true }).click();
  // The dependency projection returned zero nodes → we show the honest empty state,
  // NOT the cloud demo mock (us-east-1 / vpc-prod / alb-checkout) as if it were live.
  await expect(page.getByText("No service dependencies in this window")).toBeVisible();
  await expect(page.getByText("us-east-1")).toHaveCount(0);
  await expect(page.getByText("alb-checkout")).toHaveCount(0);
});
