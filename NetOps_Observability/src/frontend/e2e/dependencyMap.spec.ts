// Dependency map flow E2E (gap #2, last user-reachable canvas mode). Switching to
// Dependency requests the flow-derived service-dependency projection and renders it
// on the real React Flow canvas — this is also the only E2E that exercises the graph
// nodes themselves (the other specs assert side panels). Backend mocked.

import { test, expect, type Page, type Route } from "@playwright/test";

const ME = { username: "alice", role: "operator", tenant_id: "t_acme", platform_admin: false, accessible_tenants: ["t_acme"], all_tenants: false };

function node(id: string, label: string) {
  return { id, label, kind: "server", health: "ok", confidence: 1, resolved: true, metrics: {}, evidence: [{ source: "flow", confidence: 0.6 }] };
}

function topoView(mode: string) {
  if (mode === "dependency") {
    return {
      view_id: "v", mode, scope: { tenant_id: "t_acme" }, layout_type: "dependency",
      generated_at: new Date().toISOString(),
      nodes: [node("dev-app", "app1"), node("dev-db", "db1")],
      edges: [{
        id: "dep:dev-app--dev-db", source: "dev-app", target: "dev-db",
        relationship: "dependency", protocol: "flow", status: "up", confidence: 0.6,
        target_port: "PostgreSQL (5432)",
        evidence: [{ source: "flow", confidence: 0.6, detail: "depends on PostgreSQL (5432)" }],
      }],
      groups: [], overlays: ["health", "flow"],
    };
  }
  // explore default
  const n = (id: string) => ({ id, label: id, kind: "router", health: "ok", confidence: 1, metrics: {}, evidence: [{ source: "lldp", confidence: 1 }] });
  return {
    view_id: "v", mode, scope: { tenant_id: "t_acme" }, layout_type: "spine_leaf",
    generated_at: new Date().toISOString(), nodes: [n("edge1"), n("core1")],
    edges: [{ id: "e1", source: "edge1", target: "core1", status: "up", confidence: 1, evidence: [{ source: "lldp", confidence: 1 }] }],
    groups: [], overlays: ["health"],
  };
}

async function openCanvas(page: Page) {
  const modes: string[] = [];
  await page.addInitScript(() => localStorage.setItem("netops_token", "e2e-fake-token"));
  await page.route(/^https?:\/\/[^/]+\/api\//, async (route: Route) => {
    const url = new URL(route.request().url());
    const json = (b: unknown) => route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(b) });
    const p = url.pathname;
    if (p.includes("/api/auth/me")) return json(ME);
    if (p.includes("/api/scopes")) return json({ scopes: [{ tenant_id: "t_acme", tenant_name: "Acme", org_id: "o", org_name: "Acme", region: "us" }], all_tenants: false });
    if (p.includes("/api/topology/view")) {
      const mode = url.searchParams.get("mode") || "explore";
      modes.push(mode);
      return json(topoView(mode));
    }
    return json({});
  });
  await page.goto("/#/infrastructure/topology-canvas");
  return { modes };
}

test("switching to Dependency renders the flow-derived service map", async ({ page }) => {
  const { modes } = await openCanvas(page);

  // Explore loads first (the canvas's default fabric node).
  await expect(page.getByTestId("rf__node-edge1")).toBeVisible();

  await page.getByRole("button", { name: "Dependency" }).click();

  // The canvas requested the dependency projection and renders its endpoints.
  await expect(page.getByTestId("rf__node-dev-app")).toBeVisible();
  await expect(page.getByTestId("rf__node-dev-db")).toBeVisible();
  expect(modes).toContain("dependency");
  // The previous fabric node is gone — the canvas actually swapped projections.
  await expect(page.getByTestId("rf__node-edge1")).toHaveCount(0);
});
