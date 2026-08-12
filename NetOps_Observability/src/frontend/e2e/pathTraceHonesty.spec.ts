// Path Trace honesty E2E (gap #8, end-to-end). The #8 guard says an IGP-computed
// shortest path must NEVER be presented to the operator as a live trace. These drive
// the REAL topology canvas — switch to Path Trace, pick src+dst — and assert the
// provenance chip the operator actually sees: a "computed" path reads
// "Computed … not a live trace" (never "Measured"), and a "measured" path reads
// "Measured". The backend is mocked at the network boundary.

import { test, expect, type Page, type Route } from "@playwright/test";

const ME = { username: "alice", role: "operator", tenant_id: "t_acme", platform_admin: false, accessible_tenants: ["t_acme"], all_tenants: false };

function node(id: string) {
  return { id, label: id, kind: "router", health: "ok", confidence: 1, metrics: {}, evidence: [{ source: "lldp", confidence: 1 }] };
}

// A small fabric; in path_trace with src+dst it carries a path tagged with the
// provenance under test.
function topoView(mode: string, src: string | null, dst: string | null, pathSource: "computed" | "measured") {
  const view: Record<string, unknown> = {
    view_id: "v", mode, scope: { tenant_id: "t_acme" },
    layout_type: mode === "path_trace" ? "path_first" : "spine_leaf",
    generated_at: new Date().toISOString(),
    nodes: [node("edge1"), node("core1"), node("dc1")],
    edges: [
      { id: "e1", source: "edge1", target: "core1", status: "up", confidence: 1, evidence: [{ source: "lldp", confidence: 1 }] },
      { id: "e2", source: "core1", target: "dc1", status: "up", confidence: 1, evidence: [{ source: "lldp", confidence: 1 }] },
    ],
    groups: [], overlays: ["health"],
  };
  if (mode === "path_trace" && src && dst) {
    view.path = [src, "core1", dst].filter((v, i, a) => a.indexOf(v) === i);
    view.path_source = pathSource;
  }
  return view;
}

async function openPathTrace(page: Page, pathSource: "computed" | "measured") {
  await page.addInitScript(() => localStorage.setItem("netops_token", "e2e-fake-token"));
  await page.route(/^https?:\/\/[^/]+\/api\//, async (route: Route) => {
    const url = new URL(route.request().url());
    const json = (b: unknown) => route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(b) });
    if (url.pathname.includes("/api/auth/me")) return json(ME);
    if (url.pathname.includes("/api/scopes")) return json({ scopes: [{ tenant_id: "t_acme", tenant_name: "Acme", org_id: "o", org_name: "Acme", region: "us" }], all_tenants: false });
    if (url.pathname.includes("/api/topology/view"))
      return json(topoView(url.searchParams.get("mode") || "explore", url.searchParams.get("src"), url.searchParams.get("dst"), pathSource));
    return json({});
  });
  await page.goto("/#/investigate/topology");

  // Switch to Path Trace, then choose endpoints (the picker populates from the
  // loaded fabric's nodes).
  await page.getByRole("button", { name: "Path trace" }).click();
  await page.getByLabel("Path source device").selectOption("edge1");
  await page.getByLabel("Path destination device").selectOption("dc1");

  // The hop ladder appears once the path resolves.
  await expect(page.getByText(/Path · \d+ hops/)).toBeVisible();
}

test("a COMPUTED path is labeled an inference, never a live trace (#8)", async ({ page }) => {
  await openPathTrace(page, "computed");

  // The provenance label appears on the header chip AND in the per-hop detail
  // panel (#85) — anchor on the canonical chip, then require EVERY instance to
  // carry the honesty wording.
  const chip = page.locator("span.netpath-prov");
  await expect(chip).toBeVisible();
  await expect(chip).toContainText(/Computed/);
  await expect(chip).toContainText(/not a live trace/i);
  for (const el of await page.getByText(/Computed/).all()) {
    await expect(el).toContainText(/not a live trace/i);
  }
  // The non-negotiable: a computed path must NOT be presented as measured.
  await expect(page.getByText("Measured · live traceroute")).toHaveCount(0);
});

test("a MEASURED path is labeled as measured ground truth", async ({ page }) => {
  await openPathTrace(page, "measured");

  await expect(page.locator("span.netpath-prov")).toContainText(/Measured/);
  await expect(page.getByText(/not a live trace/i)).toHaveCount(0);
});
