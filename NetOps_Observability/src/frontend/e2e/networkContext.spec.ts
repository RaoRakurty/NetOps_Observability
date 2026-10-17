// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Network context (tracker 337 N-F1), end to end against a faked API that
// keeps the server's two-person rule: one administrator writes a fact and
// sends it for review, is NOT offered an Approve button, a second
// administrator approves exactly the reviewed text, and "What Iris reads"
// then shows it. Hostile fact text renders as text.

import { test, expect, type Page, type Route } from "@playwright/test";

type Version = { version: number; body: string; body_sha256: string; state: string; author: string; approver?: string; created_at: string };
type Fact = { id: string; scope: string; kind: string; key: string; created_by: string; created_at: string; updated_at: string; versions: Version[] };

const KINDS = [
  { kind: "topology_note", label: "Network layout note" },
  { kind: "terminology", label: "Our terminology" },
];

// One store shared by both administrators (the same workspace).
function newServer() {
  const facts: Fact[] = [];
  const approvals: { by: string; sha: string }[] = [];
  return { facts, approvals };
}

async function bootAs(page: Page, user: string, srv: ReturnType<typeof newServer>) {
  await page.addInitScript(() => localStorage.setItem("netops_token", "e2e-fake-token"));
  await page.route(/^https?:\/\/[^/]+\/api\//, async (route: Route) => {
    const req = route.request();
    const url = new URL(req.url());
    const p = url.pathname;
    const json = (b: unknown, status = 200) => route.fulfill({ status, contentType: "application/json", body: JSON.stringify(b) });
    const body = () => (req.postDataJSON() ?? {}) as Record<string, unknown>;
    const now = new Date().toISOString();

    if (p === "/api/auth/me") {
      return json({ username: user, role: "admin", tenant_id: "t_acme", platform_admin: false, accessible_tenants: ["t_acme"], all_tenants: false, org_id: "org-acme" });
    }
    if (p === "/api/scopes") {
      return json({ scopes: [{ tenant_id: "t_acme", tenant_name: "Acme", org_id: "org-acme", org_name: "Acme", region: "us" }], all_tenants: false });
    }
    if (p === "/api/ai/context" && req.method() === "GET") {
      return json({ facts: srv.facts, kinds: KINDS, you: user, limits: { body_bytes: 2000, key_bytes: 80, facts: 50 } });
    }
    if (p === "/api/ai/context/preview") {
      const active = srv.facts.flatMap((f) => f.versions.filter((v) => v.state === "active").map((v) => `\n- Network layout note (whole network) — ${f.key}: ${v.body}`));
      return json({ block: active.length ? "CUSTOMER-DECLARED CONTEXT — …" + active.join("") : "", facts: active.length, omitted: 0 });
    }
    if (p === "/api/ai/context" && req.method() === "POST") {
      const b = body();
      const f: Fact = {
        id: `f${srv.facts.length + 1}`, scope: String(b.scope), kind: String(b.kind), key: String(b.key), created_by: user, created_at: now, updated_at: now,
        versions: [{ version: 1, body: String(b.body), body_sha256: `sha-${srv.facts.length + 1}`, state: "draft", author: user, created_at: now }],
      };
      srv.facts.push(f);
      return json(f, 201);
    }
    const m = p.match(/^\/api\/ai\/context\/([^/]+)\/(\w+)$/);
    if (m) {
      const f = srv.facts.find((x) => x.id === m[1]);
      if (!f) return json({ error: "no such fact" }, 404);
      const v = f.versions[f.versions.length - 1];
      const b = body();
      switch (m[2]) {
        case "submit":
          if (v.author !== user) return json({ error: "only the person who wrote this draft can change it" }, 403);
          v.state = "pending";
          return json(f);
        case "approve":
          if (v.author === user) return json({ error: "you wrote this version, so another administrator has to approve it" }, 403);
          if (b.body_sha256 !== v.body_sha256 || b.version !== v.version) return json({ error: "the text changed since you reviewed it" }, 409);
          v.state = "active";
          v.approver = user;
          srv.approvals.push({ by: user, sha: String(b.body_sha256) });
          return json(f);
      }
    }
    return json({});
  });
  await page.goto("/#/admin/network-context");
}

test.use({ timezoneId: "UTC", locale: "en-US" });

test("one administrator writes, a second approves, and Iris reads it", async ({ page, browser }) => {
  const srv = newServer();
  await bootAs(page, "alice", srv);
  await page.getByLabel("Short name").fill("DR site");
  await page.getByLabel("The fact").fill("core-02 is the DR site");
  await page.getByRole("button", { name: "Save draft" }).click();
  await page.getByRole("button", { name: "Send for review" }).click();
  await expect(page.getByText("Waiting for another administrator to review it.")).toBeVisible();
  await expect(page.getByRole("button", { name: "Approve" })).toHaveCount(0);

  const bobPage = await browser.newPage();
  await bootAs(bobPage, "bob", srv);
  await expect(bobPage.getByText("Proposed")).toBeVisible();
  await bobPage.getByRole("button", { name: "Approve" }).click();
  await expect(bobPage.getByTestId("nctx-preview")).toContainText("core-02 is the DR site");
  expect(srv.approvals).toEqual([{ by: "bob", sha: "sha-1" }]);
  await bobPage.close();
});

test("fact text is shown as text, never as markup", async ({ page }) => {
  const srv = newServer();
  const now = new Date().toISOString();
  srv.facts.push({
    id: "f1", scope: "tenant", kind: "topology_note", key: "x", created_by: "carol", created_at: now, updated_at: now,
    versions: [{ version: 1, body: '<img src=x onerror="window.__nctx=1">', body_sha256: "s", state: "pending", author: "carol", created_at: now }],
  });
  await bootAs(page, "alice", srv);
  await expect(page.getByText("Proposed")).toBeVisible();
  await expect(page.locator(".nctx img")).toHaveCount(0);
  expect(await page.evaluate(() => (window as unknown as { __nctx?: number }).__nctx)).toBeUndefined();
});
