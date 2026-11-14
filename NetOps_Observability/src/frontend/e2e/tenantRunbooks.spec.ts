// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Tenant runbooks (tracker 337 N-F2), end to end against a faked API that keeps
// the server's rules: one administrator writes a runbook, its cases must pass
// before it can be sent for review, the author is NOT offered Approve, a second
// administrator approves exactly the reviewed text, and "What Iris runs" then
// lists it. Failing cases show their problems; hostile text renders as text.

import { test, expect, type Page, type Route } from "@playwright/test";

type Version = {
  version: number; skill_md: string; cases_yaml: string; body_sha256: string; state: string;
  author: string; approver?: string; harness_passed: boolean; created_at: string;
};
type Runbook = {
  id: string; name: string; kind: string; when_to_use: string; created_by: string; created_at: string; updated_at: string;
  versions: Version[]; runs_in_iris: boolean; needs_recheck: boolean;
};

function newServer() {
  const runbooks: Runbook[] = [];
  const approvals: { by: string; sha: string }[] = [];
  return { runbooks, approvals, failCases: false };
}

async function bootAs(page: Page, user: string, srv: ReturnType<typeof newServer>) {
  await page.addInitScript(() => localStorage.setItem("netops_token", "e2e-fake-token"));
  await page.route(/^https?:\/\/[^/]+\/api\//, async (route: Route) => {
    const req = route.request();
    const p = new URL(req.url()).pathname;
    const json = (b: unknown, status = 200) => route.fulfill({ status, contentType: "application/json", body: JSON.stringify(b) });
    const body = () => (req.postDataJSON() ?? {}) as Record<string, unknown>;
    const now = new Date().toISOString();

    if (p === "/api/auth/me") {
      return json({ username: user, role: "admin", tenant_id: "t_acme", platform_admin: false, accessible_tenants: ["t_acme"], all_tenants: false, org_id: "org-acme" });
    }
    if (p === "/api/scopes") {
      return json({ scopes: [{ tenant_id: "t_acme", tenant_name: "Acme", org_id: "org-acme", org_name: "Acme", region: "us" }], all_tenants: false });
    }
    if (p === "/api/ai/runbooks" && req.method() === "GET") {
      return json({ runbooks: srv.runbooks, you: user, limits: { runbooks: 30, versions: 50, cases: 40, links: 20 } });
    }
    if (p === "/api/ai/runbooks" && req.method() === "POST") {
      const b = body();
      const r: Runbook = {
        id: `r${srv.runbooks.length + 1}`, name: String(b.name), kind: String(b.kind), when_to_use: "", created_by: user,
        created_at: now, updated_at: now, runs_in_iris: false, needs_recheck: false,
        versions: [{ version: 1, skill_md: String(b.skill_md), cases_yaml: String(b.cases_yaml), body_sha256: `sha-${srv.runbooks.length + 1}`,
          state: "draft", author: user, harness_passed: false, created_at: now }],
      };
      srv.runbooks.push(r);
      return json(r, 201);
    }
    const links = p.match(/^\/api\/ai\/runbooks\/([^/]+)\/links$/);
    if (links) return json({ links: [] });
    const m = p.match(/^\/api\/ai\/runbooks\/([^/]+)\/(\w+)$/);
    if (m) {
      const r = srv.runbooks.find((x) => x.id === m[1]);
      if (!r) return json({ error: "no such runbook" }, 404);
      const v = r.versions[r.versions.length - 1];
      const b = body();
      const failing = { error: "the runbook's cases did not pass", problems: [{ case: "logs naming the carrier", message: "the verdict did not hold" }] };
      switch (m[2]) {
        case "check":
          return srv.failCases ? json(failing, 422) : json({ passed: true, cases: 2, fingerprint: "fp" });
        case "submit":
          if (v.author !== user) return json({ error: "only the person who wrote this draft can change it" }, 403);
          if (srv.failCases) return json(failing, 422);
          v.state = "pending";
          v.harness_passed = true;
          return json(r);
        case "approve":
          if (v.author === user) return json({ error: "you wrote this version, so another administrator has to approve it" }, 403);
          if (b.body_sha256 !== v.body_sha256 || b.version !== v.version) return json({ error: "the text changed since you reviewed it" }, 409);
          v.state = "active";
          v.approver = user;
          r.runs_in_iris = true;
          srv.approvals.push({ by: user, sha: String(b.body_sha256) });
          return json(r);
      }
    }
    return json({});
  });
  await page.goto("/#/admin/iris-runbooks");
}

test.use({ timezoneId: "UTC", locale: "en-US" });

test("one administrator writes and checks, a second approves, and Iris runs it", async ({ page, browser }) => {
  const srv = newServer();
  await bootAs(page, "alice", srv);
  await page.getByPlaceholder("my-wan-check").fill("my-wan-check");
  await page.getByLabel("New runbook test cases").fill("case: one\nquestion: our carrier brownout");
  await page.getByRole("button", { name: "Save draft" }).click();
  await page.getByRole("button", { name: "Run its cases" }).click();
  await expect(page.getByText("All 2 cases passed. Nothing was changed.")).toBeVisible();
  await page.getByRole("button", { name: "Send for review" }).click();
  await expect(page.getByText("Its cases passed. Waiting for another administrator to review it.")).toBeVisible();
  await expect(page.getByRole("button", { name: "Approve" })).toHaveCount(0);

  const bobPage = await browser.newPage();
  await bootAs(bobPage, "bob", srv);
  await expect(bobPage.getByText("Proposed")).toBeVisible();
  await bobPage.getByRole("button", { name: "Approve" }).click();
  await expect(bobPage.getByTestId("rbk-status")).toContainText("my-wan-check (version 1) — Iris can run it");
  expect(srv.approvals).toEqual([{ by: "bob", sha: "sha-1" }]);
  await bobPage.close();
});

test("failing cases show their problems and nothing is sent", async ({ page }) => {
  const srv = newServer();
  srv.failCases = true;
  await bootAs(page, "alice", srv);
  await page.getByPlaceholder("my-wan-check").fill("my-wan-check");
  await page.getByLabel("New runbook test cases").fill("case: one");
  await page.getByRole("button", { name: "Save draft" }).click();
  await page.getByRole("button", { name: "Send for review" }).click();
  await expect(page.getByTestId("rbk-problems")).toContainText("logs naming the carrier");
  await expect(page.getByTestId("rbk-problems")).toContainText("the verdict did not hold");
  expect(srv.runbooks[0].versions[0].state).toBe("draft");
});

test("runbook text is shown as text, never as markup", async ({ page }) => {
  const srv = newServer();
  const now = new Date().toISOString();
  srv.runbooks.push({
    id: "r1", name: "hostile", kind: "investigative", when_to_use: "", created_by: "carol", created_at: now, updated_at: now,
    runs_in_iris: false, needs_recheck: false,
    versions: [{ version: 1, skill_md: '<img src=x onerror="window.__rbk=1">', cases_yaml: "", body_sha256: "s", state: "pending",
      author: "carol", harness_passed: true, created_at: now }],
  });
  await bootAs(page, "alice", srv);
  await expect(page.getByText("Proposed")).toBeVisible();
  await expect(page.locator(".nctx img")).toHaveCount(0);
  expect(await page.evaluate(() => (window as unknown as { __rbk?: number }).__rbk)).toBeUndefined();
});
