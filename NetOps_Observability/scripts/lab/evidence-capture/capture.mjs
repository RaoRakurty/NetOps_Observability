#!/usr/bin/env node
// capture.mjs — light-mode, high-DPI screenshot harness for the Cloud Demo
// evidence book (docs/design/cloud-demo-traffic-program.md §4).
//
// It drives the RUNNING Correlix UI at http://localhost:8000, forces the LIGHT
// theme, logs in headlessly, navigates to a hash route, asserts the DOM is
// actually light, and writes a crisp (deviceScaleFactor >= 2) PNG — optionally
// scoped+zoomed to one CSS selector so a log panel's text is large and legible.
//
// HONESTY: this only makes CAPTURE repeatable. It fabricates nothing — every
// pixel comes from whatever the live stack is really rendering. During the demo
// window the cloud lanes are populated by real injections; with instances down
// they render sparse/empty, which is the honest state (that's fine for the
// harness smoke-test — we validate mechanics, not content).
//
// Playwright is used ONLY here (already vendored under src/frontend/node_modules
// per the program brief); it is NEVER added to the Go backend or any product
// dependency. Chromium comes from the ms-playwright cache.
//
// Usage:
//   node capture.mjs --route '#/dashboards/appobs' \
//                    --out ../../docs/demos/cloud-fidelity-evidence/aws/2-waf/03-correlix-signal.png
//   node capture.mjs --route '#/logs/logs?q=cloud_waf_log' \
//                    --selector '.log-table' --out .../03-correlix-signal.png
//
// Env (no secrets in code): CORRELIX_BASE (default http://localhost:8000),
//   CORRELIX_USER / CORRELIX_PASS (lab defaults; override for other stacks).

import { fileURLToPath, pathToFileURL } from "node:url";
import { createRequire } from "node:module";
import { dirname, resolve, isAbsolute } from "node:path";
import { existsSync } from "node:fs";
import { mkdir } from "node:fs/promises";
import http from "node:http";
import https from "node:https";

const __dirname = dirname(fileURLToPath(import.meta.url));

// Resolve Playwright from a frontend node_modules, regardless of cwd and whether
// we run inside a git worktree (worktrees don't get their own node_modules — the
// deps live in the main checkout where `npm install` ran). Candidates, in order:
//   1. $CORRELIX_FRONTEND (explicit override)
//   2. this repo's src/frontend (normal checkout)
//   3. the MAIN checkout's src/frontend, derived by stripping .claude/worktrees/<x>/
function resolveFrontend() {
  const candidates = [];
  if (process.env.CORRELIX_FRONTEND) candidates.push(process.env.CORRELIX_FRONTEND);
  candidates.push(resolve(__dirname, "../../../src/frontend"));
  const m = __dirname.match(/^(.*)\/\.claude\/worktrees\/[^/]+\/([^/]+)\/scripts\//);
  if (m) candidates.push(resolve(m[1], m[2], "src/frontend"));
  for (const c of candidates) {
    if (existsSync(resolve(c, "node_modules/@playwright/test"))) return c;
  }
  console.error("[capture] ERROR: @playwright/test not found. Looked in:\n  " +
                candidates.join("\n  ") +
                "\nRun `npm install` in src/frontend, or set CORRELIX_FRONTEND.");
  process.exit(3);
}
const FRONTEND = resolveFrontend();
const frontendRequire = createRequire(pathToFileURL(FRONTEND + "/package.json"));
const { chromium } = frontendRequire("@playwright/test");

// ---- args ------------------------------------------------------------------
function parseArgs(argv) {
  const a = { route: "#/dashboards/home", out: null, selector: null, query: null,
              width: 1600, height: 900, scale: 2, padMs: 1500 };
  for (let i = 0; i < argv.length; i++) {
    const k = argv[i];
    const v = argv[i + 1];
    switch (k) {
      case "--route": a.route = v; i++; break;
      case "--out": a.out = v; i++; break;
      case "--selector": a.selector = v; i++; break;
      case "--query": a.query = v; i++; break;
      case "--width": a.width = parseInt(v, 10); i++; break;
      case "--height": a.height = parseInt(v, 10); i++; break;
      case "--scale": a.scale = parseInt(v, 10); i++; break;
      case "--settle-ms": a.padMs = parseInt(v, 10); i++; break;
      case "--help": a.help = true; break;
      default: break;
    }
  }
  return a;
}

const BASE = (process.env.CORRELIX_BASE || "http://localhost:8000").replace(/\/$/, "");
const USER = process.env.CORRELIX_USER || "admin";
const PASS = process.env.CORRELIX_PASS || "netops-admin-2026"; // lab default; override via env

// ---- headless login → JWT (so we can seed localStorage before first paint) --
function login(base, user, pass) {
  return new Promise((res, rej) => {
    const url = new URL(base + "/api/auth/login");
    const lib = url.protocol === "https:" ? https : http;
    const body = JSON.stringify({ username: user, password: pass });
    const req = lib.request(url, {
      method: "POST",
      headers: { "Content-Type": "application/json",
                 "Content-Length": Buffer.byteLength(body) },
    }, (r) => {
      let buf = "";
      r.on("data", (d) => (buf += d));
      r.on("end", () => {
        if (r.statusCode !== 200) return rej(new Error(`login HTTP ${r.statusCode}: ${buf.slice(0, 200)}`));
        try { res(JSON.parse(buf).token); }
        catch (e) { rej(new Error("login: bad JSON: " + e.message)); }
      });
    });
    req.on("error", rej);
    req.write(body);
    req.end();
  });
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help || !args.out) {
    console.error("usage: node capture.mjs --route '#/...' --out <path.png> [--selector <css>] [--width 1600] [--height 900] [--scale 2]");
    process.exit(args.help ? 0 : 2);
  }
  const outPath = isAbsolute(args.out) ? args.out : resolve(process.cwd(), args.out);
  await mkdir(dirname(outPath), { recursive: true });

  console.log(`[capture] base=${BASE} route=${args.route} scale=${args.scale} out=${outPath}`);
  const token = await login(BASE, USER, PASS);
  console.log("[capture] logged in, token acquired");

  const browser = await chromium.launch({ headless: true });
  try {
    const context = await browser.newContext({
      viewport: { width: args.width, height: args.height },
      deviceScaleFactor: args.scale,            // >= 2 → crisp, zoomed text
      colorScheme: "light",
    });
    // Seed localStorage BEFORE any app script runs: force LIGHT theme + auth.
    // netops.theme=light + netops.chrome=white is exactly what the binary knob
    // writes (src/frontend/src/theme/prefs.ts); netops_token is the session key
    // (src/frontend/src/services/api.ts).
    await context.addInitScript(([tok]) => {
      try {
        localStorage.setItem("netops.theme", "light");
        localStorage.setItem("netops.chrome", "white");
        localStorage.setItem("netops.density", "comfortable");
        localStorage.setItem("netops_token", tok);
      } catch (e) { /* first run before origin: ignored, re-runs post-nav */ }
    }, [token]);

    const wantHash = args.route.startsWith("#") ? args.route : "#/" + args.route;
    const page = await context.newPage();
    // Land on home first, let the SPA finish its one-shot fresh-login landing
    // redirect (App.tsx), THEN force our route so it isn't clobbered.
    await page.goto(BASE + "/", { waitUntil: "networkidle", timeout: 45000 }).catch(() => {});
    await page.waitForTimeout(Math.min(args.padMs, 1200)); // let landing settle
    await page.evaluate((r) => { location.hash = r; }, wantHash);
    await page.waitForTimeout(args.padMs);
    // Re-assert once more in case a late effect bounced the hash.
    const finalHash = await page.evaluate((r) => {
      if (location.hash !== r) location.hash = r;
      return location.hash;
    }, wantHash);
    await page.waitForTimeout(600);
    console.log(`[capture] route settled at ${finalHash}` +
                (finalHash !== wantHash ? ` (asked ${wantHash})` : ""));

    // ---- optional: type a Lucene query into the Log Search box and run it ----
    // The logs view doesn't consume a ?q= URL param, so a lane filter must be
    // typed. Target the Log Search input (not the global top-nav search), fill,
    // and submit via Enter + any "Search" button. Best-effort: on miss, we log
    // and shoot unfiltered rather than fail the capture.
    if (args.query) {
      const applied = await page.evaluate(async (q) => {
        const inputs = [...document.querySelectorAll('input')];
        const box = inputs.find((i) => /query|lucene|level:|src_addr/i.test(i.placeholder || ""))
                 || inputs.find((i) => i.value === "*")
                 || inputs.find((i) => !/^\s*search\s*…?$/i.test(i.placeholder || "") && i.type !== "checkbox");
        if (!box) return false;
        const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value").set;
        setter.call(box, q);
        box.dispatchEvent(new Event("input", { bubbles: true }));
        box.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true }));
        const btn = [...document.querySelectorAll("button")].find((b) => /^\s*search\s*$/i.test(b.textContent || ""));
        if (btn) btn.click();
        return true;
      }, args.query);
      await page.waitForTimeout(2600); // let results reload
      console.log(applied ? `[capture] applied query: ${args.query}`
                          : `[capture] WARN query input not found — unfiltered shot`);
    }

    // ---- assert the DOM is actually LIGHT (fail loud, never a dark shot) ----
    const themeAttr = await page.evaluate(() => document.documentElement.getAttribute("data-theme"));
    const bg = await page.evaluate(() => getComputedStyle(document.body).backgroundColor);
    const isLightBg = (() => {
      const m = /rgba?\(([^)]+)\)/.exec(bg || "");
      if (!m) return false;
      const [r, g, b] = m[1].split(",").map((n) => parseFloat(n));
      return (0.2126 * r + 0.7152 * g + 0.0722 * b) > 150; // luminance → light
    })();
    if (themeAttr !== "light" || !isLightBg) {
      throw new Error(`theme assertion FAILED: data-theme=${themeAttr} body-bg=${bg} ` +
                      `(expected light). Refusing to write a mis-themed shot.`);
    }
    console.log(`[capture] theme OK: data-theme=${themeAttr} body-bg=${bg}`);

    // ---- shoot: element-scoped (zoomed) if a selector is given, else page ---
    if (args.selector) {
      const el = await page.$(args.selector);
      if (!el) throw new Error(`selector not found: ${args.selector}`);
      await el.scrollIntoViewIfNeeded();
      await el.screenshot({ path: outPath });
      console.log(`[capture] wrote element shot (${args.selector}) → ${outPath}`);
    } else {
      await page.screenshot({ path: outPath, fullPage: false });
      console.log(`[capture] wrote viewport shot → ${outPath}`);
    }
  } finally {
    await browser.close();
  }
}

main().catch((e) => { console.error("[capture] ERROR:", e.message); process.exit(1); });
