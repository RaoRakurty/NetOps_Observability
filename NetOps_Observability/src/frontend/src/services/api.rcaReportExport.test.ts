// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// api.rcaReportExport.test.ts — Export PDF on the RCA workspace and the RCA
// library. With the PDF renderer up the server's PDF downloads. With it down
// (every customer bundle: the sidecar never ships, licence audit D6) the SAME
// server document must go to the browser's Save-as-PDF dialog in place — the
// old path opened it in a new tab and left the operator on a bare page.

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";

const printed = vi.hoisted(() => ({ html: [] as string[], ok: true }));
vi.mock("../lib/printHtml", () => ({
  printHtmlDocument: (html: string) => { printed.html.push(html); return printed.ok; },
}));

import { api, clearSession, RcaNotPromotedError } from "./api";

type Reply = { status: number; body: string; type: string };

function routeFetch(byFormat: Record<string, Reply>): string[] {
  const urls: string[] = [];
  vi.stubGlobal("fetch", vi.fn(async (url: string) => {
    urls.push(url);
    const fmt = new URL(url, "http://x").searchParams.get("format") || "";
    const r = byFormat[fmt];
    if (!r) throw new Error(`unexpected fetch ${url}`);
    return new Response(r.body, { status: r.status, headers: { "Content-Type": r.type } });
  }));
  return urls;
}

const DOC = "<!doctype html><title>Incident Analysis</title><p>report</p>";
const RENDERER_DOWN: Reply = {
  status: 503, type: "application/json",
  body: JSON.stringify({ error: "pdf renderer unavailable" }),
};

beforeEach(() => {
  localStorage.clear();
  sessionStorage.clear();
  clearSession();
  printed.html = [];
  printed.ok = true;
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("downloadRcaReport", () => {
  it("renderer down: prints the server document in place and opens no tab", async () => {
    const open = vi.spyOn(window, "open");
    const urls = routeFetch({ pdf: RENDERER_DOWN, html: { status: 200, type: "text/html; charset=utf-8", body: DOC } });
    await expect(api.downloadRcaReport("42493476-abc", "P-424934")).resolves.toBe("print");
    expect(printed.html).toEqual([DOC]);
    expect(open).not.toHaveBeenCalled();
    expect(urls.map((u) => new URL(u, "http://x").searchParams.get("format"))).toEqual(["pdf", "html"]);
  });

  it("renderer up: downloads the PDF and never prints", async () => {
    const created = vi.fn(() => "blob:x");
    vi.stubGlobal("URL", Object.assign(URL, { createObjectURL: created, revokeObjectURL: vi.fn() }));
    routeFetch({ pdf: { status: 200, type: "application/pdf", body: "%PDF-1.4" } });
    await expect(api.downloadRcaReport("42493476-abc", "P-424934")).resolves.toBe("pdf");
    expect(created).toHaveBeenCalledTimes(1);
    expect(printed.html).toEqual([]);
  });

  it("an un-promoted candidate surfaces the promotion gate and prints nothing", async () => {
    routeFetch({ pdf: { status: 403, type: "application/json", body: JSON.stringify({ error: "reserved for promoted real outages" }) } });
    await expect(api.downloadRcaReport("b27", "P-1")).rejects.toBeInstanceOf(RcaNotPromotedError);
    expect(printed.html).toEqual([]);
  });

  it("never writes a non-document body into the print frame", async () => {
    routeFetch({ pdf: RENDERER_DOWN, html: { status: 200, type: "application/json", body: "{\"error\":\"x\"}" } });
    await expect(api.downloadRcaReport("42493476-abc", "P-424934")).rejects.toThrow(/no document/);
    expect(printed.html).toEqual([]);
  });

  it("a failed HTML render is an error, not a silent no-op", async () => {
    routeFetch({ pdf: RENDERER_DOWN, html: { status: 500, type: "application/json", body: "{}" } });
    await expect(api.downloadRcaReport("42493476-abc", "P-424934")).rejects.toThrow(/500/);
  });

  it("a frame that cannot be created is reported", async () => {
    printed.ok = false;
    routeFetch({ pdf: RENDERER_DOWN, html: { status: 200, type: "text/html", body: DOC } });
    await expect(api.downloadRcaReport("42493476-abc", "P-424934")).rejects.toThrow(/print dialog/);
  });
});
