// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// irisBackend.ts — the Iris API, faked at the network boundary for the Iris
// e2e specs (tracker 337 N-E5). Same harness as every other spec here: route
// interception on /api/*, no real backend, no real network.
//
// The payloads mirror the Go JSON exactly (json tags read from the source):
//   · /api/ai/ask → ai.Answer (ai/schemas.go); the data arm's `data` is
//     nlqCompiled.body() + "result" + "presentation" (ai_handlers.go), result =
//     plan.ResultSet (internal/nlquery/plan/result.go), presentation =
//     present.Plan (internal/nlquery/present/present.go).
//   · conversations → irisconvo.Conversation / Turn (internal/irisconvo/store.go);
//     a conversation the server does not hold is 404 {"error":"not found"}.
//   · aliases → entityalias.Alias; resolve → resolve.Result (refs + ambiguous).
//   · errors → writeError: {"error": "<sentence>"}.
// All timestamps are fixed, so nothing depends on the wall clock.

import type { Page, Route } from "@playwright/test";

export type Json = Record<string, unknown>;

export const FIXED_NOW = "2026-09-27T10:00:00Z";

/** A hostile cell value: if anything renders it as HTML, onerror sets the flag. */
export const XSS_IMG = '<img src=x onerror="window.__irisXss=1">';

/** present.DisclosureNotAView — the server's note when it ignored a model suggestion. */
export const SUGGESTION_IGNORED =
  "The AI model suggested a layout Iris does not have, so it was ignored and the standard layout is shown.";

export interface IrisFake {
  /** Every /api/ai/ask body, in order. */
  asks: { question: string; context?: Record<string, string>; conversation_id?: string }[];
  /** Every POST /api/ai/conversations (a conversation started). */
  started: string[];
  /** Every POST /api/ai/conversations/{id}/messages. */
  messages: { id: string; question: string; tz?: string }[];
  /** Every PUT /api/ai/aliases body. */
  aliasPuts: Json[];
  /** Every POST /api/ai/entities/resolve body. */
  resolves: { text: string; types: string[] }[];
  /** The conversations the server holds; delete one to model a restart/expiry. */
  live: Set<string>;
}

export interface IrisBackendOptions {
  /** The authenticated principal (GET /api/auth/me). */
  me?: Json;
  /** GET /api/ai/tenant-config; null = the caller is not a tenant admin (403). */
  tenantConfig?: Json | null;
  /** The /api/ai/ask answer for a question (conversation_id is stamped by the fake). */
  answer?: (question: string) => Json | { status: number; body: Json };
  /** The conversation-message answer (IrisConversationAnswer minus conversation_id/turn). */
  converse?: (question: string, id: string) => Json;
  /** POST /api/ai/entities/resolve. */
  resolve?: (text: string, types: string[]) => Json;
}

export const TENANT_ME = {
  username: "alice", role: "admin", tenant_id: "t_acme", platform_admin: false,
  accessible_tenants: ["t_acme"], all_tenants: false, org_id: "org-acme",
};

/** A tenant admin's workspace AI settings (ai_tenant_config.go), no key and no
 *  platform service — so the box stays on the grounded engine (no chat retry). */
export const TENANT_CONFIG = {
  provider: "", model: "", model_fast: "", model_strong: "",
  key_present: false, no_platform_key: false, assistant_enabled: true,
  investigations_enabled: false, platform_key_available: false,
  providers: ["anthropic", "openai", "gemini"],
  model_suggestions: {
    anthropic: ["claude-opus-4-8", "claude-sonnet-4-6", "claude-haiku-4-5-20251001"],
    openai: ["gpt-4o", "gpt-4o-mini", "gpt-4.1"],
    gemini: ["gemini-2.5-flash", "gemini-2.5-pro", "gemini-flash-latest"],
  },
};

// ---- answers -------------------------------------------------------------------

/** "top 3 devices by cpu in the last hour" — a metric_topk data answer. One
 *  device name is hostile markup; it must reach the screen as text. */
export function topCpuAnswer(): Json {
  const rows = [
    { device: "core-rtr-1", value: 91.5 },
    { device: XSS_IMG, value: 72 },
    { device: "edge-fw-2", value: 40 },
  ];
  const astTopk = {
    v: 1, query_type: "metric_topk", target: "device", metric: "cpu_util_pct", aggregation: "max",
    time_range: { kind: "relative", last: "1h" }, order_by: [{ field: "value", dir: "desc" }], limit: 3,
  };
  return {
    mode: "data_query", intent: "query_metric", modules: [],
    text: `Cpu — 3 results: core-rtr-1 91.5%; ${XSS_IMG} 72%; edge-fw-2 40%;`,
    citations: [{ id: "query:q-7f3a", kind: "query", label: "Query 5d41a8c0", href: "" }],
    disclaimers: [],
    data: {
      intent: "query_metric", entities: null, clarify: null, decline: "", unparsed: false, not_understood: null,
      validation: { valid: true }, ast: astTopk,
      result: {
        query_id: "q-7f3a", ast_hash: "5d41a8c0", catalog_version: "1", query_type: "metric_topk",
        metric: "cpu_util_pct", unit: "percent",
        window: { from: "2026-09-27T09:00:00Z", to: FIXED_NOW },
        rows, truncated: false,
        provenance: { source: "victoriametrics", executed_at: FIXED_NOW, duration_ms: 42 },
      },
    },
  };
}

/** "memory on that device" answered as a follow-up — a metric_series answer
 *  (series only, no rows: that is what the planner returns for a series). */
export function memorySeriesAnswer(): Json {
  const t0 = Date.parse("2026-09-27T09:00:00Z") / 1000;
  const points = Array.from({ length: 6 }, (_, i) => ({ t: t0 + i * 600, v: 61 + i }));
  return {
    mode: "data_query", intent: "query_metric", modules: [],
    text: "Memory for 1 series, highest peak first: core-rtr-1 peak 66% (avg 63.5%);",
    citations: [{ id: "query:q-8b21", kind: "query", label: "Query 9e107d9d", href: "" }],
    disclaimers: [],
    data: {
      intent: "query_metric", entities: [{ input_text: "that device", entity_id: "device:core-rtr-1", entity_type: "device", confidence: 1, resolution_method: "canonical_id" }],
      clarify: null, decline: "", unparsed: false, not_understood: null,
      validation: { valid: true },
      ast: {
        v: 1, query_type: "metric_series", target: "device", metric: "mem_util_pct", aggregation: "avg",
        entities: [{ type: "device", id: "device:core-rtr-1" }], time_range: { kind: "relative", last: "1h" },
      },
      result: {
        query_id: "q-8b21", ast_hash: "9e107d9d", catalog_version: "1", query_type: "metric_series",
        metric: "mem_util_pct", unit: "percent",
        window: { from: "2026-09-27T09:00:00Z", to: FIXED_NOW, step: 600000000000 },
        series: [{ entity: { device: "device:core-rtr-1" }, points }], truncated: false,
        provenance: { source: "victoriametrics", entities: [{ type: "device", id: "device:core-rtr-1" }], executed_at: FIXED_NOW, duration_ms: 18 },
      },
      // The server's PresentationPlan (N-E1, present.Plan): here the model's
      // view suggestion was out of the enum, so the server's choice stands and
      // the plan says so. (topCpuAnswer sends none — an older server.)
      presentation: {
        primary_view: "TIME_SERIES", secondary_view: "TABLE", title: "Memory over time", chosen_by: "server",
        disclosure: SUGGESTION_IGNORED,
      },
    },
  };
}

/** The engine's honest "I could not place that question" (orchestrator
 *  answerCapability) — what an unbound "that device" gets with no prior answer. */
export function capabilityAnswer(): Json {
  return {
    mode: "unavailable", intent: "capability", modules: [],
    text: "I didn't quite catch that. I can: summarize what's going on right now, list the active incidents, explain a specific incident, show flows/telemetry/app or integration health, look up a troubleshooting playbook, or point you to a feature. Try one of those — or type / for guided commands.",
    next_actions: [
      "“What's going on right now?” — the current NOC picture",
      "“Show me the critical incidents” — the actionable list",
      "“Explain this incident” — RCA with evidence + owner",
      "“How do I troubleshoot a BGP flap?” — a playbook",
    ],
    citations: [], disclaimers: null,
  };
}

/** The data arm's clarify outcome: an ambiguous name is asked back, not guessed. */
export function clarifyAnswer(): Json {
  const clarify = [
    { input_text: "hq firewall", entity_id: "device:fw-hq-01", entity_type: "device", confidence: 0.7, resolution_method: "partial_name", needs_confirmation: true },
    { input_text: "hq firewall", entity_id: "device:fw-hq-02", entity_type: "device", confidence: 0.7, resolution_method: "partial_name", needs_confirmation: true },
  ];
  return {
    mode: "data_query", intent: "query_metric", modules: [],
    text: "More than one thing matches that name — which did you mean: device:fw-hq-01, device:fw-hq-02?",
    citations: [], disclaimers: [],
    data: { intent: "query_metric", entities: null, clarify, decline: "", unparsed: false, not_understood: null },
  };
}

// ---- the fake ------------------------------------------------------------------

export async function bootIris(page: Page, opts: IrisBackendOptions = {}): Promise<IrisFake> {
  const fake: IrisFake = { asks: [], started: [], messages: [], aliasPuts: [], resolves: [], live: new Set() };
  const aliases: Json[] = [];
  let convSeq = 0;
  const turns = new Map<string, Json[]>();

  await page.addInitScript(() => localStorage.setItem("netops_token", "e2e-fake-token"));
  await page.route(/^https?:\/\/[^/]+\/api\//, async (route: Route) => {
    const req = route.request();
    const url = new URL(req.url());
    const p = url.pathname;
    const method = req.method();
    const json = (b: unknown, status = 200) =>
      route.fulfill({ status, contentType: "application/json", body: JSON.stringify(b) });
    const body = (): Json => {
      try { return (req.postDataJSON() ?? {}) as Json; } catch { return {}; }
    };

    if (p === "/api/auth/me") return json(opts.me ?? TENANT_ME);
    if (p === "/api/scopes") {
      return json({ scopes: [{ tenant_id: "t_acme", tenant_name: "Acme", org_id: "org-acme", org_name: "Acme", region: "us" }], all_tenants: false });
    }
    if (p === "/api/features") return json({ copilot: true });
    if (p === "/api/copilot/config") return json({ error: "forbidden" }, 403);
    if (p === "/api/ai/tenants") return json({ error: "forbidden" }, 403);
    if (p === "/api/ai/tenant-config") {
      return opts.tenantConfig ? json(opts.tenantConfig) : json({ error: "forbidden" }, 403);
    }
    if (p === "/api/ai/commands") return json({ commands: [] });
    if (p === "/api/ai/feedback") return route.fulfill({ status: 204, body: "" });

    if (p === "/api/ai/ask" && method === "POST") {
      const b = body() as IrisFake["asks"][number];
      fake.asks.push(b);
      if (b.conversation_id && !fake.live.has(b.conversation_id)) return json({ error: "not found" }, 404);
      const a = (opts.answer ?? (() => capabilityAnswer()))(b.question);
      if ("status" in a && typeof a.status === "number") return json(a.body, a.status);
      const out: Json = { ...a };
      if (b.conversation_id) out.conversation_id = b.conversation_id; // recorded in it
      return json(out);
    }

    if (p === "/api/ai/conversations" && method === "POST") {
      const id = `conv-${++convSeq}`;
      fake.started.push(id);
      fake.live.add(id);
      turns.set(id, []);
      return json({ id, created_at: FIXED_NOW, updated_at: FIXED_NOW, turns: [] }, 201);
    }
    const m = p.match(/^\/api\/ai\/conversations\/([^/]+)\/messages$/);
    if (m && method === "POST") {
      const id = decodeURIComponent(m[1]);
      const b = body() as { question: string; tz?: string };
      fake.messages.push({ id, question: b.question, tz: b.tz });
      if (!fake.live.has(id)) return json({ error: "not found" }, 404);
      const a = (opts.converse ?? (() => ({ unparsed: true, not_understood: [b.question] })))(b.question, id);
      const outcome = a.unparsed ? "unparsed" : (a.clarify as unknown[] | null)?.length ? "clarify" : a.decline ? "declined" : "answered";
      const res = a.result as { rows?: unknown[]; series?: unknown[] } | undefined;
      const turn = { at: FIXED_NOW, question: b.question, intent: a.intent ?? "", outcome, rows: (res?.rows?.length ?? 0) + (res?.series?.length ?? 0) };
      turns.get(id)!.push(turn);
      return json({ entities: null, clarify: null, decline: "", unparsed: false, not_understood: null, ...a, conversation_id: id, turn });
    }

    if (p === "/api/ai/aliases") {
      if (method === "GET") return json({ aliases: aliases.length ? aliases : null, max: 2000 });
      if (method === "PUT") {
        const b = body();
        fake.aliasPuts.push(b);
        const saved = {
          tenant_id: "t_acme", entity_type: b.entity_type, entity_id: b.entity_id, alias: b.alias,
          norm: String(b.alias).toLowerCase(), source: "operator", created_by: "alice", created_at: FIXED_NOW,
        };
        aliases.push(saved);
        return json(saved);
      }
      if (method === "DELETE") {
        const i = aliases.findIndex((a) => a.entity_type === url.searchParams.get("entity_type") && a.alias === url.searchParams.get("alias"));
        if (i < 0) return json({ error: "not found" }, 404);
        aliases.splice(i, 1);
        return route.fulfill({ status: 204, body: "" });
      }
    }
    if (p === "/api/ai/entities/resolve" && method === "POST") {
      const b = body() as { text: string; types: string[] };
      fake.resolves.push(b);
      return json((opts.resolve ?? (() => ({ refs: null, ambiguous: false })))(b.text, b.types ?? []));
    }

    if (p.startsWith("/api/incidents")) return json([]);
    if (p.startsWith("/api/correlations")) return json({ data: [], meta: [] });
    return json({});
  });
  return fake;
}

/** The floating Iris window (components/IrisAssistant.tsx). */
export function irisWindow(page: Page) {
  return page.getByRole("dialog", { name: "Iris" });
}

/** Open the Iris window from the bottom-right launcher and wait for the composer. */
export async function openIris(page: Page) {
  // exact: every page's `(i)` buttons are named "Ask Iris about …".
  await page.getByRole("button", { name: "Ask Iris", exact: true }).click();
  await page.getByPlaceholder(/Ask Iris AI/).waitFor();
}

/** Type a question into the Iris box and send it. */
export async function askIris(page: Page, question: string) {
  const box = page.getByPlaceholder(/Ask Iris AI/);
  await box.fill(question);
  await box.press("Enter");
}
