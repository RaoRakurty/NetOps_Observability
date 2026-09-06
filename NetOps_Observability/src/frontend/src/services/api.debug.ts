// api.debug.ts — the client for the pipeline debugger's platform routes.
//
// WHY IT IS ITS OWN MODULE. Every route below is platform-global and
// requirePlatformAdmin on the server, and one of them returns a FILE rather
// than JSON. Keeping them together — with the response shapes the api actually
// sends, named the same way — means the page never has to guess a shape, and a
// contract change has one place to land.
//
// It reuses the session the rest of the product uses (`getToken` /
// `getActiveScope` from services/api), the way pages/appobs/api.ts and
// pages/appobs/costContext.ts already do, and throws the SAME error envelope
// api.ts throws (`<status> <statusText>: <body>`) so lib/errors.ts
// `operatorError` renders these failures exactly like every other one.
//
// One thing it deliberately does NOT do: interpret a module log line. Those
// lines are already redacted where they were written, and they are rendered as
// escaped text — never as markup, never evaluated.

import { getActiveScope, getToken } from "./api";

// ── the wire shapes (internal/pipedebug) ────────────────────────────────────

export type DebugKind = "syslog" | "trap" | "flow" | "gnmi";
export type DebugVerdict = "seen" | "not_seen" | "not_observable";
export type DebugModule = "api" | "correlation" | "vector" | "router" | "ingress";
export type DebugLevel = "debug" | "info";

/** One hop of the pipeline, as a trace or a session records it. */
export type DebugStageEntry = {
  stage: string;
  index?: number;
  module?: string;
  seen?: boolean;
  t_first_seen?: string;
  latency_from_prev_ms?: number;
  evidence_ref?: string;
  verdict: DebugVerdict;
  reason?: string;
  query?: string;
  detail?: Record<string, unknown>;
};

export type TraceReceipt = {
  marker: string;
  kind: DebugKind;
  device: string;
  tenant?: string;
  injected: boolean;
  inject_error?: string;
  passive?: boolean;
  since?: string;
  path?: string;
  ttl_seconds: number;
  started: string;
  synthetic: boolean;
  status_url: string;
  session_id?: string;
  session_note?: string;
};

export type TraceStatus = {
  marker: string;
  kind: DebugKind;
  device: string;
  tenant?: string;
  started: string;
  deadline: string;
  done: boolean;
  passive?: boolean;
  stages: DebugStageEntry[];
};

export type TraceRequest = {
  kind: DebugKind;
  device: string;
  tenant?: string;
  ttl_seconds?: number;
  passive?: boolean;
  since_seconds?: number;
  path?: string;
  /** Ask the api to write the session directory this run can be reopened from. */
  persist?: boolean;
};

export type LevelChange = {
  module: DebugModule;
  applied: boolean;
  level: DebugLevel;
  previous?: DebugLevel;
  revert_at?: string;
  reason?: string;
};

export type LevelState = {
  module: DebugModule;
  level?: DebugLevel;
  revert_at?: string;
  switchable: boolean;
  source: "live" | "last-request" | "unknown";
  reason?: string;
  service?: string;
};

export type LevelStatus = {
  modules: LevelState[];
  max_window_seconds: number;
  default_window_seconds: number;
};

export type ParseMarkerState = {
  armed: boolean;
  marker?: string;
  until?: string;
  reason?: string;
};

export type SessionSummary = {
  id: string;
  verb: string;
  marker?: string;
  kind?: DebugKind;
  device?: string;
  tenant?: string;
  actor?: string;
  started: string;
  finished?: string;
  seen: number;
  not_seen: number;
  not_observable: number;
  reached_api: boolean;
  modules?: string[];
  warnings?: string[];
  bytes: number;
  incomplete?: string;
};

export type SessionIndex = {
  root: string;
  sessions: SessionSummary[];
  reason?: string;
  truncated?: boolean;
};

export type SessionModuleFile = { module: string; file: string; bytes: number };

/**
 * `manifest.json` as the run wrote it: who ran it, with which tool and flags,
 * and which redaction was applied. It is the provenance of a file an operator
 * may hand to somebody else, so it is typed rather than an opaque blob.
 */
export type SessionManifest = {
  verb: string;
  marker?: string;
  kind?: DebugKind;
  device?: string;
  tenant?: string;
  started: string;
  finished?: string;
  actor?: string;
  api_base?: string;
  flags?: Record<string, string>;
  redaction: string;
  tool: string;
  modules?: string[];
  warnings?: string[];
};

export type SessionDetail = {
  session: SessionSummary;
  manifest?: SessionManifest;
  timeline?: { marker: string; kind: DebugKind; device?: string; tenant?: string; started: string; entries: DebugStageEntry[] };
  summary_text?: string;
  modules: SessionModuleFile[];
  reason?: string;
};

export type ModuleLog = {
  session: string;
  module: string;
  file: string;
  lines: string[];
  bytes: number;
  truncated?: boolean;
  reason?: string;
};

// ── the request path ────────────────────────────────────────────────────────

function authHeaders(extra?: Record<string, string>): Record<string, string> {
  const headers: Record<string, string> = { ...extra };
  const token = getToken();
  if (token) headers.Authorization = `Bearer ${token}`;
  const scope = getActiveScope();
  if (scope) headers["X-Acting-Tenant"] = scope;
  return headers;
}

async function debugRequest<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    ...init,
    headers: authHeaders({ "Content-Type": "application/json", ...((init?.headers as Record<string, string>) ?? {}) }),
  });
  if (!res.ok) {
    throw new Error(`${res.status} ${res.statusText}: ${await res.text().catch(() => "")}`);
  }
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

/**
 * The HTTP status inside an error this module threw, or null when the value is
 * not one of ours. The page uses it to tell "this api build does not have the
 * route" apart from "the route answered no".
 */
export function debugStatusOf(e: unknown): number | null {
  const msg = e instanceof Error ? e.message : String(e ?? "");
  const m = /^(\d{3}) /.exec(msg);
  return m ? Number(m[1]) : null;
}

/**
 * True when the api answered as though the route is not part of this build: a
 * router 404 with no handler behind it, or a 405 from a handler that exists but
 * does not serve this method yet. Both mean the same thing to an operator — the
 * running api is older than this screen — and neither is an error to retry.
 */
export function isRouteAbsent(e: unknown): boolean {
  const status = debugStatusOf(e);
  if (status === 405) return true;
  if (status !== 404) return false;
  const msg = e instanceof Error ? e.message : String(e ?? "");
  return /page not found/i.test(msg);
}

// ── the routes ──────────────────────────────────────────────────────────────

export const debugApi = {
  // Trace. Contract: internal/pipedebug/http.go + internal/openapi/openapi.go.
  startTrace: (req: TraceRequest) =>
    debugRequest<TraceReceipt>("/api/debug/trace", { method: "POST", body: JSON.stringify(req) }),
  traceStatus: (marker: string) => debugRequest<TraceStatus>(`/api/debug/trace/${encodeURIComponent(marker)}`),
  stageEvidence: (
    stage: string,
    q: { marker: string; kind?: DebugKind; tenant?: string; device?: string; path?: string },
  ) => {
    const p = new URLSearchParams({ marker: q.marker });
    if (q.kind) p.set("kind", q.kind);
    if (q.tenant) p.set("tenant", q.tenant);
    if (q.device) p.set("device", q.device);
    if (q.path) p.set("path", q.path);
    return debugRequest<DebugStageEntry>(`/api/debug/stage/${encodeURIComponent(stage)}?${p.toString()}`);
  },

  // Runtime log levels.
  levelStatus: () => debugRequest<LevelStatus>("/api/debug/loglevel"),
  setLevel: (body: { module: DebugModule; level: DebugLevel; for_seconds: number }) =>
    debugRequest<LevelChange>("/api/debug/loglevel", { method: "PUT", body: JSON.stringify(body) }),

  // The parser decision-trace filter.
  parseMarker: () => debugRequest<ParseMarkerState>("/api/debug/parsemarker"),
  armParseMarker: (body: { marker: string; for_seconds: number }) =>
    debugRequest<ParseMarkerState>("/api/debug/parsemarker", { method: "PUT", body: JSON.stringify(body) }),
  disarmParseMarker: () =>
    debugRequest<ParseMarkerState>("/api/debug/parsemarker", { method: "PUT", body: JSON.stringify({ off: true }) }),

  // Sessions.
  sessions: (limit?: number) =>
    debugRequest<SessionIndex>(`/api/debug/sessions${limit ? `?limit=${limit}` : ""}`),
  session: (id: string) => debugRequest<SessionDetail>(`/api/debug/sessions/${encodeURIComponent(id)}`),
  sessionModule: (id: string, module: string) =>
    debugRequest<ModuleLog>(`/api/debug/sessions/${encodeURIComponent(id)}/module/${encodeURIComponent(module)}`),

  /**
   * Download one session's bundle. It is fetched with the session header and
   * handed to the browser as a blob — a bare link would arrive without one and
   * be refused. The api states the archive's own SHA-256 in a header; it is
   * returned here so the screen can show what was downloaded.
   */
  downloadSessionBundle: async (id: string): Promise<{ filename: string; sha256: string; bytes: number }> => {
    const res = await fetch(`/api/debug/sessions/${encodeURIComponent(id)}/bundle`, { headers: authHeaders() });
    if (!res.ok) {
      throw new Error(`${res.status} ${res.statusText}: ${await res.text().catch(() => "")}`);
    }
    const blob = await res.blob();
    const filename = `correlix-debug-${id}.tar.gz`;
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    return { filename, sha256: res.headers.get("X-Correlix-Bundle-SHA256") ?? "", bytes: blob.size };
  },
};

export default debugApi;
