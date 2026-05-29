// Minimal typed API client. Paths are relative — nginx (or Vite dev
// proxy) routes /api and /admin to the Go backend.

export type Device = {
  id: string;
  name: string;
  address: string;
  vendor?: string;
  model?: string;
  os?: string;
  preferred_protocol?: string;
  credential_ref?: string;
  labels?: Record<string, string>;
  source: string;
  last_seen: string;
};

export type CollectorStatus = {
  name: string;
  enabled: boolean;
  healthy: boolean;
  last_tick?: string;
  last_error?: string;
  targets: number;
};

export type Alert = {
  id: string;
  rule: string;
  severity: string;
  device_id?: string;
  summary: string;
  description?: string;
  labels?: Record<string, string>;
  fired_at: string;
  resolved_at?: string | null;
};

export type Rule = {
  name: string;
  expr: string;
  for: number;
  severity: string;
  labels?: Record<string, string>;
  annotations?: Record<string, string>;
};

export type MetricTile = {
  title: string;
  value: string;
  trend?: string;
};

export type Health = {
  status: string;
  version: string;
  uptime: string;
  discovery: Record<string, unknown>;
  collectors: Record<string, boolean>;
  alerts: Record<string, unknown>;
};

// ---------- OpenSearch ------------

export type OSHit = {
  _index: string;
  _id: string;
  _source: Record<string, any>;
};
export type OSResponse = {
  took?: number;
  hits: {
    total?: { value: number };
    hits: OSHit[];
  };
};

export type LogSearchOpts = {
  query: string;
  from?: string;
  to?: string;
  size?: number;
  signal?: "applogs" | "syslog" | "flows" | "";
};

// ---------- ClickHouse rows (passthrough) ----------

export type ClickHouseResponse<T = Record<string, any>> = {
  meta?: { name: string; type: string }[];
  data: T[];
  rows?: number;
};

export type Finding = {
  ts: string;
  id: string;
  kind: string;
  severity: string;
  score: number;
  device: string;
  component: string;
  summary: string;
  description: string;
};

// ---------- Copilot ----------

export type CopilotMessage = { role: "user" | "assistant" | "system"; content: string };

export type AnthropicChatResponse = {
  id: string;
  type: string;
  role: "assistant";
  content: { type: "text"; text: string }[];
  model: string;
  stop_reason: string;
};
export type OpenAIChatResponse = {
  id: string;
  choices: { message: { role: string; content: string }; finish_reason: string }[];
  model: string;
};
export type CopilotChatResponse = AnthropicChatResponse | OpenAIChatResponse;

export const TOKEN_KEY = "netops_token";

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}
export function setToken(t: string | null): void {
  if (t === null) localStorage.removeItem(TOKEN_KEY);
  else localStorage.setItem(TOKEN_KEY, t);
}

type AuthListener = (signedIn: boolean) => void;
const authListeners = new Set<AuthListener>();
export function onAuthChange(fn: AuthListener): () => void {
  authListeners.add(fn);
  return () => authListeners.delete(fn);
}
function fireAuthChange(signedIn: boolean) {
  for (const fn of authListeners) fn(signedIn);
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...((init?.headers as Record<string, string>) ?? {}),
  };
  const token = getToken();
  if (token) headers.Authorization = `Bearer ${token}`;

  const res = await fetch(path, { ...init, headers });
  if (res.status === 401) {
    // Token expired or invalid. Clear and notify listeners so App.tsx
    // can swap to the Login screen.
    if (token) {
      setToken(null);
      fireAuthChange(false);
    }
    const text = await res.text().catch(() => "");
    throw new Error(`401 Unauthorized: ${text || "please sign in"}`);
  }
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`${res.status} ${res.statusText}: ${text}`);
  }
  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}

// ---- auth types ----
export type AuthUser = {
  username: string;
  role: string;
  last_login_at?: string;
};
export type LoginResponse = { token: string; user: AuthUser };

export const api = {
  // ---- auth ----
  login: async (username: string, password: string) => {
    const r = await request<LoginResponse>("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    });
    setToken(r.token);
    fireAuthChange(true);
    return r;
  },
  logout: () => {
    setToken(null);
    fireAuthChange(false);
  },
  me: () => request<AuthUser>("/api/auth/me"),
  changePassword: (current_password: string, new_password: string) =>
    request<{ status: string }>("/api/auth/change-password", {
      method: "POST",
      body: JSON.stringify({ current_password, new_password }),
    }),

  health: () => request<Health>("/admin/health"),
  devices: () => request<Device[]>("/api/devices"),
  upsertDevice: (d: Partial<Device>) =>
    request<Device>("/api/devices", { method: "POST", body: JSON.stringify(d) }),
  deleteDevice: (id: string) =>
    request<void>(`/api/devices/${encodeURIComponent(id)}`, { method: "DELETE" }),
  collectors: () => request<CollectorStatus[]>("/api/collectors"),
  alerts: () => request<Alert[]>("/api/alerts"),
  rules: () => request<Rule[]>("/api/rules"),
  addRule: (r: Rule) =>
    request<Rule>("/api/rules", { method: "POST", body: JSON.stringify(r) }),
  credentials: () => request<Record<string, boolean>>("/api/credentials"),
  refreshDiscovery: () =>
    request<{ status: string }>("/api/discovery/refresh", { method: "POST" }),

  // Dashboard tile data — same shape /api/events emits via
  // { type: "metric_update", data: <tile> }.
  metricTiles: () =>
    request<MetricTile[]>("/api/metrics"),

  // Logs (OpenSearch)
  searchLogs: (opts: LogSearchOpts) =>
    request<OSResponse>("/api/logs/search", {
      method: "POST",
      body: JSON.stringify(opts),
    }),
  logIndices: () => request<Record<string, any>[]>("/api/logs/indices"),

  // Flows (ClickHouse)
  topTalkers: (sinceSeconds = 3600, limit = 20) =>
    request<ClickHouseResponse>(
      `/api/flows/top?since=${sinceSeconds}s&limit=${limit}`,
    ),
  flowsByProto: (sinceSeconds = 3600) =>
    request<ClickHouseResponse>(`/api/flows/by-proto?since=${sinceSeconds}s`),
  flowsTimeseries: (sinceSeconds = 3600, stepSeconds = 60) =>
    request<ClickHouseResponse>(
      `/api/flows/timeseries?since=${sinceSeconds}s&step=${stepSeconds}s`,
    ),
  findings: (limit = 100, severity?: string) => {
    const p = new URLSearchParams({ limit: String(limit) });
    if (severity) p.set("severity", severity);
    return request<ClickHouseResponse<Finding>>(`/api/findings?${p}`);
  },

  // Copilot
  copilotChat: (messages: CopilotMessage[], system?: string) =>
    request<CopilotChatResponse>("/api/copilot/chat", {
      method: "POST",
      body: JSON.stringify({ messages, system }),
    }),

  // Native metrics (Prometheus-compatible API via the Go proxy).
  metricNames: () => request<PromNamesResponse>("/api/metrics/names"),
  metricsQueryRange: (query: string, startSec: number, endSec: number, stepSec: number) => {
    const p = new URLSearchParams({
      query,
      start: String(startSec),
      end: String(endSec),
      step: String(stepSec),
    });
    return request<PromRangeResponse>(`/api/metrics/query_range?${p.toString()}`);
  },

  // Saved objects (searches / dashboards / reports) — Postgres-swappable
  // file-backed store on the API.
  listSaved: (type?: string) =>
    request<SavedObject[]>(`/api/saved${type ? `?type=${encodeURIComponent(type)}` : ""}`),
  createSaved: (type: SavedType, name: string, body: unknown) =>
    request<SavedObject>("/api/saved", {
      method: "POST",
      body: JSON.stringify({ type, name, body }),
    }),
  deleteSaved: (id: string) => request<void>(`/api/saved/${id}`, { method: "DELETE" }),

  // Global omni-search — resolves a free-text query to jump targets
  // (devices, alerts, saved objects) plus a raw log-search handoff.
  globalSearch: (q: string) =>
    request<GlobalSearchResponse>(`/api/search/global?q=${encodeURIComponent(q)}`),

  // Reports — saved objects (type=report) delivered on a schedule by the
  // server-side scheduler via the notify dispatcher.
  reportRuns: () => request<Record<string, ReportRun>>("/api/reports/runs"),
  runReport: (id: string) =>
    request<ReportRun>("/api/reports/run", {
      method: "POST",
      body: JSON.stringify({ id }),
    }),
};

export type ReportKind = "alerts_summary" | "device_inventory" | "health_summary";
export type ReportBody = {
  kind: ReportKind;
  interval_minutes: number;
  severity: string;
  enabled: boolean;
  description?: string;
};
export type ReportRun = {
  last_run?: string;
  next_run?: string;
  status?: string;
  detail?: string;
};

export type GlobalResultKind = "device" | "alert" | "saved" | "logs";
export type GlobalResult = {
  kind: GlobalResultKind;
  id: string;
  title: string;
  sub: string;
  route: string;
};
export type GlobalSearchResponse = { query: string; results: GlobalResult[] };

export type SavedType = "saved_search" | "dashboard" | "report";
export type SavedObject = {
  id: string;
  type: SavedType;
  name: string;
  owner: string;
  body: any;
  created_at: string;
  updated_at: string;
};

export type PromNamesResponse = { status: string; data: string[] };
export type PromSeries = { metric: Record<string, string>; values: [number, string][] };
export type PromRangeResponse = {
  status: string;
  data?: { resultType: string; result: PromSeries[] };
  error?: string;
};
