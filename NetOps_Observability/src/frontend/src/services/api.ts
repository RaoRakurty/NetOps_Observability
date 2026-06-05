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
  kind?: string; // "protocol" | "discovery"
  name: string;
  enabled: boolean;
  healthy: boolean;
  last_tick?: string;
  last_error?: string;
  targets: number;
  reachable?: number;
  last_poll_ms?: number;
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

// ---------- Platform stack health (platform-owner only) ----------

export type StackComponent = {
  name: string;
  category: string;
  status: "up" | "degraded" | "down";
  latency_ms: number;
  detail?: string;
};
export type StackHealth = {
  overall: "healthy" | "degraded" | "down";
  up: number;
  degraded: number;
  down: number;
  components: StackComponent[];
  subsystems: Record<string, unknown>;
};

// ---------- SNMP profiles (vendor OID/metric library) ----------

export type SnmpMetric = {
  name: string;
  oid: string;
  type: string;
  unit?: string;
  mib?: string;
  category?: string;
  description?: string;
};
export type SnmpProfile = {
  id: string;
  vendor: string;
  description?: string;
  category: string;
  sysobjectid_prefix?: string;
  builtin: boolean;
  metrics: SnmpMetric[];
};

// ---------- Notification channels ----------

export type SmtpConfig = {
  enabled: boolean;
  host: string;
  port: number;
  from: string;
  user: string;
  pass?: string; // write-only on PUT
  pass_set?: boolean; // read-only on GET
  to: string;
  security: string; // starttls | tls | none
  min_severity: string;
};
export type TwilioConfig = {
  enabled: boolean;
  account_sid: string;
  auth_token?: string;
  token_set?: boolean;
  from: string;
  to: string;
  min_severity: string;
};
export type NtfyConfig = {
  enabled: boolean;
  server: string;
  topic: string;
  token?: string;
  token_set?: boolean;
  min_severity: string;
};

export type SlackConfig = {
  enabled: boolean;
  webhook_url?: string; // write-only on PUT
  webhook_set?: boolean; // read-only on GET
  min_severity: string;
};

export type PagerDutyConfig = {
  enabled: boolean;
  routing_key?: string; // write-only on PUT
  routing_set?: boolean; // read-only on GET
  min_severity: string;
};

// ---------- Audit trail (tenant-scoped) ----------

export type AuditEvent = {
  id: string;
  time: string;
  actor: string;
  tenant?: string;
  cross?: boolean;
  method: string;
  path: string;
  status: number;
  decision: "allow" | "deny" | "error";
  remote?: string;
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

export type ExportFmt = "csv" | "json" | "ndjson" | "xlsx";

export type LogExportOpts = {
  format: ExportFmt;
  query?: string;
  from?: string;
  to?: string;
  signal?: "applogs" | "syslog" | "flows" | "";
  mode?: "sync" | "async" | "auto";
};

export type ExportStatus = {
  id: string;
  status: string;
  format?: string;
  size_bytes?: number;
  download_url?: string;
  error?: string;
};

export type Incident = {
  id: string;
  tenant_id: string;
  title: string;
  description?: string;
  severity: string;
  status: string;
  source_type: string;
  source_id?: string;
  owner?: string;
  occurrences: number;
  created_at: string;
  updated_at: string;
  first_seen_at: string;
  last_seen_at: string;
  resolved_at?: string;
  external_ticket_id?: string;
  external_url?: string;
  external_system?: string;
  sync_status: string;
  last_synced_at?: string;
};

export type IncidentEvent = {
  id: string;
  incident_id: string;
  event_type: string;
  payload?: Record<string, unknown>;
  actor: string;
  created_at: string;
};

// TimelineEntry — one item in the merged incident timeline: a lifecycle event
// (kind="lifecycle") or an ITSM sync event (kind="sync"). The discriminator says
// which fields are populated; `at` is the unified sort key.
export type TimelineEntry = {
  kind: "lifecycle" | "sync";
  at: string;
  id: string;
  // lifecycle
  event_type?: string;
  actor?: string;
  payload?: Record<string, unknown>;
  // sync
  provider?: string;
  direction?: string;
  type?: string;
  external_id?: string;
  status?: string;
  reason?: string;
  correlation_id?: string;
};

export type ExportPolicy = {
  rate_per_min: number;
  max_rows: number;
  max_bytes: number;
  max_runtime_seconds: number;
  max_range_hours: number;
  link_ttl_seconds: number;
  sync_max_rows: number;
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

// Overlay tunnel (IPsec / SD-WAN / GRE) — one current row per tunnel, served
// from netops.tunnels. Numeric fields may arrive as JSON strings from
// ClickHouse (UInt64), so coerce with Number() at the call site.
export type Tunnel = {
  ts: string;
  id: string;
  type: string; // ipsec | sdwan | gre
  local_device: string;
  local_addr: string;
  remote_device: string;
  remote_addr: string;
  status: string; // up | down
  latency_ms: number;
  jitter_ms: number;
  loss_pct: number;
  qoe: number;
  uptime_s: number;
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

// Runtime assistant config (admin). The API key stays server-side and is never
// returned — GET reports key_present instead of the secret.
export type CopilotConfig = {
  provider: string; // "anthropic" | "openai"
  model: string;
  system?: string;
  feature_enabled?: boolean;
  key_present?: boolean;
  providers?: string[];
  model_suggestions?: Record<string, string[]>;
};

export const TOKEN_KEY = "netops_token";
export const REFRESH_KEY = "netops_refresh";

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}
export function setToken(t: string | null): void {
  if (t === null) localStorage.removeItem(TOKEN_KEY);
  else localStorage.setItem(TOKEN_KEY, t);
}
export function getRefresh(): string | null {
  return localStorage.getItem(REFRESH_KEY);
}
export function setRefresh(t: string | null): void {
  if (t === null) localStorage.removeItem(REFRESH_KEY);
  else localStorage.setItem(REFRESH_KEY, t);
}

// captureSSORedirect inspects the URL fragment the SSO callback redirects to
// (#token=…&refresh=…&sso=1, or #sso_error=…) and, on success, stores the
// session and clears the fragment. Call once at startup before rendering.
// Returns an error string when the SSO round-trip failed, else null.
export function captureSSORedirect(): string | null {
  const hash = window.location.hash.replace(/^#/, "");
  if (!hash.includes("token=") && !hash.includes("sso_error=")) return null;
  const p = new URLSearchParams(hash);
  const err = p.get("sso_error");
  const clear = () => history.replaceState(null, "", window.location.pathname + window.location.search);
  if (err) {
    clear();
    return err;
  }
  const token = p.get("token");
  const refresh = p.get("refresh");
  if (token) {
    setToken(token);
    setRefresh(refresh);
    clear();
  }
  return null;
}

// Single-flight refresh: many requests can 401 at once; only one /refresh runs.
let refreshInFlight: Promise<boolean> | null = null;
async function doRefresh(rt: string): Promise<boolean> {
  try {
    const res = await fetch("/api/auth/refresh", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refresh_token: rt }),
    });
    if (!res.ok) return false;
    const data = await res.json();
    setToken(data.token);
    setRefresh(data.refresh_token);
    return true;
  } catch {
    return false;
  }
}
function tryRefresh(): Promise<boolean> {
  const rt = getRefresh();
  if (!rt) return Promise.resolve(false);
  if (!refreshInFlight) {
    refreshInFlight = doRefresh(rt).finally(() => {
      refreshInFlight = null;
    });
  }
  return refreshInFlight;
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

async function request<T>(path: string, init?: RequestInit, retried = false): Promise<T> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...((init?.headers as Record<string, string>) ?? {}),
  };
  const token = getToken();
  if (token) headers.Authorization = `Bearer ${token}`;

  const res = await fetch(path, { ...init, headers });
  if (res.status === 401) {
    // Access token expired? Trade the refresh token for a fresh one and retry
    // the original request exactly once. Skip for the auth endpoints themselves.
    const isAuthEndpoint = path.startsWith("/api/auth/login") || path.startsWith("/api/auth/refresh");
    if (!retried && !isAuthEndpoint && getRefresh()) {
      if (await tryRefresh()) return request<T>(path, init, true);
    }
    // Refresh unavailable/failed — clear and notify so App swaps to Login.
    if (token || getRefresh()) {
      setToken(null);
      setRefresh(null);
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
  tenant_id?: string;
  // platform_admin = the cross-tenant platform owner. Gates infra-stack
  // monitoring + platform-wide admin in the UI. Mirrors the backend rule.
  platform_admin?: boolean;
  last_login_at?: string;
};
export type LoginResponse = { token: string; refresh_token?: string; expires_in?: number; user: AuthUser };

// downloadResponse turns a fetch Response body into a browser file download.
async function downloadResponse(res: Response, filename: string): Promise<void> {
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

export const api = {
  // ---- auth ----
  login: async (username: string, password: string) => {
    const r = await request<LoginResponse>("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    });
    setToken(r.token);
    setRefresh(r.refresh_token ?? null);
    fireAuthChange(true);
    return r;
  },
  logout: async () => {
    const rt = getRefresh();
    if (rt) {
      // Best-effort server-side revoke of the refresh token.
      await fetch("/api/auth/logout", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ refresh_token: rt }),
      }).catch(() => {});
    }
    setToken(null);
    setRefresh(null);
    fireAuthChange(false);
  },
  // SSO (OIDC/SAML/LDAP via Keycloak). Config is public; the login flow is a
  // full-page redirect (the browser must follow 302s to the IdP and back).
  ssoConfig: () => request<SSOConfig>("/api/auth/sso/config"),
  ssoLoginUrl: (idp?: string) => `/api/auth/sso/login${idp ? `?idp=${encodeURIComponent(idp)}` : ""}`,

  // Auth-method discovery for the login page (which sign-in options are enabled).
  authMethods: () => request<AuthMethods>("/api/auth/methods"),

  // Direct (native) LDAP / TACACS+ logins — same session-issuing contract as login().
  ldapLogin: async (username: string, password: string) => {
    const r = await request<LoginResponse>("/api/auth/ldap/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    });
    setToken(r.token);
    setRefresh(r.refresh_token ?? null);
    fireAuthChange(true);
    return r;
  },
  tacacsLogin: async (username: string, password: string) => {
    const r = await request<LoginResponse>("/api/auth/tacacs/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    });
    setToken(r.token);
    setRefresh(r.refresh_token ?? null);
    fireAuthChange(true);
    return r;
  },

  // SSO/OIDC admin config (admin-gated; the client secret is write-only on the
  // server). GET/PUT return the redacted config plus whether the provider is ready.
  oidcConfig: () => request<{ config: OidcConfig; ready: boolean }>("/api/auth/oidc/config"),
  saveOidcConfig: (cfg: Partial<OidcConfig> & { client_secret?: string }) =>
    request<{ config: OidcConfig; ready: boolean }>("/api/auth/oidc/config", { method: "PUT", body: JSON.stringify(cfg) }),

  // Native-provider admin config (admin-gated; secrets are write-only on the server).
  ldapConfig: () => request<{ config: LdapConfig }>("/api/auth/ldap/config"),
  saveLdapConfig: (cfg: Partial<LdapConfig> & { bind_password?: string }) =>
    request<{ config: LdapConfig }>("/api/auth/ldap/config", { method: "PUT", body: JSON.stringify(cfg) }),
  testLdap: (username?: string, password?: string) =>
    request<AuthTestResult>("/api/auth/ldap/test", { method: "POST", body: JSON.stringify({ username, password }) }),
  tacacsConfig: () => request<{ config: TacacsConfig }>("/api/auth/tacacs/config"),
  saveTacacsConfig: (cfg: Partial<TacacsConfig> & { secret?: string }) =>
    request<{ config: TacacsConfig }>("/api/auth/tacacs/config", { method: "PUT", body: JSON.stringify(cfg) }),
  testTacacs: (username?: string, password?: string) =>
    request<AuthTestResult>("/api/auth/tacacs/test", { method: "POST", body: JSON.stringify({ username, password }) }),

  // Token policy (access/refresh lifetimes) — admin-gated, clamped server-side.
  tokenPolicy: () => request<TokenPolicy>("/api/auth/token-policy"),
  saveTokenPolicy: (p: { access_ttl_seconds: number; refresh_ttl_seconds: number }) =>
    request<TokenPolicy>("/api/auth/token-policy", { method: "PUT", body: JSON.stringify(p) }),

  me: () => request<AuthUser>("/api/auth/me"),
  changePassword: (current_password: string, new_password: string) =>
    request<{ status: string }>("/api/auth/change-password", {
      method: "POST",
      body: JSON.stringify({ current_password, new_password }),
    }),

  health: () => request<Health>("/admin/health"),
  stackHealth: () => request<StackHealth>("/api/stack/health"),
  audit: (limit = 200) => request<AuditEvent[]>(`/api/audit?limit=${limit}`),

  // Notification channels (UI-configurable; secrets write-only). _set booleans
  // tell the form whether a secret is stored without revealing it.
  smtpConfig: () => request<SmtpConfig>("/api/notify/smtp"),
  saveSmtpConfig: (c: Partial<SmtpConfig>) => request<SmtpConfig>("/api/notify/smtp", { method: "PUT", body: JSON.stringify(c) }),
  testSmtp: () => request<{ status: string }>("/api/notify/smtp/test", { method: "POST" }),
  twilioConfig: () => request<TwilioConfig>("/api/notify/twilio"),
  saveTwilioConfig: (c: Partial<TwilioConfig>) => request<TwilioConfig>("/api/notify/twilio", { method: "PUT", body: JSON.stringify(c) }),
  testTwilio: () => request<{ status: string }>("/api/notify/twilio/test", { method: "POST" }),
  ntfyConfig: () => request<NtfyConfig>("/api/notify/ntfy"),
  saveNtfyConfig: (c: Partial<NtfyConfig>) => request<NtfyConfig>("/api/notify/ntfy", { method: "PUT", body: JSON.stringify(c) }),
  testNtfy: () => request<{ status: string }>("/api/notify/ntfy/test", { method: "POST" }),
  slackConfig: () => request<SlackConfig>("/api/notify/slack"),
  saveSlackConfig: (c: Partial<SlackConfig>) => request<SlackConfig>("/api/notify/slack", { method: "PUT", body: JSON.stringify(c) }),
  testSlack: () => request<{ status: string }>("/api/notify/slack/test", { method: "POST" }),
  pagerDutyConfig: () => request<PagerDutyConfig>("/api/notify/pagerduty"),
  savePagerDutyConfig: (c: Partial<PagerDutyConfig>) => request<PagerDutyConfig>("/api/notify/pagerduty", { method: "PUT", body: JSON.stringify(c) }),
  testPagerDuty: () => request<{ status: string }>("/api/notify/pagerduty/test", { method: "POST" }),

  // Contact points — reusable, tenant-scoped delivery audiences (email group /
  // slack / webhook) referenced by reports. Managed in the Notifications section.
  contactPoints: () => request<ContactPoint[]>("/api/notify/contact-points"),
  saveContactPoint: (c: Partial<ContactPoint>) =>
    c.id
      ? request<ContactPoint>(`/api/notify/contact-points/${encodeURIComponent(c.id)}`, { method: "PUT", body: JSON.stringify(c) })
      : request<ContactPoint>("/api/notify/contact-points", { method: "POST", body: JSON.stringify(c) }),
  deleteContactPoint: (id: string) => request<void>(`/api/notify/contact-points/${encodeURIComponent(id)}`, { method: "DELETE" }),
  snmpProfiles: () => request<SnmpProfile[]>("/api/snmp/profiles"),
  addSnmpProfileMetrics: (id: string, metrics: SnmpMetric[]) =>
    request<SnmpProfile>(`/api/snmp/profiles/${encodeURIComponent(id)}/metrics`, {
      method: "POST",
      body: JSON.stringify(metrics),
    }),
  upsertSnmpProfile: (p: Partial<SnmpProfile>) =>
    request<SnmpProfile>("/api/snmp/profiles", { method: "POST", body: JSON.stringify(p) }),
  deleteSnmpProfile: (id: string) =>
    request<void>(`/api/snmp/profiles/${encodeURIComponent(id)}`, { method: "DELETE" }),
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

  // Flows (ClickHouse). `type` filters by source family (netflow|ipfix|sflow);
  // empty = all sources.
  topTalkers: (sinceSeconds = 3600, limit = 20, type = "") =>
    request<ClickHouseResponse>(
      `/api/flows/top?since=${sinceSeconds}s&limit=${limit}${type ? `&type=${type}` : ""}`,
    ),
  flowsByProto: (sinceSeconds = 3600, type = "") =>
    request<ClickHouseResponse>(`/api/flows/by-proto?since=${sinceSeconds}s${type ? `&type=${type}` : ""}`),
  flowsByType: (sinceSeconds = 3600) =>
    request<ClickHouseResponse>(`/api/flows/by-type?since=${sinceSeconds}s`),
  flowsTimeseries: (sinceSeconds = 3600, stepSeconds = 60, type = "") =>
    request<ClickHouseResponse>(
      `/api/flows/timeseries?since=${sinceSeconds}s&step=${stepSeconds}s${type ? `&type=${type}` : ""}`,
    ),
  tunnels: (limit = 200, status?: string) => {
    const p = new URLSearchParams({ limit: String(limit) });
    if (status) p.set("status", status);
    return request<ClickHouseResponse<Tunnel>>(`/api/tunnels?${p}`);
  },
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
  // Runtime assistant config (admin): provider/model picker. Key never returned.
  copilotConfig: () => request<CopilotConfig>("/api/copilot/config"),
  setCopilotConfig: (cfg: { provider: string; model: string; system?: string }) =>
    request<CopilotConfig>("/api/copilot/config", {
      method: "PUT",
      body: JSON.stringify(cfg),
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
  // The notify channels actually configured, so "Send now" offers only real
  // delivery destinations.
  reportChannels: () => request<string[]>("/api/reports/channels"),
  // Deliver a report now. channels optionally restricts this one send to named
  // notify channels; omitted/empty => all configured channels.
  runReport: (id: string, channels?: string[]) =>
    request<ReportRun & { execution_id?: string }>("/api/reports/run", {
      method: "POST",
      body: JSON.stringify(channels && channels.length ? { id, channels } : { id }),
    }),
  // Edit an existing report (or any saved object).
  updateSaved: (id: string, name: string, body: unknown) =>
    request<SavedObject>(`/api/saved/${id}`, { method: "PUT", body: JSON.stringify({ name, body }) }),
  // Async pipeline (Postgres backend): per-report execution history + detail.
  reportExecutions: (scheduleId?: string, opts?: { limit?: number; before?: string }) => {
    const p = new URLSearchParams();
    if (scheduleId) p.set("schedule_id", scheduleId);
    if (opts?.limit) p.set("limit", String(opts.limit));
    if (opts?.before) p.set("before", opts.before);
    const qs = p.toString();
    return request<ReportExecution[]>(`/api/reports/executions${qs ? `?${qs}` : ""}`);
  },
  reportExecution: (id: string) => request<ReportExecutionDetail>(`/api/reports/executions/${encodeURIComponent(id)}`),
  // Live preview — renders a report's HTML on demand without scheduling/delivering.
  reportPreview: async (name: string, body: ReportBody, format: ReportFormat = "html"): Promise<string> => {
    const token = getToken();
    const res = await fetch(`/api/reports/preview?format=${encodeURIComponent(format)}`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...(token ? { Authorization: `Bearer ${token}` } : {}) },
      body: JSON.stringify({ name, body }),
    });
    if (!res.ok) throw new Error(`${res.status}: ${await res.text().catch(() => "")}`);
    return res.text();
  },
  // Fetch a stored artifact (auth-protected) and trigger a browser download.
  downloadArtifact: async (execId: string, format: ReportFormat): Promise<void> => {
    const token = getToken();
    const res = await fetch(`/api/reports/executions/${encodeURIComponent(execId)}/artifact?format=${encodeURIComponent(format)}`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    });
    if (!res.ok) throw new Error(`${res.status}`);
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `report.${format}`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  },

  // ----- Logs export -----
  // Mode A: render the rows already loaded in the browser (selected/page) to one
  // file. Excel reuses the server OOXML renderer; csv/json/ndjson share the
  // server encoders so every format matches Mode B byte-for-byte.
  exportLogRows: async (format: ExportFmt, columns: string[], rows: string[][], filename = "logs-export"): Promise<void> => {
    const token = getToken();
    const res = await fetch("/api/logs/export/rows", {
      method: "POST",
      headers: { "Content-Type": "application/json", ...(token ? { Authorization: `Bearer ${token}` } : {}) },
      body: JSON.stringify({ format, columns, rows, filename }),
    });
    if (!res.ok) throw new Error(`Export failed: ${res.status} ${await res.text().catch(() => "")}`);
    await downloadResponse(res, `${filename}.${format}`);
  },

  // Mode B: export the ENTIRE result set. Small sets stream straight back (file
  // download, returns {}); large sets enqueue an async job and return
  // { executionId } to poll via exportStatus → exported download_url.
  exportLogQuery: async (opts: LogExportOpts): Promise<{ executionId?: string; matched?: number }> => {
    const token = getToken();
    const params = new URLSearchParams();
    params.set("format", opts.format);
    if (opts.query) params.set("query", opts.query);
    if (opts.from) params.set("from", opts.from);
    if (opts.to) params.set("to", opts.to);
    if (opts.signal) params.set("signal", opts.signal);
    if (opts.mode) params.set("mode", opts.mode);
    const res = await fetch(`/api/logs/export?${params.toString()}`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    });
    if (res.status === 202) {
      const body = await res.json();
      return { executionId: body.execution_id, matched: body.matched };
    }
    if (!res.ok) throw new Error(`Export failed: ${res.status} ${await res.text().catch(() => "")}`);
    await downloadResponse(res, `logs-export.${opts.format}`);
    return {};
  },

  exportStatus: (id: string) => request<ExportStatus>(`/api/exports/${encodeURIComponent(id)}`),

  // ----- Incidents -----
  listIncidents: (opts: { status?: string; severity?: string; limit?: number } = {}) => {
    const p = new URLSearchParams();
    if (opts.status) p.set("status", opts.status);
    if (opts.severity) p.set("severity", opts.severity);
    if (opts.limit) p.set("limit", String(opts.limit));
    const qs = p.toString();
    return request<Incident[]>(`/api/incidents${qs ? `?${qs}` : ""}`);
  },
  getIncident: (id: string) =>
    request<{ incident: Incident; events: IncidentEvent[] }>(`/api/incidents/${encodeURIComponent(id)}`),
  getIncidentTimeline: (id: string) =>
    request<{ incident: Incident; timeline: TimelineEntry[] }>(`/api/incidents/${encodeURIComponent(id)}/timeline`),
  incidentAction: (id: string, action: "ack" | "resolve" | "investigate" | "close" | "reopen" | "note" | "assign" | "promote", body: { note?: string; owner?: string } = {}) =>
    request<Incident>(`/api/incidents/${encodeURIComponent(id)}/${action}`, {
      method: "POST",
      body: JSON.stringify(body),
    }),

  // ----- Export limits (runtime policy; platform-owner only to change) -----
  exportPolicy: () => request<ExportPolicy>("/api/exports/policy"),
  saveExportPolicy: (p: ExportPolicy) =>
    request<ExportPolicy>("/api/exports/policy", { method: "PUT", body: JSON.stringify(p) }),

  // ----- Identity & access (admin) -----
  permissions: () => request<{ role: string; permissions: Record<string, number> }>("/api/auth/permissions"),

  listUsers: () => request<AdminUser[]>("/api/users"),
  createUser: (u: Partial<AdminUser> & { password?: string }) =>
    request<AdminUser>("/api/users", { method: "POST", body: JSON.stringify(u) }),
  updateUser: (username: string, patch: Partial<AdminUser> & { password?: string }) =>
    request<AdminUser>(`/api/users/${encodeURIComponent(username)}`, { method: "PATCH", body: JSON.stringify(patch) }),
  deleteUser: (username: string) =>
    request<void>(`/api/users/${encodeURIComponent(username)}`, { method: "DELETE" }),

  listRoles: () => request<{ modules: string[]; roles: Role[] }>("/api/roles"),
  saveRole: (r: Role) =>
    r.id
      ? request<Role>(`/api/roles/${encodeURIComponent(r.id)}`, { method: "PUT", body: JSON.stringify(r) })
      : request<Role>("/api/roles", { method: "POST", body: JSON.stringify(r) }),
  deleteRole: (id: string) => request<void>(`/api/roles/${encodeURIComponent(id)}`, { method: "DELETE" }),

  listTenants: () => request<Tenant[]>("/api/tenants"),
  createTenant: (name: string, note?: string) =>
    request<Tenant>("/api/tenants", { method: "POST", body: JSON.stringify({ name, note }) }),
  deleteTenant: (id: string) => request<void>(`/api/tenants/${encodeURIComponent(id)}`, { method: "DELETE" }),

  // Self-describing API + ITSM connector status.
  openapi: () => request<OpenAPISpec>("/api/openapi.json"),
  itsmServiceNow: () => request<ServiceNowStatus>("/api/itsm/servicenow"),
  itsmJira: () => request<JiraStatus>("/api/itsm/jira"),
  itsmConfig: () => request<ItsmConfig>("/api/notify/itsm"),
  saveItsmConfig: (c: ItsmConfigInput) =>
    request<ItsmConfig>("/api/notify/itsm", { method: "PUT", body: JSON.stringify(c) }),

  // Integration Platform — bidirectional-sync config (one entry per provider).
  // The webhook signing secret is write-only: omit/blank it on PUT to keep stored.
  integrations: () => request<IntegrationsResponse>("/api/integrations"),
  saveIntegration: (
    provider: string,
    body: Partial<{ enabled: boolean; sync_mode: string; webhook_enabled: boolean; webhook_secret: string; state_map: Record<string, string> }>,
  ) => request<IntegrationConfig>("/api/integrations/" + provider, { method: "PUT", body: JSON.stringify(body) }),

  listApiKeys: () => request<ApiKey[]>("/api/apikeys"),
  createApiKey: (req: CreateApiKeyRequest) =>
    request<{ key: ApiKey; secret: string }>("/api/apikeys", {
      method: "POST",
      body: JSON.stringify(req),
    }),
  revokeApiKey: (id: string) => request<void>(`/api/apikeys/${encodeURIComponent(id)}`, { method: "DELETE" }),

  // GraphQL — single typed endpoint; powers the in-app explorer.
  graphql: (query: string, variables?: Record<string, unknown>) =>
    request<{ data?: Record<string, unknown>; errors?: unknown }>("/api/graphql", {
      method: "POST",
      body: JSON.stringify({ query, variables }),
    }),

  // ----- SNMP credential profiles -----
  snmpOptions: () => request<SNMPOptions>("/api/snmp/options"),
  listSnmpCreds: () => request<SNMPCredential[]>("/api/snmp/credentials"),
  saveSnmpCred: (c: SNMPCredential) =>
    c.id
      ? request<SNMPCredential>(`/api/snmp/credentials/${encodeURIComponent(c.id)}`, { method: "PUT", body: JSON.stringify(c) })
      : request<SNMPCredential>("/api/snmp/credentials", { method: "POST", body: JSON.stringify(c) }),
  deleteSnmpCred: (id: string) => request<void>(`/api/snmp/credentials/${encodeURIComponent(id)}`, { method: "DELETE" }),

  // ----- Security Policy (#24) — NIST-aligned controls resolved through the
  // System→Tenant→Role→User hierarchy. Admin-gated; system/global = platform
  // owner. The catalog is the source of truth for what's configurable; documents
  // only carry per-scope overrides; effective is the deterministic resolution.
  policyCatalog: () => request<PolicyCatalog>("/api/policy/catalog"),
  policyEffective: (sub: PolicySubject = {}) => {
    const p = new URLSearchParams();
    if (sub.tenant) p.set("tenant", sub.tenant);
    if (sub.role) p.set("role", sub.role);
    if (sub.user) p.set("user", sub.user);
    const qs = p.toString();
    return request<{ subject: PolicySubject; resolved: PolicyResolved[] }>(`/api/policy/effective${qs ? `?${qs}` : ""}`);
  },
  policyDocuments: () => request<{ documents: PolicyDocument[] }>("/api/policy/documents"),
  policyDocument: (scope: PolicyScope, selector = "", tenant = "") => {
    const p = new URLSearchParams({ scope });
    if (selector) p.set("selector", selector);
    if (tenant) p.set("tenant", tenant);
    return request<{ document: PolicyDocument; found: boolean }>(`/api/policy/document?${p}`);
  },
  setPolicyOverride: (ref: PolicyRef, key: string, value: PolicyValue, locked = false) => {
    const p = new URLSearchParams({ scope: ref.scope });
    if (ref.selector) p.set("selector", ref.selector);
    if (ref.tenant) p.set("tenant", ref.tenant);
    return request<{ resolved: PolicyResolved }>(`/api/policy/document?${p}`, {
      method: "PUT",
      body: JSON.stringify({ key, value, locked }),
    });
  },
  clearPolicyOverride: (ref: PolicyRef, key: string, prune = true) => {
    const p = new URLSearchParams({ scope: ref.scope, key });
    if (ref.selector) p.set("selector", ref.selector);
    if (ref.tenant) p.set("tenant", ref.tenant);
    if (prune) p.set("prune", "true");
    return request<void>(`/api/policy/document?${p}`, { method: "DELETE" });
  },
  validatePolicyOverride: (ref: PolicyRef, key: string, value: PolicyValue, locked = false) =>
    request<{ ok: boolean; error?: string }>("/api/policy/validate", {
      method: "POST",
      body: JSON.stringify({ scope: ref.scope, selector: ref.selector ?? "", tenant: ref.tenant ?? "", key, value, locked }),
    }),
};

// ----- Security Policy types (mirror src/backend/policy/model.go JSON) -----
export type PolicyScope = "system" | "tenant" | "role" | "user";
export type PolicyDomain = "authentication" | "password" | "session" | "account_lifecycle";
export type PolicyKind = "bool" | "int" | "duration" | "enum" | "list";
export type PolicyHarden = "" | "higher" | "lower";

export type PolicyValue = {
  kind: PolicyKind;
  bool?: boolean;
  num?: number; // int count OR duration seconds
  str?: string; // enum selection
  list?: string[]; // list members
};
export type PolicyConstraint = {
  min?: number;
  max?: number;
  unit?: string; // "characters" | "attempts" | "seconds" | "days" | "minutes" | "hours" …
  enum?: string[];
};
export type PolicySetting = {
  key: string;
  domain: PolicyDomain;
  label: string;
  description: string;
  kind: PolicyKind;
  default: PolicyValue;
  constraint: PolicyConstraint;
  tier: "basic" | "advanced";
  nist: string[];
  lockable: boolean;
  harden: PolicyHarden;
  rationale: string;
};
export type PolicyCatalogDomain = { domain: PolicyDomain; settings: PolicySetting[] };
export type PolicyCatalog = { scopes: PolicyScope[]; domains: PolicyCatalogDomain[] };

export type PolicyTrailStep = {
  scope: PolicyScope;
  selector?: string;
  value: PolicyValue;
  locked?: boolean;
  applied: boolean;
  note?: string;
};
export type PolicyResolved = {
  key: string;
  domain: PolicyDomain;
  value: PolicyValue;
  source?: PolicyScope; // empty => from_default
  from_default: boolean;
  locked?: boolean;
  locked_at?: PolicyScope;
  trail?: PolicyTrailStep[];
};
export type PolicyOverride = { value: PolicyValue; locked?: boolean };
export type PolicyDocument = {
  scope: PolicyScope;
  selector: string;
  tenant?: string;
  overrides: Record<string, PolicyOverride>;
  updated_at?: string;
  updated_by?: string;
};
export type PolicySubject = { tenant?: string; role?: string; user?: string };
export type PolicyRef = { scope: PolicyScope; selector?: string; tenant?: string };

export type SNMPOptions = {
  versions: string[];
  security_levels: string[];
  auth_protocols: string[];
  priv_protocols: string[];
};
// Secrets (community/auth_key/priv_key) are write-only: sent on save, never
// returned. has_* booleans report whether one is stored.
export type SNMPCredential = {
  id?: string;
  name: string;
  version: string; // v1 | v2c | v3
  port?: number;
  timeout_ms?: number;
  retries?: number;
  community?: string;
  has_community?: boolean;
  security_name?: string;
  security_level?: string;
  auth_protocol?: string;
  auth_key?: string;
  has_auth_key?: boolean;
  priv_protocol?: string;
  priv_key?: string;
  has_priv_key?: boolean;
  context?: string;
  created_at?: string;
};

// ----- Identity & access types -----
export type AdminUser = {
  username: string;
  role: string;
  email?: string;
  display_name?: string;
  tenant_id?: string;
  status?: string;
  auth_source?: string;
  created_at?: string;
  last_login_at?: string;
};
export type Role = {
  id?: string;
  name: string;
  builtin?: boolean;
  description?: string;
  permissions: Record<string, number>; // module -> 0..3
};
export type Tenant = {
  id: string;
  name: string;
  slug: string;
  note?: string;
  created_at?: string;
};
export type ApiKey = {
  id: string;
  tenant_id: string;
  label: string;
  prefix: string;
  scopes: string[];
  rate_limit_per_min: number; // effective per-minute cap (0 = unlimited)
  use_count: number; // lifetime authenticated calls
  window_used: number; // calls counted in the current minute
  created_by: string;
  created_at: string;
  last_used_at?: string;
  revoked_at?: string;
  // Client metadata
  grant_types?: string[];
  client_uri?: string;
  logo_uri?: string;
  contacts?: string[];
  contact_phone?: string;
  source_cidrs?: string[];
  client_expires_at?: string;
  secret_expires_at?: string;
};

// CreateApiKeyRequest is the registration payload for minting a new key.
// Only `label` is mandatory; everything else is optional metadata.
export type CreateApiKeyRequest = {
  label: string;
  scopes: string[];
  rate_limit_per_min?: number;
  tenant_id?: string;
  grant_types?: string[];
  client_uri?: string;
  logo_uri?: string;
  contacts?: string[];
  contact_phone?: string;
  source_cidrs?: string[];
  client_expires_at?: string;
  secret_expires_at?: string;
};

export type ReportKind =
  | "alerts_summary"
  | "device_inventory"
  | "health_summary"
  | "wan_utilization"
  | "security_threats"
  | "device_utilization"
  | "latency_jitter_sla";
export type ReportBody = {
  kind: ReportKind;
  interval_minutes: number;
  severity: string;
  enabled: boolean;
  description?: string;
  // Optional delivery-channel restriction (email, slack, pagerduty, sns, twilio…).
  // Empty/undefined => all configured channels.
  channels?: string[];
  // Reusable contact points (by id) this report is delivered to. Email-type
  // points are resolved to addresses and emailed directly.
  contact_points?: string[];
  // How contact-point delivery carries the report: "body" emails the rendered
  // report; "link" emails a secure link (rolling out). Default "body".
  delivery_mode?: "body" | "link";
  // Calendar+timezone schedule (async backend). Supersedes interval_minutes when set.
  schedule?: Recurrence;
  // Output formats to render: html (always), xlsx, pdf. Empty => html only.
  formats?: ReportFormat[];
};

export type ReportFormat = "html" | "xlsx" | "pdf";
export type Weekday = "" | "sun" | "mon" | "tue" | "wed" | "thu" | "fri" | "sat";
export type Recurrence = {
  tz: string; // IANA, e.g. "America/Chicago"; "" => UTC
  hour: number; // 0..23
  minute: number; // 0..59
  weekday?: Weekday; // set => weekly
  dom?: number; // 1..31 => monthly (takes precedence over weekday)
};

export type ArtifactRef = {
  format: ReportFormat;
  content_type: string;
  size_bytes: number;
  sha256: string;
  summary: string;
  key: string;
};
export type DeliveryStatus = {
  channel: string;
  recipient: string;
  ok: boolean;
  attempt: number;
  error?: string;
  at: string;
};
export type ExecEvent = { phase: string; at: string; note?: string };
export type ReportExecution = {
  id: string;
  tenant_id?: string;
  schedule_id: string;
  job_id?: string;
  fire_time: string;
  started_at?: string;
  completed_at?: string;
  status: "queued" | "running" | "completed" | "failed" | "cancelled";
  artifacts?: ArtifactRef[];
  delivery_status?: DeliveryStatus[];
  error?: string;
};
export type ReportExecutionDetail = ReportExecution & { events?: ExecEvent[] };

export type ContactPointType = "email" | "slack" | "webhook";
export type ContactPoint = {
  id: string;
  tenant_id?: string;
  name: string;
  type: ContactPointType;
  email?: string[];
  target?: string;
  enabled: boolean;
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

// ----- SSO / API / ITSM -----
export type SSOProvider = { id: string; name: string; kind: "oidc" | "saml" | "ldap" | "tacacs" };
export type SSOConfig = { enabled: boolean; providers: SSOProvider[] };

// OIDC/SSO provider config (admin-gated). The client secret is write-only: the
// server returns client_secret_set instead of the value, and a PUT that omits
// client_secret preserves the stored one.
export type OidcConfig = {
  enabled: boolean;
  issuer: string;
  client_id: string;
  client_secret_set: boolean;
  scopes: string;
  redirect_url: string;
  post_login_url: string;
  default_role: string;
  default_tenant: string;
  admin_roles: string;
  operator_roles: string;
  providers: string;
};

// Native (non-Keycloak) auth providers, configured at runtime via the admin UI.
export type LdapRoleMapping = { group: string; role: string };
export type LdapConfig = {
  enabled: boolean;
  host: string;
  port: number;
  use_tls: boolean;
  start_tls: boolean;
  bind_dn: string;
  bind_password_set: boolean;
  base_dn: string;
  user_filter: string;
  group_base_dn: string;
  group_filter: string;
  role_mappings: LdapRoleMapping[];
  default_role: string;
  default_tenant: string;
  insecure_skip_verify: boolean;
};
export type TacacsConfig = {
  enabled: boolean;
  host: string;
  port: number;
  secret_set: boolean;
  timeout_seconds: number;
  default_role: string;
  default_tenant: string;
};
export type AuthTestResult = {
  ok: boolean;
  stage: string;
  message: string;
  resolved_dn?: string;
  groups?: string[];
  assigned_role?: string;
};
export type TokenPolicy = {
  access_ttl_seconds: number;
  refresh_ttl_seconds: number;
  bounds: {
    access_min_seconds: number; access_max_seconds: number; access_recommended_seconds: number;
    refresh_min_seconds: number; refresh_max_seconds: number; refresh_recommended_seconds: number;
  };
};
export type AuthMethods = {
  local: boolean;
  ldap: { enabled: boolean; name: string };
  tacacs: { enabled: boolean; name: string };
  sso: { enabled: boolean; providers: SSOProvider[] };
};

export type OpenAPIOperation = { tags?: string[]; summary?: string };
export type OpenAPISpec = {
  openapi: string;
  info: { title: string; version: string; description?: string };
  paths: Record<string, Record<string, OpenAPIOperation>>;
};

export type ServiceNowTicket = {
  fingerprint: string;
  number: string;
  sys_id: string;
  severity: string;
  device?: string;
  summary?: string;
  opened_at: string;
  state: string;
};
export type ServiceNowStatus = {
  enabled: boolean;
  configured: boolean;
  threshold?: string;
  auto_close?: boolean;
  open?: ServiceNowTicket[];
  open_count?: number;
};

export type JiraTicket = {
  fingerprint: string;
  key: string;
  issue_id: string;
  severity: string;
  device?: string;
  summary?: string;
  opened_at: string;
  state: string;
};
export type JiraStatus = {
  enabled: boolean;
  configured: boolean;
  project?: string;
  threshold?: string;
  auto_close?: boolean;
  open?: JiraTicket[];
  open_count?: number;
};

// ITSM connector config (admin-editable). GET returns has_password/has_token +
// configured flags (secrets are write-only and never returned); PUT sends the
// secret only when (re)setting it — leave blank to keep the stored one.
export type ItsmServiceNowConfig = {
  enabled: boolean;
  instance_url: string;
  user: string;
  has_password?: boolean;
  password?: string;
  min_severity: string;
  assignment_group: string;
  configured?: boolean;
};
export type ItsmJiraConfig = {
  enabled: boolean;
  base_url: string;
  email: string;
  has_token?: boolean;
  api_token?: string;
  project_key: string;
  issue_type: string;
  min_severity: string;
  resolve_transition: string;
  configured?: boolean;
};
// ITSM Integration Platform — bidirectional-sync config. One entry per provider
// (servicenow | jira | pagerduty | slack). The webhook signing secret is
// write-only: GET reports webhook_secret_set instead of the value, and a PUT
// that omits webhook_secret preserves the stored one. webhook_url is only
// present once a token exists; prepend window.location.origin to get the full
// URL to paste into the provider.
export type IntegrationConfig = {
  provider: string; // servicenow | jira | pagerduty | slack
  enabled: boolean;
  sync_mode: "outbound" | "bidirectional";
  webhook_enabled: boolean;
  webhook_secret_set: boolean;
  webhook_url?: string; // path only, present when a token exists
  state_map: Record<string, string> | null; // {<external>: <internal>}
};
// inbound_enabled mirrors the server's FEATURE_ITSM_INBOUND flag — inbound
// state changes are recorded regardless but only drive incident state when true.
export type IntegrationsResponse = { integrations: IntegrationConfig[]; inbound_enabled: boolean };

export type ItsmConfig = { servicenow: ItsmServiceNowConfig; jira: ItsmJiraConfig };
export type ItsmConfigInput = {
  servicenow: Omit<ItsmServiceNowConfig, "has_password" | "configured">;
  jira: Omit<ItsmJiraConfig, "has_token" | "configured">;
};

export type PromNamesResponse = { status: string; data: string[] };
export type PromSeries = { metric: Record<string, string>; values: [number, string][] };
export type PromRangeResponse = {
  status: string;
  data?: { resultType: string; result: PromSeries[] };
  error?: string;
};
