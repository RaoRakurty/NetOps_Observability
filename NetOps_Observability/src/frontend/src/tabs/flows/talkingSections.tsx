// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// talkingSections — the "Who is talking" views of Explore → Flows, carried
// over from the old Flows page (tabs/Flows.tsx, removed 2026-11-12) with three
// changes: they re-read on the page's refresh clock instead of their own 30 s
// timers, their copy is plain language with a 14 px floor, and the two port
// sections are one ("Services and ports"). The honesty rules they carried —
// an unknown application is a measured bucket, an unmeasured service is not
// idle, the app/service endpoints take only the window — are unchanged and
// still live in flowsAppViews.ts.

import { useMemo, useState, type ReactNode } from "react";
import ReactECharts from "../../components/EChart";
import { api, type FlowAppRow, type FlowAppsResp, type FlowFilters, type FlowServiceRow } from "../../services/api";
import { operatorError, httpFailure } from "../../lib/errors";
import {
  UNKNOWN_MEANING,
  UNRESOLVED_SOURCE_MEANING,
  UNMEASURED_LABEL,
  UNMEASURED_MEANING,
  DRILL_ACTION,
  isUnknownApp,
  appLabel,
  appRowKey,
  appShare,
  appTotals,
  sourceSide,
  sortAppRows,
  tierView,
  groupServiceRows,
  sortServiceRows,
  serviceMeasuredBytes,
  serviceShare,
  coverageSentence,
  drillNote,
  filterScopeNote,
  exporterView,
} from "../flowsAppViews";
import { useAppNames, type ResolvedApp } from "../../services/appNames";
import { chartBase, axisStyle } from "../../theme/charts";
import { cssVar } from "../../theme/tokens";
import { chartAnimation, flowCat, flowProtoColor } from "../../theme/flowTokens";
import DataTable, { type Column } from "../../components/DataTable";
import Icon from "../../components/Icon";
import AskIris from "../../components/AskIris";
import { EmptyHint, escapeHtml, fmtBytes, fmtNum } from "../../components/board/panels";
import { FlowEmpty, type FlowDimension } from "../flowEmpty";
import { StatStrip, Stat, Segmented } from "../../components/ui";
import { IANA_PROTO_NAMES } from "../../proto";
import { type TopNRow, topNDisplay, topNRowId } from "../flowNames";
import { useTicked } from "./useTicked";

/** The shared inputs every Who-is-talking panel reacts to. */
export type FlowQuery = { since: number; ftype: string; filters: FlowFilters; fkey: string; direction: string };

// Well-known ports → a readable name for the port views. A port is a likely
// service, never the application; the label is shown beside the number.
const PORT_NAMES: Record<string, string> = {
  "22": "SSH", "23": "Telnet", "3389": "RDP", "5900": "VNC", "5985": "WinRM", "5986": "WinRM-TLS",
  "80": "HTTP", "443": "HTTPS", "8080": "HTTP-alt", "8443": "HTTPS-alt", "8000": "HTTP-alt", "3000": "HTTP-app",
  "25": "SMTP", "465": "SMTPS", "587": "SMTP-sub", "110": "POP3", "995": "POP3S", "143": "IMAP", "993": "IMAPS",
  "53": "DNS", "853": "DNS-TLS", "123": "NTP", "389": "LDAP", "636": "LDAPS", "88": "Kerberos",
  "20": "FTP-data", "21": "FTP", "69": "TFTP", "445": "SMB", "2049": "NFS",
  "1433": "MSSQL", "1521": "Oracle", "3306": "MySQL", "5432": "PostgreSQL", "6379": "Redis",
  "27017": "MongoDB", "9092": "Kafka", "9200": "Elasticsearch", "5672": "AMQP",
  "179": "BGP", "646": "LDP", "500": "IKE", "4500": "IPsec-NAT-T", "1701": "L2TP", "1723": "PPTP",
  "3784": "BFD", "3785": "BFD-echo", "4784": "BFD-multihop", "520": "RIP", "1985": "HSRP",
  "4789": "VXLAN", "6081": "Geneve", "2152": "GTP-U", "12346": "SD-WAN DTLS/IPsec",
  "161": "SNMP", "162": "SNMP-trap", "514": "syslog", "6343": "sFlow", "2055": "NetFlow", "4739": "IPFIX",
  "57400": "gNMI", "9339": "gNMI", "6030": "gNMI", "830": "NETCONF", "9090": "metrics", "8428": "metrics",
  "49": "TACACS+", "1812": "RADIUS-auth", "1813": "RADIUS-acct", "5060": "SIP", "5061": "SIP-TLS",
  "67": "DHCP", "68": "DHCP", "3478": "STUN/TURN",
};

export const portLabel = (k: string): string => (PORT_NAMES[k] ? `${k} (${PORT_NAMES[k]})` : k);

/**
 * "6/443" → "443/tcp · HTTPS". The key is the service_port top-N dimension:
 * protocol number and the lower of the two ports. Unknown shapes are shown
 * verbatim, never guessed at.
 */
export function servicePortLabel(k: string): string {
  const m = /^(\d{1,3})\/(\d{1,5})$/.exec(k);
  if (!m) return k;
  const proto = (IANA_PROTO_NAMES[m[1]] ?? `IP/${m[1]}`).toLowerCase();
  const name = PORT_NAMES[m[2]];
  return name ? `${m[2]}/${proto} · ${name}` : `${m[2]}/${proto}`;
}

const errText = (e: unknown, what: string): string | null => (e ? operatorError(e, what) : null);

// AppNameChip — secondary line under an IP when the unified resolver names its
// application; unresolved IPs render exactly as before (no chip).
function AppNameChip({ app }: { app?: ResolvedApp }) {
  if (!app) return null;
  return (
    <span className="tr-subline" title={`identified by ${app.source}`}>
      {app.app}
    </span>
  );
}

// ── Top-N (bar / table) ──────────────────────────────────────────────────────

export function TopNView({
  title, rows, err, fmtKey, keyHeader = "Name", empty, by = "",
}: {
  title: string;
  rows: TopNRow[];
  err: string | null;
  fmtKey?: (k: string) => string;
  keyHeader?: string;
  empty?: ReactNode;
  by?: string;
}) {
  const [view, setView] = useState<"bar" | "table">("bar");
  const display = (r: TopNRow) => topNDisplay(r, by, fmtKey);
  const keys = useMemo(() => rows.map((r) => r.k), [rows]);
  const apps = useAppNames(keys);

  const cols = useMemo<Column<TopNRow>[]>(
    () => [
      {
        key: "k", header: keyHeader, width: "42%", sortable: true, text: (r) => display(r),
        render: (r) => (
          <span>
            {display(r)}
            <AppNameChip app={apps[r.k]} />
          </span>
        ),
      },
      { key: "bytes", header: "Volume", align: "right", sortable: true, sortValue: (r) => Number(r.bytes_total), render: (r) => fmtBytes(r.bytes_total) },
      { key: "packets", header: "Packets", align: "right", sortable: true, sortValue: (r) => Number(r.packets_total), render: (r) => fmtNum(r.packets_total) },
      { key: "flows", header: "Flows", align: "right", sortable: true, sortValue: (r) => Number(r.flows), render: (r) => fmtNum(r.flows) },
    ],
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [keyHeader, apps, by],
  );

  return (
    <div className="panel" style={{ minWidth: 0 }}>
      <div className="panel-tools">
        <h3>{title}</h3>
        <div className="seg-mini" role="group" aria-label="View">
          <button className={view === "bar" ? "on" : ""} aria-pressed={view === "bar"} onClick={() => setView("bar")} title="Bar chart">
            <Icon name="metrics" size={13} />
          </button>
          <button className={view === "table" ? "on" : ""} aria-pressed={view === "table"} onClick={() => setView("table")} title="Table">
            <Icon name="logs" size={13} />
          </button>
        </div>
      </div>
      {err ? (
        <div className="empty tr-error">{err}</div>
      ) : rows.length === 0 ? (
        empty ?? <EmptyHint kind="flows" />
      ) : view === "bar" ? (
        <ReactECharts
          style={{ height: Math.min(420, 36 + rows.length * 26) }}
          option={{
            ...chartBase,
            animation: chartAnimation(),
            grid: { left: 8, right: 64, top: 6, bottom: 6, containLabel: true },
            tooltip: {
              ...chartBase.tooltip,
              trigger: "axis",
              axisPointer: { type: "shadow" },
              formatter: (ps: any) => {
                const p = Array.isArray(ps) ? ps[0] : ps;
                const row = rows[p.dataIndex as number];
                const key = row ? row.k : String(p.name);
                // ECharts inserts this string via innerHTML. The row key (flow
                // endpoints / exporter fields) and the resolved app name are
                // attacker-influenced, so every dynamic part is escaped (H15).
                const app = apps[key] ? ` · ${escapeHtml(apps[key].app)}` : "";
                return `${escapeHtml(row ? display(row) : key)}${app}<br/><b>${fmtBytes(p.value)}</b>`;
              },
            },
            xAxis: { type: "value", ...axisStyle, axisLabel: { ...(axisStyle as any).axisLabel, fontSize: 14, formatter: (v: number) => fmtBytes(v) } },
            yAxis: {
              type: "category", inverse: true, data: rows.map((r) => display(r)), ...axisStyle,
              axisLabel: { ...(axisStyle as any).axisLabel, fontSize: 14 }, splitLine: { show: false },
            },
            series: [
              {
                type: "bar",
                data: rows.map((r, i) => ({ value: Number(r.bytes_total), itemStyle: { color: flowCat(i), borderRadius: [0, 4, 4, 0] } })),
                barMaxWidth: 16,
              },
            ],
          }}
        />
      ) : (
        <DataTable<TopNRow>
          rows={rows}
          columns={cols}
          rowKey={(r) => topNRowId(r)}
          rowHeight={34}
          height={Math.min(460, 40 + rows.length * 34)}
          ariaLabel={title}
          initialSort={{ key: "bytes", dir: "desc" }}
        />
      )}
    </div>
  );
}

export function TopNPanel({
  title, by, q, limit = 15, fmtKey, keyHeader = "Name", dim = "generic",
}: {
  title: string;
  by: string;
  q: FlowQuery;
  limit?: number;
  fmtKey?: (k: string) => string;
  keyHeader?: string;
  dim?: FlowDimension;
}) {
  const r = useTicked(() => api.flowsTopN(by, q.since, limit, q.ftype, q.filters), [by, q.since, q.ftype, q.fkey, limit]);
  const rows = ((r.data?.data as TopNRow[] | undefined) ?? []);
  return (
    <TopNView
      title={title} rows={rows} err={errText(r.error, `${title} could not be read for this window.`)}
      fmtKey={fmtKey} keyHeader={keyHeader} by={by} empty={r.loading ? <div className="empty board-empty" aria-busy="true" /> : <FlowEmpty q={q} dim={dim} />}
    />
  );
}

// ── Conversations ────────────────────────────────────────────────────────────

type TalkerRow = { src: string; dst: string; bytes_total: number; packets_total: number; flows: number };

/** The busiest conversations (initiator → responder, or both ends as one). */
export function ConversationsSection({ q, limit = 25, title = "Conversations" }: { q: FlowQuery; limit?: number; title?: string }) {
  const r = useTicked(() => api.topTalkers(q.since, limit, q.ftype, q.filters, q.direction), [q.since, q.ftype, q.fkey, q.direction, limit]);
  const rows = (r.data?.data as TalkerRow[] | undefined) ?? [];
  const err = errText(r.error, "Conversations could not be read for this window.");
  const talkerKeys = useMemo(() => rows.flatMap((x) => [x.src, x.dst]), [rows]);
  const apps = useAppNames(talkerKeys);
  const both = q.direction === "bi";

  const cols = useMemo<Column<TalkerRow>[]>(
    () => [
      { key: "src", header: both ? "One end" : "From", width: "26%", sortable: true, text: (x) => x.src, render: (x) => <span title={x.src}><span className="fl-ep fl-ep-src"><span className="fl-addr">{x.src}</span></span><AppNameChip app={apps[x.src]} /></span> },
      { key: "dst", header: both ? "Other end" : "To", width: "26%", sortable: true, text: (x) => x.dst, render: (x) => <span title={x.dst}><span className="fl-ep fl-ep-dst"><span className="fl-addr">{x.dst}</span></span><AppNameChip app={apps[x.dst]} /></span> },
      { key: "bytes", header: "Volume", align: "right", sortable: true, sortValue: (x) => Number(x.bytes_total), render: (x) => fmtBytes(x.bytes_total) },
      { key: "packets", header: "Packets", align: "right", sortable: true, sortValue: (x) => Number(x.packets_total), render: (x) => fmtNum(x.packets_total) },
      { key: "flows", header: "Flows", align: "right", sortable: true, sortValue: (x) => Number(x.flows), render: (x) => fmtNum(x.flows) },
    ],
    [both, apps],
  );

  return (
    <div className="panel" style={{ minWidth: 0 }}>
      <div className="panel-tools"><h3>{title}</h3></div>
      {err ? (
        <div className="empty tr-error">{err}</div>
      ) : rows.length === 0 ? (
        r.loading ? <div className="empty board-empty" aria-busy="true" /> : <FlowEmpty q={q} />
      ) : (
        <DataTable<TalkerRow>
          rows={rows}
          columns={cols}
          rowKey={(x) => `${x.src}→${x.dst}`}
          rowHeight={40}
          height={Math.min(480, 40 + rows.length * 40)}
          ariaLabel={title}
          initialSort={{ key: "bytes", dir: "desc" }}
        />
      )}
    </div>
  );
}

// ── Applications ─────────────────────────────────────────────────────────────

/**
 * The top source → destination application pairs by volume, over the window
 * and narrowed by the filter bar (a link, an address, a port, a protocol —
 * tracker 400). The Application chip narrows the list by name.
 */
export function ApplicationsSection({ q, filterKeys, appFilter = "", onDrill }: {
  q: FlowQuery;
  filterKeys: string[];
  appFilter?: string;
  onDrill: () => void;
}) {
  const r = useTicked<FlowAppsResp>(() => api.flowsApps(q.since, q.filters, q.ftype), [q.since, q.ftype, q.fkey]);
  const resp = r.data ?? null;
  const err = errText(r.error, "Application traffic could not be read for this window.");
  const all = useMemo(() => sortAppRows(resp?.apps), [resp]);
  const rows = useMemo(() => {
    const f = appFilter.trim().toLowerCase();
    return f ? all.filter((x) => appLabel(x.app).toLowerCase().includes(f) || sourceSide(x.src_app).label.toLowerCase().includes(f)) : all;
  }, [all, appFilter]);
  const totals = useMemo(() => appTotals(all), [all]);
  const named = all.filter((x) => !isUnknownApp(x.app)).length;
  const exporterNamed = all.filter((x) => exporterView(x).named).length;
  const caveat = filterScopeNote("Applications", q.direction);

  const cols = useMemo<Column<FlowAppRow>[]>(
    () => [
      {
        key: "src", header: "From", width: "20%", sortable: true,
        text: (x) => sourceSide(x.src_app).label,
        render: (x) => {
          const s = sourceSide(x.src_app);
          return (
            <span className={s.kind === "named" ? undefined : "tr-quiet"} title={s.kind === "unresolved" ? UNRESOLVED_SOURCE_MEANING : s.kind === "unknown" ? UNKNOWN_MEANING : undefined}>
              {s.label}
            </span>
          );
        },
      },
      {
        key: "app", header: "Application", width: "22%", sortable: true,
        text: (x) => appLabel(x.app),
        render: (x) => (
          <span title={isUnknownApp(x.app) ? UNKNOWN_MEANING : undefined}>
            {appLabel(x.app)}
            {isUnknownApp(x.app) && <span className="tr-subline">uncatalogued or internal</span>}
          </span>
        ),
      },
      {
        key: "exporter", header: "Device names it", width: "14%", sortable: true,
        text: (x) => exporterView(x).label,
        render: (x) => {
          const v = exporterView(x);
          return <span className={v.named ? undefined : "tr-quiet"} title={v.title}>{v.label}</span>;
        },
      },
      {
        key: "tier", header: "How sure", width: "14%", sortable: true,
        text: (x) => tierView(x.tier).label,
        render: (x) => {
          const t = tierView(x.tier);
          return <span style={{ color: t.tone }} title={t.meaning}>{t.label}</span>;
        },
      },
      { key: "bytes", header: "Volume", align: "right", sortable: true, sortValue: (x) => Number(x.bytes) || 0, render: (x) => fmtBytes(x.bytes) },
      {
        key: "share", header: "Share", align: "right", sortable: true,
        sortValue: (x) => appShare(x, totals.bytes) ?? -1,
        render: (x) => {
          const p = appShare(x, totals.bytes);
          return p === null ? "—" : `${p.toFixed(1)}%`;
        },
      },
      { key: "flows", header: "Flows", align: "right", sortable: true, sortValue: (x) => Number(x.flows) || 0, render: (x) => fmtNum(x.flows) },
      { key: "dests", header: "Destinations", align: "right", sortable: true, sortValue: (x) => Number(x.dests) || 0, render: (x) => fmtNum(x.dests) },
      {
        key: "drill", header: "Talkers", width: 190, align: "left",
        render: (x) => (
          <button className="btn-ghost" onClick={onDrill} title={drillNote(appLabel(x.app))}>
            {DRILL_ACTION}
          </button>
        ),
      },
    ],
    [totals.bytes, onDrill],
  );

  return (
    <>
      <StatStrip>
        <Stat label="Volume named" value={resp ? fmtBytes(totals.bytes) : "—"} />
        <Stat label="Applications named" value={resp ? fmtNum(named) : "—"} />
        <Stat
          label="Share unnamed"
          value={resp && totals.bytes > 0 ? `${((100 * totals.unknownBytes) / totals.bytes).toFixed(1)}%` : "—"}
          tone={totals.bytes > 0 && totals.unknownBytes / totals.bytes > 0.5 ? "warn" : ""}
        />
        <Stat label="Flow records" value={resp ? fmtNum(totals.flows) : "—"} />
      </StatStrip>
      <div className="panel" style={{ minWidth: 0 }}>
        <div className="panel-tools"><h3>Applications by volume</h3></div>
        <p className="mini-meta tr-note" title={filterKeys.length ? `Narrowed by: ${filterKeys.join(", ")}` : undefined}>{caveat}</p>
        {err ? (
          <div className="empty tr-error">{err}</div>
        ) : rows.length === 0 ? (
          <div className="empty board-empty">
            <div className="board-empty-msg">{resp ? "Nothing was named in this window." : "Reading applications…"}</div>
          </div>
        ) : (
          <DataTable<FlowAppRow>
            rows={rows}
            columns={cols}
            rowKey={appRowKey}
            rowHeight={44}
            height={Math.min(480, 40 + rows.length * 44)}
            ariaLabel="Applications by volume"
            initialSort={{ key: "bytes", dir: "desc" }}
          />
        )}
        <p className="fact-line tr-fact">
          {coverageSentence(resp?.coverage)}
          <AskIris topic="flows.app-coverage" label="Coverage" />
        </p>
        {totals.unknownRows > 0 && (
          <p className="fact-line tr-fact">
            {UNKNOWN_MEANING}
            <AskIris topic="flows.unknown-app" label="Unknown" />
          </p>
        )}
        {all.some((x) => sourceSide(x.src_app).kind === "unresolved") && (
          <p className="fact-line tr-fact">
            {UNRESOLVED_SOURCE_MEANING}
            <AskIris topic="flows.unresolved-source" label="Source not resolved" />
          </p>
        )}
      </div>
      {resp && named === 0 && exporterNamed === 0 && (
        <TopNPanel title="Likely services" by="service_port" q={q} keyHeader="Service port" fmtKey={servicePortLabel} />
      )}
    </>
  );
}

// ── Services (catalog) ───────────────────────────────────────────────────────

/**
 * The catalog view: a service with no selector is UNMEASURED, not idle. When
 * the catalog store is absent the endpoint answers 501 with a reason, and the
 * reason is what the operator sees.
 */
export function ServicesSection({ q, filterKeys, appFilter = "", onDrill }: {
  q: FlowQuery;
  filterKeys: string[];
  appFilter?: string;
  onDrill: () => void;
}) {
  const r = useTicked(() => api.flowsServices(q.since, q.filters, q.ftype), [q.since, q.ftype, q.fkey]);
  const failure = r.error ? httpFailure(r.error) : null;
  const unavailable = failure?.status === 501 ? operatorError(r.error, "The service catalog is not available on this deployment.") : null;
  const err = r.error && !unavailable ? operatorError(r.error, "Service traffic could not be read for this window.") : null;
  const all = r.error ? null : r.data?.services ?? (r.loading ? null : []);
  const rows = useMemo(() => {
    const f = appFilter.trim().toLowerCase();
    return all && f ? all.filter((x) => x.name.toLowerCase().includes(f)) : all;
  }, [all, appFilter]);
  const grouped = useMemo(() => groupServiceRows(all), [all]);
  const ordered = useMemo(() => sortServiceRows(rows), [rows]);
  const measuredBytes = useMemo(() => serviceMeasuredBytes(all), [all]);
  const caveat = filterScopeNote("Services", q.direction);

  const cols = useMemo<Column<FlowServiceRow>[]>(
    () => [
      {
        key: "name", header: "Service", width: "28%", sortable: true, text: (x) => x.name,
        render: (x) => (
          <span title={x.attributed ? undefined : UNMEASURED_MEANING}>
            {x.name}
            {!x.attributed && <span className="tr-subline">no selector yet</span>}
          </span>
        ),
      },
      { key: "criticality", header: "Criticality", width: "14%", sortable: true, text: (x) => x.criticality, render: (x) => x.criticality || "Not set" },
      {
        key: "bytes", header: "Volume", align: "right", sortable: true,
        sortValue: (x) => (x.attributed ? Number(x.bytes) || 0 : -1),
        render: (x) => (x.attributed ? fmtBytes(x.bytes) : <span className="tr-quiet" title={UNMEASURED_MEANING}>{UNMEASURED_LABEL}</span>),
      },
      {
        key: "share", header: "Share", align: "right", sortable: true,
        sortValue: (x) => serviceShare(x, measuredBytes) ?? -1,
        render: (x) => {
          const p = serviceShare(x, measuredBytes);
          return p === null ? <span className="tr-quiet">{UNMEASURED_LABEL}</span> : `${p.toFixed(1)}%`;
        },
      },
      {
        key: "flows", header: "Flows", align: "right", sortable: true,
        sortValue: (x) => (x.attributed ? Number(x.flows) || 0 : -1),
        render: (x) => (x.attributed ? fmtNum(x.flows) : <span className="tr-quiet">{UNMEASURED_LABEL}</span>),
      },
      {
        key: "drill", header: "Talkers", width: 190, align: "left",
        render: (x) => (
          <button className="btn-ghost" onClick={onDrill} title={drillNote(x.name)}>
            {DRILL_ACTION}
          </button>
        ),
      },
    ],
    [measuredBytes, onDrill],
  );

  if (unavailable) {
    return (
      <div className="panel">
        <div className="panel-tools"><h3>Services</h3></div>
        <div className="empty board-empty">
          <div className="board-empty-msg">The service view is not available on this deployment.</div>
          <div className="board-empty-hint">{unavailable}</div>
        </div>
      </div>
    );
  }

  return (
    <>
      <StatStrip>
        <Stat label="Services defined" value={all ? fmtNum(all.length) : "—"} />
        <Stat label="Being measured" value={all ? fmtNum(grouped.measured.length) : "—"} />
        <Stat label="Awaiting a selector" value={all ? fmtNum(grouped.unmeasured.length) : "—"} tone={grouped.unmeasured.length > 0 ? "warn" : ""} />
        <Stat label="Measured volume" value={all ? fmtBytes(measuredBytes) : "—"} />
      </StatStrip>
      <div className="panel" style={{ minWidth: 0 }}>
        <div className="panel-tools"><h3>Services by volume</h3></div>
        <p className="mini-meta tr-note" title={filterKeys.length ? `Narrowed by: ${filterKeys.join(", ")}` : undefined}>{caveat}</p>
        {err ? (
          <div className="empty tr-error">{err}</div>
        ) : ordered.length === 0 ? (
          <div className="empty board-empty">
            <div className="board-empty-msg">{all ? "No services are defined yet." : "Reading services…"}</div>
          </div>
        ) : (
          <DataTable<FlowServiceRow>
            rows={ordered}
            columns={cols}
            rowKey={(x) => x.service_id}
            rowHeight={44}
            height={Math.min(480, 40 + ordered.length * 44)}
            ariaLabel="Services by measured volume"
          />
        )}
        {grouped.unmeasured.length > 0 && (
          <p className="fact-line tr-fact">
            {UNMEASURED_MEANING}
            <AskIris topic="flows.unmeasured-service" label="Not measured" />
          </p>
        )}
      </div>
    </>
  );
}

// ── Services and ports (the two old port sections, merged) ──────────────────

type PortView = "service" | "dst" | "src";

export function PortsSection({ q }: { q: FlowQuery }) {
  const [view, setView] = useState<PortView>("service");
  return (
    <>
      <Segmented<PortView>
        value={view}
        ariaLabel="Group ports by"
        options={[
          { value: "service", label: "Likely service", title: "The lower port of each conversation — the end a service listens on" },
          { value: "dst", label: "Destination port" },
          { value: "src", label: "Source port" },
        ]}
        onChange={setView}
      />
      {view === "service" && <TopNPanel title="Services and ports" by="service_port" q={q} keyHeader="Port" fmtKey={servicePortLabel} />}
      {view === "dst" && <TopNPanel title="Destination ports" by="dst_port" q={q} keyHeader="Port" fmtKey={portLabel} />}
      {view === "src" && <TopNPanel title="Source ports" by="src_port" q={q} keyHeader="Port" fmtKey={portLabel} />}
    </>
  );
}

// ── Protocols ────────────────────────────────────────────────────────────────

type ProtoRow = { proto: number; proto_name?: string; bytes_total: number; packets_total: number; flows: number };

export function ProtocolsSection({ q }: { q: FlowQuery }) {
  const r = useTicked(() => api.flowsByProto(q.since, q.ftype, q.filters), [q.since, q.ftype, q.fkey]);
  const rows = (r.data?.data as ProtoRow[] | undefined) ?? [];
  const err = errText(r.error, "Protocols could not be read for this window.");
  const name = (p: ProtoRow) => p.proto_name || IANA_PROTO_NAMES[String(p.proto)] || `IP/${p.proto}`;
  return (
    <div className="panel">
      <div className="panel-tools"><h3>Protocols</h3></div>
      {err ? (
        <div className="empty tr-error">{err}</div>
      ) : rows.length === 0 ? (
        r.loading ? <div className="empty board-empty" aria-busy="true" /> : <FlowEmpty q={q} />
      ) : (
        <ReactECharts
          style={{ height: 320 }}
          option={{
            ...chartBase,
            animation: chartAnimation(),
            tooltip: { ...chartBase.tooltip, trigger: "item", formatter: (p: any) => `${escapeHtml(p.name)}: ${fmtBytes(p.value)} (${p.percent}%)` },
            legend: { ...chartBase.legend, bottom: 0, textStyle: { ...(chartBase as any).legend?.textStyle, fontSize: 14 } },
            series: [
              {
                type: "pie",
                radius: ["50%", "72%"],
                itemStyle: { borderColor: cssVar("--surface", ""), borderWidth: 2, borderRadius: 4 },
                label: { color: cssVar("--fg-muted", ""), fontSize: 14 },
                data: rows.map((p, i) => ({ name: name(p), value: Number(p.bytes_total), itemStyle: { color: [1, 6, 17, 58].includes(Number(p.proto)) ? flowProtoColor(Number(p.proto)) : flowCat(i + 3) } })),
              },
            ],
          }}
        />
      )}
    </div>
  );
}

// ── Countries (only when a location dataset is loaded) ──────────────────────

type GeoRow = { country: string; bytes_total: number; packets_total: number; flows: number };

const regionNames = typeof Intl !== "undefined" && "DisplayNames" in Intl ? new Intl.DisplayNames(["en"], { type: "region" }) : null;
export function countryLabel(code: string): string {
  if (!/^[A-Z]{2}$/.test(code)) return code || "—";
  const flag = String.fromCodePoint(...[...code].map((c) => 0x1f1a5 + c.charCodeAt(0)));
  let label = code;
  try {
    label = regionNames?.of(code) ?? code;
  } catch {
    /* unknown/reserved code — show it raw */
  }
  return `${flag} ${label}`;
}

export function CountriesSection({ q }: { q: FlowQuery }) {
  const s = useTicked(() => api.flowsGeo("src", q.since, q.ftype, q.filters), [q.since, q.ftype, q.fkey]);
  const d = useTicked(() => api.flowsGeo("dst", q.since, q.ftype, q.filters), [q.since, q.ftype, q.fkey]);
  const coerce = (rows: GeoRow[]) => rows.map((x) => ({ ...x, bytes_total: Number(x.bytes_total), packets_total: Number(x.packets_total), flows: Number(x.flows) }));
  const src = coerce((s.data?.data as GeoRow[] | undefined) ?? []);
  const dst = coerce((d.data?.data as GeoRow[] | undefined) ?? []);
  const err = errText(s.error || d.error, "Countries could not be read for this window.");
  // The unmatched bucket (private / unrouted space) is excluded from the
  // ranking but its share is stated.
  const total = src.reduce((n, x) => n + x.bytes_total, 0);
  const publicBytes = src.filter((x) => x.country !== "").reduce((n, x) => n + x.bytes_total, 0);
  const toTopN = (rows: GeoRow[]): TopNRow[] => rows.filter((x) => x.country !== "").slice(0, 15).map((x) => ({ k: x.country, bytes_total: x.bytes_total, packets_total: x.packets_total, flows: x.flows }));
  return (
    <>
      <StatStrip>
        <Stat label="Public traffic share" value={total ? `${((100 * publicBytes) / total).toFixed(1)}%` : "—"} />
        <Stat label="Source countries" value={fmtNum(src.filter((x) => x.country).length)} />
        <Stat label="Destination countries" value={fmtNum(dst.filter((x) => x.country).length)} />
      </StatStrip>
      <div className="flows-grid">
        <TopNView title="Source countries" rows={toTopN(src)} err={err} keyHeader="Country" fmtKey={countryLabel} />
        <TopNView title="Destination countries" rows={toTopN(dst)} err={err} keyHeader="Country" fmtKey={countryLabel} />
      </div>
    </>
  );
}

export function NetworksSection({ q }: { q: FlowQuery }) {
  return (
    <div className="flows-grid">
      <TopNPanel title="Source networks" by="src_as" q={q} keyHeader="Network (AS)" dim="as" />
      <TopNPanel title="Destination networks" by="dst_as" q={q} keyHeader="Network (AS)" dim="as" />
    </div>
  );
}
