import { useEffect, useMemo, useState } from "react";
import ReactECharts from "echarts-for-react";
import { api, FlowFilters } from "../services/api";
import { chartBase, axisStyle, areaGradient, paletteColor } from "../theme/charts";
import DataTable, { Column } from "../components/DataTable";
import Icon from "../components/Icon";
import { Stub } from "../pages/Placeholders";
import { EmptyHint } from "../components/board/panels";

// Flows — the NetFlow/IPFIX/sFlow analytics dashboard. Modeled on the ElastiFlow
// layout: a left in-page section nav, a global filter bar (src/dst IP, exporter
// device, ingress/egress interface) + a Unidirectional/Bidirectional toggle, and
// per-section "Top N" panels. Every panel is backed by columns we actually
// collect in netops.flows; sections needing data we don't yet have (Geo IP,
// TCP Flags, interface error/discard counters) render a "Planned" stub.

const fmtNum = (n: number) => Number(n).toLocaleString();

function fmtBytes(n: number): string {
  const x = Number(n) || 0;
  if (x < 1024) return `${x} B`;
  const u = ["KB", "MB", "GB", "TB", "PB"];
  let v = x / 1024;
  let i = 0;
  while (v >= 1024 && i < u.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v >= 10 ? 0 : 1)} ${u[i]}`;
}

const PROTO_NAMES: Record<string, string> = {
  "1": "ICMP",
  "6": "TCP",
  "17": "UDP",
  "47": "GRE",
  "50": "ESP",
  "89": "OSPF",
  "132": "SCTP",
};

// A few well-known ports, annotated for readability in the port panels.
const PORT_NAMES: Record<string, string> = {
  "22": "SSH",
  "53": "DNS",
  "80": "HTTP",
  "123": "NTP",
  "179": "BGP",
  "443": "HTTPS",
  "161": "SNMP",
  "162": "SNMP-trap",
  "514": "syslog",
  "636": "LDAPS",
  "3389": "RDP",
};

const FLOW_TYPES: { value: string; label: string }[] = [
  { value: "", label: "All sources" },
  { value: "netflow", label: "NetFlow" },
  { value: "ipfix", label: "IPFIX" },
  { value: "sflow", label: "sFlow" },
];

type TopNRow = { k: string; bytes_total: number; packets_total: number; flows: number };
type TalkerRow = { src: string; dst: string; bytes_total: number; packets_total: number; flows: number };
type TsRow = { bucket: string; bytes_total: number; packets_total: number };
type ByTypeRow = { flow_type: string; bytes_total: number; packets_total: number; flows: number; exporters: number };

// The shared query inputs every panel reacts to. fkey is a stable string of the
// committed filters so effects re-run when the filter bar is applied.
type FlowQuery = { since: number; ftype: string; filters: FlowFilters; fkey: string; direction: string };

// Left section nav — mirrors the reference dashboard's order.
const SECTIONS: { id: string; label: string; icon: string }[] = [
  { id: "traffic", label: "Traffic Volume", icon: "metrics" },
  { id: "health", label: "Device Health", icon: "infrastructure" },
  { id: "flows", label: "Flows", icon: "flows" },
  { id: "conversations", label: "Conversations", icon: "topology" },
  { id: "asn", label: "Autonomous Systems", icon: "stack" },
  { id: "geo", label: "Geo IP", icon: "explore" },
  { id: "sports", label: "Source Ports", icon: "arrow-up-right" },
  { id: "dports", label: "Destination Ports", icon: "arrow-down" },
  { id: "protocols", label: "Protocols", icon: "datasets" },
  { id: "flags", label: "Flags", icon: "reports" },
];

// ── Reusable Top-N panel (bar / table toggle) ────────────────────────────────
function TopNPanel({
  title,
  by,
  q,
  limit = 15,
  fmtKey,
  keyHeader = "Name",
}: {
  title: string;
  by: string;
  q: FlowQuery;
  limit?: number;
  fmtKey?: (k: string) => string;
  keyHeader?: string;
}) {
  const [rows, setRows] = useState<TopNRow[]>([]);
  const [view, setView] = useState<"bar" | "table">("bar");
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    const load = async () => {
      try {
        const res = await api.flowsTopN(by, q.since, limit, q.ftype, q.filters);
        if (!alive) return;
        setRows((res?.data as TopNRow[]) ?? []);
        setErr(null);
      } catch (e) {
        if (alive) setErr((e as Error).message);
      }
    };
    load();
    const id = setInterval(load, 30_000);
    return () => {
      alive = false;
      clearInterval(id);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [by, q.since, q.ftype, q.fkey, limit]);

  const label = (k: string) => (fmtKey ? fmtKey(k) : k);

  const cols = useMemo<Column<TopNRow>[]>(
    () => [
      { key: "k", header: keyHeader, width: "42%", sortable: true, text: (r) => label(r.k), render: (r) => label(r.k) },
      { key: "bytes", header: "Bytes", align: "right", sortable: true, sortValue: (r) => Number(r.bytes_total), render: (r) => fmtBytes(r.bytes_total) },
      { key: "packets", header: "Packets", align: "right", sortable: true, sortValue: (r) => Number(r.packets_total), render: (r) => fmtNum(r.packets_total) },
      { key: "flows", header: "Flows", align: "right", sortable: true, sortValue: (r) => Number(r.flows), render: (r) => fmtNum(r.flows) },
    ],
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [keyHeader],
  );

  return (
    <div className="panel" style={{ minWidth: 0 }}>
      <div className="panel-tools">
        <h3>{title}</h3>
        <div className="seg-mini" role="group" aria-label="View">
          <button className={view === "bar" ? "on" : ""} onClick={() => setView("bar")} title="Bar chart">
            <Icon name="metrics" size={13} />
          </button>
          <button className={view === "table" ? "on" : ""} onClick={() => setView("table")} title="Table">
            <Icon name="logs" size={13} />
          </button>
        </div>
      </div>
      {err ? (
        <div className="empty" style={{ color: "var(--bad)" }}>{err}</div>
      ) : rows.length === 0 ? (
        <EmptyHint kind="flows" />
      ) : view === "bar" ? (
        <ReactECharts
          style={{ height: Math.min(420, 36 + rows.length * 24) }}
          option={{
            ...chartBase,
            grid: { left: 8, right: 64, top: 6, bottom: 6, containLabel: true },
            tooltip: {
              ...chartBase.tooltip,
              trigger: "axis",
              axisPointer: { type: "shadow" },
              formatter: (ps: any) => {
                const p = Array.isArray(ps) ? ps[0] : ps;
                return `${label(String(p.name))}<br/><b>${fmtBytes(p.value)}</b>`;
              },
            },
            xAxis: { type: "value", ...axisStyle, axisLabel: { ...(axisStyle as any).axisLabel, formatter: (v: number) => fmtBytes(v) } },
            yAxis: {
              type: "category",
              inverse: true,
              data: rows.map((r) => label(r.k)),
              ...axisStyle,
              splitLine: { show: false },
            },
            series: [
              {
                type: "bar",
                data: rows.map((r) => Number(r.bytes_total)),
                itemStyle: { color: paletteColor(0), borderRadius: [0, 3, 3, 0] },
                barMaxWidth: 16,
              },
            ],
          }}
        />
      ) : (
        <DataTable<TopNRow>
          rows={rows}
          columns={cols}
          rowKey={(r) => r.k}
          height={Math.min(440, 40 + rows.length * 28)}
          ariaLabel={title}
          initialSort={{ key: "bytes", dir: "desc" }}
        />
      )}
    </div>
  );
}

// ── Section: Flows (volume timeseries + source presence chips) ────────────────
function FlowsSection({ q }: { q: FlowQuery }) {
  const [ts, setTs] = useState<TsRow[]>([]);
  const [byType, setByType] = useState<ByTypeRow[]>([]);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    const load = async () => {
      try {
        const [a, b] = await Promise.all([
          api.flowsTimeseries(q.since, Math.max(60, Math.floor(q.since / 60)), q.ftype, q.filters),
          api.flowsByType(q.since),
        ]);
        if (!alive) return;
        setTs((a?.data as TsRow[]) ?? []);
        setByType((b?.data as ByTypeRow[]) ?? []);
        setErr(null);
      } catch (e) {
        if (alive) setErr((e as Error).message);
      }
    };
    load();
    const id = setInterval(load, 30_000);
    return () => {
      alive = false;
      clearInterval(id);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [q.since, q.ftype, q.fkey]);

  return (
    <>
      <div className="panel">
        <div className="panel-tools"><h3>Source presence</h3></div>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          {byType.length === 0 ? (
            <span className="mini-meta">No flow data in this window.</span>
          ) : (
            byType.map((t) => (
              <span key={t.flow_type} className="badge accent-badge" title={`${t.exporters} exporter(s) sending ${t.flow_type}`}>
                {String(t.flow_type).toUpperCase()}: {fmtNum(t.flows)} flows · {t.exporters} exporters
              </span>
            ))
          )}
        </div>
      </div>
      <div className="panel">
        <div className="panel-tools"><h3>NetFlow volume (bytes · packets)</h3></div>
        {err ? (
          <div className="empty" style={{ color: "var(--bad)" }}>{err}</div>
        ) : ts.length === 0 ? (
          <EmptyHint kind="flows" />
        ) : (
          <ReactECharts
            style={{ height: 320 }}
            option={{
              ...chartBase,
              tooltip: { ...chartBase.tooltip, trigger: "axis" },
              legend: { ...chartBase.legend, data: ["Bytes", "Packets"], top: 0, right: 0 },
              grid: { left: 64, right: 64, top: 36, bottom: 28 },
              xAxis: { type: "time", ...axisStyle },
              yAxis: [
                { type: "value", name: "bytes", ...axisStyle, axisLabel: { ...(axisStyle as any).axisLabel, formatter: (v: number) => fmtBytes(v) } },
                { type: "value", name: "packets", ...axisStyle, splitLine: { show: false } },
              ],
              series: [
                {
                  name: "Bytes",
                  type: "line",
                  showSymbol: false,
                  smooth: true,
                  lineStyle: { color: paletteColor(0), width: 2 },
                  itemStyle: { color: paletteColor(0) },
                  areaStyle: { color: areaGradient(0) },
                  data: ts.map((r) => [r.bucket, r.bytes_total]),
                },
                {
                  name: "Packets",
                  type: "line",
                  yAxisIndex: 1,
                  showSymbol: false,
                  smooth: true,
                  lineStyle: { color: paletteColor(1), width: 2 },
                  itemStyle: { color: paletteColor(1) },
                  data: ts.map((r) => [r.bucket, r.packets_total]),
                },
              ],
            }}
          />
        )}
      </div>
    </>
  );
}

// ── Section: Conversations (initiator→responder table + endpoint top-Ns) ──────
function ConversationsSection({ q }: { q: FlowQuery }) {
  const [rows, setRows] = useState<TalkerRow[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const mono: React.CSSProperties = { fontFamily: "var(--font-mono, ui-monospace, monospace)", fontSize: 12 };

  useEffect(() => {
    let alive = true;
    const load = async () => {
      try {
        const res = await api.topTalkers(q.since, 25, q.ftype, q.filters, q.direction);
        if (!alive) return;
        setRows((res?.data as TalkerRow[]) ?? []);
        setErr(null);
      } catch (e) {
        if (alive) setErr((e as Error).message);
      }
    };
    load();
    const id = setInterval(load, 30_000);
    return () => {
      alive = false;
      clearInterval(id);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [q.since, q.ftype, q.fkey, q.direction]);

  const cols = useMemo<Column<TalkerRow>[]>(
    () => [
      { key: "src", header: q.direction === "bi" ? "Endpoint A" : "Initiator", width: "26%", sortable: true, text: (r) => r.src, render: (r) => <span style={mono} title={r.src}>{r.src}</span> },
      { key: "dst", header: q.direction === "bi" ? "Endpoint B" : "Responder", width: "26%", sortable: true, text: (r) => r.dst, render: (r) => <span style={mono} title={r.dst}>{r.dst}</span> },
      { key: "bytes", header: "Bytes", align: "right", sortable: true, sortValue: (r) => Number(r.bytes_total), render: (r) => fmtBytes(r.bytes_total) },
      { key: "packets", header: "Packets", align: "right", sortable: true, sortValue: (r) => Number(r.packets_total), render: (r) => fmtNum(r.packets_total) },
      { key: "flows", header: "Flows", align: "right", sortable: true, sortValue: (r) => Number(r.flows), render: (r) => fmtNum(r.flows) },
    ],
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [q.direction],
  );

  return (
    <>
      <div className="panel">
        <div className="panel-tools"><h3>Top conversations (Initiator → Responder)</h3></div>
        {err ? (
          <div className="empty" style={{ color: "var(--bad)" }}>{err}</div>
        ) : rows.length === 0 ? (
          <EmptyHint kind="flows" />
        ) : (
          <DataTable<TalkerRow>
            rows={rows}
            columns={cols}
            rowKey={(r) => `${r.src}→${r.dst}`}
            height={Math.min(460, 40 + rows.length * 28)}
            ariaLabel="Top conversations"
            initialSort={{ key: "bytes", dir: "desc" }}
          />
        )}
      </div>
      <div className="flows-grid">
        <TopNPanel title="Top Initiator IPs" by="src_addr" q={q} keyHeader="Source IP" />
        <TopNPanel title="Top Responder IPs" by="dst_addr" q={q} keyHeader="Destination IP" />
      </div>
    </>
  );
}

// ── Section: Protocols (donut + table) ───────────────────────────────────────
function ProtocolsSection({ q }: { q: FlowQuery }) {
  const [rows, setRows] = useState<{ proto: number; bytes_total: number; packets_total: number; flows: number }[]>([]);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    const load = async () => {
      try {
        const res = await api.flowsByProto(q.since, q.ftype, q.filters);
        if (!alive) return;
        setRows((res?.data as any[]) ?? []);
        setErr(null);
      } catch (e) {
        if (alive) setErr((e as Error).message);
      }
    };
    load();
    const id = setInterval(load, 30_000);
    return () => {
      alive = false;
      clearInterval(id);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [q.since, q.ftype, q.fkey]);

  const name = (p: number) => PROTO_NAMES[String(p)] ?? `IP/${p}`;

  return (
    <div className="panel">
      <div className="panel-tools"><h3>Top protocols</h3></div>
      {err ? (
        <div className="empty" style={{ color: "var(--bad)" }}>{err}</div>
      ) : rows.length === 0 ? (
        <EmptyHint kind="flows" />
      ) : (
        <ReactECharts
          style={{ height: 300 }}
          option={{
            ...chartBase,
            tooltip: { ...chartBase.tooltip, trigger: "item", formatter: (p: any) => `${p.name}: ${fmtBytes(p.value)} (${p.percent}%)` },
            legend: { ...chartBase.legend, bottom: 0 },
            series: [
              {
                type: "pie",
                radius: ["50%", "72%"],
                itemStyle: { borderColor: "#ffffff", borderWidth: 2 },
                label: { color: "#475467" },
                data: rows.map((p, i) => ({ name: name(p.proto), value: p.bytes_total, itemStyle: { color: paletteColor(i) } })),
              },
            ],
          }}
        />
      )}
    </div>
  );
}

// sinceSeconds is supplied by the shell's global time range; when omitted the
// component manages its own range selector.
export default function Flows({ sinceSeconds }: { sinceSeconds?: number } = {}) {
  const [since, setSince] = useState(sinceSeconds ?? 3600);
  const [ftype, setFtype] = useState("");
  const [direction, setDirection] = useState(""); // "" (uni) | "bi"
  const [section, setSection] = useState("traffic");

  // Filter bar: draft (typed) vs committed (applied). Panels react to committed.
  const empty: FlowFilters = {};
  const [draft, setDraft] = useState<FlowFilters>(empty);
  const [filters, setFilters] = useState<FlowFilters>(empty);

  useEffect(() => {
    if (sinceSeconds !== undefined) setSince(sinceSeconds);
  }, [sinceSeconds]);

  const fkey = JSON.stringify(filters);
  const q: FlowQuery = { since, ftype, filters, fkey, direction };
  const activeFilters = Object.entries(filters).filter(([, v]) => v);

  const setField = (k: keyof FlowFilters, v: string) => setDraft((d) => ({ ...d, [k]: v }));
  const apply = () => {
    const cleaned: FlowFilters = {};
    for (const [k, v] of Object.entries(draft)) if (v && v.trim()) (cleaned as any)[k] = v.trim();
    setFilters(cleaned);
  };
  const clearAll = () => {
    setDraft(empty);
    setFilters(empty);
  };

  return (
    <div className="flows-shell">
      {/* Left in-page section nav */}
      <nav className="flows-nav" aria-label="Flow sections">
        {SECTIONS.map((s) => (
          <button key={s.id} className={`flows-nav-item${section === s.id ? " active" : ""}`} onClick={() => setSection(s.id)}>
            <Icon name={s.icon} size={15} />
            <span>{s.label}</span>
          </button>
        ))}
      </nav>

      <div className="flows-main">
        {/* Filter bar */}
        <div className="card flows-filterbar">
          <div className="flows-filter-fields">
            <input placeholder="Source IP" value={draft.src ?? ""} onChange={(e) => setField("src", e.target.value)} />
            <input placeholder="Destination IP" value={draft.dst ?? ""} onChange={(e) => setField("dst", e.target.value)} />
            <input placeholder="Device (exporter IP)" value={draft.device ?? ""} onChange={(e) => setField("device", e.target.value)} />
            <input placeholder="Ingress if (index)" value={draft.in_if ?? ""} onChange={(e) => setField("in_if", e.target.value)} />
            <input placeholder="Egress if (index)" value={draft.out_if ?? ""} onChange={(e) => setField("out_if", e.target.value)} />
            <button className="btn-primary" onClick={apply}>Filter</button>
            {activeFilters.length > 0 && <button className="btn-ghost" onClick={clearAll}>Clear</button>}
          </div>
          <div className="flows-filter-controls">
            <select value={ftype} onChange={(e) => setFtype(e.target.value)} title="Flow source">
              {FLOW_TYPES.map((t) => (
                <option key={t.value} value={t.value}>{t.label}</option>
              ))}
            </select>
            {sinceSeconds === undefined && (
              <select value={since} onChange={(e) => setSince(Number(e.target.value))}>
                <option value={900}>Last 15 minutes</option>
                <option value={3600}>Last 1 hour</option>
                <option value={21600}>Last 6 hours</option>
                <option value={86400}>Last 24 hours</option>
              </select>
            )}
            <div className="seg-mini" role="group" aria-label="Direction">
              <button className={direction === "" ? "on" : ""} onClick={() => setDirection("")}>Unidirectional</button>
              <button className={direction === "bi" ? "on" : ""} onClick={() => setDirection("bi")}>Bidirectional</button>
            </div>
          </div>
          {activeFilters.length > 0 && (
            <div className="flows-active-filters">
              {activeFilters.map(([k, v]) => (
                <span key={k} className="badge accent-badge">{k}: {v}</span>
              ))}
            </div>
          )}
          <p className="mini-meta" style={{ margin: "6px 2px 0" }}>
            Counts are scaled by each device's sampling rate. Filters and the source selector apply to every panel below.
          </p>
        </div>

        {/* Active section */}
        {section === "traffic" && (
          <>
            <TopNPanel title="Top Devices (exporters)" by="device" q={q} keyHeader="Device" limit={12} />
            <div className="flows-grid">
              <TopNPanel title="Top Ingress Interfaces" by="in_if" q={q} keyHeader="Ingress ifIndex" />
              <TopNPanel title="Top Egress Interfaces" by="out_if" q={q} keyHeader="Egress ifIndex" />
            </div>
          </>
        )}
        {section === "flows" && <FlowsSection q={q} />}
        {section === "conversations" && <ConversationsSection q={q} />}
        {section === "asn" && (
          <div className="flows-grid">
            <TopNPanel title="Top Initiator AS" by="src_as" q={q} keyHeader="Source AS" />
            <TopNPanel title="Top Responder AS" by="dst_as" q={q} keyHeader="Destination AS" />
          </div>
        )}
        {section === "sports" && (
          <TopNPanel title="Top Source Ports" by="src_port" q={q} keyHeader="Source port" fmtKey={(k) => (PORT_NAMES[k] ? `${k} (${PORT_NAMES[k]})` : k)} />
        )}
        {section === "dports" && (
          <TopNPanel title="Top Destination Ports" by="dst_port" q={q} keyHeader="Destination port" fmtKey={(k) => (PORT_NAMES[k] ? `${k} (${PORT_NAMES[k]})` : k)} />
        )}
        {section === "protocols" && <ProtocolsSection q={q} />}
        {section === "geo" && (
          <Stub
            icon="explore"
            title="Geo IP"
            summary="Top initiator and responder countries, from GeoIP-resolved flow endpoints."
            planned={[
              "MaxMind GeoLite2 country/ASN enrichment at ingest",
              "Top Initiator / Responder Countries (map + table)",
              "Filter the whole dashboard by country",
            ]}
          />
        )}
        {section === "flags" && (
          <Stub
            icon="reports"
            title="TCP Flags"
            summary="Distribution of TCP control flags across flows — SYN/ACK/FIN/RST patterns useful for scan and reset detection."
            planned={[
              "Capture tcp_flags from goflow2 (NetFlow/IPFIX field)",
              "Store a tcp_flags column in netops.flows",
              "Top Flags panel + scan/reset heuristics",
            ]}
          />
        )}
        {section === "health" && (
          <Stub
            icon="infrastructure"
            title="Device Health"
            summary="Per-interface bandwidth, errors and discards. These are SNMP interface counters (VictoriaMetrics), not flow records, so they're wired separately from the flow pipeline."
            planned={[
              "Interface Bandwidth (ingress/egress) from VictoriaMetrics",
              "Interface Errors and Discards counters",
              "Cross-link an interface here to its flows",
            ]}
          />
        )}
      </div>
    </div>
  );
}
