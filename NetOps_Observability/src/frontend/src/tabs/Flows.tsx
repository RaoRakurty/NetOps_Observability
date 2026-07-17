import { useEffect, useMemo, useState } from "react";
import ReactECharts from "echarts-for-react";
import { api, FlowFilters } from "../services/api";
import { chartBase, axisStyle, timeAxisTicks, paletteColor, colorForMetric, hexToRgba } from "../theme/charts";
import { cssVar } from "../theme/tokens";
import DataTable, { Column } from "../components/DataTable";
import Icon from "../components/Icon";
import { EmptyHint, MetricStat } from "../components/board/panels";
import { StatStrip, Stat } from "../components/ui";

// Flows — the NetFlow/IPFIX/sFlow analytics dashboard. Layout: a left
// in-page section nav, a global filter bar (src/dst IP, exporter
// device, ingress/egress interface) + a Unidirectional/Bidirectional toggle, and
// per-section "Top N" panels. Every panel is backed by columns we actually
// collect in netops.flows; sections needing data we don't yet have (Geo IP)
// render a "Planned" stub.

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

// Well-known ports → application name, annotated for readability in the port
// panels (#71 ⑨ — "flows show only tcp/udp, no app names"). Broad IANA / common-
// enterprise coverage so the dst-port panel reads as applications, not bare
// numbers. The richer, attribution-grade port→app_label rollup is the #69 P1
// service-attribution job (svc_flow_rollup_1m); this is the honest client-side
// lookup that needs no backend change.
const PORT_NAMES: Record<string, string> = {
  // remote access / mgmt
  "22": "SSH", "23": "Telnet", "3389": "RDP", "5900": "VNC", "5985": "WinRM", "5986": "WinRM-TLS",
  // web
  "80": "HTTP", "443": "HTTPS", "8080": "HTTP-alt", "8443": "HTTPS-alt", "8000": "HTTP-alt", "3000": "HTTP-app",
  // mail
  "25": "SMTP", "465": "SMTPS", "587": "SMTP-sub", "110": "POP3", "995": "POP3S", "143": "IMAP", "993": "IMAPS",
  // name / time / dir
  "53": "DNS", "853": "DNS-TLS", "123": "NTP", "389": "LDAP", "636": "LDAPS", "88": "Kerberos",
  // file transfer / share
  "20": "FTP-data", "21": "FTP", "69": "TFTP", "445": "SMB", "2049": "NFS",
  // databases / cache / queue
  "1433": "MSSQL", "1521": "Oracle", "3306": "MySQL", "5432": "PostgreSQL", "6379": "Redis",
  "27017": "MongoDB", "9092": "Kafka", "9200": "Elasticsearch", "5672": "AMQP",
  // routing / network control
  "179": "BGP", "646": "LDP", "500": "IKE", "4500": "IPsec-NAT-T", "1701": "L2TP", "1723": "PPTP",
  // mgmt / telemetry
  "161": "SNMP", "162": "SNMP-trap", "514": "syslog", "6343": "sFlow", "2055": "NetFlow", "4739": "IPFIX",
  "57400": "gNMI", "9339": "gNMI", "9090": "metrics", "8428": "metrics",
  // AAA / voice
  "49": "TACACS+", "1812": "RADIUS-auth", "1813": "RADIUS-acct", "5060": "SIP", "5061": "SIP-TLS",
  // dhcp / misc
  "67": "DHCP", "68": "DHCP", "3478": "STUN/TURN",
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
// Split presentational/container: TopNView renders any {k, bytes, packets,
// flows} rows (also used by the Geo IP section); TopNPanel adds the standard
// flowsTopN fetch-and-refresh loop around it.
function TopNView({
  title,
  rows,
  err,
  fmtKey,
  keyHeader = "Name",
}: {
  title: string;
  rows: TopNRow[];
  err: string | null;
  fmtKey?: (k: string) => string;
  keyHeader?: string;
}) {
  const [view, setView] = useState<"bar" | "table">("bar");
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
                data: rows.map((r, i) => ({ value: Number(r.bytes_total), itemStyle: { color: paletteColor(i), borderRadius: [0, 3, 3, 0] } })),
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

  return <TopNView title={title} rows={rows} err={err} fmtKey={fmtKey} keyHeader={keyHeader} />;
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
              xAxis: { type: "time", ...axisStyle, ...timeAxisTicks() },
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
                  lineStyle: { color: colorForMetric("traffic bytes"), width: 2 },
                  itemStyle: { color: colorForMetric("traffic bytes") },
                  areaStyle: { color: { type: "linear", x: 0, y: 0, x2: 0, y2: 1, colorStops: [{ offset: 0, color: hexToRgba(colorForMetric("traffic bytes"), 0.45) }, { offset: 1, color: hexToRgba(colorForMetric("traffic bytes"), 0) }] } },
                  data: ts.map((r) => [r.bucket, r.bytes_total]),
                },
                {
                  name: "Packets",
                  type: "line",
                  yAxisIndex: 1,
                  showSymbol: false,
                  smooth: true,
                  lineStyle: { color: colorForMetric("packets"), width: 2 },
                  itemStyle: { color: colorForMetric("packets") },
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
                itemStyle: { borderColor: cssVar("--surface", "#ffffff"), borderWidth: 2 },
                label: { color: cssVar("--fg-muted", "#475467") },
                data: rows.map((p, i) => ({ name: name(p.proto), value: p.bytes_total, itemStyle: { color: paletteColor(i) } })),
              },
            ],
          }}
        />
      )}
    </div>
  );
}

// ── Section: Geo IP — traffic by country via the server's GeoIP dictionary ────
type GeoRow = { country: string; bytes_total: number; packets_total: number; flows: number };

// ISO 3166-1 alpha-2 → display name + flag, all built into the browser
// (Intl.DisplayNames + regional-indicator code points) — no dataset shipped.
const regionNames = new Intl.DisplayNames(["en"], { type: "region" });
function countryLabel(code: string): string {
  if (!/^[A-Z]{2}$/.test(code)) return code || "—";
  const flag = String.fromCodePoint(...[...code].map((c) => 0x1f1a5 + c.charCodeAt(0)));
  let name = code;
  try {
    name = regionNames.of(code) ?? code;
  } catch {
    /* unknown/reserved code — show it raw */
  }
  return `${flag} ${name}`;
}

function GeoSection({ q }: { q: FlowQuery }) {
  // null = first load in flight; "disabled" = dictionary not provisioned.
  const [src, setSrc] = useState<GeoRow[] | null>(null);
  const [dst, setDst] = useState<GeoRow[] | null>(null);
  const [disabled, setDisabled] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    const coerce = (rows: GeoRow[]) =>
      rows.map((r) => ({ ...r, bytes_total: Number(r.bytes_total), packets_total: Number(r.packets_total), flows: Number(r.flows) }));
    const load = async () => {
      try {
        const [s, d] = await Promise.all([
          api.flowsGeo("src", q.since, q.ftype, q.filters),
          api.flowsGeo("dst", q.since, q.ftype, q.filters),
        ]);
        if (!alive) return;
        setDisabled(s?.geo_enabled === false);
        setSrc(coerce((s?.data as GeoRow[]) ?? []));
        setDst(coerce((d?.data as GeoRow[]) ?? []));
        setErr(null);
      } catch (e) {
        if (alive) setErr((e as Error).message);
      }
    };
    load();
    const id = setInterval(load, 30_000);
    return () => { alive = false; clearInterval(id); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [q.since, q.ftype, q.fkey]);

  if (disabled) {
    return (
      <div className="panel">
        <div className="panel-tools"><h3>Geo IP</h3></div>
        <div className="empty board-empty">
          <div className="board-empty-msg">GeoIP enrichment isn't provisioned yet.</div>
          <div className="board-empty-hint">
            Licensing doesn't let the platform bundle GeoIP data, so bring your own (a few minutes, free):
            download <b>GeoLite2 Country (CSV)</b> from MaxMind or <b>DB-IP Country Lite</b>, then run{" "}
            <code>sudo python3 scripts/geoip-prepare.py &lt;download&gt;</code> on the host.
            These panels light up on their next refresh — no restarts.
          </div>
        </div>
      </div>
    );
  }

  // Country ranking excludes the unmatched bucket (country "") — in a private
  // lab it dwarfs every real country — but its share is surfaced honestly.
  const total = (src ?? []).reduce((n, r) => n + r.bytes_total, 0);
  const publicBytes = (src ?? []).filter((r) => r.country !== "").reduce((n, r) => n + r.bytes_total, 0);
  const srcCountries = (src ?? []).filter((r) => r.country !== "");
  const dstCountries = (dst ?? []).filter((r) => r.country !== "");
  const toTopN = (rows: GeoRow[]): TopNRow[] => rows.slice(0, 15).map((r) => ({ k: r.country, bytes_total: r.bytes_total, packets_total: r.packets_total, flows: r.flows }));

  return (
    <>
      <StatStrip>
        <Stat label="Public traffic share" value={total ? `${((100 * publicBytes) / total).toFixed(1)}%` : "—"} tone={total && !publicBytes ? "warn" : ""} />
        <Stat label="Initiator countries" value={src ? fmtNum(srcCountries.length) : "—"} />
        <Stat label="Responder countries" value={dst ? fmtNum(dstCountries.length) : "—"} />
        <Stat label="Top initiator country" value={srcCountries.length ? countryLabel(srcCountries[0].country) : "—"} />
      </StatStrip>
      <div className="flows-grid">
        <TopNView title="Top Initiator Countries" rows={toTopN(srcCountries)} err={err} keyHeader="Country" fmtKey={countryLabel} />
        <TopNView title="Top Responder Countries" rows={toTopN(dstCountries)} err={err} keyHeader="Country" fmtKey={countryLabel} />
      </div>
      {total > 0 && publicBytes === 0 && (
        <p className="mini-meta" style={{ margin: "8px 2px 0" }}>
          All observed traffic is private/unrouted address space (RFC 1918 etc.), which has no geography —
          expected in an internal lab. Countries appear when flows cross public addresses.
        </p>
      )}
    </>
  );
}

// ── Section: TCP Flags — tcpControlBits combos + scan/reset heuristics ────────
type FlagsRow = { tcp_flags: number; bytes_total: number; packets_total: number; flows: number };

// tcpControlBits (RFC 9293): decode the bitmask into the conventional names,
// handshake-first order so "SYN·ACK" reads naturally.
const TCP_FLAG_BITS: [number, string][] = [
  [2, "SYN"], [16, "ACK"], [1, "FIN"], [4, "RST"], [8, "PSH"], [32, "URG"], [64, "ECE"], [128, "CWR"],
];
function flagNames(mask: number): string {
  if (!mask) return "none";
  const parts = TCP_FLAG_BITS.filter(([b]) => mask & b).map(([, n]) => n);
  return parts.length ? parts.join("·") : `0x${mask.toString(16)}`;
}

function FlagsSection({ q }: { q: FlowQuery }) {
  const [rows, setRows] = useState<FlagsRow[]>([]);
  const [view, setView] = useState<"bar" | "table">("bar");
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    const load = async () => {
      try {
        const res = await api.flowsFlags(q.since, 20, q.ftype, q.filters);
        if (!alive) return;
        setRows(((res?.data as FlagsRow[]) ?? []).map((r) => ({
          ...r, tcp_flags: Number(r.tcp_flags), bytes_total: Number(r.bytes_total),
          packets_total: Number(r.packets_total), flows: Number(r.flows),
        })));
        setErr(null);
      } catch (e) {
        if (alive) setErr((e as Error).message);
      }
    };
    load();
    const id = setInterval(load, 30_000);
    return () => { alive = false; clearInterval(id); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [q.since, q.ftype, q.fkey]);

  const total = rows.reduce((n, r) => n + r.flows, 0);
  const flagged = rows.filter((r) => r.tcp_flags > 0).reduce((n, r) => n + r.flows, 0);
  const synOnly = rows.filter((r) => r.tcp_flags === 2).reduce((n, r) => n + r.flows, 0);
  const rst = rows.filter((r) => r.tcp_flags & 4).reduce((n, r) => n + r.flows, 0);
  const pct = (n: number, of: number) => (of > 0 ? (100 * n) / of : 0);
  // Heuristics are computed over flag-bearing flows only — a v5/v9 exporter that
  // doesn't fill tcpControlBits would otherwise drown the signal in "none" rows.
  const synPct = pct(synOnly, flagged);
  const rstPct = pct(rst, flagged);

  const cols = useMemo<Column<FlagsRow>[]>(() => [
    { key: "flags", header: "Flags", width: "36%", sortable: true, text: (r) => flagNames(r.tcp_flags), sortValue: (r) => r.tcp_flags, render: (r) => flagNames(r.tcp_flags) },
    { key: "flows", header: "Flows", align: "right", sortable: true, sortValue: (r) => r.flows, render: (r) => fmtNum(r.flows) },
    { key: "packets", header: "Packets", align: "right", sortable: true, sortValue: (r) => r.packets_total, render: (r) => fmtNum(r.packets_total) },
    { key: "bytes", header: "Bytes", align: "right", sortable: true, sortValue: (r) => r.bytes_total, render: (r) => fmtBytes(r.bytes_total) },
  ], []);

  return (
    <>
      <StatStrip>
        <Stat label="TCP flows" value={fmtNum(total)} />
        <Stat label="With flags reported" value={total ? `${pct(flagged, total).toFixed(0)}%` : "—"} tone={total && !flagged ? "warn" : ""} />
        <Stat label="SYN-only (scan signal)" value={flagged ? `${synPct.toFixed(1)}%` : "—"} tone={synPct > 50 ? "bad" : synPct > 20 ? "warn" : ""} />
        <Stat label="RST-bearing (resets)" value={flagged ? `${rstPct.toFixed(1)}%` : "—"} tone={rstPct > 30 ? "bad" : rstPct > 10 ? "warn" : ""} />
      </StatStrip>
      <div className="panel" style={{ minWidth: 0 }}>
        <div className="panel-tools">
          <h3>TCP flag combinations</h3>
          <div className="seg-mini" role="group" aria-label="View">
            <button className={view === "bar" ? "on" : ""} onClick={() => setView("bar")} title="Bar chart"><Icon name="metrics" size={13} /></button>
            <button className={view === "table" ? "on" : ""} onClick={() => setView("table")} title="Table"><Icon name="logs" size={13} /></button>
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
                ...chartBase.tooltip, trigger: "axis", axisPointer: { type: "shadow" },
                formatter: (ps: any) => {
                  const p = Array.isArray(ps) ? ps[0] : ps;
                  return `${p.name}<br/><b>${fmtNum(p.value)} flows</b>`;
                },
              },
              xAxis: { type: "value", ...axisStyle },
              yAxis: { type: "category", inverse: true, data: rows.map((r) => flagNames(r.tcp_flags)), ...axisStyle, splitLine: { show: false } },
              series: [{ type: "bar", data: rows.map((r) => r.flows), itemStyle: { color: paletteColor(0), borderRadius: [0, 3, 3, 0] }, barMaxWidth: 16 }],
            }}
          />
        ) : (
          <DataTable<FlagsRow>
            rows={rows}
            columns={cols}
            rowKey={(r) => String(r.tcp_flags)}
            height={Math.min(440, 40 + rows.length * 28)}
            ariaLabel="TCP flag combinations"
            initialSort={{ key: "flows", dir: "desc" }}
          />
        )}
        {rows.length > 0 && !flagged && (
          <p className="mini-meta" style={{ margin: "8px 2px 0" }}>
            All TCP flows report empty flags — this exporter isn't filling tcpControlBits.
            Enable TCP-flag export on the device (full IPFIX/NetFlow-v9 templates include it; sFlow carries it natively).
          </p>
        )}
      </div>
    </>
  );
}

// ── Section: Device Health — compact health of the devices behind the flows ────
// Deliberately a SUMMARY (no duplicate panels): full per-device / per-interface
// health lives in Device Monitoring + Interface Performance, which this links to.
function DeviceHealthSummary({ minutes }: { minutes: number }) {
  return (
    <>
      <StatStrip>
        <MetricStat label="Avg CPU (%)" query="avg(device_cpu_percent)" minutes={minutes} fmt={(n) => `${n.toFixed(0)}%`} tone={(n) => (n >= 85 ? "bad" : n >= 70 ? "warn" : "good")} />
        <MetricStat label="Avg memory (%)" query="avg(device_mem_percent)" minutes={minutes} fmt={(n) => `${n.toFixed(0)}%`} tone={(n) => (n >= 85 ? "bad" : n >= 70 ? "warn" : "good")} />
        <MetricStat label="Interfaces up" query="count(device_if_oper_status == 1) or vector(0)" minutes={minutes} fmt={(n) => `${n.toFixed(0)}`} tone={() => "good"} />
        <MetricStat label="Ifaces with errors (5m)" query="count((rate(device_if_in_errors[5m]) + rate(device_if_out_errors[5m])) > 0) or vector(0)" minutes={minutes} fmt={(n) => `${n.toFixed(0)}`} tone={(n) => (n > 0 ? "bad" : "good")} />
      </StatStrip>
      <div className="panel">
        <div className="panel-tools"><h3>Device health</h3></div>
        <p className="mini-meta" style={{ margin: 0 }}>
          Health of the devices behind these flows, at a glance. Full per-device CPU/memory/interface health lives in{" "}
          <a href="#/infrastructure/monitoring" style={{ color: "var(--accent)", fontWeight: 600 }}>Device Monitoring</a> and{" "}
          <a href="#/infrastructure/ifperf" style={{ color: "var(--accent)", fontWeight: 600 }}>Interface Performance</a>.
        </p>
      </div>
    </>
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
              <TopNPanel title="Top Ingress Interfaces" by="in_if" q={q} keyHeader="Ingress interface" />
              <TopNPanel title="Top Egress Interfaces" by="out_if" q={q} keyHeader="Egress interface" />
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
        {section === "geo" && <GeoSection q={q} />}
        {section === "flags" && <FlagsSection q={q} />}
        {section === "health" && <DeviceHealthSummary minutes={Math.max(1, Math.round(since / 60))} />}
      </div>
    </div>
  );
}
