import { useEffect, useState } from "react";
import { api, Rule, PromInstantSeries } from "../services/api";
import { useShell } from "../context/shell";
import Wizard from "../components/Wizard";
import Icon from "../components/Icon";

// New Monitor — guided monitor creation over the alert rules engine
// (build-order #9). Three steps: pick a signal template (every template is
// backed by a metric the collectors actually emit), tune the condition
// (scope / threshold / hold-for / severity), then review with a LIVE preview —
// the final PromQL is instant-evaluated so the operator sees exactly which
// series would fire right now before creating anything.

// A template's expr contains two placeholders:
//   {S} — the optional device scope, e.g. `{device=~"leaf.*"}` (or "")
//   {T} — the threshold value (omitted for state-match templates)
type Template = {
  id: string;
  category: string;
  title: string;
  desc: string;
  expr: string;
  unit?: string; // threshold unit shown next to the input
  threshold?: number; // default; absence = no-threshold (state) template
  forSec: number;
  severity: string;
  nameHint: string;
};

const TEMPLATES: Template[] = [
  // Availability
  { id: "unreachable", category: "Availability", title: "Device unreachable", desc: "A monitored device stopped answering its collector.", expr: `collector_target_up{S} == 0`, forSec: 120, severity: "critical", nameHint: "DeviceUnreachable" },
  { id: "ifdown", category: "Availability", title: "Interface down", desc: "An admin-up interface went operationally down.", expr: `device_if_oper_status{S} == 2 and device_if_admin_status{S} == 1`, forSec: 120, severity: "critical", nameHint: "InterfaceDown" },
  { id: "flap", category: "Availability", title: "Interface flapping", desc: "An interface changed oper state repeatedly in 10 minutes.", expr: `changes(device_if_oper_status{S}[10m]) >= {T}`, threshold: 4, unit: "changes/10m", forSec: 0, severity: "warning", nameHint: "InterfaceFlapping" },
  // Resources
  { id: "cpu", category: "Resources", title: "High CPU", desc: "Device CPU utilization above a threshold.", expr: `device_cpu_percent{S} > {T}`, threshold: 85, unit: "%", forSec: 300, severity: "warning", nameHint: "HighCPU" },
  { id: "mem", category: "Resources", title: "High memory", desc: "Device memory utilization above a threshold.", expr: `device_mem_percent{S} > {T}`, threshold: 85, unit: "%", forSec: 300, severity: "warning", nameHint: "HighMemory" },
  // Interfaces
  { id: "iferr", category: "Interfaces", title: "Interface errors", desc: "Input + output error rate above a threshold.", expr: `rate(device_if_in_errors{S}[5m]) + rate(device_if_out_errors{S}[5m]) > {T}`, threshold: 1, unit: "errs/s", forSec: 300, severity: "warning", nameHint: "InterfaceErrors" },
  { id: "ifdisc", category: "Interfaces", title: "Interface discards", desc: "Packet discard rate above a threshold (congestion signal).", expr: `rate(device_if_in_discards{S}[5m]) + rate(device_if_out_discards{S}[5m]) > {T}`, threshold: 1, unit: "pkts/s", forSec: 300, severity: "warning", nameHint: "InterfaceDiscards" },
  { id: "ifutil", category: "Interfaces", title: "Interface utilization", desc: "Inbound bandwidth as a share of line speed.", expr: `rate(device_if_in_octets{S}[5m]) * 8 * 100 / ((device_if_speed{S} > 0) * 1000000) > {T}`, threshold: 90, unit: "%", forSec: 300, severity: "warning", nameHint: "InterfaceUtilization" },
  // Routing
  { id: "bgp", category: "Routing", title: "BGP peer down", desc: "A BGP session left Established (state < 6).", expr: `device_bgp_peer_state{S} < 6`, forSec: 120, severity: "critical", nameHint: "BGPPeerDown" },
  { id: "ospf", category: "Routing", title: "OSPF neighbor down", desc: "An OSPF adjacency left Full (state < 8).", expr: `device_ospf_nbr_state{S} < 8`, forSec: 120, severity: "critical", nameHint: "OSPFNeighborDown" },
  // Path SLA (STAMP active probes)
  { id: "rtt", category: "Path SLA", title: "Path RTT", desc: "Active-probe (STAMP) round-trip time above a threshold.", expr: `probe_rtt_ms{S} > {T}`, threshold: 150, unit: "ms", forSec: 300, severity: "warning", nameHint: "PathRTTHigh" },
  { id: "loss", category: "Path SLA", title: "Path loss", desc: "Active-probe (STAMP) packet loss above a threshold.", expr: `probe_loss_pct{S} > {T}`, threshold: 1, unit: "%", forSec: 300, severity: "critical", nameHint: "PathLossHigh" },
  // Custom
  { id: "custom", category: "Custom", title: "Custom PromQL", desc: "Write any PromQL/MetricsQL condition — full expressive power, no guardrails.", expr: ``, forSec: 300, severity: "warning", nameHint: "" },
];

const CATEGORIES = [...new Set(TEMPLATES.map((t) => t.category))];

// Underlying metric each template watches — used to flag a template whose signal
// the stack isn't currently collecting (so "nothing happens" is explained, not a
// silent dead end). Custom has no fixed base.
const BASE_METRIC: Record<string, string> = {
  unreachable: "collector_target_up", ifdown: "device_if_oper_status", flap: "device_if_oper_status",
  cpu: "device_cpu_percent", mem: "device_mem_percent", iferr: "device_if_in_errors",
  ifdisc: "device_if_in_discards", ifutil: "device_if_in_octets", bgp: "device_bgp_peer_state",
  ospf: "device_ospf_nbr_state", rtt: "probe_rtt_ms", loss: "probe_loss_pct",
};

// buildExpr renders a template's placeholders. The device scope becomes a
// PromQL label matcher; quotes/backslashes are stripped so a pasted value
// can't break out of the selector string.
function buildExpr(t: Template, scope: string, threshold: number): string {
  const dev = scope.trim().replace(/["\\{}]/g, "");
  const sel = dev ? `{device=~"${dev}"}` : "";
  return t.expr.split("{S}").join(sel).split("{T}").join(String(threshold));
}

export default function NewMonitor() {
  const { navigate } = useShell();
  const [tpl, setTpl] = useState<Template | null>(null);
  const [scope, setScope] = useState("");
  const [threshold, setThreshold] = useState(0);
  const [forSec, setForSec] = useState(300);
  const [severity, setSeverity] = useState("warning");
  const [name, setName] = useState("");
  const [customExpr, setCustomExpr] = useState("");
  const [created, setCreated] = useState<Rule | null>(null);
  // Live metric catalog — lets us flag templates whose base signal isn't flowing.
  const [metricNames, setMetricNames] = useState<Set<string>>(new Set());
  useEffect(() => {
    api.metricNames().then((r) => setMetricNames(new Set(r?.data ?? []))).catch(() => {});
  }, []);
  const hasLiveData = (t: Template): boolean => {
    const base = BASE_METRIC[t.id];
    return !base || metricNames.size === 0 || metricNames.has(base);
  };

  const pick = (t: Template) => {
    setTpl(t);
    setThreshold(t.threshold ?? 0);
    setForSec(t.forSec);
    setSeverity(t.severity);
    setName(t.nameHint);
    setCustomExpr("");
  };

  const expr = tpl?.id === "custom" ? customExpr.trim() : tpl ? buildExpr(tpl, scope, threshold) : "";

  if (created) {
    return (
      <div className="card form-card form-card-wide">
        <div className="form-head">
          <span className="form-head-icon"><Icon name="check" size={18} /></span>
          <div>
            <h2>Monitor created</h2>
            <p className="form-sub">
              <code>{created.name}</code> is live — the engine evaluates it every 30 seconds
              {created.for ? <> and fires after the condition holds for {created.for}s</> : null}.
            </p>
          </div>
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          <button className="btn-accent" onClick={() => navigate("monitoring/monitors")}>View monitors →</button>
          <button className="btn-ghost" onClick={() => { setCreated(null); setTpl(null); }}>Create another</button>
        </div>
      </div>
    );
  }

  return (
    <div className="card form-card form-card-wide">
      <div className="form-head">
        <span className="form-head-icon"><Icon name="alerts" size={18} /></span>
        <div>
          <h2>Create Monitor</h2>
          <p className="form-sub">Guided creation of an alerting monitor from supported telemetry signals — every template is backed by telemetry this platform already collects.</p>
        </div>
      </div>

      <Wizard
        finishLabel="Create monitor"
        steps={[
          {
            id: "signal",
            title: "Signal",
            hint: "What should this monitor watch?",
            isValid: () => tpl !== null,
            render: () => (
              <div>
                {CATEGORIES.map((cat) => (
                  <div key={cat} className="tpl-cat">
                    <div className="tpl-cat-label">{cat}</div>
                    <div className="tpl-grid">
                      {TEMPLATES.filter((t) => t.category === cat).map((t) => {
                        const sel = tpl?.id === t.id;
                        const live = hasLiveData(t);
                        return (
                          <button
                            key={t.id}
                            type="button"
                            onClick={() => pick(t)}
                            className={`tpl-card${sel ? " on" : ""}`}
                            aria-pressed={sel}
                          >
                            <div className="tpl-card-title">
                              <span>{t.title}</span>
                              {sel && <span className="tpl-card-check"><Icon name="check" size={13} /></span>}
                            </div>
                            <div className="tpl-card-desc">{t.desc}</div>
                            {!live && (
                              <span className="tpl-card-nodata" title="No matching telemetry is arriving yet — the monitor is valid, but won't fire until this signal is collected.">
                                no live data
                              </span>
                            )}
                          </button>
                        );
                      })}
                    </div>
                  </div>
                ))}
              </div>
            ),
          },
          {
            id: "condition",
            title: "Condition",
            hint: "Scope it, set the threshold, and decide how long it must hold.",
            isValid: () => (tpl?.id === "custom" ? customExpr.trim() !== "" : true),
            render: () => (
              <div className="form-grid">
                {tpl?.id === "custom" ? (
                  <div className="form-field wide">
                    <label className="form-label" htmlFor="nm-expr">PromQL expression<span className="form-req">*</span></label>
                    <input id="nm-expr" className="form-input mono" placeholder='e.g. avg by (device) (device_cpu_percent) > 90' value={customExpr} onChange={(e) => setCustomExpr(e.target.value)} />
                    <span className="form-hint">Evaluated as an instant query; the monitor fires while it returns ≥ 1 series.</span>
                  </div>
                ) : (
                  <>
                    <div className="form-field wide">
                      <label className="form-label" htmlFor="nm-scope">Device scope</label>
                      <input id="nm-scope" className="form-input mono" placeholder='all devices — or a regex like leaf.* or edge-1' value={scope} onChange={(e) => setScope(e.target.value)} />
                      <span className="form-hint">Optional. Matches the device label (regex). Empty = the whole fleet.</span>
                    </div>
                    {tpl?.threshold !== undefined && (
                      <div className="form-field">
                        <label className="form-label" htmlFor="nm-threshold">Threshold</label>
                        <div className="form-suffix-wrap">
                          <input id="nm-threshold" className="form-input" type="number" value={threshold} onChange={(e) => setThreshold(Number(e.target.value) || 0)} />
                          {tpl.unit && <span className="form-suffix">{tpl.unit}</span>}
                        </div>
                      </div>
                    )}
                  </>
                )}
                <div className="form-field">
                  <label className="form-label" htmlFor="nm-for">Must hold for</label>
                  <div className="form-suffix-wrap">
                    <input id="nm-for" className="form-input" type="number" min={0} value={forSec} onChange={(e) => setForSec(Math.max(0, Number(e.target.value) || 0))} />
                    <span className="form-suffix">seconds</span>
                  </div>
                  <span className="form-hint">0 fires on the first matching evaluation (every 30s).</span>
                </div>
                <div className="form-field">
                  <label className="form-label" htmlFor="nm-sev">Severity</label>
                  <select id="nm-sev" className="form-select" value={severity} onChange={(e) => setSeverity(e.target.value)}>
                    <option value="info">info</option>
                    <option value="warning">warning</option>
                    <option value="critical">critical</option>
                  </select>
                </div>
              </div>
            ),
          },
          {
            id: "review",
            title: "Review",
            hint: "Name it and sanity-check the live preview before creating.",
            isValid: () => /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(name) && expr !== "",
            render: () => (
              <div className="form-grid">
                <div className="form-field wide">
                  <label className="form-label" htmlFor="nm-name">Monitor name<span className="form-req">*</span></label>
                  <input id="nm-name" className="form-input" placeholder="e.g. HighCPU-Leafs" value={name} onChange={(e) => setName(e.target.value)} />
                  <span className="form-hint">Letters, digits, dashes, underscores. Must be unique.</span>
                </div>
                <div className="form-field wide">
                  <span className="form-label">Final expression</span>
                  <code style={{ display: "block", padding: "8px 10px", background: "var(--hover)", borderRadius: 6, fontSize: 12.5, overflowX: "auto" }}>{expr}</code>
                </div>
                <div className="form-field wide">
                  <LivePreview expr={expr} />
                </div>
                <p className="mini-meta wide" style={{ margin: 0 }}>
                  Firing alerts appear under <b>Monitoring → Triggered</b> and route through your configured
                  notification channels and incident pipeline (see Incident Response → Notifications).
                </p>
              </div>
            ),
          },
        ]}
        onFinish={async () => {
          const rule: Rule = { name: name.trim(), expr, for: forSec, severity };
          await api.addRule(rule);
          setCreated(rule);
        }}
      />
    </div>
  );
}

// LivePreview instant-evaluates the condition and reports which series would
// fire RIGHT NOW — the difference between "looks right" and "is right".
function LivePreview({ expr }: { expr: string }) {
  const [series, setSeries] = useState<PromInstantSeries[] | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    if (!expr) return;
    let alive = true;
    setSeries(null);
    setErr(null);
    api
      .metricsQuery(expr)
      .then((res) => {
        if (!alive) return;
        if (res.status !== "success") setErr(res.error || "query failed");
        else setSeries(res.data?.result ?? []);
      })
      .catch((e) => alive && setErr((e as Error).message));
    return () => { alive = false; };
  }, [expr]);

  const label = (m: Record<string, string>) =>
    Object.entries(m).filter(([k]) => k !== "__name__").map(([k, v]) => `${k}=${v}`).join(" ") || m.__name__ || "series";

  if (err) return <div className="empty" style={{ color: "var(--bad)" }}>Expression error: {err}</div>;
  if (series === null) return <div className="mini-meta">Checking what this would fire on right now…</div>;
  return (
    <div>
      <span className={`badge ${series.length ? "warn" : "good"}`}>
        {series.length ? `would fire on ${series.length} series right now` : "quiet right now — fires when the condition starts holding"}
      </span>
      {series.length > 0 && (
        <ul className="dm-list" style={{ marginTop: 8 }}>
          {series.slice(0, 8).map((s, i) => (
            <li key={i}><span style={{ fontFamily: "var(--font-mono, monospace)", fontSize: 12 }}>{label(s.metric)}</span><strong>{Number(s.value[1]).toFixed(2)}</strong></li>
          ))}
          {series.length > 8 && <li className="mini-meta">…and {series.length - 8} more</li>}
        </ul>
      )}
    </div>
  );
}
