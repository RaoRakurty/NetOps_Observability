import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { api, WanCircuit, WanEndpoint, WanInterfaceRow, WanMeasurementPolicy } from "../services/api";
import DataTable, { Column, Sev } from "../components/DataTable";
import { latSev, lossSev } from "../tabs/Tunnels";
import { Section, useCap, ShowAll } from "./bgp/Section";
import { operatorError } from "../lib/errors";
import {
  MAX_NEXT_HOPS,
  blankNextHopRow,
  endpointKind,
  formFromPolicy,
  isDirty,
  matchesCircuit,
  matchesEndpoint,
  noTargetCount,
  policyPatch,
  provenanceCounts,
  sortCircuits,
  sortEndpoints,
  targetKindChip,
  targetKindLabel,
  targetKindMeaning,
  validateForm,
  type NextHopRow,
  type PolicyForm,
} from "./wanCircuits.model";

// WAN Interface Metrics — one row per WAN (or WAN-connected) interface.
//
// No hub/spoke. The whole row is resolved server-side (GET /api/wan/interfaces):
// live utilization/oper status (device_if_*), the interface's DERIVED measurement
// TARGET (directly-connected peer via LLDP in the lab; ISP next-hop or a public-DNS
// reachability anchor in prod), and the SLA — latency/jitter/loss/QoE/availability —
// resolved through the 5-tier measurement-source ranking with a per-row tier +
// method badge. SLA cells show an honest "—" where no target or no probe has
// measured it — never a fabricated number.
//
// BELOW THE METRICS TABLE the page now shows the rest of the same projection,
// which had no surface at all before:
//
//   * PATHS      (GET /api/wan/circuits)  — the 1:1 interface→target links.
//   * ENDPOINTS  (GET /api/wan/endpoints) — the derived registry each link is
//                                           assembled from.
//   * POLICY     (GET/PUT /api/wan/policy) — the ONLY persisted thing here. The
//     projection above is derived on read, so saving the policy changes what the
//     other two sections return on their next read — which is exactly what the
//     save does: it re-reads them.
//
// Each section owns its own read and its own failure (the Panel plumbing below,
// the same shape pages/DataProtection.tsx uses): a dead policy read must not
// blank the paths, because during an incident the paths are the evidence.

const jitSev = (ms: number): Sev => (ms < 30 ? "ok" : ms < 60 ? "warn" : "crit");
const qoeSev = (q: number): Sev => (q >= 8 ? "ok" : q >= 5 ? "warn" : "crit");
const utilSev = (pct: number): Sev => (pct < 70 ? "ok" : pct < 90 ? "warn" : "crit");

function fmtBps(v: number): string {
  if (!isFinite(v) || v <= 0) return "0";
  const u = ["bps", "Kbps", "Mbps", "Gbps", "Tbps"];
  let i = 0;
  while (v >= 1000 && i < u.length - 1) { v /= 1000; i++; }
  return `${v.toFixed(v < 10 && i > 0 ? 1 : 0)} ${u[i]}`;
}

const dash = <span className="mini-meta">—</span>;

// Sparkline — a tiny inline SVG throughput graph that redraws each poll (the
// backend returns a fresh rolling window), so the line advances live. A pulsing
// dot marks the current value. Auto-scaled; area + line for a dense NOC look.
function Sparkline({ data, sev }: { data?: number[]; sev?: Sev }) {
  if (!data || data.length < 2) return <span className="mini-meta">—</span>;
  const w = 96, h = 26, pad = 3;
  const n = data.length;
  const max = Math.max(...data, 1);
  const x = (i: number) => pad + (i / (n - 1)) * (w - 2 * pad);
  const y = (v: number) => h - pad - (v / max) * (h - 2 * pad);
  const line = data.map((v, i) => `${x(i).toFixed(1)},${y(v).toFixed(1)}`).join(" ");
  const area = `${pad.toFixed(1)},${(h - pad).toFixed(1)} ${line} ${(w - pad).toFixed(1)},${(h - pad).toFixed(1)}`;
  const color = sev === "crit" ? "var(--crit, #ef4444)" : sev === "warn" ? "var(--warn, #f59e0b)" : "var(--accent, #3b82f6)";
  const last = data[n - 1];
  const bps = last >= 1e9 ? `${(last / 1e9).toFixed(1)} Gbps` : last >= 1e6 ? `${(last / 1e6).toFixed(1)} Mbps` : last >= 1e3 ? `${(last / 1e3).toFixed(0)} Kbps` : `${last.toFixed(0)} bps`;
  return (
    <svg className="wan-spark" width={w} height={h} viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none">
      <title>{`live throughput · now ${bps} · peak ${(max >= 1e6 ? (max / 1e6).toFixed(1) + " Mbps" : (max / 1e3).toFixed(0) + " Kbps")}`}</title>
      <polygon points={area} fill={color} opacity={0.13} />
      <polyline points={line} fill="none" stroke={color} strokeWidth={1.5} vectorEffect="non-scaling-stroke" />
      <circle className="wan-spark-dot" cx={x(n - 1)} cy={y(last)} r={2.3} fill={color} />
    </svg>
  );
}

// ── panel plumbing (the DataProtection convention) ──────────────────────────

type Panel<T> = { data: T | null; error: string | null; loading: boolean; at: number };

/**
 * One independent read. Each section owns its failure as an operator sentence,
 * so one dead route never blanks a neighbouring section's evidence.
 */
function usePanel<T>(read: () => Promise<T>, fallback: string): [Panel<T>, () => void] {
  const [state, setState] = useState<Panel<T>>({ data: null, error: null, loading: true, at: 0 });
  const readRef = useRef(read);
  readRef.current = read;
  const reload = useCallback(() => {
    setState((p) => ({ ...p, loading: true }));
    readRef.current()
      .then((data) => setState({ data, error: null, loading: false, at: Date.now() }))
      .catch((e: unknown) => setState({ data: null, error: operatorError(e, fallback), loading: false, at: Date.now() }));
  }, [fallback]);
  useEffect(() => { reload(); }, [reload]);
  return [state, reload];
}

function PanelState({ panel, what, onRetry, children }: {
  panel: Panel<unknown>; what: string; onRetry: () => void; children: ReactNode;
}) {
  if (panel.error) {
    return (
      <div className="empty" role="alert">
        <span className="dp-bad-text">{panel.error}</span>{" "}
        <button type="button" className="bgp-more" onClick={onRetry}>Read it again</button>
      </div>
    );
  }
  if (panel.loading && panel.data == null) return <div className="empty">Reading {what}…</div>;
  return <>{children}</>;
}

/** The provenance chip, in the operator's words, with what it means on hover. */
function KindChip({ kind }: { kind: string | undefined }) {
  const k = kind ?? "";
  return (
    <span className={`badge${k === "" ? "" : k === "direct_peer" ? " good" : ""}`}
      style={{ textTransform: "none" }} title={`${targetKindLabel(k)} — ${targetKindMeaning(k)}`}>
      {targetKindChip(k)}
    </span>
  );
}

const mono = { fontFamily: "var(--font-mono, monospace)" } as const;

// ── 2 · derived WAN paths (GET /api/wan/circuits) ───────────────────────────

const PATH_CAP = 25;

function PathsSection({ panel, onRetry, q }: {
  panel: Panel<{ circuits: WanCircuit[] }>; onRetry: () => void; q: string;
}) {
  const rows = useMemo(() => {
    const all = sortCircuits(panel.data?.circuits ?? []);
    return q.trim() ? all.filter((c) => matchesCircuit(c, q)) : all;
  }, [panel.data, q]);
  const cap = useCap(rows, PATH_CAP);

  return (
    <Section
      id="wan-measured-paths" title="Measured paths" updatedAt={panel.at || null}
      note={<>one interface → its own derived target, 1:1</>}
      actions={<span className="mini-meta">{rows.length} path{rows.length === 1 ? "" : "s"}</span>}
    >
      <PanelState panel={panel} what="the measured paths" onRetry={onRetry}>
        {rows.length === 0 ? (
          <div className="empty">
            {q.trim()
              ? "No measured path matches this filter."
              : "Nothing has been derived yet. A path appears once an interface has an IP address and one end to measure to — a neighbour it sees on the wire, an ISP next-hop declared in the measurement policy below, or a reachability anchor."}
          </div>
        ) : (
          <>
            <table className="dp-tbl">
              <thead>
                <tr>
                  <th>Local device</th><th>Local interface</th><th>Local address</th>
                  <th>Far end</th><th>Far interface</th><th>Measured to</th>
                  <th>Derived from</th><th>Measuring</th>
                </tr>
              </thead>
              <tbody>
                {cap.rows.map((c) => (
                  <tr key={c.id}>
                    <th scope="row">{c.local.device}</th>
                    <td style={mono}>{c.local.interface}</td>
                    <td style={mono}>{c.local.address || dash}</td>
                    <td>{c.remote.device || dash}</td>
                    <td style={mono}>{c.remote.interface || dash}</td>
                    <td style={mono}>{c.remote.measurable_addr || c.remote.address || c.local.target || dash}</td>
                    <td><KindChip kind={c.kind} /></td>
                    <td>
                      {c.enabled
                        ? <span className="badge good">on</span>
                        : <span className="badge" title="This path is in the registry but is not being measured.">held</span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            <ShowAll cap={cap} noun="paths" />
          </>
        )}
      </PanelState>
    </Section>
  );
}

// ── 3 · derived endpoint registry (GET /api/wan/endpoints) ──────────────────

const ENDPOINT_CAP = 25;

function EndpointsSection({ panel, onRetry, q }: {
  panel: Panel<{ endpoints: WanEndpoint[] }>; onRetry: () => void; q: string;
}) {
  const all = useMemo(() => sortEndpoints(panel.data?.endpoints ?? []), [panel.data]);
  const rows = useMemo(() => (q.trim() ? all.filter((e) => matchesEndpoint(e, q)) : all), [all, q]);
  const cap = useCap(rows, ENDPOINT_CAP);
  const counts = useMemo(() => provenanceCounts(all), [all]);
  const undecided = noTargetCount(all);

  return (
    <Section
      id="wan-endpoints" title="Endpoint registry" updatedAt={panel.at || null}
      note={<>derived from interface addresses × neighbours × the policy</>}
      actions={<span className="mini-meta">{rows.length} of {all.length} interfaces</span>}
    >
      <PanelState panel={panel} what="the endpoint registry" onRetry={onRetry}>
        {all.length === 0 ? (
          <div className="empty">
            The registry is empty. It fills with every interface on a device the
            measurement policy matches by name, plus every interface directly
            connected to one, as soon as those interfaces report an IP address.
          </div>
        ) : (
          <>
            <div className="dp-badges" style={{ marginBottom: 8 }}>
              {counts.map((c) => (
                <span key={c.kind || "none"} className="badge" style={{ textTransform: "none" }}
                  title={targetKindMeaning(c.kind)}>
                  {c.label}: {c.count}
                </span>
              ))}
            </div>
            {undecided > 0 && (
              <p className="dp-sub" style={{ marginTop: 0 }}>
                {undecided} interface{undecided === 1 ? " has" : "s have"} no target to
                measure to yet. Declare an ISP next-hop below, or leave them to the
                reachability anchor once they carry an address.
              </p>
            )}
            {rows.length === 0 ? (
              <div className="empty">No endpoint matches this filter.</div>
            ) : (
              <>
                <table className="dp-tbl">
                  <thead>
                    <tr>
                      <th>Device</th><th>Interface</th><th>Address</th>
                      <th>Address the far end targets</th><th>Site</th>
                      <th>Measured to</th><th>Derived from</th>
                    </tr>
                  </thead>
                  <tbody>
                    {cap.rows.map((e) => (
                      <tr key={`${e.device}#${e.interface}`}>
                        <th scope="row">{e.device}</th>
                        <td style={mono}>
                          <span style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
                            {e.interface}
                            {e.connected_to_wan && (
                              <span className="badge" title="Not on a WAN device itself — directly connected to one, so it is measured too.">linked</span>
                            )}
                          </span>
                        </td>
                        <td style={mono}>{e.address || dash}</td>
                        <td style={mono}>{e.measurable_addr || dash}</td>
                        <td>{e.site || dash}</td>
                        <td style={mono} title={e.target_label ?? ""}>{e.target || dash}</td>
                        <td><KindChip kind={endpointKind(e)} /></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                <ShowAll cap={cap} noun="endpoints" />
              </>
            )}
          </>
        )}
      </PanelState>
    </Section>
  );
}

// ── 4 · the measurement policy (GET / PUT /api/wan/policy) ──────────────────

function PolicySection({ panel, onRetry, canEdit, onSaved }: {
  panel: Panel<WanMeasurementPolicy>;
  onRetry: () => void;
  canEdit: boolean | null;
  onSaved: () => void;
}) {
  const stored = panel.data;
  const [form, setForm] = useState<PolicyForm | null>(null);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ tone: "good" | "bad"; text: string } | null>(null);

  // The form is seeded from the read ONCE per read. A failed save must leave the
  // operator's text exactly where they left it, so nothing re-seeds on error.
  const seededAt = useRef(0);
  useEffect(() => {
    if (stored && panel.at !== seededAt.current) {
      seededAt.current = panel.at;
      setForm(formFromPolicy(stored));
    }
  }, [stored, panel.at]);

  const problems = form ? validateForm(form) : [];
  const dirty = form ? isDirty(form, stored) : false;
  const editable = canEdit !== false;

  const patch = (over: Partial<PolicyForm>) => setForm((f) => (f ? { ...f, ...over } : f));
  const setRow = (id: string, over: Partial<NextHopRow>) =>
    patch({ nextHops: (form?.nextHops ?? []).map((r) => (r.id === id ? { ...r, ...over } : r)) });

  const save = async () => {
    if (!form) return;
    setBusy(true);
    setMsg(null);
    try {
      await api.setWanPolicy(policyPatch(form));
      setMsg({ tone: "good", text: "Measurement policy saved. The paths and endpoints above were derived again from it." });
      onSaved();
    } catch (e: unknown) {
      setMsg({ tone: "bad", text: operatorError(e, "The measurement policy was not accepted.") });
    } finally {
      setBusy(false);
    }
  };

  return (
    <Section
      id="wan-policy" title="Measurement policy" updatedAt={panel.at || null}
      note={<>the only thing stored here — everything above is derived from it</>}
    >
      <PanelState panel={panel} what="the measurement policy" onRetry={onRetry}>
        {form && (
          <div className="dp-form">
            <p className="dp-sub" style={{ marginTop: 0 }}>
              This policy decides which devices count as WAN devices and what each
              of their interfaces measures to. Saving it re-derives the endpoint
              registry and the measured paths above.
            </p>

            <label className="dp-field">
              <span>WAN device name pattern</span>
              <input
                className="dp-input mono" style={mono}
                aria-label="WAN device name pattern"
                value={form.pattern} disabled={busy || !editable}
                onChange={(ev) => patch({ pattern: ev.target.value })}
              />
              <span className="dp-sub">
                A device whose name matches is a WAN device. Matching ignores case.
              </span>
            </label>

            <label className="dp-check">
              <input
                type="checkbox" checked={form.includeConnected} disabled={busy || !editable}
                onChange={(ev) => patch({ includeConnected: ev.target.checked })}
              />
              Also measure interfaces directly connected to a WAN device
            </label>

            <label className="dp-field">
              <span>Reachability anchors</span>
              <input
                className="dp-input mono" style={mono}
                aria-label="Reachability anchors"
                value={form.anchorsText} disabled={busy || !editable}
                onChange={(ev) => patch({ anchorsText: ev.target.value })}
              />
              <span className="dp-sub">
                Where an interface measures to when it has neither a neighbour on
                the wire nor a declared ISP next-hop. Separate them with commas.
              </span>
            </label>

            <fieldset className="dp-fieldset" disabled={busy || !editable}>
              <legend>ISP next-hop overrides</legend>
              <p className="dp-sub" style={{ marginTop: 0 }}>
                A next-hop is where your ownership of the path hands off to the ISP.
                Declare one per device, or per single interface with{" "}
                <code style={mono}>device/interface</code>, and that interface measures
                to it instead of to an anchor. Up to {MAX_NEXT_HOPS} of them.
              </p>
              <table className="dp-tbl">
                <thead>
                  <tr>
                    <th>Device, or device/interface</th>
                    <th>ISP next-hop to measure to</th>
                    <th aria-label="Row actions" />
                  </tr>
                </thead>
                <tbody>
                  {form.nextHops.length === 0 ? (
                    <tr className="dp-row-na">
                      <td colSpan={3}>
                        No ISP next-hop has been declared, so every interface without a
                        neighbour on the wire measures to an anchor.
                      </td>
                    </tr>
                  ) : form.nextHops.map((r, i) => (
                    <tr key={r.id}>
                      <td>
                        <input
                          className="dp-input mono" style={mono}
                          aria-label={`Device or device and interface, override ${i + 1}`}
                          value={r.key} onChange={(ev) => setRow(r.id, { key: ev.target.value })}
                        />
                      </td>
                      <td>
                        <input
                          className="dp-input mono" style={mono}
                          aria-label={`ISP next-hop address, override ${i + 1}`}
                          value={r.target} onChange={(ev) => setRow(r.id, { target: ev.target.value })}
                        />
                      </td>
                      <td>
                        <button
                          type="button" className="btn"
                          aria-label={`Remove override ${i + 1}`}
                          onClick={() => patch({ nextHops: form.nextHops.filter((x) => x.id !== r.id) })}
                        >
                          Remove
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <div className="dp-actions" style={{ justifyContent: "flex-start" }}>
                <button
                  type="button" className="btn"
                  onClick={() => patch({ nextHops: [...form.nextHops, blankNextHopRow()] })}
                >
                  Add an override
                </button>
              </div>
            </fieldset>

            {problems.length > 0 && (
              <ul className="dp-sub" role="alert" style={{ margin: 0, paddingLeft: 18 }}>
                {problems.map((p) => <li key={p} className="dp-bad-text">{p}</li>)}
              </ul>
            )}

            {msg && <p className={`dp-msg dp-${msg.tone}`} role="status">{msg.text}</p>}

            <p className="dp-sub" style={{ margin: 0 }}>
              {stored?.updated_by
                ? `Last changed by ${stored.updated_by}${stored.updated_at ? ` on ${new Date(stored.updated_at).toLocaleString()}` : ""}.`
                : "Nobody has changed this policy — these are the measurement defaults."}
            </p>

            {editable ? (
              <div className="dp-actions">
                <button
                  type="button" className="btn"
                  disabled={busy || !dirty}
                  onClick={() => setForm(formFromPolicy(stored))}
                >
                  Undo my changes
                </button>
                <button
                  type="button" className="btn accent"
                  disabled={busy || !dirty || problems.length > 0}
                  onClick={save}
                >
                  {busy ? "Saving…" : "Save policy"}
                </button>
              </div>
            ) : (
              <p className="dp-sub">
                You can read the measurement policy but not change it. Changing what
                the WAN measures needs write access to infrastructure — an
                administrator for this tenant can grant it.
              </p>
            )}
          </div>
        )}
      </PanelState>
    </Section>
  );
}

// ── the page ────────────────────────────────────────────────────────────────

export default function WanCircuits() {
  const [rows, setRows] = useState<WanInterfaceRow[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [q, setQ] = useState("");

  useEffect(() => {
    let alive = true;
    const tick = async () => {
      try {
        const res = await api.wanInterfaces();
        if (alive) { setRows(res?.interfaces ?? []); setErr(null); setLoaded(true); }
      } catch (e) {
        if (alive) { setErr((e as Error).message); setLoaded(true); }
      }
    };
    tick();
    const id = setInterval(tick, 5000); // 5s → the in-row live sparkline advances smoothly
    return () => { alive = false; clearInterval(id); };
  }, []);

  // The three derived surfaces, each its own read and its own failure.
  const [endpoints, reloadEndpoints] = usePanel(
    () => api.wanEndpoints(), "The endpoint registry could not be read.");
  const [circuits, reloadCircuits] = usePanel(
    () => api.wanCircuits(), "The measured paths could not be read.");
  const [policy, reloadPolicy] = usePanel(
    () => api.wanPolicy(), "The measurement policy could not be read.");

  // Write access to infrastructure is what the PUT needs. Without it the editor
  // explains itself rather than offering a button that 403s.
  const [canEdit, setCanEdit] = useState<boolean | null>(null);
  useEffect(() => {
    let live = true;
    api.permissions()
      .then((p) => { if (live) setCanEdit((p.permissions?.infrastructure ?? 0) >= 2); })
      .catch(() => { if (live) setCanEdit(false); });
    return () => { live = false; };
  }, []);

  // A saved policy is a NEW projection, so both derived reads run again.
  const afterPolicySave = useCallback(() => {
    reloadPolicy();
    reloadEndpoints();
    reloadCircuits();
  }, [reloadPolicy, reloadEndpoints, reloadCircuits]);

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    if (!needle) return rows;
    return rows.filter((r) =>
      `${r.device} ${r.interface} ${r.remote_device ?? ""} ${r.target ?? ""} ${r.target_label ?? ""} ${r.source_label ?? ""}`.toLowerCase().includes(needle));
  }, [rows, q]);

  const rowKey = (r: WanInterfaceRow) => `${r.device}#${r.interface}`;

  // How the measurement target was derived (provenance chip).
  const targetKindLabelShort: Record<string, string> = {
    direct_peer: "Peer", next_hop: "Next-hop", anchor: "Anchor",
  };
  const connectedChip = (r: WanInterfaceRow) =>
    r.connected_to_wan
      ? <span className="badge" title="This interface is directly connected to a WAN device (measured too).">linked</span>
      : null;

  const utilCell = (r: WanInterfaceRow) => {
    if (!r.has_util) return dash;
    return (
      <span style={{ display: "inline-flex", alignItems: "center", gap: 8, justifyContent: "flex-end", width: "100%" }}>
        <span style={{ position: "relative", width: 52, height: 6, borderRadius: 3, background: "var(--panel-border)", overflow: "hidden" }}>
          <span style={{ position: "absolute", inset: 0, width: `${Math.min(100, r.util_pct)}%`, borderRadius: 3,
            background: r.util_pct < 70 ? "var(--ok, #22c55e)" : r.util_pct < 90 ? "var(--warn, #f59e0b)" : "var(--crit, #ef4444)" }} />
        </span>
        <span style={{ fontVariantNumeric: "tabular-nums", minWidth: 40, textAlign: "right" }}>{r.util_pct.toFixed(1)}%</span>
      </span>
    );
  };

  // SLA cell: honest dash when the field has no measurement.
  const sla = (has: (r: WanInterfaceRow) => boolean, val: (r: WanInterfaceRow) => number,
    fmt: (n: number) => string, sev: (n: number) => Sev) => ({
    sev: (r: WanInterfaceRow) => (has(r) ? sev(val(r)) : undefined),
    sortValue: (r: WanInterfaceRow) => (has(r) ? val(r) : -1),
    render: (r: WanInterfaceRow) => (has(r) ? fmt(val(r)) : dash),
  });

  const columns = useMemo<Column<WanInterfaceRow>[]>(() => [
    { key: "device", header: "Router", width: "13%", sortable: true,
      text: (r) => r.device, sortValue: (r) => r.device, render: (r) => <span title={r.device}>{r.device}</span> },
    { key: "iface", header: "Interface", width: "13%", sortable: true,
      text: (r) => r.interface, sortValue: (r) => r.interface,
      render: (r) => <span style={{ display: "inline-flex", alignItems: "center", gap: 7 }}>
        <span style={{ fontFamily: "var(--font-mono, monospace)" }}>{r.interface}</span>{connectedChip(r)}</span> },
    { key: "util", header: "Utilization", width: 122, align: "right", sortable: true,
      sortValue: (r) => (r.has_util ? r.util_pct : -1), sev: (r) => (r.has_util ? utilSev(r.util_pct) : undefined), render: utilCell },
    { key: "in", header: "↓ In", width: 84, align: "right", sortable: true,
      sortValue: (r) => r.in_bps, render: (r) => (r.has_util ? fmtBps(r.in_bps) : dash) },
    { key: "out", header: "↑ Out", width: 84, align: "right", sortable: true,
      sortValue: (r) => r.out_bps, render: (r) => (r.has_util ? fmtBps(r.out_bps) : dash) },
    { key: "live", header: "Live", width: 108, sortable: false,
      render: (r) => <Sparkline data={r.spark} sev={r.has_util ? utilSev(r.util_pct) : undefined} /> },
    { key: "target", header: "Measured to", width: "18%", sortable: true,
      text: (r) => `${r.remote_device ?? ""} ${r.target ?? ""}`, sortValue: (r) => r.target_kind ?? "",
      render: (r) => r.has_target
        ? <span style={{ display: "inline-flex", alignItems: "center", gap: 6 }}
            title={r.target_label ?? `${r.remote_device ?? ""} ${r.target ?? ""}`}>
            {r.target_kind ? <span className="badge" style={{ textTransform: "none" }}>{targetKindLabelShort[r.target_kind] ?? r.target_kind}</span> : null}
            <span>{r.remote_device || "—"}</span>
            {r.remote_if ? <span className="mini-meta" style={{ fontFamily: "var(--font-mono, monospace)" }}>{r.remote_if}</span> : null}
            <span className="mini-meta" style={{ fontFamily: "var(--font-mono, monospace)" }}>{r.target}</span>
          </span>
        : dash },
    { key: "latency", header: "Latency", width: 90, align: "right", sortable: true,
      ...sla((r) => r.has_latency, (r) => r.latency_ms, (n) => `${n.toFixed(1)} ms`, latSev) },
    { key: "jitter", header: "Jitter", width: 84, align: "right", sortable: true,
      ...sla((r) => r.has_jitter, (r) => r.jitter_ms, (n) => `${n.toFixed(1)} ms`, jitSev) },
    { key: "loss", header: "Loss", width: 78, align: "right", sortable: true,
      ...sla((r) => r.has_loss, (r) => r.loss_pct, (n) => `${n.toFixed(2)} %`, lossSev) },
    { key: "qoe", header: "QoE", width: 64, align: "right", sortable: true,
      ...sla((r) => r.has_qoe, (r) => r.qoe, (n) => n.toFixed(1), qoeSev) },
    { key: "avail", header: "Avail.", width: 78, align: "right", sortable: true,
      ...sla((r) => r.has_availability, (r) => r.availability_pct,
        (n) => `${n.toFixed(2)} %`, (n) => (n < 95 ? "crit" : n < 99 ? "warn" : undefined) as Sev) },
    { key: "source", header: "Measured by", width: 132, sortable: true,
      text: (r) => r.source_label ?? "", sortValue: (r) => (r.tier ?? 9) * 100 + (r.source_label?.length ?? 0),
      render: (r) => (r.source_label
        ? <span style={{ display: "inline-flex", alignItems: "center", gap: 5 }}>
            {r.tier ? <span className={`badge tier-t${r.tier}`} title={`Tier ${r.tier} — ${r.tier_label} (closer to Tier 1 = closer to user experience)`}>T{r.tier}</span> : null}
            <span className="badge" title={`method: ${r.source_label}${r.tier_label ? " · " + r.tier_label : ""}`}>{r.source_label}</span>
          </span>
        : dash) },
    { key: "status", header: "Status", width: 80, sortable: true,
      text: (r) => (r.has_oper ? (r.oper_up ? "up" : "down") : ""), sortValue: (r) => (r.has_oper ? (r.oper_up ? 1 : 0) : -1),
      render: (r) => (r.has_oper ? <span className={`badge ${r.oper_up ? "good" : "bad"}`}>{r.oper_up ? "up" : "down"}</span> : dash) },
  ], []);

  const down = rows.filter((r) => r.has_oper && !r.oper_up).length;
  const totIn = rows.reduce((a, r) => a + (r.has_util ? r.in_bps : 0), 0);
  const totOut = rows.reduce((a, r) => a + (r.has_util ? r.out_bps : 0), 0);
  const peak = rows.filter((r) => r.has_util).reduce((m, r) => Math.max(m, r.util_pct), 0);
  const measured = rows.filter((r) => r.has_latency || r.has_loss).length;

  return (
    <div className="card">
      <h2>WAN Interface Metrics</h2>
      <p className="mini-meta" style={{ marginTop: -6, marginBottom: 14 }}>
        One row per WAN interface — plus any interface directly connected to a WAN
        device (marked <span className="badge" style={{ verticalAlign: "middle" }}>linked</span>),
        so a lab WAN router <i>and</i> the Spine link to it are both measured. Each
        interface measures to a <b>derived target</b> (<b>Measured to</b>): a
        directly-connected peer (LLDP), an ISP next-hop, or a public-DNS reachability
        anchor. Utilization and status are live; latency / jitter / loss / QoE /
        availability resolve through the <b>5-tier measurement-source ranking</b> —
        closest to the user experience wins: <b>T1</b> application → <b>T2</b> active
        path probe → <b>T3</b> device-native (STAMP) → <b>T4</b> passive → <b>T5</b>
        flow. The <b>Measured by</b> column shows the winning tier + method per row.
      </p>
      {err && <p style={{ color: "var(--bad)" }}>{err}</p>}

      <div className="stat-grid" style={{ marginBottom: 18 }}>
        <div className={`stat ${rows.length ? "s-good" : "s-muted"}`}>
          <span className="stat-label">WAN interfaces</span>
          <span className="stat-value">{rows.length}</span>
          <span className="stat-sub">{measured} with measured SLA</span>
        </div>
        <div className="stat s-muted">
          <span className="stat-label">Throughput</span>
          <span className="stat-value" style={{ fontSize: 26 }}>{fmtBps(totIn + totOut)}</span>
          <span className="stat-sub">↓ {fmtBps(totIn)} · ↑ {fmtBps(totOut)}</span>
        </div>
        <div className={`stat ${rows.length ? (peak < 70 ? "s-good" : peak < 90 ? "s-warn" : "s-bad") : "s-muted"}`}>
          <span className="stat-label">Peak utilization</span>
          <span className="stat-value">{rows.length ? peak.toFixed(1) : "—"}{rows.length ? <span style={{ fontSize: 20, color: "var(--muted)" }}> %</span> : null}</span>
          <span className="stat-sub">busiest interface</span>
        </div>
        <div className={`stat ${down ? "s-bad" : "s-muted"}`}>
          <span className="stat-label">Interfaces down</span>
          <span className="stat-value">{down}</span>
          <span className="stat-sub">{rows.length ? (down ? `${down} down` : "all up") : "none reported"}</span>
        </div>
      </div>

      <div className="dt-toolbar">
        <label className="dt-search">
          <span className="omni-icon">⌕</span>
          <input placeholder="Search devices, interfaces, targets…" value={q} onChange={(e) => setQ(e.target.value)} />
        </label>
        <span className="dt-count">{filtered.length} of {rows.length} interfaces</span>
      </div>

      {loaded && rows.length === 0 ? (
        <div className="empty">
          No WAN interfaces yet. WAN devices are matched by the measurement policy
          (default name pattern <code>wan|edge|gw|dmz</code>); their interfaces —
          plus any interface directly connected to them — appear once they export
          <code>device_if_*</code> metrics. SLA columns populate once a probe
          measures each interface's derived target.
        </div>
      ) : (
        <DataTable<WanInterfaceRow>
          rows={filtered}
          columns={columns}
          rowKey={rowKey}
          height="60vh"
          ariaLabel="WAN circuits"
          initialSort={{ key: "util", dir: "desc" }}
          empty="No WAN interfaces match this filter."
        />
      )}

      <PathsSection panel={circuits} onRetry={reloadCircuits} q={q} />
      <EndpointsSection panel={endpoints} onRetry={reloadEndpoints} q={q} />
      <PolicySection panel={policy} onRetry={reloadPolicy} canEdit={canEdit} onSaved={afterPolicySave} />
    </div>
  );
}
