// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { useCallback, useEffect, useMemo, useState } from "react";
import { api, WanEndpoint, WanInterfaceRow } from "../services/api";
import DataTable, { Column, Sev } from "../components/DataTable";
import { latSev, lossSev } from "../tabs/Tunnels";
import { Section, useCap, ShowAll } from "./bgp/Section";
import { operatorError } from "../lib/errors";
import AskIris from "../components/AskIris";
import { matchesSite } from "./paths/pathsModel";
import { PanelState, usePanel, type Panel } from "./wanPanel";
import { OtherPaths, PathCell, PathPanel, PathsReadNote } from "./paths/MeasuredPaths";
import { destText, wanRowPaths, unclaimedPaths, type AttachedPath } from "./paths/measuredFold";
import type { MeasuredState } from "./paths/useMeasuredPaths";
import {
  endpointKind,
  matchesEndpoint,
  noTargetCount,
  provenanceCounts,
  sortCandidates,
  sortEndpoints,
  targetKindChip,
  targetKindLabel,
  targetKindMeaning,
  wanBasisLabel,
  wanWhyTitle,
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
//   * ENDPOINTS  (GET /api/wan/endpoints) — the derived registry each link is
//                                           assembled from.
//
// IN THE ROWS (2026-11-22). The "Measured paths" section (GET /api/wan/circuits,
// one row per interface→target link) only said whether a link was measured, and
// the Measured paths tab showed the prober's traces apart from the circuit they
// measured. Both are folded into the rows: a link the registry holds unmeasured
// reads "held" in its Measured-to cell, and the prober's path to the row's target
// or router is its Path column, opened hop by hop from the row
// (paths/measuredFold.ts, paths/MeasuredPaths.tsx). Paths no row claims are
// listed apart, collapsed.
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

// ── 3 · derived endpoint registry (GET /api/wan/endpoints) ──────────────────

const ENDPOINT_CAP = 25;

function EndpointsSection({ panel, onRetry, q, site = "", canEdit = null, onMarked }: {
  panel: Panel<{ endpoints: WanEndpoint[]; candidates?: WanEndpoint[] }>; onRetry: () => void; q: string; site?: string;
  canEdit?: boolean | null; onMarked?: () => void;
}) {
  const all = useMemo(
    () => sortEndpoints(panel.data?.endpoints ?? []).filter((e) => matchesSite(site, e.site)),
    [panel.data, site],
  );
  const rows = useMemo(() => (q.trim() ? all.filter((e) => matchesEndpoint(e, q)) : all), [all, q]);
  const cap = useCap(rows, ENDPOINT_CAP);
  const counts = useMemo(() => provenanceCounts(all), [all]);
  const undecided = noTargetCount(all);

  return (
    <Section
      id="wan-endpoints" title="Endpoint registry" updatedAt={panel.at || null}
      note={<>derived, never stored<AskIris topic="wan.registry" label="Endpoint registry" /></>}
      actions={<span className="wan-count">{rows.length} of {all.length} interfaces</span>}
    >
      <PanelState panel={panel} what="the endpoint registry" onRetry={onRetry}>
        {all.length === 0 ? (
          <div className="empty">
            The registry is empty.
            <AskIris topic="wan.registry" label="Empty registry" />
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
              <p className="wan-line">
                {undecided} interface{undecided === 1 ? " has" : "s have"} no target yet.
                <AskIris topic="wan.derived-target" label="No target derived" />
              </p>
            )}
            {rows.length === 0 ? (
              <div className="empty">No endpoint matches this filter.</div>
            ) : (
              <>
                <table className="dp-tbl">
                  <thead>
                    <tr>
                      <th>Device</th><th>Interface</th><th>Why WAN</th><th>Address</th>
                      <th>Far end targets</th><th>Site</th>
                      <th>Measured to</th><th>Derived from</th>
                      {canEdit === true && onMarked && <th>Decide</th>}
                    </tr>
                  </thead>
                  <tbody>
                    {cap.rows.map((e) => (
                      <tr key={`${e.device}#${e.interface}`}>
                        <th scope="row">{e.device}</th>
                        <td style={mono}>{e.interface}</td>
                        <td title={wanWhyTitle(e)} data-testid="wan-why">{wanBasisLabel(e.wan_basis)}</td>
                        <td style={mono}>{e.address || dash}</td>
                        <td style={mono}>{e.measurable_addr || dash}</td>
                        <td>{e.site || dash}</td>
                        <td style={mono} title={e.target_label ?? ""}>{e.target || dash}</td>
                        <td><KindChip kind={endpointKind(e)} /></td>
                        {canEdit === true && onMarked && (
                          <td><MarkButtons ep={e} offerWan={false} onMarked={onMarked} /></td>
                        )}
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

// ── 3b · possible WAN interfaces (the registry's `candidates`) ──────────────
//
// Interfaces with a hint but no proof: a WAN-sounding description, a public
// address, the port facing a WAN router, or a WAN router with nothing confirmed.
// Never measured; collapsed by default so they never read as WAN circuits.

/** Mark / Not WAN for one interface. Rendered only with infrastructure write
 *  access; a refused write says why instead of failing silently. */
function MarkButtons({ ep, offerWan, onMarked }: {
  ep: WanEndpoint; offerWan: boolean; onMarked: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  if (!ep.device_id) return null;
  const mark = async (m: "wan" | "not_wan") => {
    setBusy(true);
    setError(null);
    try {
      await api.setWanMark(ep.device_id ?? "", ep.interface, m);
      onMarked();
    } catch (e) {
      setError(operatorError(e, "The mark could not be saved."));
    } finally {
      setBusy(false);
    }
  };
  return (
    <span style={{ display: "inline-flex", gap: 6, alignItems: "center" }}>
      {offerWan && (
        <button type="button" className="btn sm" disabled={busy} onClick={() => mark("wan")}>Mark as WAN</button>
      )}
      <button type="button" className="btn sm" disabled={busy} onClick={() => mark("not_wan")}>Not WAN</button>
      {error && <span role="alert" style={{ color: "var(--bad)" }}>{error}</span>}
    </span>
  );
}

function PossibleSection({ panel, site = "", canEdit, onMarked }: {
  panel: Panel<{ endpoints: WanEndpoint[]; candidates?: WanEndpoint[] }>; site?: string;
  canEdit: boolean | null; onMarked: () => void;
}) {
  const rows = useMemo(
    () => sortCandidates(panel.data?.candidates).filter((e) => matchesSite(site, e.site)),
    [panel.data, site],
  );
  if (rows.length === 0) return null;
  return (
    <details className="wan-possible" data-testid="wan-possible" style={{ marginTop: 18 }}>
      <summary>
        Possible WAN — not confirmed ({rows.length})
        <AskIris topic="wan.basis" label="Possible WAN" />
      </summary>
      <p className="wan-line">Not measured until someone marks them as WAN.</p>
      <table className="dp-tbl">
        <thead>
          <tr>
            <th>Device</th><th>Interface</th><th>Address</th><th>Why it might be WAN</th>
            {canEdit === true && <th>Decide</th>}
          </tr>
        </thead>
        <tbody>
          {rows.map((e) => (
            <tr key={`${e.device}#${e.interface}`}>
              <th scope="row">{e.device}</th>
              <td style={mono}>{e.interface}</td>
              <td style={mono}>{e.address || dash}</td>
              <td title={wanWhyTitle(e)}>{wanBasisLabel(e.wan_basis)}</td>
              {canEdit === true && <td><MarkButtons ep={e} offerWan onMarked={onMarked} /></td>}
            </tr>
          ))}
        </tbody>
      </table>
    </details>
  );
}

// ── the page ────────────────────────────────────────────────────────────────

export default function WanCircuits({ site = "", onSites, measured: probe }: {
  /** The Paths page's site filter (a siteKey): an interface on a router there. "" is All sites. */
  site?: string;
  /** Reports the sites these interfaces name, for the Paths page's site list. */
  onSites?: (labels: string[]) => void;
  /** The prober's measured paths (read once by the Paths page); absent → no Path column. */
  measured?: MeasuredState;
} = {}) {
  const [rows, setRows] = useState<WanInterfaceRow[]>([]);
  const [err, setErr] = useState<string | null>(null);
  // Evidence the SERVER could not read while deriving this table (tracker 290).
  // Distinct from `err`, which is this read failing: the table below is real, but
  // without the adjacency evidence every "Anchor" in the Target column may be a
  // fallback the projection took because the peer was never looked for.
  const [degraded, setDegraded] = useState<string[]>([]);
  const [loaded, setLoaded] = useState(false);
  // Whether the interface list has ANSWERED at least once. Until it has, no path
  // can be judged "claimed by no WAN interface": with rows still [] every
  // measured path used to read as unclaimed, so "Measured paths to other
  // targets (2)" appeared before anything was read (2026-11-25; also the race
  // behind a CI flake). A failed first read says so instead of counting.
  const [haveRows, setHaveRows] = useState(false);
  const [q, setQ] = useState("");

  useEffect(() => {
    let alive = true;
    const tick = async () => {
      try {
        const res = await api.wanInterfaces();
        if (alive) { setRows(res?.interfaces ?? []); setDegraded(res?.degraded ?? []); setErr(null); setLoaded(true); setHaveRows(true); }
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
    () => api.wanCircuits(), "Which links are held could not be read.");
  // A link the registry holds but does not measure: "held" in its row.
  const held = useMemo(() => {
    const out = new Set<string>();
    for (const c of circuits.data?.circuits ?? []) {
      if (!c.enabled) out.add(`${c.local.device}#${c.local.interface}`);
    }
    return out;
  }, [circuits.data]);

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

  // A mark changes which interfaces are WAN, so both derived reads run again.
  const afterMark = useCallback(() => {
    reloadEndpoints();
    reloadCircuits();
  }, [reloadEndpoints, reloadCircuits]);


  useEffect(() => { onSites?.(rows.map((r) => r.site ?? "")); }, [rows, onSites]);
  // The page's site filter scopes the tiles, the table and both registries.
  const scoped = useMemo(() => rows.filter((r) => matchesSite(site, r.site)), [rows, site]);

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    if (!needle) return scoped;
    return scoped.filter((r) =>
      `${r.device} ${r.interface} ${r.remote_device ?? ""} ${r.target ?? ""} ${r.target_label ?? ""} ${r.source_label ?? ""}`.toLowerCase().includes(needle));
  }, [scoped, q]);

  const rowKey = (r: WanInterfaceRow) => `${r.device}#${r.interface}`;

  // The prober's paths on each row, and the ones no row claims.
  const index = probe?.index ?? null;
  const pathsOf = useMemo(() => {
    const m = new Map<string, AttachedPath[]>();
    for (const r of rows) m.set(rowKey(r), wanRowPaths(index, r));
    return m;
  }, [rows, index]);
  const others = useMemo(() => {
    const claimed = new Set<string>();
    for (const list of pathsOf.values()) for (const a of list) claimed.add(a.m.key);
    return unclaimedPaths(index, claimed);
  }, [pathsOf, index]);
  const [panel, setPanel] = useState<{ title: string; paths: AttachedPath[] } | null>(null);
  const openRow = useCallback((r: WanInterfaceRow) => {
    const list = pathsOf.get(rowKey(r)) ?? [];
    if (list.length) setPanel({ title: `${r.device} ${r.interface}`, paths: list });
  }, [pathsOf]);
  const closePanel = useCallback(() => setPanel(null), []);

  // How the measurement target was derived (provenance chip).
  const targetKindLabelShort: Record<string, string> = {
    direct_peer: "Peer", next_hop: "Next-hop", anchor: "Anchor",
  };

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
      render: (r) => <span style={{ fontFamily: "var(--font-mono, monospace)" }}>{r.interface}</span> },
    { key: "why", header: "Why WAN", width: "12%", sortable: true,
      text: (r) => wanBasisLabel(r.wan_basis), sortValue: (r) => wanBasisLabel(r.wan_basis),
      render: (r) => <span title={wanWhyTitle(r)}>{wanBasisLabel(r.wan_basis)}</span> },
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
            {r.remote_if ? <span className="wan-mono">{r.remote_if}</span> : null}
            <span className="wan-mono">{r.target}</span>
            {held.has(rowKey(r)) && <span className="badge" data-testid="wan-held" title="In the registry, not being measured">held</span>}
          </span>
        : dash },
    ...(probe ? [{ key: "path", header: "Path", width: 176, sortable: true,
      text: (r: WanInterfaceRow) => (pathsOf.get(rowKey(r)) ?? []).map((a) => destText(a.m)).join(" "),
      sortValue: (r: WanInterfaceRow) => {
        const top = (pathsOf.get(rowKey(r)) ?? [])[0];
        return top ? ["unreached", "loss", "changed", "degraded", "ok"].indexOf(top.m.verdict) : 9;
      },
      render: (r: WanInterfaceRow) => <PathCell paths={pathsOf.get(rowKey(r)) ?? []} /> } as Column<WanInterfaceRow>] : []),
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
            {r.tier ? <span className={`badge tier-t${r.tier}`} title={`Tier ${r.tier} — ${r.tier_label}`}>T{r.tier}</span> : null}
            <span className="badge" title={`method: ${r.source_label}${r.tier_label ? " · " + r.tier_label : ""}`}>{r.source_label}</span>
          </span>
        : dash) },
    { key: "status", header: "Status", width: 80, sortable: true,
      text: (r) => (r.has_oper ? (r.oper_up ? "up" : "down") : ""), sortValue: (r) => (r.has_oper ? (r.oper_up ? 1 : 0) : -1),
      render: (r) => (r.has_oper ? <span className={`badge ${r.oper_up ? "good" : "bad"}`}>{r.oper_up ? "up" : "down"}</span> : dash) },
  ], [held, probe, pathsOf]);

  const down = scoped.filter((r) => r.has_oper && !r.oper_up).length;
  const totIn = scoped.reduce((a, r) => a + (r.has_util ? r.in_bps : 0), 0);
  const totOut = scoped.reduce((a, r) => a + (r.has_util ? r.out_bps : 0), 0);
  const peak = scoped.filter((r) => r.has_util).reduce((m, r) => Math.max(m, r.util_pct), 0);
  const measured = scoped.filter((r) => r.has_latency || r.has_loss).length;

  return (
    <div className="card paths-page">
      <h2>WAN circuits</h2>
      <p className="wan-line" style={{ marginTop: -6, marginBottom: 14 }}>
        One row per confirmed WAN interface, with the reason it counts.
        <AskIris topic="wan.basis" label="Why WAN" />
        Each row names the tier that measured it.
        <AskIris topic="wan.tiers" label="Measured by" />
        {probe && <>Open a row to see its path hop by hop.</>}
      </p>
      {probe && <PathsReadNote error={probe.error} />}
      {circuits.error && <p className="proto-key" role="alert" data-testid="wan-held-error">{circuits.error}</p>}
      {err && <p style={{ color: "var(--bad)" }}>{err}</p>}
      {degraded.map((note) => (
        <p key={note} role="alert" data-testid="wan-degraded" style={{ color: "var(--bad)" }}>{note}</p>
      ))}

      <div className="stat-grid" style={{ marginBottom: 18 }}>
        <div className={`stat ${scoped.length ? "s-good" : "s-muted"}`}>
          <span className="stat-label">WAN interfaces</span>
          <span className="stat-value">{scoped.length}</span>
          <span className="stat-foot">{measured} with measured SLA</span>
        </div>
        <div className="stat s-muted">
          <span className="stat-label">Throughput</span>
          <span className="stat-value">{fmtBps(totIn + totOut)}</span>
          <span className="stat-foot">↓ {fmtBps(totIn)} · ↑ {fmtBps(totOut)}</span>
        </div>
        <div className={`stat ${scoped.length ? (peak < 70 ? "s-good" : peak < 90 ? "s-warn" : "s-bad") : "s-muted"}`}>
          <span className="stat-label">Peak utilization</span>
          <span className="stat-value">{scoped.length ? peak.toFixed(1) : "—"}{scoped.length ? <span className="stat-unit"> %</span> : null}</span>
          <span className="stat-foot">busiest interface</span>
        </div>
        <div className={`stat ${down ? "s-bad" : "s-muted"}`}>
          <span className="stat-label">Interfaces down</span>
          <span className="stat-value">{down}</span>
          <span className="stat-foot">{scoped.length ? (down ? `${down} down` : "all up") : "none reported"}</span>
        </div>
      </div>

      <div className="dt-toolbar">
        <label className="dt-search">
          <span className="omni-icon">⌕</span>
          <input placeholder="Search devices, interfaces, targets…" value={q} onChange={(e) => setQ(e.target.value)} />
        </label>
        <span className="dt-count">{filtered.length} of {scoped.length} interfaces</span>
      </div>

      {loaded && rows.length === 0 ? (
        <div className="empty">
          No confirmed WAN interfaces yet. Possible ones, if any, are listed below.
          <AskIris topic="wan.basis" label="No WAN interfaces" />
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
          onRowClick={probe ? openRow : undefined}
        />
      )}

      {probe && haveRows && (
        <OtherPaths paths={others} site={site}
          onOpen={(m) => setPanel({ title: destText(m), paths: [{ m, role: "other" }] })} />
      )}
      {probe && !haveRows && loaded && err && (
        <p className="wan-line" data-testid="paths-other-unknown">
          Which measured paths belong to a WAN interface is not known: the interface list could not be read.
        </p>
      )}
      <EndpointsSection panel={endpoints} onRetry={reloadEndpoints} q={q} site={site} canEdit={canEdit} onMarked={afterMark} />
      <PossibleSection panel={endpoints} site={site} canEdit={canEdit} onMarked={afterMark} />
      <p className="wan-line" data-testid="wan-settings-link" style={{ marginTop: 18 }}>
        What WAN interfaces measure to — anchors, ISP next-hops — is set in{" "}
        <a href="#/admin/discovery/wan">WAN settings</a>.
        <AskIris topic="wan.policy" label="WAN settings" />
      </p>
      {probe && <PathPanel title={panel?.title ?? ""} paths={panel?.paths ?? null} onClose={closePanel} />}
    </div>
  );
}
