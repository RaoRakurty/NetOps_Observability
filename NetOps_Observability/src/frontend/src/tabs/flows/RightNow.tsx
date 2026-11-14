// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// RightNow — the default tab of Explore → Flows: what the network is
// carrying, link by link, and — for the link the operator picks — what that
// traffic was, what changed against the window before, who sent it, and which
// problems overlapped it.
//
// Sources (P2, tracker 400 — exact windows, one call per view):
//   · busiest links   — /api/flows/links: in/out bytes, the previous window
//                       from the same scan, interface name, router, site and
//                       whether the router exports each direction;
//   · utilisation     — the interface counters, through lib/ifUtilisation
//                       (the queries Device Monitoring and Interface
//                       Performance use);
//   · link in / out   — /api/flows/links/series, zero-filled buckets;
//   · what changed    — /api/flows/links/movers (talkers, apps, ports);
//   · talkers         — /api/flows/top with device + if;
//   · problems        — /api/correlations, matched on the devices each
//                       problem itself lists.

import { useMemo, useState } from "react";
import ReactECharts from "../../components/EChart";
import { api, type Device, type FlowMover, type FlowMoversBy } from "../../services/api";
import { operatorError } from "../../lib/errors";
import { buildDeviceNames } from "../../lib/deviceNames";
import { fmtTime } from "../../lib/time";
import DataTable, { type Column } from "../../components/DataTable";
import AskIris from "../../components/AskIris";
import { Segmented, StatStrip, Stat } from "../../components/ui";
import { fmtBps, fmtBytes, escapeHtml } from "../../components/board/panels";
import { chartBase, axisStyle, timeAxisTicks } from "../../theme/charts";
import { chartAnimation, flowColor } from "../../theme/flowTokens";
import { friendlyProblemId, signatureNocTitle } from "../../components/rca/labels";
import { ifRateBps, ifSpeedBps, deviceAnySelector } from "../../lib/ifUtilisation";
import { FlowEmpty, FlowSamplingNote } from "../flowEmpty";
import {
  attachUtil, changeLabel, directionNote, fmtPctOrDash, linkLabel, linkRowKey, linksFromApi, moverChange, moverTone,
  problemsForLink, samplingNote, seriesRates, utilTone, windowQuery, type LinkRow, type FlowsWindow,
} from "./flowsModel";
import { ConversationsSection, TopNPanel, servicePortLabel, type FlowQuery } from "./talkingSections";
import { useTicked } from "./useTicked";
import { Sparkline, UtilMeter } from "./viz";

const LINKS_LIMIT = 50;

type Props = {
  win: FlowsWindow;
  ftype: string;
  includePlatform: boolean;
  /** The selected link's key (exporter|ifIndex), from the route or a click. */
  selected: string;
  onSelect: (l: { exporter: string; ifIndex: string } | null) => void;
  onTalkers: (l: { exporter: string; ifIndex: string }) => void;
};

/** The end of the window, and its length, for the interface-counter reads. */
function counterSpan(win: FlowsWindow): { end: number; span: number; past: boolean } {
  const q = windowQuery(win);
  if (q.from !== undefined && q.to !== undefined) {
    const end = Math.floor(q.to / 1000);
    return { end, span: Math.max(300, Math.round((q.to - q.from) / 1000)), past: Date.now() - q.to > 120_000 };
  }
  return { end: Math.floor(Date.now() / 1000), span: win.since, past: false };
}

/** One direction's cell: "Not exported", or the bytes with a "reads low" marker. */
function DirCell({ row, dir }: { row: LinkRow; dir: "in" | "out" }) {
  const missing = dir === "in" ? row.inMissing : row.outMissing;
  const note = directionNote(row, dir);
  if (missing) return <span className="tr-quiet" title={note ?? undefined}>Not exported</span>;
  const v = dir === "in" ? row.inBytes : row.outBytes;
  return (
    <span title={note ?? undefined}>
      {fmtBytes(v)}
      {note && <span className="tr-reads-low" aria-label={note}> ≈</span>}
    </span>
  );
}

export default function RightNow({ win, ftype, includePlatform, selected, onSelect, onTalkers }: Props) {
  const since = win.since;
  const wq = windowQuery(win);
  const wkey = JSON.stringify(wq);
  const base = includePlatform ? { traffic: "all" } : {};
  const fkey = JSON.stringify(base);

  const devices = useTicked<Device[]>(() => api.devices(), []);
  const names = useMemo(() => buildDeviceNames(devices.data ?? []), [devices.data]);

  const cur = useTicked(() => api.flowsLinks(wq, LINKS_LIMIT, ftype, base), [wkey, ftype, fkey]);

  const withDevices = useMemo(
    () => linksFromApi(cur.data?.links).map((l) => (l.deviceId && names.get(l.deviceId) ? { ...l, deviceName: names.get(l.deviceId) } : l)),
    [cur.data, names],
  );
  const deviceIds = useMemo(() => [...new Set(withDevices.map((l) => l.deviceId).filter((x): x is string => !!x))].sort(), [withDevices]);
  const sel = deviceAnySelector(deviceIds);
  const cs = counterSpan(win);

  // Interface counters for the devices in the table: one range query per
  // direction (sparklines + the value at the end of the window) and the speeds.
  const counters = useTicked(
    async () => {
      const step = Math.max(60, Math.round(cs.span / 30));
      const [i, o, sp] = await Promise.all([
        api.metricsQueryRange(ifRateBps(sel, "in"), cs.end - cs.span, cs.end, step),
        api.metricsQueryRange(ifRateBps(sel, "out"), cs.end - cs.span, cs.end, step),
        api.metricsQuery(ifSpeedBps(sel)),
      ]);
      return { i: i.data?.result ?? [], o: o.data?.result ?? [], sp: sp.data?.result ?? [] };
    },
    [sel, cs.span, cs.past ? cs.end : 0],
    sel !== "",
  );
  const links = useMemo(
    () => (counters.data ? attachUtil(withDevices, counters.data.i, counters.data.o, counters.data.sp) : withDevices),
    [withDevices, counters.data],
  );

  // Fleet totals now, from the interface counters (the same sums the Overview uses).
  const fleet = useTicked(async () => {
    const [i, o] = await Promise.all([api.metricsQuery(`sum(${ifRateBps("", "in")})`), api.metricsQuery(`sum(${ifRateBps("", "out")})`)]);
    const v = (r: typeof i) => {
      const x = Number(r.data?.result?.[0]?.value?.[1]);
      return Number.isFinite(x) ? x : undefined;
    };
    return { in: v(i), out: v(o) };
  }, []);

  const busiest = [...links].sort((a, b) => (b.utilPct ?? -1) - (a.utilPct ?? -1))[0];
  const flowTotal = links.reduce((n, l) => n + l.totalBytes, 0);
  const selRow = links.find((l) => l.key === selected);
  const q = { since, ftype, filters: base, fkey };
  const err = cur.error ? operatorError(cur.error, "Busiest links could not be read for this window.") : null;
  const winEcho = cur.data?.window;
  const respSampling = samplingNote(cur.data?.basis.sampling);
  const utilWord = cs.past ? "at the end of this window" : "now";

  const cols = useMemo<Column<LinkRow>[]>(
    () => [
      {
        key: "link", header: "Link", width: "30%", sortable: true, text: (l) => linkLabel(l),
        render: (l) => (
          <span title={`${l.exporter} · interface index ${l.ifIndex}${l.tenantId ? ` · tenant ${l.tenantId}` : ""}`}>
            {linkLabel(l)}
            {(l.speedBps || l.site) && (
              <span className="tr-subline">{[l.site, l.speedBps ? `${fmtBps(l.speedBps)} link` : ""].filter(Boolean).join(" · ")}</span>
            )}
          </span>
        ),
      },
      { key: "in", header: <span className="tr-dir in">In</span>, align: "right", sortable: true, sortValue: (l) => (l.inMissing ? -1 : l.inBytes), render: (l) => <DirCell row={l} dir="in" /> },
      { key: "out", header: <span className="tr-dir out">Out</span>, align: "right", sortable: true, sortValue: (l) => (l.outMissing ? -1 : l.outBytes), render: (l) => <DirCell row={l} dir="out" /> },
      {
        key: "util", header: "Utilisation", align: "right", sortable: true, sortValue: (l) => l.utilPct ?? -1,
        render: (l) => <UtilMeter pct={l.utilPct} title={l.utilPct === undefined ? "Speed not reported" : `Busier direction, ${utilWord}`} />,
      },
      {
        key: "change", header: "Change", align: "right", sortable: true, sortValue: (l) => l.change ?? -Infinity,
        render: (l) => (
          <span title={l.prevBytes === null ? "The window before is not known" : "Against the previous window of the same length"}>{changeLabel(l)}</span>
        ),
      },
      { key: "trend", header: "Trend", width: 128, render: (l) => <Sparkline values={l.spark} label={`Trend for ${linkLabel(l)}`} /> },
    ],
    [utilWord],
  );

  return (
    <>
      <StatStrip>
        <Stat label="Inbound now" value={fleet.data?.in !== undefined ? fmtBps(fleet.data.in) : "—"} />
        <Stat label="Outbound now" value={fleet.data?.out !== undefined ? fmtBps(fleet.data.out) : "—"} />
        <Stat
          label={busiest?.utilPct !== undefined ? `Busiest link · ${linkLabel(busiest)}` : "Busiest link"}
          value={busiest?.utilPct !== undefined ? fmtPctOrDash(busiest.utilPct) : "—"}
          tone={utilTone(busiest?.utilPct)}
        />
        <Stat label="Seen in flows" value={cur.data ? fmtBytes(flowTotal) : "—"} />
      </StatStrip>

      <div className="panel" style={{ minWidth: 0 }}>
        <div className="panel-tools">
          <h3>Busiest links</h3>
          <AskIris topic="flows.busiest-links" label="Busiest links" />
        </div>
        {err ? (
          <div className="empty tr-error">{err}</div>
        ) : links.length === 0 ? (
          cur.loading ? <div className="empty board-empty" aria-busy="true" /> : <FlowEmpty q={q} />
        ) : (
          <DataTable<LinkRow>
            rows={links}
            columns={cols}
            rowKey={linkRowKey}
            rowHeight={48}
            height={Math.min(520, 40 + links.length * 48)}
            ariaLabel="Busiest links"
            onRowClick={(l) => onSelect(l.key === selected ? null : { exporter: l.exporter, ifIndex: l.ifIndex })}
            rowSelected={(l) => l.key === selected}
            rowClassName={(l) => (l.key === selected ? "tr-row-selected" : "")}
          />
        )}
        <p className="mini-meta tr-note"><FlowSamplingNote q={q} /></p>
        {respSampling && <p className="mini-meta tr-note" data-testid="links-sampling">{respSampling}</p>}
        {winEcho?.starts_before_retention && (
          <p className="mini-meta tr-note" data-testid="links-retention">
            Part of this window is older than the {winEcho.retention_days} days flow records are kept, so its totals read low.
          </p>
        )}
        {links.some((l) => directionNote(l, "in") || directionNote(l, "out")) && (
          <p className="mini-meta tr-note" data-testid="links-reads-low">
            ≈ reads low: some records name no interface. Hover for the share.
          </p>
        )}
      </div>

      {selected && (
        <LinkDetail
          key={selected}
          linkKey={selected}
          row={selRow}
          devices={devices.data ?? []}
          names={names}
          win={win}
          ftype={ftype}
          base={base}
          utilWord={utilWord}
          onClose={() => onSelect(null)}
          onTalkers={onTalkers}
        />
      )}
    </>
  );
}

// ── one link ─────────────────────────────────────────────────────────────────

function LinkDetail({ linkKey, row, devices, names, win, ftype, base, utilWord, onClose, onTalkers }: {
  linkKey: string;
  row?: LinkRow;
  devices: Device[];
  names: ReadonlyMap<string, string>;
  win: FlowsWindow;
  ftype: string;
  base: { traffic?: string };
  utilWord: string;
  onClose: () => void;
  onTalkers: (l: { exporter: string; ifIndex: string }) => void;
}) {
  const [exporter, ifIndex] = linkKey.split("|");
  const since = win.since;
  const wq = windowQuery(win);
  const wkey = JSON.stringify(wq);
  const device = devices.find((d) => d.address === exporter);
  const ident = {
    exporter, ifIndex, ifName: row?.ifName ?? "",
    deviceName: row?.deviceName ?? (device ? names.get(device.id) ?? device.name : undefined),
  };
  const label = linkLabel(ident);
  const fkey = JSON.stringify(base);
  const link = { exporter, ifIndex, tenant: row?.tenantId };

  const ts = useTicked(() => api.flowsLinkSeries(link, wq, ftype, base.traffic ?? ""), [exporter, ifIndex, row?.tenantId, wkey, ftype, fkey]);
  const problems = useTicked(() => api.correlations(200, since), [since]);

  const from = wq.from ?? Date.now() - since * 1000;
  const to = wq.to ?? Date.now();
  const marks = useMemo(
    () => problemsForLink(problems.data?.data ?? [], from, to, { exporter, deviceId: device?.id ?? row?.deviceId, deviceName: ident.deviceName }),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [problems.data, exporter, device?.id, ident.deviceName, wkey],
  );

  const rates = seriesRates(ts.data);
  const step = ts.data?.step_seconds ?? 60;
  const tsErr = ts.error ? operatorError(ts.error, "Flows on this link could not be read.") : null;
  const q: FlowQuery = { since, ftype, filters: { ...base, device: exporter, if: ifIndex }, fkey: `${linkKey}|${fkey}`, direction: "" };
  const inNote = ts.data ? directionNote({ inMissing: rates.inMissing, inBasis: ts.data.in_basis, inUnnamedPct: ts.data.in_unnamed_pct }, "in") : null;
  const outNote = ts.data ? directionNote({ outMissing: rates.outMissing, outBasis: ts.data.out_basis, outUnnamedPct: ts.data.out_unnamed_pct }, "out") : null;
  const empty = rates.in.every((p) => p[1] === 0) && rates.out.every((p) => p[1] === 0);

  const markArea = [
    ...(win.problem ? [[{ name: "Problem window", xAxis: win.problem.from }, { xAxis: win.problem.to }]] : []),
    ...marks.map((m) => [{ name: signatureNocTitle(m.hypothesis), xAxis: m.from }, { xAxis: Math.max(m.to, m.from + step * 1000) }]),
  ];
  const bad = flowColor("util-crit");
  const inColor = flowColor("in");
  const outColor = flowColor("out");

  return (
    <section className="panel tr-link" aria-label={`Link ${label}`} data-testid="link-detail">
      <div className="panel-tools">
        <h3>{label}</h3>
        <div className="tr-link-actions">
          {device && <a className="btn-ghost" href={`#/analytics/interface-performance/${encodeURIComponent(device.id)}`}>Interface details</a>}
          <button className="btn-ghost" onClick={() => onTalkers({ exporter, ifIndex })}>Who is talking here</button>
          <button className="btn-ghost" onClick={onClose} aria-label="Close link">Close</button>
        </div>
      </div>
      <StatStrip>
        <Stat label={`Utilisation ${utilWord}`} value={fmtPctOrDash(row?.utilPct)} tone={utilTone(row?.utilPct)} />
        <Stat label="Link speed" value={row?.speedBps ? fmtBps(row.speedBps) : "—"} />
        <Stat label="In this window" value={row ? fmtBytes(row.totalBytes) : "—"} />
        <Stat label="Change" value={row ? changeLabel(row) : "—"} />
        <Stat label="Problems here" value={problems.error ? "—" : String(marks.length)} tone={marks.length ? "warn" : ""} />
      </StatStrip>

      <div className="panel-tools"><h3>In and out</h3></div>
      {tsErr ? (
        <div className="empty tr-error">{tsErr}</div>
      ) : !ts.data ? (
        <div className="empty board-empty" aria-busy="true" />
      ) : empty ? (
        <FlowEmpty q={q} />
      ) : (
        <ReactECharts
          style={{ height: 300 }}
          option={{
            ...chartBase,
            animation: chartAnimation(),
            tooltip: { ...chartBase.tooltip, trigger: "axis", textStyle: { ...chartBase.tooltip.textStyle, fontSize: 14 }, valueFormatter: (v: number) => fmtBps(v) },
            legend: { ...chartBase.legend, data: ["In", "Out"], top: 0, right: 0, textStyle: { ...(chartBase as any).legend?.textStyle, fontSize: 14 } },
            grid: { left: 72, right: 24, top: 36, bottom: 32 },
            xAxis: { type: "time", ...axisStyle, ...timeAxisTicks(), axisLabel: { ...timeAxisTicks().axisLabel, fontSize: 14 } },
            yAxis: { type: "value", ...axisStyle, axisLabel: { ...(axisStyle as any).axisLabel, fontSize: 14, formatter: (v: number) => fmtBps(v) } },
            series: [
              {
                name: "In", type: "line", showSymbol: false, data: rates.in,
                lineStyle: { color: inColor, width: 2 }, itemStyle: { color: inColor },
                areaStyle: { color: inColor, opacity: 0.08 },
                markArea: markArea.length
                  ? {
                    silent: false,
                    itemStyle: { color: bad, opacity: 0.12 },
                    // The names come from the engine's signature catalogue, but
                    // ECharts renders labels as text and tooltips via innerHTML.
                    label: { color: bad, fontSize: 14, formatter: (p: any) => escapeHtml(String(p.name ?? "")) },
                    data: markArea,
                  }
                  : undefined,
              },
              {
                name: "Out", type: "line", showSymbol: false, data: rates.out,
                lineStyle: { color: outColor, width: 2 }, itemStyle: { color: outColor },
                areaStyle: { color: outColor, opacity: 0.08 },
              },
            ],
          }}
        />
      )}
      {(inNote || outNote) && (
        <p className="mini-meta tr-note" data-testid="series-basis">{[inNote && `In: ${inNote}.`, outNote && `Out: ${outNote}.`].filter(Boolean).join(" ")}</p>
      )}
      {ts.data && !ts.data.last_bucket_complete && (
        <p className="mini-meta tr-note">The latest {Math.round(step / 60)}-minute bucket is still filling and is not drawn.</p>
      )}
      {win.problem && (
        <p className="mini-meta tr-note" data-testid="problem-window">
          Problem window {fmtTime(new Date(win.problem.from).toISOString())} – {fmtTime(new Date(win.problem.to).toISOString())} is shaded.
        </p>
      )}

      <WhatChanged link={link} win={win} traffic={base.traffic ?? ""} />

      <div className="flows-grid">
        <ConversationsSection q={q} limit={10} title="Top talkers" />
        <TopNPanel title="Services on link" by="service_port" q={q} limit={10} keyHeader="Port" fmtKey={servicePortLabel} />
      </div>

      <div className="panel-tools"><h3>Problems in window</h3></div>
      {problems.error ? (
        <div className="empty tr-error">{operatorError(problems.error, "Problems could not be read for this window.")}</div>
      ) : marks.length === 0 ? (
        <div className="empty board-empty"><div className="board-empty-msg">{problems.loading ? "Reading problems…" : "No problems name this device."}</div></div>
      ) : (
        <ul className="tr-problems">
          {marks.map((m) => (
            <li key={m.id}>
              <a href={`#/investigate/rca?id=${encodeURIComponent(m.id)}`}>{signatureNocTitle(m.hypothesis)}</a>
              <span className="tr-quiet"> · {friendlyProblemId(m.id)} · {fmtTime(new Date(m.from).toISOString())}</span>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

// ── what changed ─────────────────────────────────────────────────────────────

const MOVER_TABS: { value: FlowMoversBy; label: string }[] = [
  { value: "talker", label: "Talkers" },
  { value: "app", label: "Applications" },
  { value: "port", label: "Ports" },
];

/**
 * The keys whose traffic on this link moved most against the previous window
 * of the same length. A talker's bytes count toward both ends of a
 * conversation, so talker rows do not add up to the link total.
 */
function WhatChanged({ link, win, traffic }: { link: { exporter: string; ifIndex: string; tenant?: string }; win: FlowsWindow; traffic: string }) {
  const [by, setBy] = useState<FlowMoversBy>("talker");
  const wq = windowQuery(win);
  const r = useTicked(() => api.flowsLinkMovers(link, wq, by, "both", 10, traffic), [link.exporter, link.ifIndex, link.tenant, JSON.stringify(wq), by, traffic]);
  const err = r.error ? operatorError(r.error, "What changed on this link could not be read.") : null;
  const movers = r.data?.movers ?? [];
  const noPrev = r.data?.totals.prev_bytes === null;

  const cols = useMemo<Column<FlowMover>[]>(
    () => [
      {
        key: "key", header: by === "talker" ? "Host" : by === "app" ? "Application" : "Port", width: "40%", sortable: true,
        text: (m) => (by === "port" ? servicePortLabel(m.key) : m.key),
        render: (m) => <span className="mono">{by === "port" ? servicePortLabel(m.key) : m.key}</span>,
      },
      { key: "now", header: "This window", align: "right", sortable: true, sortValue: (m) => m.bytes, render: (m) => fmtBytes(m.bytes) },
      { key: "before", header: "Window before", align: "right", sortable: true, sortValue: (m) => m.prev_bytes ?? -1, render: (m) => (m.prev_bytes === null ? "—" : fmtBytes(m.prev_bytes)) },
      { key: "change", header: "Change", align: "right", sortable: true, sortValue: (m) => m.delta ?? 0, render: (m) => <span className={moverTone(m) ? "tr-warn" : undefined}>{moverChange(m)}</span> },
    ],
    [by],
  );

  return (
    <div className="panel tr-movers" data-testid="what-changed">
      <div className="panel-tools">
        <h3>What changed</h3>
        <Segmented<FlowMoversBy> value={by} ariaLabel="What changed by" options={MOVER_TABS} onChange={setBy} />
      </div>
      {err ? (
        <div className="empty tr-error">{err}</div>
      ) : movers.length === 0 ? (
        <div className="empty board-empty">
          <div className="board-empty-msg">{r.loading ? "Reading what changed…" : "Nothing moved on this link against the window before."}</div>
        </div>
      ) : (
        <DataTable<FlowMover>
          rows={movers}
          columns={cols}
          rowKey={(m) => m.key}
          rowHeight={44}
          height={Math.min(480, 40 + movers.length * 44)}
          ariaLabel="What changed on this link"
        />
      )}
      <p className="mini-meta tr-note">
        {noPrev
          ? "The window before is older than the flow records kept, so there is nothing to compare with."
          : r.data
            ? `This window ${fmtBytes(r.data.totals.bytes)} · window before ${fmtBytes(r.data.totals.prev_bytes ?? 0)}.${by === "talker" ? " A conversation counts toward both of its hosts." : ""}`
            : ""}
      </p>
    </div>
  );
}
