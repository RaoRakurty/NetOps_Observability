// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// RightNow — the default tab of Explore → Flows: what the network is
// carrying now, link by link, and — for the link the operator picks — what
// that traffic was, who sent it, and which problems overlapped it.
//
// Sources (all existing APIs, nothing new):
//   · busiest links   — /api/flows/topn?by=in_if and ?by=out_if (interface
//                       names from the device's own IF-MIB via iface_names),
//                       the same pair over twice the window for "change";
//   · utilisation     — the interface counters, through lib/ifUtilisation
//                       (the queries Device Monitoring and Interface
//                       Performance use);
//   · link in / out   — /api/flows/timeseries with device + in_if (entering)
//                       and device + out_if (leaving);
//   · talkers         — /api/flows/top with device + if;
//   · problems        — /api/correlations, matched on the devices each
//                       problem itself lists.

import { useMemo } from "react";
import ReactECharts from "../../components/EChart";
import { api, type Device } from "../../services/api";
import { operatorError } from "../../lib/errors";
import { buildDeviceNames } from "../../lib/deviceNames";
import { fmtTime } from "../../lib/time";
import DataTable, { type Column } from "../../components/DataTable";
import AskIris from "../../components/AskIris";
import { StatStrip, Stat } from "../../components/ui";
import { fmtBps, fmtBytes, escapeHtml } from "../../components/board/panels";
import { chartBase, axisStyle, timeAxisTicks } from "../../theme/charts";
import { chartAnimation, flowColor } from "../../theme/flowTokens";
import { friendlyProblemId, signatureNocTitle } from "../../components/rca/labels";
import { ifRateBps, ifSpeedBps, deviceAnySelector } from "../../lib/ifUtilisation";
import { FlowEmpty, FlowSamplingNote } from "../flowEmpty";
import type { TopNRow } from "../flowNames";
import {
  attachDevices, attachUtil, changeLabel, fmtPctOrDash, linkLabel, mergeLinks, parseCorrTs,
  problemsForLink, utilTone, withPrevious, type LinkRow, type FlowsWindow,
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

export default function RightNow({ win, ftype, includePlatform, selected, onSelect, onTalkers }: Props) {
  const since = win.since;
  const base = includePlatform ? { traffic: "all" } : {};
  const fkey = JSON.stringify(base);

  const devices = useTicked<Device[]>(() => api.devices(), []);
  const names = useMemo(() => buildDeviceNames(devices.data ?? []), [devices.data]);

  const cur = useTicked(
    () => Promise.all([
      api.flowsTopN("in_if", since, LINKS_LIMIT, ftype, base),
      api.flowsTopN("out_if", since, LINKS_LIMIT, ftype, base),
    ]),
    [since, ftype, fkey],
  );
  const prev = useTicked(
    () => Promise.all([
      api.flowsTopN("in_if", since * 2, LINKS_LIMIT * 2, ftype, base),
      api.flowsTopN("out_if", since * 2, LINKS_LIMIT * 2, ftype, base),
    ]),
    [since, ftype, fkey],
  );

  const flowLinks = useMemo(() => {
    const [i, o] = cur.data ?? [];
    const now = mergeLinks((i?.data as TopNRow[]) ?? [], (o?.data as TopNRow[]) ?? []);
    if (!prev.data) return now;
    const [pi, po] = prev.data;
    return withPrevious(now, mergeLinks((pi?.data as TopNRow[]) ?? [], (po?.data as TopNRow[]) ?? []));
  }, [cur.data, prev.data]);

  const withDevices = useMemo(() => attachDevices(flowLinks, devices.data ?? [], names), [flowLinks, devices.data, names]);
  const deviceIds = useMemo(() => [...new Set(withDevices.map((l) => l.deviceId).filter((x): x is string => !!x))].sort(), [withDevices]);
  const sel = deviceAnySelector(deviceIds);

  // Interface counters for the devices in the table: one range query per
  // direction (sparklines + now) and one for the speeds.
  const counters = useTicked(
    async () => {
      const end = Math.floor(Date.now() / 1000);
      const step = Math.max(60, Math.round(since / 30));
      const [i, o, sp] = await Promise.all([
        api.metricsQueryRange(ifRateBps(sel, "in"), end - since, end, step),
        api.metricsQueryRange(ifRateBps(sel, "out"), end - since, end, step),
        api.metricsQuery(ifSpeedBps(sel)),
      ]);
      return { i: i.data?.result ?? [], o: o.data?.result ?? [], sp: sp.data?.result ?? [] };
    },
    [sel, since],
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

  const cols = useMemo<Column<LinkRow>[]>(
    () => [
      {
        key: "link", header: "Link", width: "30%", sortable: true, text: (l) => linkLabel(l),
        render: (l) => (
          <span title={`${l.exporter} · interface index ${l.ifIndex}`}>
            {linkLabel(l)}
            {l.speedBps ? <span className="tr-subline">{fmtBps(l.speedBps)} link</span> : null}
          </span>
        ),
      },
      { key: "in", header: <span className="tr-dir in">In</span>, align: "right", sortable: true, sortValue: (l) => l.inBytes, render: (l) => fmtBytes(l.inBytes) },
      { key: "out", header: <span className="tr-dir out">Out</span>, align: "right", sortable: true, sortValue: (l) => l.outBytes, render: (l) => fmtBytes(l.outBytes) },
      {
        key: "util", header: "Utilisation", align: "right", sortable: true, sortValue: (l) => l.utilPct ?? -1,
        render: (l) => <UtilMeter pct={l.utilPct} title={l.utilPct === undefined ? "Speed not reported" : "Busier direction, now"} />,
      },
      {
        key: "change", header: "Change", align: "right", sortable: true, sortValue: (l) => l.change ?? -Infinity,
        render: (l) => <span title="Against the previous window of the same length">{changeLabel(l)}</span>,
      },
      { key: "trend", header: "Trend", width: 128, render: (l) => <Sparkline values={l.spark} label={`Trend for ${linkLabel(l)}`} /> },
    ],
    [],
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
            rowKey={(l) => l.key}
            rowHeight={48}
            height={Math.min(520, 40 + links.length * 48)}
            ariaLabel="Busiest links"
            onRowClick={(l) => onSelect(l.key === selected ? null : { exporter: l.exporter, ifIndex: l.ifIndex })}
            rowSelected={(l) => l.key === selected}
            rowClassName={(l) => (l.key === selected ? "tr-row-selected" : "")}
          />
        )}
        <p className="mini-meta tr-note"><FlowSamplingNote q={q} /></p>
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
          onClose={() => onSelect(null)}
          onTalkers={onTalkers}
        />
      )}
    </>
  );
}

// ── one link ─────────────────────────────────────────────────────────────────

type TsRow = { bucket: string; bytes_total: number };

function LinkDetail({ linkKey, row, devices, names, win, ftype, base, onClose, onTalkers }: {
  linkKey: string;
  row?: LinkRow;
  devices: Device[];
  names: ReadonlyMap<string, string>;
  win: FlowsWindow;
  ftype: string;
  base: { traffic?: string };
  onClose: () => void;
  onTalkers: (l: { exporter: string; ifIndex: string }) => void;
}) {
  const [exporter, ifIndex] = linkKey.split("|");
  const since = win.since;
  const step = Math.max(60, Math.round(since / 120));
  const device = devices.find((d) => d.address === exporter);
  const ident = { exporter, ifIndex, ifName: row?.ifName ?? "", deviceName: device ? names.get(device.id) ?? device.name : undefined };
  const label = linkLabel(ident);
  const fkey = JSON.stringify(base);

  const ts = useTicked(
    () => Promise.all([
      api.flowsTimeseries(since, step, ftype, { ...base, device: exporter, in_if: ifIndex }),
      api.flowsTimeseries(since, step, ftype, { ...base, device: exporter, out_if: ifIndex }),
    ]),
    [exporter, ifIndex, since, step, ftype, fkey],
  );
  const problems = useTicked(() => api.correlations(200, since), [since]);

  const now = Date.now();
  const from = now - since * 1000;
  const marks = useMemo(
    () => problemsForLink(problems.data?.data ?? [], from, now, { exporter, deviceId: device?.id, deviceName: ident.deviceName }),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [problems.data, exporter, device?.id, ident.deviceName, since],
  );

  const toPoints = (rows: TsRow[] | undefined) =>
    (rows ?? []).map((r) => [parseCorrTs(r.bucket) ?? 0, (Number(r.bytes_total) * 8) / step] as [number, number]).filter((p) => p[0] > 0);
  const inPts = toPoints(ts.data?.[0]?.data as TsRow[] | undefined);
  const outPts = toPoints(ts.data?.[1]?.data as TsRow[] | undefined);
  const tsErr = ts.error ? operatorError(ts.error, "Flows on this link could not be read.") : null;
  const q: FlowQuery = { since, ftype, filters: { ...base, device: exporter, if: ifIndex }, fkey: `${linkKey}|${fkey}`, direction: "" };

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
        <Stat label="Utilisation now" value={fmtPctOrDash(row?.utilPct)} tone={utilTone(row?.utilPct)} />
        <Stat label="Link speed" value={row?.speedBps ? fmtBps(row.speedBps) : "—"} />
        <Stat label="In this window" value={row ? fmtBytes(row.totalBytes) : "—"} />
        <Stat label="Problems here" value={problems.error ? "—" : String(marks.length)} tone={marks.length ? "warn" : ""} />
      </StatStrip>

      <div className="panel-tools"><h3>In and out</h3></div>
      {tsErr ? (
        <div className="empty tr-error">{tsErr}</div>
      ) : inPts.length === 0 && outPts.length === 0 ? (
        ts.loading ? <div className="empty board-empty" aria-busy="true" /> : <FlowEmpty q={q} />
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
                name: "In", type: "line", showSymbol: false, smooth: true, data: inPts,
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
                name: "Out", type: "line", showSymbol: false, smooth: true, data: outPts,
                lineStyle: { color: outColor, width: 2 }, itemStyle: { color: outColor },
                areaStyle: { color: outColor, opacity: 0.08 },
              },
            ],
          }}
        />
      )}
      {win.problem && (
        <p className="mini-meta tr-note" data-testid="problem-window">
          Problem window {fmtTime(new Date(win.problem.from).toISOString())} – {fmtTime(new Date(win.problem.to).toISOString())} is shaded.
        </p>
      )}

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

