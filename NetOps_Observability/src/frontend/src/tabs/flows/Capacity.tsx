// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Capacity — per-link headroom over the chosen window and when each link is
// on course to reach 90 %, from GET /api/flows/capacity (P2, tracker 400).
//
// Read from the INTERFACE COUNTERS, not from flows: counters are exact and
// kept 30 days, while flow records are kept 7 days and a sampling router that
// reports no rate reads low. For each link:
//   · 95th percentile — the busiest 5 % of five-minute samples set aside, so
//     one burst does not read as a full link (the busier direction);
//   · peak — the highest five-minute rate;
//   · headroom — the speed minus the 95th percentile;
//   · reaches 90 % — a straight line through each complete day's 95th
//     percentile; given only with 14 days of history and a steady trend.
// A link whose router reports no speed (or an implausible one) keeps its
// throughput and gets no percentage, headroom or forecast — said on screen.
// A row opens that link in Right now.

import { useMemo, useState } from "react";
import { api } from "../../services/api";
import { operatorError } from "../../lib/errors";
import AskIris from "../../components/AskIris";
import { Segmented, StatStrip, Stat } from "../../components/ui";
import { fmtBps } from "../../components/board/panels";
import {
  capacityFromApi, forecastText, forecastTone, groupCapacity, utilTone, windowQuery, UTIL_CRIT,
  type CapacityRow, type FlowsWindow,
} from "./flowsModel";
import { useTicked } from "./useTicked";
import { UtilMeter } from "./viz";

const SHOWN = 100;

const pct = (v: number | null): number | undefined => (v === null ? undefined : v);

export default function Capacity({ win, onOpenLink }: { win: FlowsWindow; onOpenLink: (l: { exporter: string; ifIndex: string }) => void }) {
  const [by, setBy] = useState<"site" | "device">("site");
  const [showNoSpeed, setShowNoSpeed] = useState(false);
  const wq = windowQuery(win);

  const cap = useTicked(() => api.flowsCapacity(wq, SHOWN), [JSON.stringify(wq)]);
  const rows = useMemo(() => capacityFromApi(cap.data?.interfaces), [cap.data]);
  const { groups, noSpeed } = useMemo(() => groupCapacity(rows, by), [rows, by]);
  const withSpeed = rows.filter((r) => r.speed_basis === "reported");
  const overCrit = withSpeed.filter((r) => (r.p95_pct ?? 0) >= UTIL_CRIT).length;
  const soon = withSpeed.filter((r) => r.forecast.status === "rising" && (r.forecast.days_to_90 ?? Infinity) <= 30).length;
  const tightest = withSpeed[0];
  const err = cap.error ? operatorError(cap.error, "Link capacity could not be read for this window.") : null;
  const total = cap.data?.total ?? rows.length;

  const open = (r: CapacityRow) => {
    if (r.exporter && r.ifindex) onOpenLink({ exporter: r.exporter, ifIndex: r.ifindex });
  };
  const linkName = (r: CapacityRow, withDevice: boolean) =>
    `${withDevice ? `${r.device_name || r.device_id} · ` : ""}${r.if_name || `interface ${r.ifindex}`}`;

  return (
    <>
      <StatStrip>
        <Stat label="Links measured" value={cap.data ? String(total) : "—"} />
        <Stat label={`95th percentile above ${UTIL_CRIT}%`} value={cap.data ? String(overCrit) : "—"} tone={overCrit ? "bad" : ""} />
        <Stat label="Reach 90% within 30 days" value={cap.data ? String(soon) : "—"} tone={soon ? "warn" : ""} />
        <Stat
          label={tightest ? `Least headroom · ${linkName(tightest, true)}` : "Least headroom"}
          value={tightest?.headroom_bps !== null && tightest?.headroom_bps !== undefined ? `${fmtBps(tightest.headroom_bps)} free` : "—"}
          tone={utilTone(pct(tightest?.p95_pct ?? null))}
        />
      </StatStrip>

      <div className="panel" style={{ minWidth: 0 }}>
        <div className="panel-tools">
          <span className="tr-title">
            <h3>Link capacity</h3>
            <AskIris topic="flows.capacity" label="Link capacity" />
          </span>
          <Segmented<"site" | "device">
            value={by}
            ariaLabel="Group links by"
            options={[{ value: "site", label: "By site" }, { value: "device", label: "By device" }]}
            onChange={setBy}
          />
        </div>
        {err ? (
          <div className="empty tr-error">{err}</div>
        ) : rows.length === 0 ? (
          <div className="empty board-empty">
            <div className="board-empty-msg">{cap.loading ? "Reading link capacity…" : "No interface counters for this window yet."}</div>
          </div>
        ) : (
          <table className="ds-table tr-cap" aria-label="Link capacity">
            <thead>
              <tr>
                <th scope="col">Link</th>
                <th scope="col" className="num">Speed</th>
                <th scope="col" className="num">95th percentile</th>
                <th scope="col" className="num">Peak</th>
                <th scope="col" className="num">Headroom</th>
                <th scope="col">Reaches 90%</th>
              </tr>
            </thead>
            {groups.map((g) => (
              <tbody key={g.group}>
                <tr className="tr-cap-group"><th scope="rowgroup" colSpan={6}>{g.group}</th></tr>
                {g.rows.map((r) => (
                  <tr
                    key={r.key}
                    className={r.exporter ? "tr-cap-row" : undefined}
                    onClick={() => open(r)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") open(r);
                    }}
                    tabIndex={r.exporter ? 0 : undefined}
                    title={r.exporter ? "Open this link in Right now" : `interface index ${r.ifindex}`}
                  >
                    <td>{linkName(r, by === "site")}</td>
                    <td className="num">{r.speed_bps ? fmtBps(r.speed_bps) : "—"}</td>
                    <td className="num"><UtilMeter pct={pct(r.p95_pct)} title={r.p95_bps !== null ? fmtBps(r.p95_bps) : undefined} /></td>
                    <td className="num"><UtilMeter pct={pct(r.peak_pct)} title={r.peak_bps !== null ? fmtBps(r.peak_bps) : undefined} /></td>
                    <td className="num">{r.headroom_bps !== null ? `${fmtBps(r.headroom_bps)} free` : "—"}</td>
                    <td className={`tr-forecast ${forecastTone(r.forecast)}`} title={r.forecast.r2 !== null ? `Trend fit R² ${r.forecast.r2}` : undefined}>
                      {forecastText(r.forecast)}
                    </td>
                  </tr>
                ))}
              </tbody>
            ))}
          </table>
        )}
        {noSpeed.length > 0 && (
          <div className="tr-nospeed">
            <button className="btn-ghost" aria-expanded={showNoSpeed} onClick={() => setShowNoSpeed((v) => !v)}>
              Links with no reported speed ({noSpeed.length})
            </button>
            {showNoSpeed && (
              <>
                <p className="mini-meta tr-note">
                  These routers do not report a usable interface speed, so there is no percentage, headroom or forecast — only the throughput.
                </p>
                <table className="ds-table tr-cap" aria-label="Links with no reported speed">
                  <thead>
                    <tr>
                      <th scope="col">Link</th>
                      <th scope="col" className="num">95th percentile</th>
                      <th scope="col" className="num">Peak</th>
                      <th scope="col">Why</th>
                    </tr>
                  </thead>
                  <tbody>
                    {noSpeed.map((r) => (
                      <tr key={r.key} onClick={() => open(r)} className={r.exporter ? "tr-cap-row" : undefined}>
                        <td>{linkName(r, true)}</td>
                        <td className="num">{r.p95_bps !== null ? fmtBps(r.p95_bps) : "—"}</td>
                        <td className="num">{r.peak_bps !== null ? fmtBps(r.peak_bps) : "—"}</td>
                        <td>{r.speed_basis === "implausible" ? "Reported speed is lower than the traffic it carries" : "Speed not reported"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </>
            )}
          </div>
        )}
        <p className="mini-meta tr-note" data-testid="capacity-method">
          95th percentile and peak use five-minute rates over this window (busier direction). "Reaches 90%" fits a straight line through each complete day's
          95th percentile over the last {cap.data?.forecast.days ?? 28} days; it needs {cap.data?.forecast.min_days ?? 14} days and a steady trend.
          {cap.data?.forecast.unavailable ? " The daily history could not be read just now, so no forecast is shown." : ""}
        </p>
        {total > rows.length && <p className="fact-line tr-fact">The {rows.length} busiest of {total} links are shown.</p>}
      </div>
    </>
  );
}
