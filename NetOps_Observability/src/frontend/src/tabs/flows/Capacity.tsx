// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Capacity — per-link utilisation over the chosen window (average and peak of
// the 5-minute rate, in percent of the reported speed), busiest peak first,
// grouped by site or by device. Read from the interface counters through
// lib/ifUtilisation — the same queries Device Monitoring and Interface
// Performance draw — and the site binding from /api/devices/locations.
//
// What P1 does NOT compute is said on screen, not faked: the 95th percentile,
// the headroom left and the days until a link reaches 90 % need the per-link
// series the P2 traffic APIs will serve (tracker).

import { useMemo, useState } from "react";
import { api, type Device, type DeviceLocationRow } from "../../services/api";
import { operatorError } from "../../lib/errors";
import { buildDeviceNames } from "../../lib/deviceNames";
import AskIris from "../../components/AskIris";
import { Segmented, StatStrip, Stat } from "../../components/ui";
import { fmtBps } from "../../components/board/panels";
import { ifSpeedBps, ifUtilPct, overWindow } from "../../lib/ifUtilisation";
import { capacityRows, fmtPctOrDash, groupCapacity, utilTone, UTIL_CRIT, UTIL_WARN, type CapacityRow } from "./flowsModel";
import { useTicked } from "./useTicked";
import { UtilMeter } from "./viz";

const SHOWN = 100;

const Pct = ({ v }: { v?: number }) => <UtilMeter pct={v} />;

export default function Capacity({ since }: { since: number }) {
  const [by, setBy] = useState<"site" | "device">("site");

  const devices = useTicked<Device[]>(() => api.devices(), []);
  const locations = useTicked<{ devices: DeviceLocationRow[] }>(() => api.deviceLocations(), []);
  const names = useMemo(() => buildDeviceNames(devices.data ?? []), [devices.data]);
  const sites = useMemo(() => {
    const m = new Map<string, string>();
    for (const d of locations.data?.devices ?? []) if (d.site) m.set(d.id, d.site);
    return m;
  }, [locations.data]);

  const util = useTicked(async () => {
    const q = (expr: string) => api.metricsQuery(expr).then((r) => r.data?.result ?? []);
    const [avgIn, peakIn, avgOut, peakOut, speed] = await Promise.all([
      q(overWindow("avg", ifUtilPct("", "in"), since)),
      q(overWindow("max", ifUtilPct("", "in"), since)),
      q(overWindow("avg", ifUtilPct("", "out"), since)),
      q(overWindow("max", ifUtilPct("", "out"), since)),
      q(ifSpeedBps("")),
    ]);
    return { avgIn, peakIn, avgOut, peakOut, speed };
  }, [since]);

  const rows = useMemo(() => (util.data ? capacityRows(util.data, names, sites) : []), [util.data, names, sites]);
  const groups = useMemo(() => groupCapacity(rows.slice(0, SHOWN), by), [rows, by]);
  const overCrit = rows.filter((r) => (r.peak ?? 0) >= UTIL_CRIT).length;
  const overWarn = rows.filter((r) => (r.peak ?? 0) >= UTIL_WARN).length;
  const err = util.error ? operatorError(util.error, "Link utilisation could not be read for this window.") : null;

  return (
    <>
      <StatStrip>
        <Stat label="Links measured" value={util.data ? String(rows.length) : "—"} />
        <Stat label={`Peaked above ${UTIL_CRIT}%`} value={util.data ? String(overCrit) : "—"} tone={overCrit ? "bad" : ""} />
        <Stat label={`Peaked above ${UTIL_WARN}%`} value={util.data ? String(overWarn) : "—"} tone={overWarn ? "warn" : ""} />
        <Stat label="Busiest peak" value={rows[0] ? fmtPctOrDash(rows[0].peak) : "—"} tone={utilTone(rows[0]?.peak)} />
      </StatStrip>

      <div className="panel" style={{ minWidth: 0 }}>
        <div className="panel-tools">
          <span className="tr-title">
            <h3>Link utilisation</h3>
            <AskIris topic="flows.capacity" label="Link utilisation" />
          </span>
          <Segmented<"site" | "device">
            value={by}
            ariaLabel="Group links by"
            options={[{ value: "site", label: "By site" }, { value: "device", label: "By device" }]}
            onChange={setBy}
          />
        </div>
        <p className="mini-meta tr-note" data-testid="capacity-next">Coming next: 95th percentile · headroom · days until 90%.</p>
        {err ? (
          <div className="empty tr-error">{err}</div>
        ) : rows.length === 0 ? (
          <div className="empty board-empty">
            <div className="board-empty-msg">{util.loading ? "Reading link utilisation…" : "No link reports its speed yet."}</div>
          </div>
        ) : (
          <table className="ds-table tr-cap" aria-label="Link utilisation">
            <thead>
              <tr>
                <th scope="col">Link</th>
                <th scope="col" className="num">Speed</th>
                <th scope="col" className="num">Average</th>
                <th scope="col" className="num">Peak</th>
                <th scope="col" className="num">Peak in</th>
                <th scope="col" className="num">Peak out</th>
              </tr>
            </thead>
            {groups.map((g) => (
              <tbody key={g.group}>
                <tr className="tr-cap-group"><th scope="rowgroup" colSpan={6}>{g.group}</th></tr>
                {g.rows.map((r: CapacityRow) => (
                  <tr key={r.key}>
                    <td title={`interface index ${r.ifIndex}`}>
                      {by === "site" ? `${r.deviceName} · ` : ""}{r.ifName || `interface ${r.ifIndex}`}
                    </td>
                    <td className="num">{r.speedBps ? fmtBps(r.speedBps) : "—"}</td>
                    <td className="num"><Pct v={r.avg} /></td>
                    <td className="num"><Pct v={r.peak} /></td>
                    <td className="num"><Pct v={r.peakIn} /></td>
                    <td className="num"><Pct v={r.peakOut} /></td>
                  </tr>
                ))}
              </tbody>
            ))}
          </table>
        )}
        {rows.length > SHOWN && <p className="fact-line tr-fact">The {SHOWN} busiest of {rows.length} links are shown.</p>}
      </div>
    </>
  );
}
