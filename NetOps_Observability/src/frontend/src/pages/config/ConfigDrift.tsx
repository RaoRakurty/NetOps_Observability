// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// ConfigDrift — the fleet-wide "Config drift" list (Infrastructure section).
//
// One row per device: its configuration state, when it was last captured, the
// version that capture produced, the golden baseline it is measured against,
// and the reason when a capture failed. Filter chips narrow by state; the list
// is cursor-paginated and rows are APPENDED, never re-ordered.
//
// Honesty: "Unknown" is a first-class state — a device that was never captured,
// or that has no golden baseline, is unknown, not compliant. An empty result
// says which filter emptied it. A device missing from this list has not been
// assessed; it is not thereby in sync.
//
// Tenant isolation (§3a) is enforced server-side: this page sends no tenant and
// offers no cross-tenant control.
//
// Feature flag: the endpoint family is dormant unless FEATURE_CONFIG_BACKUP is
// set on the backend. A 404/501 renders as the calm "not enabled" card.

import { useCallback, useEffect, useRef, useState } from "react";
import { api, type ConfigDriftPage, type ConfigDriftRow } from "../../services/api";
import { Group, Panel } from "../../components/board/panels";
import { fmtDateTime } from "../../lib/time";
import {
  DRIFT_FILTERS,
  DRIFT_HELP,
  FEATURE_OFF_HINT,
  FEATURE_OFF_MESSAGE,
  classifyError,
  shortSha,
  statusBadge,
} from "./configModel";

const PAGE_SIZE = 100;

/** Deep link into the device inventory, which pre-filters on ?q=… */
export function deviceHref(row: ConfigDriftRow): string {
  return `#/infrastructure/devices?q=${encodeURIComponent(row.device_name || row.device_id)}`;
}

export default function ConfigDrift() {
  const [state, setState] = useState("");
  const [rows, setRows] = useState<ConfigDriftRow[]>([]);
  const [cursor, setCursor] = useState<string | null>(null);
  const [total, setTotal] = useState(0);
  const [off, setOff] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [loaded, setLoaded] = useState(false);
  // Guards against an out-of-order response overwriting a newer one.
  const reqId = useRef(0);

  const load = useCallback(async (st: string, cur?: string) => {
    const my = ++reqId.current;
    setBusy(true);
    try {
      const page: ConfigDriftPage = await api.configDriftList({
        state: st || undefined,
        cursor: cur || undefined,
        limit: PAGE_SIZE,
      });
      if (my !== reqId.current) return;
      const items = Array.isArray(page.items) ? page.items : [];
      setRows((prev) => (cur ? [...prev, ...items] : items));
      setCursor(page.next_cursor ?? null);
      setTotal(Number(page.total) || 0);
      setOff(false);
      setErr(null);
    } catch (e) {
      if (my !== reqId.current) return;
      if (classifyError(e) === "off") {
        setOff(true);
        setErr(null);
      } else {
        setErr(String((e as Error).message ?? e));
      }
      if (!cur) {
        setRows([]);
        setCursor(null);
        setTotal(0);
      }
    } finally {
      if (my === reqId.current) {
        setBusy(false);
        setLoaded(true);
      }
    }
  }, []);

  useEffect(() => { void load(state); }, [state, load]);

  const chosen = DRIFT_FILTERS.find((f) => f.value === state);

  if (off) {
    return (
      <div className="dm-board">
        <Panel title="Config drift">
          <div className="empty" role="status">
            {FEATURE_OFF_MESSAGE}. {FEATURE_OFF_HINT}
          </div>
        </Panel>
      </div>
    );
  }

  return (
    <div className="dm-board">
      <Group title="Config drift" hue="#0EA5E9">
        <div className="cfg-toolbar" role="group" aria-label="Filter by configuration state">
          {DRIFT_FILTERS.map((f) => (
            <button
              key={f.value || "all"}
              type="button"
              className={`btn${state === f.value ? " accent" : ""}`}
              aria-pressed={state === f.value}
              onClick={() => setState(f.value)}
            >
              {f.label}
            </button>
          ))}
        </div>

        {err ? (
          <div className="empty cfg-bad" role="alert">{err}</div>
        ) : !loaded ? (
          <div className="empty" role="status">Loading configuration state…</div>
        ) : rows.length === 0 ? (
          <div className="empty">
            {state
              ? `No device is in the "${chosen?.label ?? state}" state. Clear the filter to see the whole fleet.`
              : "No device has a configuration record yet. An empty list means nothing was captured — not that the fleet is in sync."}
          </div>
        ) : (
          <>
            <div className="ds-table-wrap">
              <table className="ds-table" aria-label="Configuration drift by device">
                <thead>
                  <tr>
                    <th scope="col">Device</th>
                    <th scope="col">State</th>
                    <th scope="col">Last capture</th>
                    <th scope="col">Last version</th>
                    <th scope="col">Golden</th>
                    <th scope="col">Detail</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((r) => {
                    const badge = statusBadge(r);
                    return (
                      <tr key={r.device_id}>
                        <th scope="row" style={{ textAlign: "left", fontWeight: 500 }}>
                          <a className="dtv-link" href={deviceHref(r)} title="Open the device Configuration panel">
                            {r.device_name || r.device_id}
                          </a>
                        </th>
                        <td><span className={`badge ${badge.tone}`} title={badge.help}>{badge.label}</span></td>
                        <td>{r.last_capture_at ? fmtDateTime(r.last_capture_at) : "never"}</td>
                        <td className="mono" title={r.last_sha || ""}>{r.last_sha ? shortSha(r.last_sha) : "—"}</td>
                        <td className="mono" title={r.golden_sha || ""}>{r.golden_sha ? `★ ${shortSha(r.golden_sha)}` : "none"}</td>
                        <td className="mini-meta">{r.last_error || (r.next_scheduled_at ? `next ${fmtDateTime(r.next_scheduled_at)}` : "")}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
            <div className="cfg-toolbar">
              <button
                type="button" className="btn" disabled={!cursor || busy}
                onClick={() => { void load(state, cursor ?? undefined); }}
              >
                {cursor ? (busy ? "Loading…" : "Load more") : "All rows loaded"}
              </button>
              <span className="mini-meta" role="status">
                {rows.length.toLocaleString()} of {total.toLocaleString()} device
                {total === 1 ? "" : "s"} shown — more rows are added as you scroll; the order never changes.
              </span>
            </div>
          </>
        )}

        <p className="mini-meta cfg-note">
          A device is only listed once a capture has been attempted. {DRIFT_HELP.unknown}
        </p>
      </Group>
    </div>
  );
}
