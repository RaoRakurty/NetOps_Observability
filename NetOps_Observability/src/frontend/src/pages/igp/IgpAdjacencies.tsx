// IgpAdjacencies — the OSPF / IS-IS adjacency view (Project 4 D item 11).
//
// It reads /api/protocols/{proto}/{adjacencies,summary,health} and renders
// exactly what those answered — no more. The panel exists because the PromQL
// board above it cannot tell "0 adjacencies down" apart from "nothing is
// watching this protocol": `count(...) or vector(0)` renders both as a green 0.
// Here an uncollected source is a COVERAGE CHIP that says "not collected" and a
// count that says "not collected", never a digit.
//
// HONESTY (the five states, the InvestigationLanes vocabulary):
//   loading / error / not_connected / empty / ready. "not connected" (neither
//   evidence class answered) and "empty" (they answered and the window was
//   quiet) are different facts and are never collapsed.
//
// SECURITY (§3 / §15): every value below — device ids, neighbour ids, interface
// names, server notes — is remote-authored text rendered as an escaped React
// text node. No innerHTML, no dangerouslySetInnerHTML.

import { useEffect, useMemo, useState } from "react";
import {
  api,
  type Device,
  type IgpAdjacenciesResponse,
  type IgpHealthResponse,
  type IgpProto,
  type IgpSummaryResponse,
} from "../../services/api";
import { Segmented, Stat, StatStrip } from "../../components/ui";
import { Panel } from "../../components/board/panels";
import {
  IGP_WINDOWS,
  PEER_LABEL,
  PROTO_LABEL,
  PROTO_STATES,
  adjCounts,
  adjKey,
  adjTone,
  classifyAdjacencies,
  classifyHealth,
  classifySummary,
  areasCell,
  areasView,
  countOrNotCollected,
  coverageChips,
  currentStateLabel,
  holdLabel,
  igpError,
  igpLoading,
  isMeasured,
  lsdbView,
  spfView,
  stateSourceLabel,
  timelineTicks,
  timerCell,
  timersView,
  windowLabel,
  worstFirst,
  type DepthView,
  type IgpResult,
} from "./igpModel";

// ── the shared state renderer ───────────────────────────────────────────────

function StateBlock({ result, children }: { result: IgpResult<unknown>; children?: React.ReactNode }) {
  switch (result.state) {
    case "loading":
      return <div className="empty" role="status">Loading…</div>;
    case "error":
      return <div className="empty" role="alert" style={{ color: "var(--bad)" }}>{result.note}</div>;
    case "not_connected":
      return (
        <div className="empty igp-notwired" role="status">
          <span className="badge">Not collected</span> {result.note}
        </div>
      );
    case "empty":
      return <div className="empty" role="status">{result.note}</div>;
    default:
      return <>{children}</>;
  }
}

// ── coverage strip ──────────────────────────────────────────────────────────

function CoverageStrip({ coverage, notes }: { coverage?: IgpAdjacenciesResponse["coverage"]; notes?: string[] }) {
  const chips = coverageChips(coverage, notes);
  return (
    <ul className="igp-coverage" aria-label="Evidence coverage">
      {chips.map((c) => (
        <li
          key={c.id}
          className="igp-cov-chip"
          data-source={c.id}
          data-collected={c.collected ? "yes" : "no"}
          title={c.detail}
        >
          <span className="igp-cov-label">{c.label}</span>
          <span className="igp-cov-state">{c.collected ? "collected" : "not collected"}</span>
          <span className="mini-meta igp-cov-detail">{c.detail}</span>
        </li>
      ))}
    </ul>
  );
}

// ── timeline ────────────────────────────────────────────────────────────────

function Timeline({ ticks }: { ticks: ReturnType<typeof timelineTicks> }) {
  if (ticks.length === 0) {
    return <span className="mini-meta">no change in window</span>;
  }
  return (
    <span className="igp-timeline" aria-label={`${ticks.length} adjacency changes, oldest first`}>
      {ticks.map((t) => (
        <span
          key={t.key}
          className="igp-tick"
          data-state={t.state}
          title={`${t.ts} — ${t.state} (${t.source})`}
        >
          {t.state === "up" ? "▲" : t.state === "down" ? "▼" : "•"}
        </span>
      ))}
    </span>
  );
}

// ── the advanced depth panels ───────────────────────────────────────────────
//
// One renderer for the two counting blocks (LSDB size, SPF runs). A block that
// was not collected prints the server's reason and NO number — not a dash that
// could be mistaken for a measurement, and never a 0.

function DepthCount({ title, view }: { title: string; view: DepthView }) {
  if (!view.collected) {
    return (
      <div className="igp-depth" data-block={title} data-collected="no">
        <span className="mini-meta igp-depth-title">{title}</span>
        <div className="empty igp-notwired" role="status">
          <span className="badge">Not collected</span> {view.note}
        </div>
      </div>
    );
  }
  return (
    <div className="igp-depth" data-block={title} data-collected="yes">
      <span className="mini-meta igp-depth-title">{title}</span>
      <span className="igp-depth-value mono">{view.value}</span>
      {view.scopes.length > 0 && (
        <ul className="mini-meta igp-depth-scopes" aria-label={`${title} by ${view.scopeLabel}`}>
          {view.scopes.map((sc) => (
            <li key={sc.scope}>
              <span className="mono">{sc.scope}</span>: <span className="mono">{sc.count}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function TimersPanel({ result }: { result: IgpResult<IgpHealthResponse> }) {
  const h = result.data;
  if (!h) return null;
  const view = timersView(h.timers, h.coverage?.timers ?? false, h.protocol);
  return (
    <Panel title="IGP timers">
      {!view.collected ? (
        <div className="empty igp-notwired" role="status">
          <span className="badge">Not collected</span> {view.note}
        </div>
      ) : (
        <>
          <table className="ds-table igp-timers">
            <thead>
              <tr>
                <th scope="col">{view.scopeHeading}</th>
                {view.kind === "adjacency" ? (
                  <>
                    <th scope="col">Interface</th>
                    <th scope="col">Level</th>
                    <th scope="col">Hold remaining</th>
                  </>
                ) : (
                  <>
                    <th scope="col">Hello</th>
                    <th scope="col">Dead</th>
                  </>
                )}
              </tr>
            </thead>
            <tbody>
              {view.rows.map((row) => (
                <tr key={`${row.device} ${row.scope}`}>
                  <td className="mono">{row.scope || "—"}</td>
                  {view.kind === "adjacency" ? (
                    <>
                      <td className="mono">{row.ifname || "—"}</td>
                      <td className="mono">{row.level || "—"}</td>
                      <td className="mono">{timerCell(row.hold_seconds)}</td>
                    </>
                  ) : (
                    <>
                      <td className="mono">{timerCell(row.hello_seconds)}</td>
                      <td className="mono">{timerCell(row.dead_seconds)}</td>
                    </>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
          {view.caveat && <p className="mini-meta igp-timer-caveat">{view.caveat}</p>}
        </>
      )}
    </Panel>
  );
}

// ── health block ────────────────────────────────────────────────────────────

function HealthBlock({ result }: { result: IgpResult<IgpHealthResponse> }) {
  const h = result.data;
  return (
    <Panel title="Device IGP health">
      <StateBlock result={result}>
        {h && (
          <>
            <StatStrip>
              <Stat label="Neighbours" value={countOrNotCollected(h.neighbor_count)} />
              <Stat
                label="Adjacencies up"
                value={countOrNotCollected(h.adjacencies_up)}
                tone={isMeasured(h.adjacencies_up) && h.adjacencies_up > 0 ? "good" : ""}
              />
              <Stat
                label="Adjacencies down"
                value={countOrNotCollected(h.adjacencies_down)}
                tone={isMeasured(h.adjacencies_down) && h.adjacencies_down > 0 ? "bad" : ""}
              />
              <Stat label="Flaps in window" value={String(h.flaps)} tone={h.flaps > 0 ? "warn" : ""} />
              <Stat label="Stability" value={h.stability ? h.stability.score.toFixed(1) : "—"} />
            </StatStrip>
            <div className="igp-depth-row">
              <DepthCount title="LSDB / LSP count" view={lsdbView(h.lsdb, h.coverage?.lsdb ?? false)} />
              <DepthCount title="SPF runs" view={spfView(h.spf_runs, h.coverage?.spf_runs ?? false)} />
            </div>
            {h.stability?.basis && <p className="mini-meta">{h.stability.basis}</p>}
            <table className="ds-table">
              <tbody>
                <tr>
                  <th scope="row">Device</th>
                  <td className="mono">{h.device_name || h.device}</td>
                </tr>
                <tr>
                  <th scope="row">{h.protocol === "isis" ? "IS-IS area addresses" : "OSPF areas"}</th>
                  {/* Area membership now has its own collected series. It is a
                      different fact from `levels` below, which is derived from
                      the adjacency labels — where this router HAS a neighbour. */}
                  <td>{areasView(h.areas, h.coverage?.areas ?? false).value}</td>
                </tr>
                <tr>
                  <th scope="row">{h.protocol === "isis" ? "Levels with an adjacency" : "Adjacency levels"}</th>
                  <td>{h.levels && h.levels.length ? h.levels.join(", ") : "not collected"}</td>
                </tr>
                <tr>
                  <th scope="row">Adjacency changes</th>
                  <td className="mono">{h.adjacency_changes}</td>
                </tr>
                <tr>
                  <th scope="row">Last change</th>
                  <td className="mono">{h.last_change || "none in window"}</td>
                </tr>
              </tbody>
            </table>
            {(h.notes ?? []).length > 0 && (
              <ul className="mini-meta igp-notes">
                {h.notes.map((n) => <li key={n}>{n}</li>)}
              </ul>
            )}
          </>
        )}
      </StateBlock>
    </Panel>
  );
}

// ── the view ────────────────────────────────────────────────────────────────

export interface IgpAdjacenciesProps {
  proto: IgpProto;
  /** Initial ?since= token. Must be one the server accepts (1m..7d). */
  defaultWindow?: string;
}

export default function IgpAdjacencies({ proto, defaultWindow = "24h" }: IgpAdjacenciesProps) {
  const [win, setWin] = useState<string>(defaultWindow);
  const [device, setDevice] = useState<string>("");
  const [devices, setDevices] = useState<Device[]>([]);

  const [adj, setAdj] = useState<IgpResult<IgpAdjacenciesResponse>>(igpLoading);
  const [sum, setSum] = useState<IgpResult<IgpSummaryResponse>>(igpLoading);
  const [health, setHealth] = useState<IgpResult<IgpHealthResponse>>(igpLoading);

  // The device picker reads the caller's OWN inventory; a device that is not in
  // it cannot be selected, and the server 404s it anyway.
  useEffect(() => {
    let alive = true;
    api.devices()
      .then((d) => { if (alive) setDevices(Array.isArray(d) ? d : []); })
      .catch(() => { if (alive) setDevices([]); }); // the picker degrades to "all devices"
    return () => { alive = false; };
  }, []);

  useEffect(() => {
    let alive = true;
    setAdj(igpLoading);
    setSum(igpLoading);
    Promise.resolve(api.igpAdjacencies(proto, { device: device || undefined, since: win }))
      .then((r) => { if (alive) setAdj(classifyAdjacencies(r)); })
      .catch((e) => { if (alive) setAdj(igpError(e)); });
    Promise.resolve(api.igpSummary(proto, { since: win }))
      .then((r) => { if (alive) setSum(classifySummary(r)); })
      .catch((e) => { if (alive) setSum(igpError(e)); });
    return () => { alive = false; };
  }, [proto, device, win]);

  useEffect(() => {
    if (!device) { setHealth(igpLoading); return; }
    let alive = true;
    setHealth(igpLoading);
    Promise.resolve(api.igpHealth(proto, device, { since: win }))
      .then((r) => { if (alive) setHealth(classifyHealth(r)); })
      .catch((e) => { if (alive) setHealth(igpError(e)); });
    return () => { alive = false; };
  }, [proto, device, win]);

  const payload = adj.data;
  const rows = useMemo(() => worstFirst(payload?.adjacencies ?? []), [payload]);
  const counts = useMemo(
    () => adjCounts(payload?.adjacencies, payload?.coverage?.live_series ?? false),
    [payload],
  );

  return (
    <div className="igp-view" data-proto={proto} data-state={adj.state}>
      <div className="igp-controls">
        <Segmented
          value={win}
          options={IGP_WINDOWS}
          onChange={setWin}
          ariaLabel={`${PROTO_LABEL[proto]} time window`}
        />
        <label className="igp-device-pick">
          <span className="mini-meta">Device</span>
          <select value={device} onChange={(e) => setDevice(e.target.value)} aria-label="Device">
            <option value="">All devices</option>
            {devices.map((d) => (
              <option key={d.id} value={d.id}>{d.name || d.id}</option>
            ))}
          </select>
        </label>
        {payload && (
          <span className="mini-meta">
            window {windowLabel(payload.window_seconds)} · evidence: {payload.source}
          </span>
        )}
      </div>

      <CoverageStrip coverage={payload?.coverage} notes={payload?.notes} />

      <StatStrip>
        <Stat label="Adjacencies reported" value={String(counts.reported)} />
        <Stat
          label="Up now"
          value={countOrNotCollected(counts.up)}
          tone={isMeasured(counts.up) && counts.up > 0 ? "good" : ""}
        />
        <Stat
          label="Down now"
          value={countOrNotCollected(counts.down)}
          tone={isMeasured(counts.down) && counts.down > 0 ? "bad" : ""}
        />
        <Stat label="Flaps in window" value={String(counts.flaps)} tone={counts.flaps > 0 ? "warn" : ""} />
      </StatStrip>

      <Panel title={`${PROTO_LABEL[proto]} adjacencies`}>
        <StateBlock result={adj}>
          <div className="ds-table-wrap">
            <table className="ds-table">
              <thead>
                <tr>
                  <th scope="col">Device</th>
                  <th scope="col">{PEER_LABEL[proto]}</th>
                  <th scope="col">Interface</th>
                  {proto === "isis" && <th scope="col">Level</th>}
                  <th scope="col">State</th>
                  {/* OSPF-MIB has no per-neighbour timer column, so this
                      column exists only where a per-adjacency timer can be
                      collected at all. */}
                  {proto === "isis" && <th scope="col">Hold remaining</th>}
                  <th scope="col">Flaps</th>
                  <th scope="col">Last change</th>
                  <th scope="col">Timeline (oldest → newest)</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((a) => (
                  <tr key={adjKey(a)} data-tone={adjTone(a)} data-source={a.state_source}>
                    <td className="mono">{a.device}</td>
                    <td className="mono">{a.peer || "—"}</td>
                    <td className="mono">{a.ifname || "—"}</td>
                    {proto === "isis" && <td>{a.level || "—"}</td>}
                    <td>
                      <span className="igp-state" data-tone={adjTone(a)}>{currentStateLabel(a)}</span>{" "}
                      <span className="mini-meta">({stateSourceLabel(a)})</span>
                    </td>
                    {proto === "isis" && <td className="mono">{holdLabel(a)}</td>}
                    <td className="mono">{a.flaps}</td>
                    <td className="mono">{a.last_change || "—"}</td>
                    <td><Timeline ticks={timelineTicks(a)} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {payload?.truncated && (
            <p className="mini-meta">
              This page is truncated at {payload.limit} events — the window holds more.
            </p>
          )}
          {(payload?.notes ?? []).length > 0 && (
            <ul className="mini-meta igp-notes">
              {payload!.notes.map((n) => <li key={n}>{n}</li>)}
            </ul>
          )}
        </StateBlock>
        <p className="mini-meta">
          <strong>{PROTO_LABEL[proto]} state</strong>: {PROTO_STATES[proto]}
        </p>
      </Panel>

      {device && <HealthBlock result={health} />}
      {device && <TimersPanel result={health} />}

      <Panel title={`${PROTO_LABEL[proto]} roll-up by device (worst first)`}>
        <StateBlock result={sum}>
          <div className="ds-table-wrap">
            <table className="ds-table">
              <thead>
                <tr>
                  <th scope="col">Device</th>
                  <th scope="col">Adjacencies</th>
                  <th scope="col">Down</th>
                  <th scope="col">Flaps</th>
                  <th scope="col">Changes</th>
                  <th scope="col">LSDB</th>
                  <th scope="col">SPF runs</th>
                  <th scope="col">{proto === "isis" ? "Area addresses" : "Areas"}</th>
                  <th scope="col">Last change</th>
                </tr>
              </thead>
              <tbody>
                {(sum.data?.devices ?? []).map((d) => (
                  <tr key={d.device}>
                    <td className="mono">{d.device}</td>
                    <td className="mono">{countOrNotCollected(d.adjacencies)}</td>
                    <td
                      className="mono"
                      data-tone={isMeasured(d.down_adjacencies) && d.down_adjacencies > 0 ? "bad" : ""}
                    >
                      {countOrNotCollected(d.down_adjacencies)}
                    </td>
                    <td className="mono">{d.flaps}</td>
                    <td className="mono">{d.changes}</td>
                    {/* Per device, not per fleet: a router that reports no LSDB
                        series says "not collected" on its own row while its
                        neighbour shows a real count. */}
                    <td className="mono">{countOrNotCollected(d.lsp_count)}</td>
                    <td className="mono">{countOrNotCollected(d.spf_runs)}</td>
                    <td className="mono">{areasCell(d.areas)}</td>
                    <td className="mono">{d.last_change || "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {sum.data?.truncated && (
            <p className="mini-meta">
              This roll-up is partial — see the notes below for what it covers.
            </p>
          )}
          {(sum.data?.notes ?? []).length > 0 && (
            <ul className="mini-meta igp-notes">
              {sum.data!.notes.map((n) => <li key={n}>{n}</li>)}
            </ul>
          )}
        </StateBlock>
      </Panel>
    </div>
  );
}
