import { useEffect, useMemo, useState } from "react";
import { api, Device, VrfInterface, VrfInterfaceGroup, VrfInterfacesResponse } from "../../services/api";
import { vrfTermPlural } from "../../lib/vendorTerms";
import { operatorError } from "../../lib/errors";
import {
  PANEL_SOURCE,
  coverageHeadline,
  dialectFootnote,
  fmtErrRate,
  fmtPct,
  fmtRate,
  groupHeading,
  groupKey,
  groupSummary,
  initiallyOpen,
  panelState,
  panelTitle,
  rowTone,
} from "./vrfInterfacesModel";

// VrfInterfaces — the "Interfaces by routing instance" tab of the device page
// (frontend-wave item 4). One read: GET /api/devices/{id}/interfaces/by-vrf.
//
// The panel's job is as much to be HONEST as to be useful. On today's telemetry
// no interface series carries a routing-instance label on either transport, so
// the API returns every interface in one ungrouped bucket and says why — and
// this panel shows that sentence FIRST, above the tables. It never labels the
// bucket "default": that would be a claim about the device that nothing we
// collect supports. The day a deployment does collect the binding, the same
// component renders real groups with no code change.

const WINDOWS: { id: string; label: string }[] = [
  { id: "5m", label: "5 min" },
  { id: "15m", label: "15 min" },
  { id: "1h", label: "1 hour" },
  { id: "24h", label: "24 hours" },
];

const th: React.CSSProperties = {
  textAlign: "left", fontSize: 11, textTransform: "uppercase", letterSpacing: ".04em",
  color: "var(--fg-muted)", padding: "4px 12px", fontWeight: 600,
};
const td: React.CSSProperties = {
  padding: "5px 12px", fontSize: 12.5, borderTop: "1px solid var(--panel-border, var(--border))",
};
const mono: React.CSSProperties = { ...td, fontFamily: "var(--font-mono)" };
const num: React.CSSProperties = { ...td, textAlign: "right", fontVariantNumeric: "tabular-nums" };

const TONE_COLOR: Record<string, string> = {
  good: "var(--good)", bad: "var(--bad)", warn: "var(--warn, #f59e0b)", "": "var(--fg-muted)",
};

function StateDot({ tone }: { tone: string }) {
  return (
    <span
      aria-hidden
      style={{
        display: "inline-block", width: 8, height: 8, borderRadius: 999, marginRight: 8, flex: "none",
        background: TONE_COLOR[tone] ?? TONE_COLOR[""],
        // No measurement → a hollow dot, so "unknown" never reads as healthy.
        boxShadow: tone === "" ? "inset 0 0 0 1px var(--fg-muted)" : undefined,
        opacity: tone === "" ? 0.5 : 1,
      }}
    />
  );
}

function InterfaceRow({ iface }: { iface: VrfInterface }) {
  const tone = rowTone(iface);
  return (
    <tr>
      <td style={mono}>
        {iface.ifname}
        {iface.ifalias ? <span className="fact-line" style={{ marginLeft: 8 }}>{iface.ifalias}</span> : null}
      </td>
      <td style={td}><StateDot tone={tone} />{iface.oper}</td>
      <td style={td}>{iface.admin}</td>
      <td style={num}>{fmtRate(iface.in_bps)}</td>
      <td style={num}>{fmtPct(iface.in_util_pct)}</td>
      <td style={num}>{fmtRate(iface.out_bps)}</td>
      <td style={num}>{fmtPct(iface.out_util_pct)}</td>
      <td style={num}>{fmtErrRate(iface.in_errors_per_s)}</td>
      <td style={num}>{fmtErrRate(iface.out_errors_per_s)}</td>
    </tr>
  );
}

function GroupTable({ members }: { members: VrfInterface[] }) {
  return (
    <div style={{ overflowX: "auto" }}>
      <table style={{ width: "100%", borderCollapse: "collapse" }}>
        <thead>
          <tr>
            <th style={th}>Interface</th>
            <th style={th}>Oper</th>
            <th style={th}>Admin</th>
            <th style={{ ...th, textAlign: "right" }}>In</th>
            <th style={{ ...th, textAlign: "right" }}>In util</th>
            <th style={{ ...th, textAlign: "right" }}>Out</th>
            <th style={{ ...th, textAlign: "right" }}>Out util</th>
            <th style={{ ...th, textAlign: "right" }}>In errors</th>
            <th style={{ ...th, textAlign: "right" }}>Out errors</th>
          </tr>
        </thead>
        <tbody>
          {members.map((m) => <InterfaceRow key={m.ifname} iface={m} />)}
        </tbody>
      </table>
    </div>
  );
}

function Group({
  group, heading, open, onToggle,
}: { group: VrfInterfaceGroup; heading: string; open: boolean; onToggle: () => void }) {
  return (
    <div className="cc-panel" style={{ marginBottom: 12 }}>
      <button
        type="button"
        className="cc-panel-h"
        aria-expanded={open}
        onClick={onToggle}
        style={{
          display: "flex", alignItems: "center", gap: 10, width: "100%", background: "none",
          border: "none", textAlign: "left", cursor: "pointer", padding: "8px 12px",
        }}
      >
        <span aria-hidden style={{ fontSize: 11, color: "var(--fg-muted)" }}>{open ? "▾" : "▸"}</span>
        <h3 className="cc-panel-t" style={{ margin: 0 }}>{heading}</h3>
        {group.membership === "not_collected" && (
          <span className="badge" style={{ fontSize: 10, textTransform: "uppercase" }}>not collected</span>
        )}
        <span className="cc-panel-meta" style={{ marginLeft: "auto" }}>{groupSummary(group)}</span>
      </button>
      {open && <GroupTable members={group.members} />}
    </div>
  );
}

export default function VrfInterfaces({ device }: { device: Device }) {
  const [data, setData] = useState<VrfInterfacesResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [window_, setWindow] = useState("5m");
  const [open, setOpen] = useState<Record<string, boolean>>({});
  const id = device.id;

  useEffect(() => {
    let alive = true;
    setLoading(true);
    setError(null);
    api.deviceInterfacesByVrf(id, window_)
      .then((r) => {
        if (!alive) return;
        setData(r);
        setOpen(initiallyOpen(r.groups ?? []));
      })
      .catch((e: unknown) => {
        if (!alive) return;
        setData(null);
        setError(operatorError(e, "Interface data could not be loaded."));
      })
      .finally(() => { if (alive) setLoading(false); });
    return () => { alive = false; };
  }, [id, window_]);

  const result = useMemo(() => panelState(loading, error, data), [loading, error, data]);
  // Heading falls back to the frontend dialect library until the server answers,
  // so the tab never flashes a word that is wrong for this vendor.
  const title = data ? panelTitle(data.dialect) : `Interfaces by ${vrfTermPlural(device.vendor).replace(/s$/, "")}`;
  const footnote = data ? dialectFootnote(data.dialect) : null;

  return (
    <div style={{ maxWidth: 1200 }} data-testid="vrf-interfaces">
      <div style={{ display: "flex", alignItems: "baseline", gap: 12, marginBottom: 10, flexWrap: "wrap" }}>
        <h2 style={{ margin: 0, fontSize: 16 }}>{title}</h2>
        <span className="fact-line" style={{ fontFamily: "var(--font-mono)" }}>{PANEL_SOURCE}</span>
        <div role="group" aria-label="Rate window" style={{ marginLeft: "auto", display: "flex", gap: 4 }}>
          {WINDOWS.map((w) => (
            <button
              key={w.id}
              type="button"
              className={window_ === w.id ? "on" : ""}
              aria-pressed={window_ === w.id}
              onClick={() => setWindow(w.id)}
              style={{ fontSize: 11, padding: "2px 8px" }}
            >
              {w.label}
            </button>
          ))}
        </div>
      </div>

      {/* Coverage strip — read before the tables. It is deliberately ABOVE the
          data: what the platform cannot see is part of the answer. */}
      {data && (
        <div
          className="cc-panel"
          data-testid="vrf-coverage"
          style={{ marginBottom: 12, padding: "10px 12px", fontSize: 12.5 }}
        >
          <div>{coverageHeadline(data.coverage, data.dialect)}</div>
          <ul className="fact-line" style={{ margin: "6px 0 0", paddingLeft: 18 }}>
            {data.coverage.notes.map((n, i) => <li key={i}>{n}</li>)}
          </ul>
          {footnote && <div className="fact-line" style={{ marginTop: 6 }}>{footnote}</div>}
          {data.routing_instances.length > 0 && (
            <div className="fact-line" style={{ marginTop: 6 }}>
              {data.dialect.term_plural} this device reports on its BGP control plane:{" "}
              <span style={{ fontFamily: "var(--font-mono)" }}>
                {data.routing_instances.map((ri) => ri.name).join(", ")}
              </span>
              {" — that lane carries the instance name but not its interface membership."}
            </div>
          )}
        </div>
      )}

      {result.state === "loading" && <div className="empty" data-testid="vrf-state-loading">Loading…</div>}
      {result.state === "error" && (
        <div className="empty" data-testid="vrf-state-error" role="alert">
          Interfaces could not be read: {result.note}
        </div>
      )}
      {result.state === "not_connected" && (
        <div className="empty" data-testid="vrf-state-not_connected">{result.note}</div>
      )}
      {result.state === "empty" && (
        <div className="empty" data-testid="vrf-state-empty">{result.note}</div>
      )}
      {result.state === "ready" && data && (
        <div data-testid="vrf-state-ready">
          {data.groups.map((g, i) => {
            const key = groupKey(g, i);
            return (
              <Group
                key={key}
                group={g}
                heading={groupHeading(g, data.dialect)}
                open={open[key] ?? true}
                onToggle={() => setOpen((prev) => ({ ...prev, [key]: !(prev[key] ?? true) }))}
              />
            );
          })}
        </div>
      )}
    </div>
  );
}
