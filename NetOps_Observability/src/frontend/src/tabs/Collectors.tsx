// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { fmtDateTime } from "../lib/time";
import { useEffect, useState } from "react";
import { api, CollectorStatus, type PlatformFeature } from "../services/api";
import { operatorError } from "../lib/errors";
import { useFeatureSwitches } from "../pages/platform/useFeatureSwitches";
// Friendly display names for collector ids. Unknown ids fall back to the raw
// name uppercased, so new collectors still render sensibly.
const COLLECTOR_LABELS: Record<string, string> = {
  snmpv2c: "SNMP v2c",
  snmpv3: "SNMP v3",
  snmpmetrics: "SNMP metrics",
  gnmi: "gNMI",
  netconf: "NETCONF",
  snmptrap: "SNMP traps",
  tunnels: "Tunnels",
};

// Which platform switch turns each collector on (internal/featureflags/specs.go;
// every one applies after a restart and none is licence-gated). The two SNMP
// transports share one switch.
export const COLLECTOR_SWITCH: Record<string, string> = {
  snmpv2c: "ENABLE_SNMP_COLLECTION",
  snmpv3: "ENABLE_SNMP_COLLECTION",
  snmpmetrics: "ENABLE_SNMP_METRICS",
  gnmi: "ENABLE_GNMI_COLLECTION",
  netconf: "ENABLE_NETCONF_COLLECTION",
  snmptrap: "FEATURE_SNMP_TRAPS",
};

/** What a switch is doing now: the RUNNING value, or what it becomes after the restart. */
export function switchState(f: PlatformFeature): string {
  if (f.restart_pending) return f.desired ? "On after restart" : "Off after restart";
  return f.running ? "On" : "Off";
}

function collectorLabel(name: string): string {
  return COLLECTOR_LABELS[name] ?? name.toUpperCase();
}

// Heat class for a poll-duration cell: fast=ok, sluggish=warn, slow=bad.
function pollClass(ms?: number): string {
  if (ms == null) return "";
  if (ms < 500) return "cell-ok";
  if (ms < 2000) return "cell-warn";
  return "cell-bad";
}

// Heat class for the reachable/targets cell.
function reachClass(c: CollectorStatus): string {
  if (c.targets === 0) return "";
  if ((c.reachable ?? 0) === 0) return "cell-bad";
  if ((c.reachable ?? 0) < c.targets) return "cell-warn";
  return "cell-ok";
}

export default function Collectors() {
  const [items, setItems] = useState<CollectorStatus[]>([]);
  const [err, setErr] = useState<string | null>(null);
  // The switches are platform-global (requirePlatformAdmin). This page is
  // already platform-only; a 403 simply leaves the Switch column out.
  const sw = useFeatureSwitches();
  const features = sw.load.kind === "ready" ? sw.load.data : null;
  const featureByEnv = new Map((features?.features ?? []).map((f) => [f.env, f]));

  useEffect(() => {
    let alive = true;
    const tick = async () => {
      try {
        const c = await api.collectors();
        // This tab shows the transport/protocol collectors plus the SNMP trap
        // receiver (kind "trap": targets = traps received, reachable = decoded).
        // Feature collectors (e.g. tunnel discovery, kind "discovery") have their
        // own views and are filtered out here.
        if (alive) setItems((c ?? []).filter((x) => ["protocol", "trap"].includes(x.kind ?? "protocol")));
      } catch (e) {
        if (alive) setErr(operatorError(e, "The collector list could not be loaded."));
      }
    };
    tick();
    const id = setInterval(tick, 10000);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, []);

  const enabled = items.filter((c) => c.enabled);
  const healthy = enabled.filter((c) => c.healthy).length;
  const totalTargets = items.reduce((n, c) => n + c.targets, 0);
  const totalReachable = items.reduce((n, c) => n + (c.reachable ?? 0), 0);
  const reachAccent =
    totalTargets === 0
      ? "s-muted"
      : totalReachable === 0
      ? "s-bad"
      : totalReachable < totalTargets
      ? "s-warn"
      : "s-good";

  const switchCell = (env: string | undefined) => {
    const f = env ? featureByEnv.get(env) : undefined;
    if (!f) return <td>—</td>;
    const next = !f.desired;
    return (
      <td>
        <span className="sensor-switch">
          <span className={`badge ${f.running ? "good" : "warn"}`}>{switchState(f)}</span>
          <button className="btn" disabled={sw.busy !== null || sw.restart.kind === "restarting"}
            onClick={() => void sw.save(f.env, next, false)} aria-label={`${next ? "Turn on" : "Turn off"} ${f.label}`}>
            {next ? "Turn on" : "Turn off"}
          </button>
        </span>
        {sw.rowError?.env === f.env && <div role="alert" style={{ color: "var(--bad)" }}>{sw.rowError.message}</div>}
      </td>
    );
  };
  // A collector that is switched off may not register at all: its switch
  // still needs a row, or there is nothing to turn back on. (A switch that IS
  // running with no row of its own reports under another collector.)
  const shownEnvs = new Set(items.map((c) => COLLECTOR_SWITCH[c.name]).filter(Boolean));
  const offOnly = features ? [...new Set(Object.values(COLLECTOR_SWITCH))].filter((env) => !shownEnvs.has(env) && featureByEnv.has(env)) : [];

  return (
    <div className="card">
      <h2>Collectors</h2>
      {features && (features.restart_pending || sw.restart.kind !== "idle") && (
        <div className="cc-panel" data-testid="sensor-restart-banner" style={{ padding: "10px 12px", marginBottom: 12, display: "flex", gap: 12, alignItems: "center", flexWrap: "wrap" }}>
          {sw.restart.kind === "restarting" ? (
            <span>Restarting Correlix… this page will update when it is back.</span>
          ) : sw.restart.kind === "done" ? (
            <span>Correlix restarted. The new settings are running.</span>
          ) : sw.restart.kind === "failed" ? (
            <span role="alert">{sw.restart.message}</span>
          ) : features.can_restart ? (
            <>
              <span>A change applies after a restart.</span>
              <button className="btn accent" onClick={() => void sw.requestRestart()}>Restart now</button>
            </>
          ) : (
            <span>A change applies after a restart. Restart the Correlix service from the host.</span>
          )}
        </div>
      )}
      {err && <p style={{ color: "var(--bad)" }}>{err}</p>}

      <div className="stat-grid" style={{ marginBottom: 18 }}>
        <div className="stat s-accent">
          <span className="stat-label">Collectors</span>
          <span className="stat-value">{items.length}</span>
          <span className="stat-foot">registered</span>
        </div>
        <div className={`stat ${enabled.length ? "s-good" : "s-muted"}`}>
          <span className="stat-label">Enabled</span>
          <span className="stat-value">{enabled.length}</span>
          <span className="stat-foot">of {items.length}</span>
        </div>
        <div
          className={`stat ${
            enabled.length === 0
              ? "s-muted"
              : healthy === enabled.length
              ? "s-good"
              : "s-bad"
          }`}
        >
          <span className="stat-label">Healthy</span>
          <span className="stat-value">{healthy}</span>
          <span className="stat-foot">of {enabled.length} enabled</span>
        </div>
        <div className={`stat ${reachAccent}`}>
          <span className="stat-label">Targets reachable</span>
          <span className="stat-value">
            {totalReachable}
            <span style={{ fontSize: 20, color: "var(--muted)" }}>
              /{totalTargets}
            </span>
          </span>
          <span className="stat-foot">across all collectors</span>
        </div>
      </div>

      {items.length === 0 && offOnly.length === 0 ? (
        <div className="empty">No collectors registered.</div>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Enabled</th>
              <th>Healthy</th>
              <th className="num">Targets</th>
              <th className="num">Reachable</th>
              <th className="num">Last poll</th>
              <th>Last tick</th>
              {features && <th>Switch</th>}
            </tr>
          </thead>
          <tbody>
            {items.map((c) => (
              <tr key={c.name} className="dt-row">
                <td>{collectorLabel(c.name)}</td>
                <td>
                  <span className={`badge ${c.enabled ? "good" : "warn"}`}>
                    {c.enabled ? "on" : "off"}
                  </span>
                </td>
                <td>
                  <span className={`badge ${c.healthy ? "good" : "bad"}`}>
                    {c.healthy ? "ok" : "fail"}
                  </span>
                </td>
                <td className="num">{c.targets}</td>
                <td
                  className={`num ${reachClass(c)}`}
                  title={c.last_error || undefined}
                >
                  {c.targets > 0 ? `${c.reachable ?? 0}/${c.targets}` : "—"}
                </td>
                <td className={`num ${pollClass(c.last_poll_ms)}`}>
                  {c.last_poll_ms != null ? `${c.last_poll_ms} ms` : "—"}
                </td>
                <td>
                  {c.last_tick ? fmtDateTime(c.last_tick) : "—"}
                </td>
                {features && switchCell(COLLECTOR_SWITCH[c.name])}
              </tr>
            ))}
            {offOnly.map((env) => (
              <tr key={env} className="dt-row" data-testid={`sensor-off-${env}`}>
                <td>{featureByEnv.get(env)?.label}</td>
                {/* No collector row of its own: when its switch runs, the work
                    reports under another collector — never claim "off" here. */}
                <td>{featureByEnv.get(env)?.running ? <span className="badge">no separate status</span> : <span className="badge warn">off</span>}</td>
                <td>—</td>
                <td className="num">—</td>
                <td className="num">—</td>
                <td className="num">—</td>
                <td>—</td>
                {switchCell(env)}
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
