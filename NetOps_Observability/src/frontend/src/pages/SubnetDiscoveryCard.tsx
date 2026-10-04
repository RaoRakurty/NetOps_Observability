// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// SubnetDiscoveryCard — the ONE subnet-discovery screen (Administration → Data
// sources → Subnet Discovery, #/admin/discovery). Platform-operated: every
// route behind it (/api/discovery/config, /api/discovery/refresh) is
// requireCrossTenant on the server.
//
// SNMP credentials live in ONE place — SNMP Profiles (#/admin/snmp,
// /api/snmp/credentials). Discovery has no community of its own: the sweep tries
// the platform-owned profiles (v1/v2c and v3) in profile-name order per host
// until one answers, and binds each found device to the profile that answered.
// A PUT carrying `community` is refused 400, so this card never sends one.
//
// The workflow is shown as three numbered steps (credentials → subnets → turn
// on), then the results: the sweep stats and the devices it found, each with
// the profile that answered.

import { fmtDate } from "../lib/time";
import { useCallback, useEffect, useState } from "react";
import { api, DiscoveryConfig, DiscoveryConfigEnvelope, DiscoveryFoundDevice } from "../services/api";
import { StatStrip, Stat, InfoTip } from "../components/ui";
import { httpFailure, operatorError } from "../lib/errors";
import AskIris from "../components/AskIris";

// scopeCount mirrors the server's range-expansion math (display only — the
// server re-validates): each valid IPv4 CIDR contributes 2^(32-prefix)
// addresses toward the scan budget. Unparseable tokens are reported so the
// meter can flag them before a round-trip.
export function scopeCount(text: string): { total: number; invalid: string | null } {
  let total = 0;
  for (const raw of text.split(",")) {
    const t = raw.trim();
    if (!t) continue;
    const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/.exec(t);
    if (!m || m.slice(1, 5).some((o) => Number(o) > 255) || Number(m[5]) > 32) {
      return { total, invalid: t };
    }
    total += 2 ** (32 - Number(m[5]));
  }
  return { total, invalid: null };
}

// relSweepTime renders a sweep timestamp for operators: relative when recent,
// "never" for the zero time a fresh process reports.
function relSweepTime(iso?: string): string {
  if (!iso) return "never";
  const t = new Date(iso).getTime();
  if (!isFinite(t) || t < 86_400_000) return "never"; // zero-time from a fresh process
  const age = Date.now() - t;
  if (age < 60_000) return "just now";
  if (age < 3_600_000) return `${Math.round(age / 60_000)} min ago`;
  if (age < 86_400_000) return `${Math.round(age / 3_600_000)} h ago`;
  return fmtDate(iso);
}

const plural = (n: number, one: string, many: string) => (n === 1 ? one : many);

// profileSummary states, in plain words, which SNMP profiles the next sweep
// will try. Null when the server did not say (older api) — the step then just
// points at SNMP Profiles without inventing a count.
function profileSummary(p: DiscoveryConfigEnvelope["scan_profiles"]): string | null {
  if (!p || p.total <= 0) return null;
  const parts: string[] = [];
  if (p.v2c > 0) parts.push(`${p.v2c} v2c`);
  if (p.v3 > 0) parts.push(`${p.v3} v3`);
  const mix = parts.length ? ` (${parts.join(", ")})` : "";
  return `${p.total} SNMP ${plural(p.total, "profile", "profiles")} will be tried${mix}, in name order.`;
}

export default function SubnetDiscoveryCard() {
  const [cfg, setCfg] = useState<DiscoveryConfig | null>(null);
  const [limits, setLimits] = useState<DiscoveryConfigEnvelope["limits"]>();
  const [stats, setStats] = useState<DiscoveryConfigEnvelope["stats"]>();
  const [profiles, setProfiles] = useState<DiscoveryConfigEnvelope["scan_profiles"]>();
  const [found, setFound] = useState<DiscoveryFoundDevice[]>([]);
  const [unavailable, setUnavailable] = useState<string | null>(null);
  // credential_ref → profile name, for the "Answered with" column. Best effort:
  // when the profile list cannot be read the column shows the raw reference.
  const [profileNames, setProfileNames] = useState<Record<string, string>>({});
  const [enabled, setEnabled] = useState(false);
  const [ranges, setRanges] = useState("");
  const [allowNonPrivate, setAllowNonPrivate] = useState(false);
  const [saving, setSaving] = useState(false);
  const [msg, setMsg] = useState<{ kind: "ok" | "err"; text: string } | null>(null);
  const [denied, setDenied] = useState(false);
  // A 500 is not a 403. Rendering every failure as "you are not authorized" gives
  // the operator the one explanation they will never investigate — so an outage
  // in the discovery config store looked like a deliberate permission boundary.
  const [loadErr, setLoadErr] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const env = await api.discoveryConfig();
      setCfg(env.config);
      setLimits(env.limits);
      setStats(env.stats);
      setProfiles(env.scan_profiles);
      setFound(env.found ?? []);
      setUnavailable(env.config_unavailable ? env.config_error || "The saved discovery settings could not be read." : null);
      setEnabled(env.config.enabled);
      setRanges(env.config.ranges.join(", "));
      setAllowNonPrivate(env.config.allow_non_private);
      setDenied(false);
      setLoadErr(null);
    } catch (e) {
      const text = operatorError(e, "Discovery settings could not be reached.");
      const status = httpFailure(e)?.status;
      if (status === 401 || status === 403) {
        // Refused by design for a non-platform principal — the page shows the
        // tenant explanation instead; never render a form that can only fail.
        setDenied(true);
        setLoadErr(null);
      } else {
        setLoadErr(text);
      }
    }
  }, []);

  useEffect(() => {
    load();
    api
      .listSnmpCreds()
      .then((list) => {
        const m: Record<string, string> = {};
        for (const c of list ?? []) if (c.id) m[c.id] = c.name;
        setProfileNames(m);
      })
      .catch(() => setProfileNames({})); // column falls back to the reference itself
  }, [load]);

  if (denied) return null;
  if (loadErr && !cfg) {
    return (
      <div className="cc-panel" role="alert" style={{ padding: "11px 13px" }}>
        <strong style={{ color: "var(--bad)" }}>Discovery settings could not be loaded.</strong>
        <div style={{ marginTop: 4, fontSize: 14 }}>{loadErr}</div>
      </div>
    );
  }
  if (!cfg) return null;

  const save = async () => {
    setSaving(true);
    setMsg(null);
    try {
      const env = await api.saveDiscoveryConfig({
        enabled,
        ranges: ranges.split(",").map((r) => r.trim()).filter(Boolean),
        allow_non_private: allowNonPrivate,
      });
      setCfg(env.config);
      setRanges(env.config.ranges.join(", "));
      setMsg({ kind: "ok", text: enabled ? "Saved. A scan has been scheduled." : "Saved. Scanning is off." });
      await load(); // pick up the fresh profile counts and results
    } catch (e) {
      setMsg({ kind: "err", text: operatorError(e, "The discovery settings could not be saved.") });
    } finally {
      setSaving(false);
    }
  };

  const scanNow = async () => {
    try {
      await api.refreshDiscovery();
      setMsg({ kind: "ok", text: "Scan scheduled. Scan now runs at most once a minute." });
    } catch (e) {
      setMsg({ kind: "err", text: operatorError(e, "The scan could not be started.") });
    }
  };

  const maxHosts = limits?.max_hosts ?? 4096;
  const scope = scopeCount(ranges);
  const over = scope.total > maxHosts;
  const noProfiles = profiles != null && profiles.total <= 0;
  const summary = profileSummary(profiles);
  const state: { cls: string; label: string } = !cfg.enabled
    ? { cls: "off", label: "Off" }
    : stats?.last_error || noProfiles || unavailable
    ? { cls: "warn", label: "Needs attention" }
    : { cls: "on", label: "Active" };

  return (
    <div className="card disc-card" style={{ marginBottom: 16 }}>
      <div className="disc-head">
        <div>
          <div className="disc-title-row">
            <h2 className="disc-title">Subnet discovery</h2>
            <span className={`disc-state ${state.cls}`}>
              <span className="disc-dot" aria-hidden />
              {state.label}
            </span>
          </div>
          <p className="disc-desc">Find SNMP devices on your subnets and add them to Devices.</p>
        </div>
      </div>

      {unavailable && (
        <div className="disc-refusal" role="alert">
          <b>Settings unreadable</b>
          <span>{unavailable}</span>
        </div>
      )}

      <ol className="disc-steps" aria-label="Set up subnet discovery">
        <li className="disc-step">
          <span className="disc-step-num" aria-hidden>1</span>
          <div className="disc-step-body">
            <h3 className="disc-step-title">Add SNMP credentials</h3>
            {noProfiles ? (
              <div className="disc-refusal" role="alert">
                <b>No SNMP profiles</b>
                <span>Nothing can be found until you add one.</span>
              </div>
            ) : (
              <p className="disc-text">
                {summary ?? "Discovery tries your SNMP profiles in name order."}
              </p>
            )}
            <a className="disc-link" href="#/admin/snmp">
              {noProfiles ? "Add an SNMP profile" : "Open SNMP Profiles"}
            </a>{" "}
            <AskIris topic="discovery.snmp-profiles" label="which credentials are tried" />
          </div>
        </li>

        <li className="disc-step">
          <span className="disc-step-num" aria-hidden>2</span>
          <div className="disc-step-body">
            <h3 className="disc-step-title">Choose subnets</h3>
            <label className="disc-field">
              <span>Subnets to scan, comma-separated</span>
              <input
                className="mono"
                value={ranges}
                onChange={(e) => setRanges(e.target.value)}
                placeholder="10.20.0.0/24, 10.30.5.0/26"
                spellCheck={false}
              />
            </label>
            <div className={`disc-meter${over ? " over" : ""}`}>
              <div className="disc-meter-track">
                <div
                  className="disc-meter-fill"
                  style={{ width: `${Math.min(100, (scope.total / maxHosts) * 100)}%` }}
                />
              </div>
              <span className="disc-meter-read">
                {scope.invalid
                  ? `"${scope.invalid}" is not a subnet like 10.0.0.0/24`
                  : `${scope.total.toLocaleString()} / ${maxHosts.toLocaleString()} addresses`}
              </span>
            </div>
            <div className="disc-switches">
              <label className="uf-switch">
                <input
                  type="checkbox"
                  checked={allowNonPrivate}
                  onChange={(e) => setAllowNonPrivate(e.target.checked)}
                />
                <span className="uf-switch-track" aria-hidden />
                <span>Allow public address ranges</span>
              </label>
              <InfoTip label="About public address ranges">
                Only for networks that use public addresses internally. Loopback,
                link-local and multicast stay blocked either way.
              </InfoTip>
            </div>
          </div>
        </li>

        <li className="disc-step">
          <span className="disc-step-num" aria-hidden>3</span>
          <div className="disc-step-body">
            <h3 className="disc-step-title">Turn on scanning</h3>
            <div className="disc-switches">
              <label className="uf-switch">
                <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
                <span className="uf-switch-track" aria-hidden />
                <span>Scanning on</span>
              </label>
              <button className="btn primary" onClick={save} disabled={saving || over || !!scope.invalid}>
                {saving ? "Saving…" : "Save"}
              </button>
              <button
                className="btn"
                onClick={scanNow}
                disabled={!cfg.enabled}
                title={cfg.enabled ? "Scan now" : "Turn scanning on and save first"}
              >
                Scan now
              </button>
            </div>
            {msg && <p className={`disc-msg ${msg.kind}`} role={msg.kind === "err" ? "alert" : "status"}>{msg.text}</p>}
          </div>
        </li>
      </ol>

      <h3 className="disc-results-title">Results</h3>
      <StatStrip>
        <Stat label="Last scan" value={relSweepTime(stats?.last_poll)} />
        <Stat
          label="Devices found"
          value={stats?.devices ?? found.length}
          tone={(stats?.devices ?? found.length) > 0 ? "good" : ""}
        />
        <Stat
          label={cfg.ranges.length === 1 ? "Subnet scanned" : "Subnets scanned"}
          value={cfg.ranges.length}
          tone={cfg.ranges.length ? "accent" : ""}
        />
      </StatStrip>
      {stats?.last_error && (
        <div className="disc-refusal" role="alert">
          <b>Last scan stopped</b>
          <span>{stats.last_error}</span>
        </div>
      )}

      {found.length === 0 ? (
        <div className="empty">No devices found yet.</div>
      ) : (
        <table aria-label="Devices found">
          <thead>
            <tr>
              <th>Name</th>
              <th>Address</th>
              <th>Vendor</th>
              <th>Answered with</th>
            </tr>
          </thead>
          <tbody>
            {found.map((d) => (
              <tr key={d.id} className="dt-row">
                <td>{d.name || d.id}</td>
                <td className="mono">{d.address}</td>
                <td>{d.vendor || "—"}</td>
                <td>{d.credential_ref ? profileNames[d.credential_ref] ?? d.credential_ref : "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <div className="disc-foot">
        <span>
          Scans every 5 minutes while on · Scan now runs at most once a minute · up to{" "}
          <span className="mono">{limits?.max_ranges ?? 32}</span> subnets,{" "}
          <span className="mono">{maxHosts.toLocaleString()}</span> addresses
        </span>
      </div>
    </div>
  );
}
