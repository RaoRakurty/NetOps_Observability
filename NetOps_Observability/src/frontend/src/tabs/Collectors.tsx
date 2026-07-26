import { fmtDate, fmtDateTime } from "../lib/time";
import { useEffect, useState } from "react";
import { api, CollectorStatus, DiscoveryConfig, DiscoveryConfigEnvelope } from "../services/api";
import { StatStrip, Stat, InfoTip } from "../components/ui";

// Friendly display names for collector ids. Unknown ids fall back to the raw
// name uppercased, so new collectors still render sensibly.
const COLLECTOR_LABELS: Record<string, string> = {
  snmpv2c: "SNMP v2c",
  snmpv3: "SNMP v3",
  snmpmetrics: "SNMP metrics",
  gnmi: "gNMI",
  netconf: "NETCONF",
  tunnels: "Tunnels",
};

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

// scopeCount mirrors the server's range-expansion math (display only — the
// server re-validates): each valid IPv4 CIDR contributes 2^(32-prefix)
// addresses toward the scan budget. Unparseable tokens are reported so the
// meter can flag them before a round-trip.
function scopeCount(text: string): { total: number; invalid: string | null } {
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

// Subnet discovery configuration (platform-owner). Scopes the SNMP prober:
// which private CIDR ranges it may sweep, with what community, how often.
// Guardrails mirror the server's: private (RFC 1918) IPv4 ranges only, bounded
// expansion — the server refuses anything wider, this card just explains it.
function DiscoveryCard() {
  const [cfg, setCfg] = useState<DiscoveryConfig | null>(null);
  const [limits, setLimits] = useState<DiscoveryConfigEnvelope["limits"]>();
  const [stats, setStats] = useState<DiscoveryConfigEnvelope["stats"]>();
  const [enabled, setEnabled] = useState(false);
  const [ranges, setRanges] = useState("");
  const [community, setCommunity] = useState("");
  const [allowNonPrivate, setAllowNonPrivate] = useState(false);
  const [saving, setSaving] = useState(false);
  const [msg, setMsg] = useState<{ kind: "ok" | "err"; text: string } | null>(null);
  const [denied, setDenied] = useState(false);
  // A 500 is not a 403. Rendering every failure as "you are not authorized" gives
  // the operator the one explanation they will never investigate — so an outage
  // in the discovery config store looked like a deliberate permission boundary.
  const [loadErr, setLoadErr] = useState<string | null>(null);

  const load = async () => {
    try {
      const env = await api.discoveryConfig();
      setCfg(env.config);
      setLimits(env.limits);
      setStats(env.stats);
      setEnabled(env.config.enabled);
      setRanges(env.config.ranges.join(", "));
      setAllowNonPrivate(env.config.allow_non_private);
      setDenied(false);
      setLoadErr(null);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      if (/^\s*40[13]\b/.test(msg)) {
        // Tenant-scoped admins are refused by design — hide the card entirely
        // rather than render a form that can only fail.
        setDenied(true);
        setLoadErr(null);
      } else {
        setLoadErr(msg);
      }
    }
  };
  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  if (denied) return null;
  if (loadErr && !cfg) {
    return (
      <div className="cc-panel" role="alert" style={{ padding: "11px 13px" }}>
        <strong style={{ color: "var(--bad)" }}>Discovery settings could not be loaded.</strong>
        <div style={{ marginTop: 4, fontSize: 12.5 }}>{loadErr}</div>
        <div style={{ marginTop: 4, fontSize: 12.5, color: "var(--muted)" }}>
          This is a failure to read the configuration, not a permission decision — the current
          discovery state is unknown.
        </div>
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
        community: community || undefined,
        allow_non_private: allowNonPrivate,
      });
      setCfg(env.config);
      setRanges(env.config.ranges.join(", "));
      setCommunity("");
      setMsg({ kind: "ok", text: enabled ? "Saved — a sweep has been scheduled." : "Saved. Discovery is off." });
    } catch (e) {
      setMsg({ kind: "err", text: (e as Error).message });
    } finally {
      setSaving(false);
    }
  };

  const maxHosts = limits?.max_hosts ?? 4096;
  const scope = scopeCount(ranges);
  const over = scope.total > maxHosts;
  const state: { cls: string; label: string } = !cfg.enabled
    ? { cls: "off", label: "Off" }
    : stats?.last_error
    ? { cls: "warn", label: "Needs attention" }
    : { cls: "on", label: "Active" };

  const scanNow = async () => {
    try {
      await api.refreshDiscovery();
      setMsg({ kind: "ok", text: "Sweep scheduled — rate-limited to one per minute." });
    } catch (e) {
      setMsg({ kind: "err", text: (e as Error).message });
    }
  };

  return (
    <div className="card disc-card" style={{ marginBottom: 16 }}>
      <div className="disc-head">
        <div>
          <div className="disc-eyebrow">Device onboarding</div>
          <div className="disc-title-row">
            <h2 className="disc-title">Subnet discovery</h2>
            <span className={`disc-state ${state.cls}`}>
              <span className="disc-dot" aria-hidden />
              {state.label}
            </span>
          </div>
          <p className="disc-desc">
            Sweep your management subnets for SNMP-reachable devices and add them to
            the inventory automatically. Scope it to the subnets you own.
          </p>
        </div>
        <div className="disc-actions">
          <button
            className="btn"
            onClick={scanNow}
            disabled={!cfg.enabled}
            title={cfg.enabled ? "Run a sweep now" : "Enable and save first"}
          >
            Scan now
          </button>
          <button className="btn primary" onClick={save} disabled={saving || over}>
            {saving ? "Saving…" : "Save changes"}
          </button>
        </div>
      </div>

      <StatStrip>
        <Stat label="Last sweep" value={relSweepTime(stats?.last_poll)} />
        <Stat
          label="Devices discovered"
          value={stats?.devices ?? 0}
          tone={(stats?.devices ?? 0) > 0 ? "good" : ""}
        />
        <Stat
          label={cfg.ranges.length === 1 ? "Range in scope" : "Ranges in scope"}
          value={cfg.ranges.length}
          tone={cfg.ranges.length ? "accent" : ""}
        />
      </StatStrip>

      <div className="disc-grid">
        <label className="disc-field">
          <span>Scan ranges — CIDR, comma-separated</span>
          <input
            className="mono"
            value={ranges}
            onChange={(e) => setRanges(e.target.value)}
            placeholder="10.20.0.0/24, 10.30.5.0/26"
            spellCheck={false}
          />
          <div className={`disc-meter${over ? " over" : ""}`}>
            <div className="disc-meter-track">
              <div
                className="disc-meter-fill"
                style={{ width: `${Math.min(100, (scope.total / maxHosts) * 100)}%` }}
              />
            </div>
            <span className="disc-meter-read">
              {scope.invalid
                ? `"${scope.invalid}" is not CIDR notation`
                : `${scope.total.toLocaleString()} / ${maxHosts.toLocaleString()} addresses`}
            </span>
          </div>
        </label>
        <label className="disc-field">
          <span>
            Probe communities, comma-separated{" "}
            {cfg.community_set ? "· set — blank keeps them" : "· default: public"}
          </span>
          <input
            type="password"
            value={community}
            onChange={(e) => setCommunity(e.target.value)}
            placeholder={cfg.community_set ? "••••••••" : "public, vendor-ro, …"}
            autoComplete="new-password"
          />
          <span className="disc-note">
            Tried per address in order until one answers. Stored encrypted, never shown again.
          </span>
        </label>
      </div>

      <div className="disc-switches">
        <label className="uf-switch">
          <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
          <span className="uf-switch-track" aria-hidden />
          <span>Discovery enabled</span>
        </label>
        <label className="uf-switch">
          <input
            type="checkbox"
            checked={allowNonPrivate}
            onChange={(e) => setAllowNonPrivate(e.target.checked)}
          />
          <span className="uf-switch-track" aria-hidden />
          <span>Allow non-private ranges</span>
        </label>
        <InfoTip label="About non-private ranges">
          Only for networks that use public address space internally. Loopback,
          link-local and multicast ranges stay blocked either way.
        </InfoTip>
      </div>

      {msg && <p className={`disc-msg ${msg.kind}`}>{msg.text}</p>}
      {stats?.last_error && (
        <div className="disc-refusal">
          <b>Sweep refused</b>
          <span>{stats.last_error}</span>
        </div>
      )}

      <div className="disc-foot">
        <span>
          Sweeps every 5 minutes while enabled · manual sweeps rate-limited to one per
          minute · up to <span className="mono">{limits?.max_ranges ?? 32}</span> ranges,{" "}
          <span className="mono">{maxHosts.toLocaleString()}</span> addresses
        </span>
      </div>
    </div>
  );
}

export default function Collectors() {
  const [items, setItems] = useState<CollectorStatus[]>([]);
  const [err, setErr] = useState<string | null>(null);

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
        if (alive) setErr((e as Error).message);
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

  return (
    <>
    <DiscoveryCard />
    <div className="card">
      <h2>Collectors</h2>
      {err && <p style={{ color: "var(--bad)" }}>{err}</p>}

      <div className="stat-grid" style={{ marginBottom: 18 }}>
        <div className="stat s-accent">
          <span className="stat-label">Collectors</span>
          <span className="stat-value">{items.length}</span>
          <span className="stat-sub">registered</span>
        </div>
        <div className={`stat ${enabled.length ? "s-good" : "s-muted"}`}>
          <span className="stat-label">Enabled</span>
          <span className="stat-value">{enabled.length}</span>
          <span className="stat-sub">of {items.length}</span>
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
          <span className="stat-sub">of {enabled.length} enabled</span>
        </div>
        <div className={`stat ${reachAccent}`}>
          <span className="stat-label">Targets reachable</span>
          <span className="stat-value">
            {totalReachable}
            <span style={{ fontSize: 20, color: "var(--muted)" }}>
              /{totalTargets}
            </span>
          </span>
          <span className="stat-sub">across all collectors</span>
        </div>
      </div>

      {items.length === 0 ? (
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
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
    </>
  );
}
