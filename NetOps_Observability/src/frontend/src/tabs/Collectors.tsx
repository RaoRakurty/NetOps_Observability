import { useEffect, useState } from "react";
import { api, CollectorStatus, DiscoveryConfig, DiscoveryConfigEnvelope } from "../services/api";

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

  const load = async () => {
    try {
      const env = await api.discoveryConfig();
      setCfg(env.config);
      setLimits(env.limits);
      setStats(env.stats);
      setEnabled(env.config.enabled);
      setRanges(env.config.ranges.join(", "));
      setAllowNonPrivate(env.config.allow_non_private);
    } catch {
      // Tenant-scoped admins are refused by design — hide the card entirely
      // rather than render a form that can only fail.
      setDenied(true);
    }
  };
  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  if (denied || !cfg) return null;

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

  return (
    <div className="card" style={{ marginBottom: 16 }}>
      <h2>Subnet discovery</h2>
      <p style={{ color: "var(--muted)", fontSize: 13, marginTop: 2 }}>
        Sweep your management subnets for SNMP-reachable devices and add them to the
        inventory automatically. Private (RFC&nbsp;1918) IPv4 ranges only, up to{" "}
        {limits?.max_hosts ?? 4096} addresses total — scope it to the subnets you own.
      </p>

      <div style={{ display: "flex", flexWrap: "wrap", gap: 12, alignItems: "flex-end", marginTop: 10 }}>
        <label style={{ display: "flex", alignItems: "center", gap: 8, paddingBottom: 6 }}>
          <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
          <span>Enabled</span>
        </label>
        <label style={{ display: "flex", flexDirection: "column", gap: 4, flex: "1 1 320px" }}>
          <span style={{ fontSize: 12, color: "var(--muted)" }}>
            Ranges (CIDR, comma-separated) — e.g. 10.20.0.0/24, 10.30.5.0/26
          </span>
          <input
            value={ranges}
            onChange={(e) => setRanges(e.target.value)}
            placeholder="10.20.0.0/24, 10.30.5.0/26"
            spellCheck={false}
          />
        </label>
        <label style={{ display: "flex", flexDirection: "column", gap: 4, flex: "0 1 260px" }}>
          <span style={{ fontSize: 12, color: "var(--muted)" }}>
            Probe communities, comma-separated{" "}
            {cfg.community_set ? "(set — blank keeps them)" : "(default: public)"}
          </span>
          <input
            type="password"
            value={community}
            onChange={(e) => setCommunity(e.target.value)}
            placeholder={cfg.community_set ? "••••••••" : "public, vendor-ro, …"}
            autoComplete="new-password"
          />
        </label>
        <button className="btn primary" onClick={save} disabled={saving}>
          {saving ? "Saving…" : "Save"}
        </button>
        <button
          className="btn"
          onClick={async () => {
            try {
              await api.refreshDiscovery();
              setMsg({ kind: "ok", text: "Sweep scheduled (rate-limited to one per minute)." });
            } catch (e) {
              setMsg({ kind: "err", text: (e as Error).message });
            }
          }}
          disabled={!cfg.enabled}
          title={cfg.enabled ? "Run a sweep now" : "Enable and save first"}
        >
          Scan now
        </button>
      </div>

      <label style={{ display: "flex", alignItems: "center", gap: 8, marginTop: 10, fontSize: 13 }}>
        <input
          type="checkbox"
          checked={allowNonPrivate}
          onChange={(e) => setAllowNonPrivate(e.target.checked)}
        />
        <span>
          Allow non-private ranges — only if your network uses public address space
          internally (loopback, link-local and multicast stay blocked)
        </span>
      </label>

      {msg && (
        <p style={{ color: msg.kind === "ok" ? "var(--good)" : "var(--bad)", fontSize: 13, marginTop: 8 }}>
          {msg.text}
        </p>
      )}
      <p style={{ color: "var(--muted)", fontSize: 12, marginTop: 8 }}>
        Last sweep:{" "}
        {stats?.last_poll ? new Date(stats.last_poll).toLocaleString() : "never"}
        {typeof stats?.devices === "number" ? ` · ${stats.devices} device${stats.devices === 1 ? "" : "s"} discovered` : ""}
        {stats?.last_error ? (
          <span style={{ color: "var(--bad)" }}> · {stats.last_error}</span>
        ) : null}
      </p>
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
                  {c.last_tick ? new Date(c.last_tick).toLocaleString() : "—"}
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
