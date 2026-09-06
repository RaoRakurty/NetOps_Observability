import { useCallback, useEffect, useMemo, useState } from "react";
import {
  api,
  NmsConnector,
  NmsHealth,
  NmsIntegration,
  NmsIntegrationInput,
  NmsStateRow,
} from "../services/api";
import Wizard, { WizardStep } from "../components/Wizard";
import { Modal, Skeleton, Stat, StatStrip } from "../components/ui";
import { NmsDashArt, NmsMark } from "../components/NmsControllerArt";
import AskIris from "../components/AskIris";

// NMS Integrations (#95) — the vendor-controller gallery + guided setup +
// integration manager. Controller INTELLIGENCE ingestion: each connected
// platform's computed state/metrics/alarms become normalized RCA evidence
// (3-class routing), reconciled against direct telemetry. Read-only; no
// config push. Dormant unless FEATURE_NMS_INTEGRATIONS=true on the api.

type VendorMeta = { tagline: string; domain: string };

const VENDOR_META: Record<string, VendorMeta> = {
  meraki: { tagline: "Cloud-managed campus — wireless, switching, appliances", domain: "Campus / Cloud" },
  catalyst_center: { tagline: "Campus assurance scores, issues & inventory", domain: "Campus" },
  vmanage: { tagline: "SD-WAN overlay health — tunnels, BFD, app-route SLA", domain: "SD-WAN" },
  ndfc: { tagline: "Nexus Dashboard fabric state & switch health", domain: "Data center" },
  versa_director: { tagline: "Versa SASE / SD-WAN appliance services", domain: "SD-WAN / SASE" },
  versa_concerto: { tagline: "Versa multi-tenant orchestration layer", domain: "SD-WAN / SASE" },
  prime: { tagline: "Legacy campus NMS — alarms & inventory", domain: "Campus (legacy)" },
  generic: { tagline: "Any controller with REST or webhooks — normalized ingest", domain: "Universal" },
};

type CredField = { key: string; label: string; secret?: boolean; hint?: string };

// Per-vendor credential fields (vendor-verified auth flows, e80ec26). Extras
// like org / domain / webhook_secret ride Credentials.Extra server-side.
const CRED_FIELDS: Record<string, CredField[]> = {
  meraki: [
    { key: "api_key", label: "Dashboard API key", secret: true },
    { key: "org", label: "Organization ID", hint: "Identifies your organisation with the vendor." },
    { key: "webhook_secret", label: "Webhook shared secret", secret: true, hint: "optional — verifies inbound alert webhooks" },
  ],
  catalyst_center: [
    { key: "username", label: "Username", hint: "read-only observer role is enough" },
    { key: "password", label: "Password", secret: true },
  ],
  vmanage: [
    { key: "username", label: "Username", hint: "read-only netadmin/observer" },
    { key: "password", label: "Password", secret: true },
  ],
  ndfc: [
    { key: "username", label: "Username" },
    { key: "password", label: "Password", secret: true },
    { key: "domain", label: "Login domain", hint: "blank = local" },
  ],
  prime: [
    { key: "username", label: "Username" },
    { key: "password", label: "Password", secret: true },
  ],
  versa_director: [
    { key: "client_id", label: "OAuth client ID", hint: "preferred — leave blank to use Basic" },
    { key: "client_secret", label: "OAuth client secret", secret: true },
    { key: "username", label: "Username (Basic fallback)" },
    { key: "password", label: "Password", secret: true },
  ],
  versa_concerto: [
    { key: "client_id", label: "OAuth client ID", hint: "preferred — leave blank to use Basic" },
    { key: "client_secret", label: "OAuth client secret", secret: true },
    { key: "username", label: "Username (Basic fallback)" },
    { key: "password", label: "Password", secret: true },
  ],
  generic: [
    { key: "token", label: "Bearer token", secret: true, hint: "or use username/password below" },
    { key: "username", label: "Username" },
    { key: "password", label: "Password", secret: true },
    { key: "webhook_secret", label: "Webhook HMAC secret", secret: true, hint: "optional — verifies inbound webhooks" },
  ],
};

function credsValid(vendor: string, c: Record<string, string>) {
  switch (vendor) {
    case "meraki":
      return !!c.api_key;
    case "versa_director":
    case "versa_concerto":
      return (!!c.client_id && !!c.client_secret) || (!!c.username && !!c.password);
    case "generic":
      return !!c.token || (!!c.username && !!c.password) || !!c.webhook_secret;
    default:
      return !!c.username && !!c.password;
  }
}

function relTime(iso?: string): string {
  if (!iso) return "—";
  const t = new Date(iso).getTime();
  if (!isFinite(t) || t <= 0) return "—";
  const s = Math.max(0, (Date.now() - t) / 1000);
  if (s < 60) return `${Math.floor(s)}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

function HealthDot({ h }: { h?: NmsHealth }) {
  const never = !h || (!h.lastSuccess && !h.lastError);
  const color = never ? "var(--muted)" : h!.healthy ? "var(--good, #16a34a)" : "var(--bad, #dc2626)";
  const label = never ? "never polled" : h!.healthy ? "healthy" : "failing";
  return (
    <span
      title={label}
      aria-label={label}
      style={{
        display: "inline-block", width: 8, height: 8, borderRadius: 999, background: color,
        boxShadow: `0 0 0 2px color-mix(in srgb, ${color} 25%, transparent)`,
      }}
    />
  );
}

function Field({ label, value, onChange, type = "text", hint, mono }: {
  label: string; value: string; onChange: (v: string) => void; type?: string; hint?: string; mono?: boolean;
}) {
  return (
    <label className="nms-field">
      <span className="nms-field-l">{label}</span>
      <input
        type={type}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className={mono ? "mono" : undefined}
        autoComplete="off"
        spellCheck={false}
      />
      {hint ? <span className="nms-field-h">{hint}</span> : null}
    </label>
  );
}

export default function NmsIntegrations() {
  const [connectors, setConnectors] = useState<NmsConnector[] | undefined>();
  const [integrations, setIntegrations] = useState<NmsIntegration[] | undefined>();
  const [health, setHealth] = useState<Record<string, NmsHealth>>({});
  const [dormant, setDormant] = useState(false);
  const [err, setErr] = useState("");
  const [banner, setBanner] = useState("");
  const [setupVendor, setSetupVendor] = useState<NmsConnector | null>(null);
  const [manage, setManage] = useState<NmsIntegration | null>(null);

  const load = useCallback(async () => {
    try {
      const [c, i] = await Promise.all([api.nmsConnectors(), api.nmsIntegrations()]);
      setConnectors(c.connectors);
      setIntegrations(i.integrations);
      setDormant(false);
      setErr("");
      const hs: Record<string, NmsHealth> = {};
      await Promise.all(
        (i.integrations || []).map(async (it) => {
          try {
            hs[it.id] = await api.nmsHealth(it.id);
          } catch {
            /* health is best-effort */
          }
        }),
      );
      setHealth(hs);
    } catch (e: any) {
      if (/404|not found/i.test(String(e?.message))) {
        setDormant(true);
        setConnectors([]);
        setIntegrations([]);
      } else {
        setErr(String(e?.message || e));
      }
    }
  }, []);

  useEffect(() => {
    load();
    const t = setInterval(load, 30_000);
    return () => clearInterval(t);
  }, [load]);

  const byVendor = useMemo(() => {
    const m: Record<string, NmsIntegration[]> = {};
    for (const it of integrations || []) (m[it.vendor] = m[it.vendor] || []).push(it);
    return m;
  }, [integrations]);

  const totals = useMemo(() => {
    const list = integrations || [];
    let healthy = 0;
    let events = 0;
    for (const it of list) {
      const h = health[it.id];
      if (h?.healthy) healthy++;
      events += h?.eventsIngested || 0;
    }
    return { connected: list.length, healthy, events };
  }, [integrations, health]);

  if (dormant) {
    return (
      <div className="nms-page">
        <PageHead />
        <div className="board-empty">
          <div className="board-empty-msg">Controller integrations are turned off.</div>
          <div className="board-empty-hint">
            This deployment has NMS controller integrations disabled. Re-enable them
            from the platform configuration to connect vendor controllers (Cisco
            Catalyst Center, Nexus Dashboard, Meraki, Cisco vManage, Versa and more).
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="nms-page">
      <PageHead />
      <StatStrip>
        <Stat label="Vendors available" value={connectors ? connectors.length : <Skeleton w={24} />} />
        <Stat label="Connected" value={integrations ? totals.connected : <Skeleton w={24} />} tone="accent" />
        <Stat
          label="Healthy"
          value={integrations ? totals.healthy : <Skeleton w={24} />}
          tone={totals.connected === 0 ? "" : totals.healthy === totals.connected ? "good" : "warn"}
        />
        <Stat label="Controller events ingested" value={integrations ? totals.events.toLocaleString() : <Skeleton w={40} />} />
      </StatStrip>
      {err ? <div className="note bad">{err}</div> : null}
      {banner ? (
        <div className="note good" role="status">
          {banner} <button className="linklike" onClick={() => setBanner("")}>dismiss</button>
        </div>
      ) : null}

      <div className="nms-grid">
        {(connectors || []).map((c) => {
          const meta = VENDOR_META[c.vendor] || VENDOR_META.generic;
          const mine = byVendor[c.vendor] || [];
          const anyBad = mine.some((it) => health[it.id] && !health[it.id].healthy && (health[it.id].lastError || health[it.id].lastSuccess));
          return (
            <button key={c.vendor} className="nms-tile" onClick={() => setSetupVendor(c)} aria-label={`Set up ${c.product}`}>
              <div className="nms-tile-art">
                <NmsDashArt vendor={c.vendor} />
              </div>
              <div className="nms-tile-body">
                <div className="nms-tile-head">
                  <span className="nms-mark"><NmsMark vendor={c.vendor} size={20} /></span>
                  <div className="nms-tile-title">
                    <span className="nms-tile-name">{c.product}</span>
                    <span className="nms-tile-domain">{meta.domain}</span>
                  </div>
                  {mine.length > 0 ? (
                    <span className={`conn-status ${anyBad ? "warn" : "good"}`}>
                      {mine.length} connected
                    </span>
                  ) : null}
                </div>
                <div className="nms-tile-tag">{meta.tagline}</div>
                <div className="nms-tile-caps">
                  {c.poll ? <span className="nms-cap">POLL</span> : null}
                  {c.webhook ? <span className="nms-cap">PUSH</span> : null}
                  <span className="nms-cap dim">{c.preferredAuth.toUpperCase()}</span>
                  <span className="nms-cap dim">{c.streams.length} streams</span>
                  <span className="nms-cta">{mine.length ? "Add another →" : "Connect →"}</span>
                </div>
              </div>
            </button>
          );
        })}
        {connectors === undefined
          ? [...Array(4)].map((_, i) => <Skeleton key={i} w="100%" h={230} />)
          : null}
      </div>

      <ConfiguredList
        integrations={integrations}
        health={health}
        onManage={setManage}
        onChanged={load}
      />

      {setupVendor ? (
        <SetupWizard
          connector={setupVendor}
          onClose={() => setSetupVendor(null)}
          onDone={async (msg) => {
            setSetupVendor(null);
            setBanner(msg);
            await load();
          }}
        />
      ) : null}
      {manage ? (
        <ManageModal
          integration={manage}
          health={health[manage.id]}
          onClose={() => setManage(null)}
          onChanged={async () => {
            await load();
          }}
          onDeleted={async () => {
            setManage(null);
            await load();
          }}
        />
      ) : null}
    </div>
  );
}

function PageHead() {
  return (
    <div className="nms-head">
      <div>
        <h2>NMS Integrations</h2>
        <div className="nms-sub">
          Controller intelligence — harvest what each vendor platform already computed (state, SLA metrics,
          alarms) as normalized RCA evidence. Read-only; a controller alone never confirms a root cause.
        </div>
      </div>
    </div>
  );
}

function ConfiguredList({ integrations, health, onManage, onChanged }: {
  integrations?: NmsIntegration[];
  health: Record<string, NmsHealth>;
  onManage: (i: NmsIntegration) => void;
  onChanged: () => Promise<void> | void;
}) {
  const [busyId, setBusyId] = useState("");
  if (integrations === undefined) return <Skeleton w="100%" h={80} />;
  if (integrations.length === 0) {
    return (
      <div className="fp-empty nms-none">
        <span className="fp-empty-mark" />
        <span className="fp-empty-t">No controllers connected yet</span>
        <span className="fp-empty-h">Pick a platform above — a read-only account is all a connector needs.</span>
      </div>
    );
  }
  return (
    <div className="nms-list">
      <h3>Connected integrations</h3>
      <table className="ds-table">
        <thead>
          <tr>
            <th></th>
            <th>Name</th>
            <th>Vendor</th>
            <th>Base URL</th>
            <th>Interval</th>
            <th>Last success</th>
            <th className="num">Events</th>
            <th className="num">Error rate</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {integrations.map((it) => {
            const h = health[it.id];
            return (
              <tr key={it.id} className={it.enabled ? "" : "nms-row-off"}>
                <td><HealthDot h={h} /></td>
                <td>
                  <button className="linklike strong" onClick={() => onManage(it)}>{it.displayName || it.id}</button>
                  {!it.enabled ? <span className="nms-off-pill">paused</span> : null}
                </td>
                <td>{it.product || it.vendor}</td>
                <td className="mono nms-url">{it.baseUrl}</td>
                <td className="mono">{it.pollIntervalS}s</td>
                <td>{relTime(h?.lastSuccess)}</td>
                <td className="num mono">{(h?.eventsIngested ?? 0).toLocaleString()}</td>
                <td className="num mono">{h ? `${Math.round((h.errorRate || 0) * 100)}%` : "—"}</td>
                <td className="nms-row-actions">
                  <button
                    className="btn sm"
                    disabled={busyId === it.id}
                    onClick={async () => {
                      setBusyId(it.id);
                      try {
                        await api.pollNmsIntegration(it.id);
                        await onChanged();
                      } finally {
                        setBusyId("");
                      }
                    }}
                  >
                    {busyId === it.id ? "Collecting…" : "Collect now"}
                  </button>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function SetupWizard({ connector, onClose, onDone }: {
  connector: NmsConnector;
  onClose: () => void;
  onDone: (banner: string) => Promise<void>;
}) {
  const meta = VENDOR_META[connector.vendor] || VENDOR_META.generic;
  const [name, setName] = useState("");
  const [baseUrl, setBaseUrl] = useState("https://");
  const [interval, setIntervalS] = useState(String(connector.defaultPollS || 300));
  const [tlsSkip, setTlsSkip] = useState(false);
  const [streams, setStreams] = useState<string[]>(connector.streams);
  const [creds, setCreds] = useState<Record<string, string>>({});

  const fields = CRED_FIELDS[connector.vendor] || CRED_FIELDS.generic;

  const steps: WizardStep[] = [
    {
      id: "connection",
      title: "Connection",
      hint: "Where the controller lives and how often to poll it.",
      isValid: () => !!name.trim() && /^https?:\/\/.+/.test(baseUrl.trim()),
      render: () => (
        <div className="nms-form">
          <Field label="Display name" value={name} onChange={setName} hint={`e.g. "${meta.domain} — production"`} />
          <Field label="Base URL" value={baseUrl} onChange={setBaseUrl} mono hint="https://controller.example.com" />
          <Field label="Poll interval (seconds)" value={interval} onChange={setIntervalS} mono hint={`vendor default ${connector.defaultPollS}s; floored at 30s`} />
          <label className="nms-check">
            <input type="checkbox" checked={tlsSkip} onChange={(e) => setTlsSkip(e.target.checked)} />
            <span>
              Accept self-signed certificate <span className="nms-field-h">(lab / on-prem controllers; leave off when the controller has a real cert)</span>
            </span>
          </label>
          {connector.poll ? (
            <div className="nms-streams">
              <span className="nms-field-l">Streams</span>
              <div className="nms-stream-grid">
                {connector.streams.map((s) => (
                  <label key={s} className="nms-check sm">
                    <input
                      type="checkbox"
                      checked={streams.includes(s)}
                      onChange={(e) =>
                        setStreams((prev) => (e.target.checked ? [...prev, s] : prev.filter((x) => x !== s)))
                      }
                    />
                    <span className="mono">{s}</span>
                  </label>
                ))}
              </div>
            </div>
          ) : null}
        </div>
      ),
    },
    {
      id: "credentials",
      title: "Credentials",
      hint: "Stored write-only in the encrypted vault — and is never displayed again.",
      isValid: () => credsValid(connector.vendor, creds),
      render: () => (
        <div className="nms-form">
          {fields.map((f) => (
            <Field
              key={f.key}
              label={f.label}
              type={f.secret ? "password" : "text"}
              value={creds[f.key] || ""}
              onChange={(v) => setCreds((p) => ({ ...p, [f.key]: v }))}
              hint={f.hint}
              mono={!f.secret}
            />
          ))}
        </div>
      ),
    },
    {
      id: "review",
      title: "Review & connect",
      hint: "Creates the integration, runs a live authentication test, then polls once.",
      isValid: () => true,
      render: () => (
        <div className="nms-review">
          <dl>
            <dt>Platform</dt><dd>{connector.product}</dd>
            <dt>Name</dt><dd>{name}</dd>
            <dt>Base URL</dt><dd className="mono">{baseUrl}</dd>
            <dt>Poll</dt><dd className="mono">{connector.poll ? `every ${interval}s · ${streams.length} streams` : "push only"}</dd>
            <dt>Credentials</dt>
            <dd>{fields.filter((f) => creds[f.key]).map((f) => f.label).join(", ") || "None set"}</dd>
          </dl>
          <div className="nms-field-h">
            The connector is read-only: it never writes to the controller. Controller evidence alone caps at
            “suspected” — confirmation always needs corroborating direct telemetry.
          </div>
        </div>
      ),
    },
  ];

  return (
    <Modal
      title={connector.product}
      subtitle={meta.tagline}
      logo={<span className="nms-mark"><NmsMark vendor={connector.vendor} size={18} /></span>}
      onClose={onClose}
    >
      <Wizard
        steps={steps}
        onCancel={onClose}
        finishLabel="Connect"
        onFinish={async () => {
          const body: NmsIntegrationInput = {
            vendor: connector.vendor,
            displayName: name.trim(),
            baseUrl: baseUrl.trim().replace(/\/+$/, ""),
            enabled: true,
            pollIntervalS: Math.max(30, parseInt(interval, 10) || connector.defaultPollS),
            streams,
            tlsSkipVerify: tlsSkip,
            credentials: Object.fromEntries(Object.entries(creds).filter(([, v]) => v !== "")),
          };
          const created = await api.createNmsIntegration(body);
          let msg = `${connector.product} connected.`;
          try {
            const t = await api.testNmsIntegration(created.id);
            msg = t.ok
              ? `${connector.product} connected — authentication verified.`
              : `${connector.product} saved, but the auth test failed: ${t.error}`;
            if (t.ok && connector.poll) {
              api.pollNmsIntegration(created.id).catch(() => {});
              msg += " First poll started.";
            }
          } catch {
            msg = `${connector.product} saved (auth test unavailable).`;
          }
          if (created.webhookUrl) msg += ` Webhook endpoint: ${created.webhookUrl}`;
          await onDone(msg);
        }}
      />
    </Modal>
  );
}

function ManageModal({ integration, health, onClose, onChanged, onDeleted }: {
  integration: NmsIntegration;
  health?: NmsHealth;
  onClose: () => void;
  onChanged: () => Promise<void>;
  onDeleted: () => Promise<void>;
}) {
  const it = integration;
  const [states, setStates] = useState<NmsStateRow[] | undefined>();
  const [h, setH] = useState<NmsHealth | undefined>(health);
  const [busy, setBusy] = useState("");
  const [note, setNote] = useState("");

  const refresh = useCallback(async () => {
    try {
      const [hh, ss] = await Promise.all([api.nmsHealth(it.id), api.nmsStates(it.id)]);
      setH(hh);
      setStates(ss.states);
    } catch {
      setStates([]);
    }
  }, [it.id]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const act = async (label: string, fn: () => Promise<any>) => {
    setBusy(label);
    setNote("");
    try {
      const r = await fn();
      if (label === "test") setNote(r.ok ? "Authentication OK." : `Auth failed: ${r.error}`);
      if (label === "poll") setNote(r.error ? `Poll ${r.status}: ${r.error}` : `Poll ok — ${r.events} events in ${r.durationMs}ms.`);
      await refresh();
      await onChanged();
    } catch (e: any) {
      setNote(String(e?.message || e));
    } finally {
      setBusy("");
    }
  };

  return (
    <Modal
      title={it.displayName || it.id}
      subtitle={`${it.product || it.vendor} · ${it.baseUrl}`}
      logo={<span className="nms-mark"><NmsMark vendor={it.vendor} size={18} /></span>}
      onClose={onClose}
      wide
    >
      <div className="nms-manage">
        <StatStrip>
          <Stat label="Status" value={h ? (h.healthy ? "healthy" : h.lastError ? "failing" : "idle") : "—"} tone={h?.healthy ? "good" : h?.lastError ? "bad" : ""} />
          <Stat label="Last success" value={relTime(h?.lastSuccess)} />
          <Stat label="Events ingested" value={(h?.eventsIngested ?? 0).toLocaleString()} />
          <Stat label="Error rate" value={h ? `${Math.round((h.errorRate || 0) * 100)}%` : "—"} tone={(h?.errorRate || 0) > 0.3 ? "warn" : ""} />
        </StatStrip>

        <div className="nms-actions">
          <button className="btn" disabled={!!busy} onClick={() => act("poll", () => api.pollNmsIntegration(it.id))}>
            {busy === "poll" ? "Collecting…" : "Collect now"}
          </button>
          <button className="btn" disabled={!!busy} onClick={() => act("test", () => api.testNmsIntegration(it.id))}>
            {busy === "test" ? "Testing…" : "Test connection"}
          </button>
          <button
            className="btn"
            disabled={!!busy}
            onClick={() => act("toggle", () => api.updateNmsIntegration(it.id, { enabled: !it.enabled }))}
          >
            {it.enabled ? "Pause collection" : "Resume collection"}
          </button>
          <span className="nms-spacer" />
          <button
            className="btn danger"
            disabled={!!busy}
            onClick={async () => {
              if (!confirm(`Delete "${it.displayName || it.id}"? Checkpoints, health and state history go with it.`)) return;
              await api.deleteNmsIntegration(it.id);
              await onDeleted();
            }}
          >
            Delete
          </button>
        </div>
        {note ? <div className="note">{note}</div> : null}
        {it.webhookUrl ? (
          <div className="nms-field-h">
            Webhook endpoint: <code className="mono">{it.webhookUrl}</code> (authenticated by token + signature)
          </div>
        ) : null}

        <div className="nms-panes">
          <div>
            <h4>Controller state</h4>
            <div className="fact-line">
              What the controller believes now.
              <AskIris topic="nms.controller-state" label="Controller state" />
            </div>
            {states === undefined ? (
              <Skeleton w="100%" h={60} />
            ) : states.length === 0 ? (
              <div className="panel-empty">No tracked state yet — poll at least once.</div>
            ) : (
              <table className="ds-table sm">
                <thead>
                  <tr><th>Entity</th><th>Kind</th><th>State</th><th>Prev</th><th className="num">Flaps</th><th>Last seen</th></tr>
                </thead>
                <tbody>
                  {states.slice(0, 12).map((s) => (
                    <tr key={s.entityKey + s.stateKind}>
                      <td className="mono">{s.entityKey}</td>
                      <td className="mono">{s.stateKind}</td>
                      <td>
                        <span className={`nms-state ${s.currentState === "up" ? "up" : s.currentState === "down" ? "down" : ""}`}>
                          {s.currentState}
                        </span>
                      </td>
                      <td className="mono dim">{s.previousState || "—"}</td>
                      <td className="num mono">{s.flapCount}</td>
                      <td>{relTime(s.lastSeen)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
          <div>
            <h4>Recent runs</h4>
            {!h?.runs?.length ? (
              <div className="panel-empty">No runs recorded yet.</div>
            ) : (
              <table className="ds-table sm">
                <thead>
                  <tr><th>Started</th><th>Status</th><th className="num">Events</th><th>Error</th></tr>
                </thead>
                <tbody>
                  {h.runs.slice(0, 10).map((r) => (
                    <tr key={r.runId}>
                      <td>{relTime(r.started)}</td>
                      <td>
                        <span className={`nms-state ${r.status === "ok" ? "up" : "down"}`}>{r.status}</span>
                      </td>
                      <td className="num mono">{r.events}</td>
                      <td className="nms-err">{r.error || "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      </div>
    </Modal>
  );
}
