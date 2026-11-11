// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// PlatformAlerts — Platform → Configuration → Platform alerts.
//
// Owner decision 2026-11-11 (binding): platform self-health alerts are set up
// HERE, not in env. Where the stack's own alerts go — ntfy and/or Twilio text
// messages, chosen per kind of alert.
//
// GATE. /api/platform/alerting/host-route{,/test} are requirePlatformAdmin
// (platform-global, CLAUDE.md §3a rule 3); the page lives in the provider-only
// Platform section and a 403 renders as "denied", never as a failure.
//
// HONESTY RULES:
//   · Secrets are never shown — only "saved". An empty field keeps it.
//   · "Send test" uses the SAVED settings, so it is disabled while the form has
//     unsaved changes (otherwise a pass would prove settings nobody saved).
//   · Pages reaching nobody is a banner at the top, not a footnote.

import { useCallback, useEffect, useMemo, useState } from "react";
import { api, type PlatformAlertRoute, type PlatformAlertTestResult } from "../../services/api";
import { httpFailure, operatorError } from "../../lib/errors";
import { fmtDateTime } from "../../lib/time";
import {
  type Draft,
  draftFrom,
  isDirty,
  receivesLine,
  routeBanner,
  toUpdate,
  validateDraft,
  verdictTone,
  MAX_SMS_RECIPIENTS,
} from "./platformAlertsModel";

type Load = { kind: "loading" } | { kind: "denied" } | { kind: "error"; message: string } | { kind: "ready"; data: PlatformAlertRoute };

const field: React.CSSProperties = { display: "grid", gap: 4, marginBottom: 10 };
const input: React.CSSProperties = { fontSize: 14, padding: "6px 8px", maxWidth: 460, width: "100%" };
const toneColor = { good: "var(--good)", warn: "var(--warn)", bad: "var(--bad)" } as const;

export default function PlatformAlerts() {
  const [load, setLoad] = useState<Load>({ kind: "loading" });
  const [draft, setDraft] = useState<Draft | null>(null);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState<{ tone: "good" | "bad"; text: string } | null>(null);
  const [testing, setTesting] = useState<"ntfy" | "sms" | null>(null);
  const [results, setResults] = useState<Partial<Record<"ntfy" | "sms", PlatformAlertTestResult>>>({});

  const refresh = useCallback(async () => {
    try {
      const data = await api.platformAlertRoute();
      setLoad({ kind: "ready", data });
      setDraft(draftFrom(data));
    } catch (e) {
      if (httpFailure(e)?.status === 403) setLoad({ kind: "denied" });
      else setLoad({ kind: "error", message: operatorError(e, "Platform alert settings could not be read.") });
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const saved = load.kind === "ready" ? load.data : null;
  const dirty = useMemo(() => (saved && draft ? isDirty(draft, saved) : false), [saved, draft]);

  if (load.kind === "loading" || (load.kind === "ready" && !draft)) return <div className="empty">Loading…</div>;
  if (load.kind === "denied") return <div className="empty">Only the platform administrator can set up platform alerts.</div>;
  if (load.kind === "error") return <div className="empty" role="alert">{load.message}</div>;
  const data = load.data;
  const d = draft as Draft;
  const set = (fn: (x: Draft) => Draft) => setDraft((cur) => (cur ? fn(structuredClone(cur)) : cur));

  const save = async () => {
    const problem = validateDraft(d, data);
    if (problem) {
      setMessage({ tone: "bad", text: problem });
      return;
    }
    setSaving(true);
    setMessage(null);
    try {
      const next = await api.savePlatformAlertRoute(toUpdate(d));
      setLoad({ kind: "ready", data: next });
      setDraft(draftFrom(next));
      setResults({});
      setMessage({ tone: "good", text: "Saved. The new settings are in use now." });
    } catch (e) {
      setMessage({ tone: "bad", text: operatorError(e, "The settings could not be saved. Nothing was changed.") });
    } finally {
      setSaving(false);
    }
  };

  const test = async (channel: "ntfy" | "sms") => {
    setTesting(channel);
    try {
      const res = await api.testPlatformAlertRoute(channel);
      setResults((r) => ({ ...r, [channel]: res }));
    } catch (e) {
      setResults((r) => ({ ...r, [channel]: { channel, verdict: "unreachable", message: operatorError(e, "The test could not be sent.") } }));
    } finally {
      setTesting(null);
    }
  };

  const banner = routeBanner(data);
  const busy = saving || testing !== null;

  const testRow = (channel: "ntfy" | "sms", label: string) => {
    const res = results[channel];
    return (
      <div style={{ display: "flex", gap: 12, alignItems: "center", flexWrap: "wrap", marginTop: 6 }}>
        <button className="btn-ghost" style={{ fontSize: 14 }} disabled={busy || dirty} onClick={() => void test(channel)}>
          {testing === channel ? "Sending…" : `Send test ${label}`}
        </button>
        {dirty && <span className="fact-line">Save first — a test uses the saved settings.</span>}
        {res && (
          <span role="status" data-testid={`verdict-${channel}`} style={{ color: toneColor[verdictTone(res.verdict)] }}>
            {res.message}
          </span>
        )}
      </div>
    );
  };

  const tiers = (ch: "ntfy" | "sms") => (
    <fieldset style={{ border: 0, padding: 0, margin: "4px 0 8px" }}>
      <legend style={{ fontWeight: 600, marginBottom: 4 }}>What it receives</legend>
      <label style={{ display: "flex", gap: 8, alignItems: "center" }}>
        <input
          type="checkbox"
          checked={d[ch].tiers.page}
          onChange={(e) => set((x) => ((x[ch].tiers.page = e.target.checked), x))}
        />
        Pages — an engine stopped, data stopped arriving, storage refused writes, or alert delivery broke (and the all-clear after each)
      </label>
      <label style={{ display: "flex", gap: 8, alignItems: "center" }}>
        <input
          type="checkbox"
          checked={d[ch].tiers.warning}
          onChange={(e) => set((x) => ((x[ch].tiers.warning = e.target.checked), x))}
        />
        Warning summary — everything else, at most one message every 30 minutes
      </label>
      <div className="fact-line">{receivesLine(d[ch].tiers)}</div>
    </fieldset>
  );

  return (
    <div className="platform-alerts-page" style={{ fontSize: 14, maxWidth: 1000 }}>
      <h2 style={{ margin: "0 0 4px" }}>Platform alerts</h2>
      <p style={{ margin: "0 0 8px" }}>
        Where Correlix sends alerts about its own health: an engine that stops working, data that stops arriving, storage
        that refuses writes. These are not your network alerts — those use Notification channels.
      </p>
      <p className="fact-line" style={{ margin: "0 0 12px" }}>
        The separate host watchdog keeps its own settings on the server, so it can still warn you if Correlix itself is down.
      </p>

      {banner && (
        <div className="cc-panel" role="alert" data-testid="platform-alerts-banner" style={{ padding: "10px 12px", marginBottom: 12, borderColor: "var(--bad)" }}>
          {banner}
        </div>
      )}
      {data.store_status === "stale" && (
        <div className="cc-panel" role="alert" style={{ padding: "10px 12px", marginBottom: 12, borderColor: "var(--warn)" }}>
          The saved settings could not be re-read just now. The last settings Correlix read are still in use; it retries every minute.
        </div>
      )}
      {data.store_status === "cached" && (
        <div className="cc-panel" role="alert" data-testid="store-cached" style={{ padding: "10px 12px", marginBottom: 12, borderColor: "var(--warn)" }}>
          The saved settings could not be read since Correlix started. The last copy kept on this server is in use; Correlix retries every minute.
        </div>
      )}
      {data.ignored_env.length > 0 && (
        <div className="cc-panel" data-testid="ignored-env" style={{ padding: "10px 12px", marginBottom: 12, borderColor: "var(--warn)" }}>
          These settings in the installation file do nothing any more: {data.ignored_env.join(", ")}. Platform alerts are set up only on
          this page. Remove them from the installation file when convenient.
        </div>
      )}

      <ol style={{ paddingLeft: 20, margin: 0 }}>
        <li style={{ marginBottom: 16 }}>
          <section className="cc-panel" style={{ padding: "12px 14px" }} aria-labelledby="pa-ntfy">
            <h3 id="pa-ntfy" style={{ margin: "0 0 8px", fontSize: 15 }}>Phone push (ntfy)</h3>
            <label style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 10 }}>
              <input
                type="checkbox"
                role="switch"
                aria-label="Use ntfy"
                checked={d.ntfy.enabled}
                onChange={(e) => set((x) => ((x.ntfy.enabled = e.target.checked), x))}
                style={{ width: 20, height: 20 }}
              />
              {d.ntfy.enabled ? "On" : "Off"}
            </label>
            <label style={field}>
              Server
              <input style={input} value={d.ntfy.server} onChange={(e) => set((x) => ((x.ntfy.server = e.target.value), x))} />
            </label>
            <p className="fact-line" style={{ margin: "-4px 0 10px" }}>
              A server on your own network must first be allowed by the installation (SSRF_ALLOWED_HOSTS).
            </p>
            <label style={field}>
              Topic (subscribe to this name in the ntfy app; treat it like a password)
              <input
                style={input}
                value={d.ntfy.topic}
                autoComplete="off"
                onChange={(e) => set((x) => ((x.ntfy.topic = e.target.value), x))}
              />
            </label>
            <label style={field}>
              Access token (only for a protected topic)
              <input
                style={input}
                type="password"
                autoComplete="new-password"
                value={d.ntfy.token}
                disabled={d.ntfy.clearToken}
                placeholder={data.ntfy.token_set ? "Saved — leave empty to keep it" : "Not set"}
                onChange={(e) => set((x) => ((x.ntfy.token = e.target.value), x))}
              />
            </label>
            {data.ntfy.token_set && (
              <label style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 8 }}>
                <input type="checkbox" checked={d.ntfy.clearToken} onChange={(e) => set((x) => ((x.ntfy.clearToken = e.target.checked), x))} />
                Remove the saved access token
              </label>
            )}
            {tiers("ntfy")}
            {testRow("ntfy", "push")}
          </section>
        </li>

        <li style={{ marginBottom: 16 }}>
          <section className="cc-panel" style={{ padding: "12px 14px" }} aria-labelledby="pa-sms">
            <h3 id="pa-sms" style={{ margin: "0 0 8px", fontSize: 15 }}>Text messages (Twilio)</h3>
            <label style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 10 }}>
              <input
                type="checkbox"
                role="switch"
                aria-label="Use text messages"
                checked={d.sms.enabled}
                onChange={(e) => set((x) => ((x.sms.enabled = e.target.checked), x))}
                style={{ width: 20, height: 20 }}
              />
              {d.sms.enabled ? "On" : "Off"}
            </label>
            <label style={field}>
              Account SID
              <input style={input} value={d.sms.accountSid} autoComplete="off" onChange={(e) => set((x) => ((x.sms.accountSid = e.target.value), x))} />
            </label>
            <label style={field}>
              Auth token
              <input
                style={input}
                type="password"
                autoComplete="new-password"
                value={d.sms.authToken}
                disabled={d.sms.clearAuthToken}
                placeholder={data.sms.auth_token_set ? "Saved — leave empty to keep it" : "Not set"}
                onChange={(e) => set((x) => ((x.sms.authToken = e.target.value), x))}
              />
            </label>
            {data.sms.auth_token_set && (
              <label style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 8 }}>
                <input
                  type="checkbox"
                  checked={d.sms.clearAuthToken}
                  onChange={(e) => set((x) => ((x.sms.clearAuthToken = e.target.checked), x))}
                />
                Remove the saved auth token
              </label>
            )}
            <label style={field}>
              Send from (your Twilio number, for example +14155550100)
              <input style={input} value={d.sms.from} onChange={(e) => set((x) => ((x.sms.from = e.target.value), x))} />
            </label>
            <label style={field}>
              Numbers to text (one per line, up to {MAX_SMS_RECIPIENTS})
              <textarea
                style={{ ...input, minHeight: 72, fontFamily: "inherit" }}
                value={d.sms.toText}
                onChange={(e) => set((x) => ((x.sms.toText = e.target.value), x))}
              />
            </label>
            <label style={field}>
              Most text messages per hour (all numbers together)
              <input
                style={{ ...input, maxWidth: 120 }}
                type="number"
                min={1}
                max={60}
                value={d.sms.maxPerHour}
                onChange={(e) => set((x) => ((x.sms.maxPerHour = e.target.value), x))}
              />
            </label>
            <p className="fact-line" style={{ margin: "0 0 8px" }}>
              Text messages cost money. Each number is one message. Half of this limit is kept for pages; past it, texts stop
              until the hour is up, and ntfy still carries the alert if it is on. If Twilio fails, a page is tried up to 5 times
              in all, within one message of the limit.
              {data.sms_budget_remaining >= 0 && ` Left this hour: ${data.sms_budget_remaining}.`}
            </p>
            {tiers("sms")}
            {testRow("sms", "text")}
          </section>
        </li>

        <li style={{ marginBottom: 16 }}>
          <section className="cc-panel" style={{ padding: "12px 14px" }}>
            <h3 style={{ margin: "0 0 8px", fontSize: 15 }}>Save</h3>
            {data.store_status === "unreadable" && (
              <label style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 8 }}>
                <input type="checkbox" checked={d.replaceUnreadable} onChange={(e) => set((x) => ((x.replaceUnreadable = e.target.checked), x))} />
                Replace the saved settings (they could not be read) with what is entered above
              </label>
            )}
            <div style={{ display: "flex", gap: 12, alignItems: "center", flexWrap: "wrap" }}>
              <button className="btn" style={{ fontSize: 14 }} disabled={busy || !dirty} onClick={() => void save()}>
                {saving ? "Saving…" : "Save"}
              </button>
              {message && (
                <span role={message.tone === "bad" ? "alert" : "status"} style={{ color: toneColor[message.tone] }}>
                  {message.text}
                </span>
              )}
            </div>
            {data.updated_by && data.updated_at && (
              <div className="fact-line" style={{ marginTop: 6 }}>
                Last changed by {data.updated_by} on {fmtDateTime(data.updated_at)}.
              </div>
            )}
          </section>
        </li>
      </ol>
    </div>
  );
}
