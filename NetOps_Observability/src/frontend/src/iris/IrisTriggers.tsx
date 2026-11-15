// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// IrisTriggers — triggered investigations (tracker 337 N-I2).
//
// A workspace admin asks Iris to investigate on its own: when a new incident
// matches a filter, or on a schedule. The page shows, in order:
//   1. the workspace switch and the daily caps (runs, AI tokens);
//   2. the triggers, each with an on/off control and Delete;
//   3. a form to add one;
//   4. the recent runs, each with its outcome or the reason it was skipped.
// Every server string renders as escaped React text. Runs are read-only and
// never run active probes.

import { useCallback, useEffect, useState } from "react";
import {
  api,
  type InvestigationTrigger,
  type InvestigationTriggerInput,
  type InvestigationTriggerKind,
  type InvestigationTriggerOverview,
  type InvestigationTriggerRun,
  type InvestigationTriggerSettings,
} from "../services/api";
import { httpFailure, operatorError } from "../lib/errors";

const text14 = { fontSize: 14 } as const;
const muted = { color: "var(--muted)", fontSize: 14 } as const;
const field = { fontSize: 14, padding: "4px 6px", minWidth: 200 } as const;
const row = { display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" as const, margin: "4px 0" };

const SEVERITIES = ["info", "notice", "warning", "error", "critical"] as const;

const SKIP_LABEL: Record<string, string> = {
  model_unavailable: "Skipped — no AI model answered",
  daily_run_cap: "Skipped — daily run limit reached",
  daily_token_cap: "Skipped — daily token limit reached",
  not_entitled: "Skipped — AI investigations are off",
  workspace_off: "Skipped — switched off",
};
const DONE_LABEL: Record<string, string> = {
  concluded: "Explanation found",
  inconclusive: "No single explanation",
  no_evidence: "Nothing to read",
};

export function runOutcome(r: InvestigationTriggerRun): string {
  if (r.status === "running") return "Running";
  if (r.status === "failed") return "Failed";
  if (r.status === "skipped") return SKIP_LABEL[r.reason ?? ""] ?? "Skipped";
  return DONE_LABEL[r.reason ?? ""] ?? "Done";
}

const DEFAULT_LIMITS: InvestigationTriggerOverview["limits"] = {
  max_triggers: 20, min_every_minutes: 15, max_every_minutes: 1440, max_runs_per_day: 100, max_tokens_per_day: 1000000,
};

/** Fill anything an older server or a proxy left out, so a partial answer can
 *  never take the whole settings page down. */
export function normalizeOverview(raw: Partial<InvestigationTriggerOverview> | null | undefined): InvestigationTriggerOverview {
  const r = raw ?? {};
  const s = (r.settings ?? {}) as Partial<InvestigationTriggerSettings>;
  return {
    settings: {
      enabled: s.enabled === true,
      max_runs_per_day: typeof s.max_runs_per_day === "number" ? s.max_runs_per_day : 20,
      max_tokens_per_day: typeof s.max_tokens_per_day === "number" ? s.max_tokens_per_day : 200000,
    },
    triggers: Array.isArray(r.triggers) ? r.triggers : [],
    runs: Array.isArray(r.runs) ? r.runs : [],
    tokens_today: typeof r.tokens_today === "number" ? r.tokens_today : 0,
    investigations_on: r.investigations_on === true,
    durable: r.durable !== false,
    limits: { ...DEFAULT_LIMITS, ...(r.limits ?? {}) },
  };
}

function describe(t: InvestigationTrigger): string {
  if (t.kind === "schedule") return `Every ${t.schedule?.every_minutes ?? "?"} min`;
  const f = t.filter ?? {};
  const parts: string[] = [];
  if (f.min_severity) parts.push(`${f.min_severity} or worse`);
  if (f.signature) parts.push(`text “${f.signature}”`);
  if (f.site) parts.push(`site ${f.site}`);
  if (f.role) parts.push(`role ${f.role}`);
  return `New incident: ${parts.join(", ")}`;
}

export default function IrisTriggers() {
  const [data, setData] = useState<InvestigationTriggerOverview | null>(null);
  const [denied, setDenied] = useState(false);
  const [loadErr, setLoadErr] = useState("");
  const [err, setErr] = useState("");

  const load = useCallback(async () => {
    try {
      setData(normalizeOverview(await api.investigationTriggers()));
      setLoadErr("");
    } catch (e) {
      if (httpFailure(e)?.status === 403) {
        setDenied(true);
        return;
      }
      setLoadErr(operatorError(e, "Triggered investigations could not be loaded."));
    }
  }, []);
  useEffect(() => { void load(); }, [load]);

  if (denied) return <p style={muted}>Workspace admins set up triggered investigations.</p>;
  if (loadErr) return <p style={muted}>{loadErr}</p>;
  if (!data) return <p style={muted}>Loading…</p>;

  const act = async (fn: () => Promise<unknown>, fallback: string) => {
    setErr("");
    try {
      await fn();
      await load();
    } catch (e) {
      setErr(operatorError(e, fallback));
    }
  };

  return (
    <div data-testid="iris-triggers" style={text14}>
      {!data.investigations_on && (
        <p style={muted} data-testid="triggers-need-investigations">
          Needs AI investigations: turn them on for this workspace under workspace access.
        </p>
      )}
      {!data.durable && <p style={muted}>This installation keeps triggers in memory; a restart clears them.</p>}
      <SettingsForm settings={data.settings} tokensToday={data.tokens_today} onSave={(s) => act(() => api.saveInvestigationTriggerSettings(s), "The settings could not be saved.")} />

      <div style={{ marginTop: 10 }}><strong>Triggers</strong></div>
      {data.triggers.length === 0 && <p style={muted}>No triggers yet.</p>}
      <ul style={{ margin: "4px 0 0", paddingLeft: 18 }} data-testid="trigger-list">
        {data.triggers.map((t) => (
          <li key={t.id} style={text14}>
            {t.name} — {describe(t)}{t.enabled ? "" : " (off)"}
            <button type="button" style={{ ...text14, marginLeft: 8 }} onClick={() => void act(() => api.setInvestigationTriggerEnabled(t.id, !t.enabled), "The trigger could not be changed.")}>
              {t.enabled ? "Turn off" : "Turn on"}
            </button>
            <button type="button" style={{ ...text14, marginLeft: 8 }} onClick={() => void act(() => api.deleteInvestigationTrigger(t.id), "The trigger could not be deleted.")}>Delete</button>
          </li>
        ))}
      </ul>
      {data.triggers.length < data.limits.max_triggers && (
        <AddTrigger minEvery={data.limits.min_every_minutes} onAdd={(input) => act(() => api.createInvestigationTrigger(input), "The trigger could not be added.")} />
      )}

      <div style={{ marginTop: 10 }}><strong>Recent runs</strong></div>
      {data.runs.length === 0 && <p style={muted}>No runs yet.</p>}
      <ul style={{ margin: "4px 0 0", paddingLeft: 18 }} data-testid="trigger-runs">
        {data.runs.map((r) => (
          <li key={r.id} style={text14}>
            {new Date(r.started_at).toLocaleString()} · {r.trigger_name}{r.incident_id ? ` · ${r.incident_id}` : ""} — {runOutcome(r)}
            {r.summary && r.status === "done" && <div style={muted}>{r.summary}</div>}
          </li>
        ))}
      </ul>
      {err && <p role="alert" style={text14}>{err}</p>}
    </div>
  );
}

function SettingsForm({ settings, tokensToday, onSave }: {
  settings: InvestigationTriggerSettings;
  tokensToday: number;
  onSave: (s: InvestigationTriggerSettings) => Promise<void>;
}) {
  const [f, setF] = useState(settings);
  useEffect(() => setF(settings), [settings]);
  return (
    <ol style={{ ...text14, paddingLeft: 20, margin: "4px 0" }} data-testid="trigger-settings">
      <li style={row}>
        <label style={text14}>
          <input type="checkbox" style={text14} checked={f.enabled} onChange={(e) => setF({ ...f, enabled: e.target.checked })} /> Let Iris investigate on its own
        </label>
      </li>
      <li style={row}>
        <label style={text14}>
          Runs per day{" "}
          <input aria-label="Runs per day" style={{ ...field, minWidth: 80 }} type="number" min={1} max={100} value={f.max_runs_per_day}
            onChange={(e) => setF({ ...f, max_runs_per_day: Number(e.target.value) })} />
        </label>
      </li>
      <li style={row}>
        <label style={text14}>
          AI tokens per day{" "}
          <input aria-label="AI tokens per day" style={{ ...field, minWidth: 120 }} type="number" min={1000} max={1000000} step={1000} value={f.max_tokens_per_day}
            onChange={(e) => setF({ ...f, max_tokens_per_day: Number(e.target.value) })} />
        </label>
        <span style={muted}>{tokensToday.toLocaleString()} used today</span>
      </li>
      <li style={row}>
        <button type="button" style={text14} onClick={() => void onSave(f)}>Save</button>
      </li>
    </ol>
  );
}

function AddTrigger({ minEvery, onAdd }: { minEvery: number; onAdd: (i: InvestigationTriggerInput) => Promise<void> }) {
  const [kind, setKind] = useState<InvestigationTriggerKind>("incident");
  const [name, setName] = useState("");
  const [severity, setSeverity] = useState("critical");
  const [signature, setSignature] = useState("");
  const [site, setSite] = useState("");
  const [role, setRole] = useState("");
  const [every, setEvery] = useState(60);
  const [question, setQuestion] = useState("");

  const submit = async () => {
    await onAdd({
      name: name.trim(),
      kind,
      filter: kind === "incident" ? { min_severity: severity, signature: signature.trim(), site: site.trim(), role: role.trim() } : {},
      schedule: { every_minutes: kind === "schedule" ? every : 0 },
      question: question.trim(),
    });
    setName("");
    setSignature("");
    setQuestion("");
  };

  return (
    <fieldset data-testid="trigger-add" style={{ border: "1px solid var(--border)", padding: 8, margin: "8px 0" }}>
      <legend style={text14}><strong>New trigger</strong></legend>
      <ol style={{ ...text14, paddingLeft: 20, margin: 0 }}>
        <li style={row}>
          <label style={text14}>Name <input aria-label="Trigger name" style={field} maxLength={80} value={name} onChange={(e) => setName(e.target.value)} /></label>
        </li>
        <li style={row}>
          <label style={text14}>
            Runs{" "}
            <select aria-label="When it runs" style={text14} value={kind} onChange={(e) => setKind(e.target.value as InvestigationTriggerKind)}>
              <option value="incident">On a new incident</option>
              <option value="schedule">On a schedule</option>
            </select>
          </label>
        </li>
        {kind === "incident" ? (
          <li style={row}>
            <label style={text14}>
              Severity{" "}
              <select aria-label="Lowest severity" style={text14} value={severity} onChange={(e) => setSeverity(e.target.value)}>
                {SEVERITIES.map((s) => <option key={s} value={s}>{s} or worse</option>)}
              </select>
            </label>
            <label style={text14}>Text <input aria-label="Text in the incident" style={field} maxLength={100} value={signature} onChange={(e) => setSignature(e.target.value)} /></label>
            <label style={text14}>Site <input aria-label="Site" style={{ ...field, minWidth: 120 }} maxLength={100} value={site} onChange={(e) => setSite(e.target.value)} /></label>
            <label style={text14}>Role <input aria-label="Device role" style={{ ...field, minWidth: 120 }} maxLength={100} value={role} onChange={(e) => setRole(e.target.value)} /></label>
          </li>
        ) : (
          <li style={row}>
            <label style={text14}>
              Every{" "}
              <input aria-label="Minutes between runs" style={{ ...field, minWidth: 80 }} type="number" min={minEvery} max={1440} value={every}
                onChange={(e) => setEvery(Number(e.target.value))} /> minutes
            </label>
          </li>
        )}
        <li style={row}>
          <label style={text14}>Look into (optional) <input aria-label="What Iris should look into" style={{ ...field, minWidth: 320 }} maxLength={300} value={question} onChange={(e) => setQuestion(e.target.value)} /></label>
        </li>
      </ol>
      <div style={row}>
        <button type="button" style={text14} disabled={name.trim() === ""} onClick={() => void submit()}>Create trigger</button>
      </div>
    </fieldset>
  );
}
