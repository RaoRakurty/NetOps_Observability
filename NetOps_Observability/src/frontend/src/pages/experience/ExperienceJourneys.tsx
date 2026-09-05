// ExperienceJourneys.tsx — the Journeys tab.
//
// A journey is the only thing on this surface a person declares by hand, and it
// is the thing every other number is built on: an application's experience is
// the workflows people actually complete, not the checks we happen to run. So
// the editor is a first-class part of the page, not an admin afterthought.
//
// THE EDITOR MODELS THE REAL SHAPE. Steps branch (`next`), may be optional, may
// loop, and end at a success or a failure terminal. A linear step list would
// have quietly forbidden the journeys that matter most — a checkout with a
// retry, a login with an MFA fork.
//
// TWO HONESTY RULES THE FORM ENFORCES BY SHAPE, not by validation message:
//   - A step with no target is DECLARED but NOT MEASURED, and the list says so
//     rather than counting it as a success.
//   - A business value cannot be entered without a currency. An unlabelled
//     number is not an amount, and the server refuses it too.

import { useMemo, useState } from "react";

import { api } from "../../services/api";
import type {
  DemJourneyDefinition, DemJourneyHealth, DemJourneyStep, DemJourneyWrite,
  DemJourneysResponse, DemTargetsResponse, DemWindow,
} from "../../services/api";
import { operatorError } from "../../lib/errors";
import {
  BandChip, Loading, LoadError, Money, NotMeasured, Panel, bandFor, pct, reasonText,
} from "./honest";
import { useDemRead } from "./state";

const IMPORTANCE = ["critical", "high", "normal", "low"] as const;

export default function ExperienceJourneys({ window: win }: { window: DemWindow }) {
  const res = useDemRead<DemJourneysResponse>(() => api.demJourneys(win), [win]);
  const targets = useDemRead<DemTargetsResponse>(() => api.demTargets(), []);
  const [editing, setEditing] = useState<DemJourneyDefinition | "new" | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  const healthById = useMemo(() => {
    const m = new Map<string, DemJourneyHealth>();
    for (const h of res.data?.health ?? []) m.set(h.journey_id, h);
    return m;
  }, [res.data]);

  const save = async (body: DemJourneyWrite, id?: string) => {
    setBusy(true);
    setErr("");
    try {
      if (id) await api.demUpdateJourney(id, body);
      else await api.demCreateJourney(body);
      setEditing(null);
      res.reload();
    } catch (e) {
      setErr(operatorError(e, "The journey could not be saved"));
    } finally {
      setBusy(false);
    }
  };

  const remove = async (id: string) => {
    setBusy(true);
    setErr("");
    try {
      await api.demDeleteJourney(id);
      res.reload();
    } catch (e) {
      setErr(operatorError(e, "The journey could not be removed"));
    } finally {
      setBusy(false);
    }
  };

  if (res.status === "loading") return <Loading what="the declared journeys" />;
  if (res.status === "error" || !res.data) {
    return <LoadError what="The declared journeys" error={res.error} onRetry={res.reload} />;
  }

  return (
    <div className="dx-section">
      {err && <p className="dx-error" role="alert">{err}</p>}

      <Panel title="Declared journeys" label="Declared journeys"
        actions={
          <button type="button" className="btn-accent" onClick={() => setEditing("new")}>
            Declare a journey
          </button>
        }>
        {res.data.journeys.length === 0 ? (
          <p className="dx-note">
            {reasonText(res.data.reason)} {res.data.note}
          </p>
        ) : (
          <p className="dx-cap">
            {res.data.count} of at most {res.data.limit} for this tenant.
          </p>
        )}

        <div className="dx-section">
          {res.data.journeys.map((j) => {
            const h = healthById.get(j.id);
            return (
              <article className="dx-journey" key={j.id} aria-label={`Journey ${j.name}`}>
                <div className="dx-src-head">
                  <h3 className="dx-h3">{j.name}</h3>
                  <span className="dx-card-foot">
                    <span className="dx-chip">{j.business_importance}</span>
                    <span className="dx-chip">version {j.version}</span>
                    <button type="button" className="btn" onClick={() => setEditing(j)}>Edit</button>
                    <button type="button" className="btn" disabled={busy}
                      onClick={() => remove(j.id)}>Remove</button>
                  </span>
                </div>
                {j.description && <p className="dx-note">{j.description}</p>}
                <p className="dx-cap">
                  {j.app || "no application declared"} · objective {pct(j.slo.success_pct)}
                  {j.slo.latency_ms ? ` and p95 under ${j.slo.latency_ms}ms` : " (no latency objective declared)"}
                </p>

                {h && h.measured && h.success_pct !== undefined ? (
                  <div className="dx-card-foot">
                    <span className="dx-mono">{pct(h.success_pct)}</span>
                    <BandChip band={bandFor(h.success_pct)} />
                    <span className={h.meets_slo ? "dx-subtle" : "dx-delta dx-delta--down"}>
                      {h.meets_slo ? "meets its objective" : "misses its objective"}
                    </span>
                    <span className="dx-cap">{h.steps_measured} of {h.steps_declared} steps measured</span>
                  </div>
                ) : (
                  <NotMeasured reason={h?.reason ?? "journey_not_measured"} detail={h?.detail} />
                )}

                <StepGraph steps={j.steps} health={h} entry={j.entry_step_id} />

                {h?.business_impact !== undefined && (
                  <p className="dx-cap">
                    Value not realised in this window:{" "}
                    <Money value={h.business_impact} currency={h.business_impact_currency} />
                  </p>
                )}
              </article>
            );
          })}
        </div>
      </Panel>

      {editing && (
        <JourneyForm
          initial={editing === "new" ? undefined : editing}
          targets={targets.data?.targets ?? []}
          busy={busy}
          onCancel={() => setEditing(null)}
          onSave={(body) => save(body, editing === "new" ? undefined : editing.id)} />
      )}
    </div>
  );
}

// ── step graph ──────────────────────────────────────────────────────────────

function StepGraph({ steps, health, entry }: {
  steps: DemJourneyStep[]; health?: DemJourneyHealth; entry: string;
}) {
  const byId = new Map((health?.steps ?? []).map((s) => [s.step_id, s]));
  return (
    <div className="dx-steps">
      {steps.map((s) => {
        const h = byId.get(s.id);
        const failing = h?.failing === true;
        const measured = h?.measured === true;
        return (
          <span key={s.id}
            className={`dx-step${failing ? " dx-step--failing" : ""}${measured ? "" : " dx-step--unmeasured"}`}
            title={measured
              ? `${pct(h?.success_pct)} over ${h?.samples ?? 0} observations`
              : reasonText(h?.reason ?? (s.target_id ? "step_no_measurement" : "step_not_bound"))}>
            <span className="dx-step-label">
              {s.id === entry ? "▶ " : ""}{s.label}
              {s.optional ? " (optional)" : ""}
              {s.terminal_success ? " ✓" : ""}{s.terminal_failure ? " ✗" : ""}
            </span>
            <span>{measured ? pct(h?.success_pct) : "not measured"}</span>
            <span className="dx-cap">
              {s.next?.length ? `→ ${s.next.join(", ")}` : "end"}
            </span>
          </span>
        );
      })}
    </div>
  );
}

// ── editor ──────────────────────────────────────────────────────────────────

interface DraftStep extends DemJourneyStep { nextText: string }

function toDraft(s: DemJourneyStep): DraftStep {
  return { ...s, nextText: (s.next ?? []).join(", ") };
}

function emptyStep(n: number): DraftStep {
  return { id: `step-${n}`, label: "", nextText: "", next: [] };
}

function JourneyForm({ initial, targets, busy, onSave, onCancel }: {
  initial?: DemJourneyDefinition;
  targets: { id: string; name: string; site?: string; app?: string }[];
  busy: boolean;
  onSave: (body: DemJourneyWrite) => void;
  onCancel: () => void;
}) {
  const [name, setName] = useState(initial?.name ?? "");
  const [app, setApp] = useState(initial?.app ?? "");
  const [description, setDescription] = useState(initial?.description ?? "");
  const [importance, setImportance] = useState(initial?.business_importance ?? "normal");
  const [value, setValue] = useState(String(initial?.business_value_per_success ?? ""));
  const [currency, setCurrency] = useState(initial?.currency ?? "");
  const [successPct, setSuccessPct] = useState(String(initial?.slo.success_pct ?? 99));
  const [latencyMs, setLatencyMs] = useState(String(initial?.slo.latency_ms ?? ""));
  const [entry, setEntry] = useState(initial?.entry_step_id ?? "");
  const [steps, setSteps] = useState<DraftStep[]>(
    initial?.steps?.length ? initial.steps.map(toDraft) : [{ ...emptyStep(1), terminal_success: true }],
  );

  const setStep = (i: number, patch: Partial<DraftStep>) =>
    setSteps((prev) => prev.map((s, k) => (k === i ? { ...s, ...patch } : s)));

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    const body: DemJourneyWrite = {
      name, app, description,
      business_importance: importance,
      business_value_per_success: Number(value) || 0,
      currency,
      entry_step_id: entry || steps[0]?.id || "",
      steps: steps.map((s) => ({
        id: s.id,
        label: s.label,
        optional: s.optional,
        next: s.nextText.split(",").map((x) => x.trim()).filter(Boolean),
        terminal_success: s.terminal_success,
        terminal_failure: s.terminal_failure,
        target_id: s.target_id,
        slo_success_pct: s.slo_success_pct,
        slo_latency_ms: s.slo_latency_ms,
      })),
      slo: {
        success_pct: Number(successPct) || 0,
        latency_ms: Number(latencyMs) || 0,
        window: initial?.slo.window ?? "",
      },
    };
    onSave(body);
  };

  const noSuccessTerminal = !steps.some((s) => s.terminal_success);
  const valueWithoutCurrency = Number(value) > 0 && !currency.trim();

  return (
    <Panel title={initial ? `Edit ${initial.name}` : "Declare a journey"}
      label="Journey editor">
      <form className="dx-form" onSubmit={submit}>
        <div className="dx-field-row">
          <div className="dx-field">
            <label htmlFor="dx-j-name">Name</label>
            <input id="dx-j-name" value={name} required
              onChange={(e) => setName(e.target.value)} />
          </div>
          <div className="dx-field">
            <label htmlFor="dx-j-app">Application</label>
            <input id="dx-j-app" value={app} onChange={(e) => setApp(e.target.value)} />
          </div>
          <div className="dx-field">
            <label htmlFor="dx-j-importance">Business importance</label>
            <select id="dx-j-importance" value={importance}
              onChange={(e) => setImportance(e.target.value)}>
              {IMPORTANCE.map((i) => <option key={i} value={i}>{i}</option>)}
            </select>
          </div>
        </div>

        <div className="dx-field">
          <label htmlFor="dx-j-desc">Description</label>
          <textarea id="dx-j-desc" rows={2} value={description}
            onChange={(e) => setDescription(e.target.value)} />
        </div>

        <div className="dx-field-row">
          <div className="dx-field">
            <label htmlFor="dx-j-slo">Objective, success percent</label>
            <input id="dx-j-slo" type="number" min={0} max={100} step="0.1"
              value={successPct} onChange={(e) => setSuccessPct(e.target.value)} />
          </div>
          <div className="dx-field">
            <label htmlFor="dx-j-lat">Objective, p95 milliseconds</label>
            <input id="dx-j-lat" type="number" min={0} value={latencyMs}
              onChange={(e) => setLatencyMs(e.target.value)} />
            <span className="dx-cap">Leave empty to declare no latency objective — none is invented.</span>
          </div>
          <div className="dx-field">
            <label htmlFor="dx-j-value">Value of one successful traversal</label>
            <input id="dx-j-value" type="number" min={0} step="0.01" value={value}
              onChange={(e) => setValue(e.target.value)} />
          </div>
          <div className="dx-field">
            <label htmlFor="dx-j-ccy">Currency</label>
            <input id="dx-j-ccy" value={currency} maxLength={8}
              onChange={(e) => setCurrency(e.target.value)} />
          </div>
        </div>
        {valueWithoutCurrency && (
          <p className="dx-error" role="alert">
            A value needs a currency. An unlabelled number is not an amount.
          </p>
        )}

        <div className="dx-field">
          <label htmlFor="dx-j-entry">Entry step</label>
          <select id="dx-j-entry" value={entry} onChange={(e) => setEntry(e.target.value)}>
            <option value="">First step</option>
            {steps.map((s) => <option key={s.id} value={s.id}>{s.id}</option>)}
          </select>
        </div>

        <h3 className="dx-h3">Steps</h3>
        <p className="dx-cap">
          A step may branch to several others, may point back at an earlier one (a retry
          loop is legal), and must end somewhere: at least one step has to be a success
          terminal, or the journey has no way to succeed and no success rate.
        </p>

        {steps.map((s, i) => (
          <fieldset className="dx-journey" key={i}>
            <legend className="dx-h3">Step {i + 1}</legend>
            <div className="dx-field-row">
              <div className="dx-field">
                <label htmlFor={`dx-s-id-${i}`}>Step id</label>
                <input id={`dx-s-id-${i}`} value={s.id} required
                  onChange={(e) => setStep(i, { id: e.target.value })} />
              </div>
              <div className="dx-field">
                <label htmlFor={`dx-s-label-${i}`}>Label</label>
                <input id={`dx-s-label-${i}`} value={s.label}
                  onChange={(e) => setStep(i, { label: e.target.value })} />
              </div>
              <div className="dx-field">
                <label htmlFor={`dx-s-next-${i}`}>Next steps</label>
                <input id={`dx-s-next-${i}`} value={s.nextText}
                  placeholder="step-2, step-3"
                  onChange={(e) => setStep(i, { nextText: e.target.value })} />
              </div>
              <div className="dx-field">
                <label htmlFor={`dx-s-target-${i}`}>Measured by</label>
                <select id={`dx-s-target-${i}`} value={s.target_id ?? ""}
                  onChange={(e) => setStep(i, { target_id: e.target.value })}>
                  <option value="">Nothing — declared, not measured</option>
                  {targets.map((t) => (
                    <option key={t.id} value={t.id}>
                      {t.name}{t.site ? ` · ${t.site}` : ""}
                    </option>
                  ))}
                </select>
              </div>
            </div>
            <div className="dx-actions">
              <label>
                <input type="checkbox" checked={s.optional ?? false}
                  onChange={(e) => setStep(i, { optional: e.target.checked })} />
                {" "}Optional
              </label>
              <label>
                <input type="checkbox" checked={s.terminal_success ?? false}
                  onChange={(e) => setStep(i, { terminal_success: e.target.checked, terminal_failure: false })} />
                {" "}Ends in success
              </label>
              <label>
                <input type="checkbox" checked={s.terminal_failure ?? false}
                  onChange={(e) => setStep(i, { terminal_failure: e.target.checked, terminal_success: false })} />
                {" "}Ends in failure
              </label>
              <button type="button" className="btn" disabled={steps.length === 1}
                onClick={() => setSteps((prev) => prev.filter((_, k) => k !== i))}>
                Remove step
              </button>
            </div>
            {!s.target_id && (
              <p className="dx-cap">
                Nothing measures this step, so it will be reported as a coverage gap rather
                than as a success.
              </p>
            )}
          </fieldset>
        ))}

        {noSuccessTerminal && (
          <p className="dx-error" role="alert">
            No step ends in success, so this journey has no way to succeed and cannot have a
            success rate.
          </p>
        )}

        <div className="dx-actions">
          <button type="button" className="btn"
            onClick={() => setSteps((prev) => [...prev, emptyStep(prev.length + 1)])}>
            Add a step
          </button>
          <button type="submit" className="btn-accent"
            disabled={busy || noSuccessTerminal || valueWithoutCurrency}>
            {initial ? "Save changes" : "Declare journey"}
          </button>
          <button type="button" className="btn" onClick={onCancel}>Cancel</button>
        </div>
      </form>
    </Panel>
  );
}
