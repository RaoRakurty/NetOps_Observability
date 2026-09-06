// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { ReactNode, useState } from "react";

// Wizard — the shared guided-setup primitive. Every multi-field setup flow
// (ITSM, auth providers, API keys, notifications, …) should use this instead of
// dumping a raw form: it presents one logical step at a time and REFUSES to
// advance until the current step's required fields are valid (step.isValid()),
// so an operator can't skip ahead and submit a half-filled config.
//
// Usage:
//   <Wizard
//     steps={[{ id, title, hint?, render: () => <…/>, isValid: () => boolean }, …]}
//     onFinish={submit}      // called only after the LAST step is valid
//     onCancel={() => …}     // optional
//     finishLabel="Create"
//   />

export type WizardStep = {
  id: string;
  title: string;
  hint?: string;
  render: () => ReactNode;
  isValid: () => boolean;
};

export default function Wizard({
  steps,
  onFinish,
  onCancel,
  finishLabel = "Finish",
}: {
  steps: WizardStep[];
  onFinish: () => void | Promise<void>;
  onCancel?: () => void;
  finishLabel?: string;
}) {
  const [i, setI] = useState(0);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const step = steps[i];
  const last = i === steps.length - 1;
  const canAdvance = step.isValid();

  const next = async () => {
    if (!canAdvance) return;
    setErr(null);
    if (!last) {
      setI(i + 1);
      return;
    }
    setBusy(true);
    try {
      await onFinish();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="wizard">
      {/* Step rail */}
      <ol className="wizard-steps" style={stepsRow}>
        {steps.map((s, idx) => {
          const state = idx < i ? "done" : idx === i ? "active" : "todo";
          return (
            <li key={s.id} style={stepItem}>
              <span style={stepCircle(state)}>{state === "done" ? "✓" : idx + 1}</span>
              <span style={{ fontSize: 12, fontWeight: idx === i ? 700 : 500, color: idx === i ? "var(--fg)" : "var(--muted)" }}>
                {s.title}
              </span>
              {idx < steps.length - 1 && <span style={stepBar(idx < i)} />}
            </li>
          );
        })}
      </ol>

      {step.hint && <p style={{ color: "var(--muted)", fontSize: 12, margin: "4px 0 10px" }}>{step.hint}</p>}

      <div className="wizard-body">{step.render()}</div>

      {err && <p style={{ color: "var(--bad)", fontSize: 13 }}>{err}</p>}

      <div style={footer}>
        <div>
          {onCancel && <button className="btn" onClick={onCancel} disabled={busy}>Cancel</button>}
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          {i > 0 && <button className="btn" onClick={() => setI(i - 1)} disabled={busy}>Back</button>}
          <button
            className="btn accent"
            onClick={next}
            disabled={!canAdvance || busy}
            title={canAdvance ? "" : "Fill the required fields on this step to continue"}
          >
            {busy ? "Working…" : last ? finishLabel : "Next"}
          </button>
        </div>
      </div>
    </div>
  );
}

const stepsRow: React.CSSProperties = { display: "flex", listStyle: "none", padding: 0, margin: "0 0 12px", gap: 0, flexWrap: "wrap" };
const stepItem: React.CSSProperties = { display: "flex", alignItems: "center", gap: 8, paddingRight: 8 };
const footer: React.CSSProperties = { display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: 14 };

function stepCircle(state: "done" | "active" | "todo"): React.CSSProperties {
  const bg = state === "done" ? "var(--good)" : state === "active" ? "var(--accent)" : "var(--hover)";
  const color = state === "todo" ? "var(--muted)" : "#fff";
  return { width: 22, height: 22, borderRadius: 999, background: bg, color, fontSize: 12, fontWeight: 700, display: "inline-flex", alignItems: "center", justifyContent: "center", flex: "none" };
}
function stepBar(done: boolean): React.CSSProperties {
  return { width: 28, height: 2, background: done ? "var(--good)" : "var(--panel-border, #e2e6ee)", margin: "0 4px" };
}
