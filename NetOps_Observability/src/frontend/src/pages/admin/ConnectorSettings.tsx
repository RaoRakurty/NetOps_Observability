// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// ConnectorSettings — the inline form behind Configure on one case connector.
//
// WHY IT EXISTS. Every connector on this page used to read "Not configured",
// permanently, on every deployment: the backend could read a tenant's vendor
// credentials and nothing could ever write them. This is where a customer
// brings its own Jira, ServiceNow, Cisco, Juniper or SMTP relay.
//
// WHAT IT WILL NOT DO.
//   · It never shows a stored secret. The server does not send one; the field
//     says "stored" and offers Replace or Remove, and a save that touched
//     neither sends nothing for it (connectorForms.payloadFromState).
//   · It never sends a tenant. The owner is stamped from the token server-side.
//   · Test asks the vendor one READ-ONLY question. It opens no case, and the
//     answer is the server's named outcome, not an invented verdict.
//   · Remove states its one consequence before it is pressed, not after.
//
// The connector's standing vendor research is NOT here: it is behind the row's
// (i) (AskIris topic="tac.connector.<id>"), because a settings form is a place
// to act, not to read (docs/design/UI_WORDS_IRIS_EXPLAINS_2026-09-06.md).

import { useCallback, useEffect, useState } from "react";
import { api, TacConnectorConfigView, TacConnectorProbe } from "../../services/api";
import { operatorError } from "../../lib/errors";
import {
  CONFIG_READ_FAILED,
  CONFIG_REMOVE_FAILED,
  CONFIG_SAVE_FAILED,
  CONFIG_TEST_FAILED,
  ConnectorField,
  FormState,
  PROBE_SENTENCE,
  REMOVE_CONSEQUENCE,
  fieldsFor,
  formStateFromView,
  payloadFromState,
  probeTone,
  secretLabel,
} from "./connectorForms";

export default function ConnectorSettings({ id, onChanged }: {
  /** Registry id, e.g. "email-arista". */
  id: string;
  /** Called after a save or a removal so the list re-reads its states. */
  onChanged: () => void;
}) {
  const [view, setView] = useState<TacConnectorConfigView | null>(null);
  const [form, setForm] = useState<FormState | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState<"" | "save" | "test" | "remove">("");
  const [saved, setSaved] = useState<string | null>(null);
  const [probe, setProbe] = useState<TacConnectorProbe | null>(null);
  const [confirmRemove, setConfirmRemove] = useState(false);

  const load = useCallback(async () => {
    try {
      const v = await api.tacConnectorConfig(id);
      setView(v);
      setForm(formStateFromView(v));
      setErr(null);
    } catch (e) {
      setView(null);
      setForm(null);
      setErr(operatorError(e, CONFIG_READ_FAILED));
    }
  }, [id]);

  useEffect(() => { void load(); }, [load]);

  const setValue = useCallback((name: string, value: string | boolean) => {
    setForm((f) => (f ? { ...f, values: { ...f.values, [name]: value } } : f));
  }, []);
  const setSecret = useCallback((name: string, mode: "keep" | "replace" | "clear", value: string) => {
    setForm((f) => (f ? { ...f, secrets: { ...f.secrets, [name]: { mode, value } } } : f));
  }, []);

  const save = useCallback(async () => {
    if (!view || !form) return;
    setBusy("save");
    setSaved(null);
    setProbe(null);
    try {
      const next = await api.tacConnectorSave(id, payloadFromState(view.section, form));
      setView(next);
      setForm(formStateFromView(next));
      setErr(null);
      setSaved(next.configured ? "Saved. This path is ready." : next.status_note || "Saved.");
      onChanged();
    } catch (e) {
      setErr(operatorError(e, CONFIG_SAVE_FAILED));
    } finally {
      setBusy("");
    }
  }, [form, id, onChanged, view]);

  const test = useCallback(async () => {
    setBusy("test");
    setProbe(null);
    try {
      setProbe(await api.tacConnectorTest(id));
      setErr(null);
    } catch (e) {
      setErr(operatorError(e, CONFIG_TEST_FAILED));
    } finally {
      setBusy("");
    }
  }, [id]);

  const remove = useCallback(async () => {
    setBusy("remove");
    setSaved(null);
    setProbe(null);
    try {
      const next = await api.tacConnectorRemove(id);
      setView(next);
      setForm(formStateFromView(next));
      setErr(null);
      setConfirmRemove(false);
      setSaved("Removed.");
      onChanged();
    } catch (e) {
      setErr(operatorError(e, CONFIG_REMOVE_FAILED));
    } finally {
      setBusy("");
    }
  }, [id, onChanged]);

  if (err && !view) {
    return <p className="adm-line" role="alert" style={{ color: "var(--bad)" }}>{err}</p>;
  }
  if (!view || !form) {
    return <p className="adm-line" role="status">Reading the settings…</p>;
  }
  if (!view.editable) {
    return <p className="adm-line">{view.status_note || "There is nothing to configure here."}</p>;
  }

  const fields = fieldsFor(view.section);
  return (
    <div className="tdc-form" data-testid={`ticket-conn-form-${id}`}>
      {fields.map((f) => (
        <ConnectorFieldRow
          key={f.name}
          id={id}
          field={f}
          form={form}
          stored={view.secrets?.[f.name] === true}
          onValue={setValue}
          onSecret={setSecret}
        />
      ))}

      <div className="tdc-form-actions">
        <button type="button" className="btn" onClick={() => void save()} disabled={busy !== ""}>
          {busy === "save" ? "Saving…" : "Save"}
        </button>
        <button type="button" className="btn" onClick={() => void test()} disabled={busy !== ""}>
          {busy === "test" ? "Testing…" : "Test"}
        </button>
        {confirmRemove ? (
          <>
            <button type="button" className="btn" onClick={() => void remove()} disabled={busy !== ""}>
              {busy === "remove" ? "Removing…" : "Remove for good"}
            </button>
            <button type="button" className="btn" onClick={() => setConfirmRemove(false)}>Keep</button>
            <span className="adm-line">{REMOVE_CONSEQUENCE}</span>
          </>
        ) : (
          <button type="button" className="btn" onClick={() => setConfirmRemove(true)} disabled={busy !== ""}>
            Remove
          </button>
        )}
      </div>

      {saved && <p className="adm-line" role="status">{saved}</p>}
      {err && <p className="adm-line" role="alert" style={{ color: "var(--bad)" }}>{err}</p>}
      {probe && (
        <p className="adm-line" role="status" data-testid={`ticket-conn-probe-${id}`}>
          <span className={`chip ${probeTone(probe.outcome)}`}>{probe.outcome}</span>{" "}
          {PROBE_SENTENCE[probe.outcome] ?? ""} {probe.note}
        </p>
      )}
    </div>
  );
}

/** One field. A secret renders as its state plus the control that changes it. */
function ConnectorFieldRow({ id, field, form, stored, onValue, onSecret }: {
  id: string;
  field: ConnectorField;
  form: FormState;
  stored: boolean;
  onValue: (name: string, value: string | boolean) => void;
  onSecret: (name: string, mode: "keep" | "replace" | "clear", value: string) => void;
}) {
  const fieldId = `conn-${id}-${field.name}`;
  if (field.kind === "toggle") {
    return (
      <div className="tdc-field">
        <label htmlFor={fieldId}>
          <input
            id={fieldId}
            type="checkbox"
            checked={form.values[field.name] === true}
            onChange={(e) => onValue(field.name, e.target.checked)}
          />{" "}
          {field.label}
        </label>
      </div>
    );
  }
  if (field.kind === "secret") {
    const state = form.secrets[field.name] ?? { mode: "keep" as const, value: "" };
    return (
      <div className="tdc-field">
        <label htmlFor={fieldId}>{field.label}</label>
        {state.mode === "replace" ? (
          <input
            id={fieldId}
            type="password"
            autoComplete="new-password"
            value={state.value}
            onChange={(e) => onSecret(field.name, "replace", e.target.value)}
          />
        ) : (
          <span className="tdc-secret" data-testid={`ticket-conn-secret-${id}-${field.name}`}>
            {secretLabel(stored, state.mode)}
          </span>
        )}
        <span className="tdc-field-actions">
          <button type="button" className="btn" onClick={() => onSecret(field.name, "replace", "")}>
            {stored ? "Replace" : "Set"}
          </button>
          {stored && state.mode !== "clear" && (
            <button type="button" className="btn" onClick={() => onSecret(field.name, "clear", "")}>Remove</button>
          )}
          {state.mode !== "keep" && (
            <button type="button" className="btn" onClick={() => onSecret(field.name, "keep", "")}>Undo</button>
          )}
        </span>
      </div>
    );
  }
  if (field.kind === "select") {
    return (
      <div className="tdc-field">
        <label htmlFor={fieldId}>{field.label}</label>
        <select
          id={fieldId}
          value={String(form.values[field.name] ?? "")}
          onChange={(e) => onValue(field.name, e.target.value)}
        >
          {(field.options ?? []).map((o) => (
            <option key={o.value} value={o.value}>{o.label}</option>
          ))}
        </select>
      </div>
    );
  }
  if (field.kind === "map") {
    return (
      <div className="tdc-field">
        <label htmlFor={fieldId}>{field.label}</label>
        <textarea
          id={fieldId}
          rows={4}
          value={String(form.values[field.name] ?? "")}
          onChange={(e) => onValue(field.name, e.target.value)}
        />
      </div>
    );
  }
  return (
    <div className="tdc-field">
      <label htmlFor={fieldId}>{field.label}</label>
      <input
        id={fieldId}
        type={field.kind === "number" ? "number" : "text"}
        inputMode={field.kind === "number" ? "numeric" : undefined}
        placeholder={field.placeholder}
        value={String(form.values[field.name] ?? "")}
        onChange={(e) => onValue(field.name, e.target.value)}
      />
    </div>
  );
}
