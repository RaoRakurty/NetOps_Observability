// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// AlertPolicyPanel — the BGP alert policy, on the one-page outage screen.
//
// WHY IT SITS HERE. Everything the Incidents section above shows is a VERDICT
// this policy decided: which origin AS is expected, which upstreams are
// legitimate, and how much visibility loss counts as loss. Until now the policy
// was reachable only by curl, so the operator could read a verdict on this page
// and had nowhere to change the rule that produced it. The panel is directly
// beneath the incidents it governs, and the two consequences an empty field
// carries are printed next to that field:
//
//   * no expected origin ⇒ the baseline is LEARNED, and the chip in the
//     Incidents section says "learned baseline" for exactly this reason;
//   * no upstream set    ⇒ the route-leak check does not run at all, so its
//     silence is unmeasured rather than clean.
//
// TENANT SCOPE. GET is requirePerm(infrastructure, read) and PUT is
// requirePerm(infrastructure, write), both narrowed to the caller's own tenant
// (bgp_alerts.go bgpWatchAuthz). There is NO tenant field on the wire: the
// server stamps the owner from the token, so this panel never sends one.
//
// WHAT THE SERVER CHANGES ON SAVE. TenantPolicy.Normalize() dedupes each ASN
// set, drops AS0, sorts ascending, rewrites every policy key to its canonical
// prefix ("193.0.0.1/21" → "193.0.0.0/21") and sorts the keys. The panel
// therefore re-renders from the RESPONSE, not from what was typed — otherwise
// the screen would show an intent the platform is not holding.
//
// UI-WORDS SWEEP 5 (tracker 270). That paragraph used to be printed on the
// screen behind a "What happens when you save" disclosure; it is now
// ai/skills/explain/policy.bgp-canonical.md, reached from the `(i)` beside the
// save button, and what each of the four rule fields means is
// bgp.alert-rules.md behind the `(i)` in the section header. The field labels,
// the empty-set consequences, the validation errors and "Last set by …" are
// STATED FACTS, so they wear `.fact-line` rather than `.mini-meta`.

import { useCallback, useEffect, useState } from "react";
import { api, type BgpAlertConfigResp, type BgpAlertStatus } from "../../services/api";
import { operatorError } from "../../lib/errors";
import { Section } from "./Section";
import AskIris from "../../components/AskIris";
import {
  EMPTY_POLICY_CONFIG,
  emptySetConsequence,
  policyBody,
  policyDirty,
  policyEvaluationNote,
  policyForm,
  policyLimits,
  validatePolicy,
  type PolicyConfigForm,
  type PolicyFieldErrors,
  type PolicyForm,
} from "./bgpAlerts.model";

const EMPTY_FORM: PolicyForm = { def: { ...EMPTY_POLICY_CONFIG }, prefixes: [] };

function FieldError({ msg }: { msg?: string }) {
  if (!msg) return null;
  return <span role="alert" className="fact-line fact-bad">{msg}</span>;
}

/** One policy block — the tenant default, or one prefix override. */
function ConfigFields({ id, cfg, errs, keyPrefix, disabled, onChange }: {
  id: string;
  cfg: PolicyConfigForm;
  errs: PolicyFieldErrors;
  keyPrefix: string;
  disabled: boolean;
  onChange: (next: PolicyConfigForm) => void;
}) {
  const set = (k: keyof PolicyConfigForm) => (e: { target: { value: string } }) =>
    onChange({ ...cfg, [k]: e.target.value });
  const originNote = emptySetConsequence("expected_origins", cfg.expectedOrigins);
  const upstreamNote = emptySetConsequence("upstreams", cfg.upstreams);
  return (
    <div style={{ display: "grid", gap: 8 }}>
      <label style={{ display: "grid", gap: 3 }}>
        <span className="fact-line">Which AS should announce it</span>
        <input
          className="ccw-input mono"
          type="text"
          value={cfg.expectedOrigins}
          disabled={disabled}
          placeholder="AS64500, AS64501"
          aria-label={`${id} expected origin AS`}
          onChange={set("expectedOrigins")}
        />
        {originNote && <span className="fact-line fact-warn">{originNote}</span>}
        <FieldError msg={errs[`${keyPrefix}expected_origins`]} />
      </label>

      <label style={{ display: "grid", gap: 3 }}>
        <span className="fact-line">Which carriers are allowed</span>
        <input
          className="ccw-input mono"
          type="text"
          value={cfg.upstreams}
          disabled={disabled}
          placeholder="AS3356, AS1299"
          aria-label={`${id} upstream AS`}
          onChange={set("upstreams")}
        />
        {upstreamNote && <span className="fact-line fact-warn">{upstreamNote}</span>}
        <FieldError msg={errs[`${keyPrefix}upstreams`]} />
      </label>

      <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
        <label style={{ display: "grid", gap: 3 }}>
          <span className="fact-line">Least acceptable reach</span>
          <input
            className="ccw-input mono"
            type="text"
            inputMode="decimal"
            style={{ width: 110 }}
            value={cfg.minVisibility}
            disabled={disabled}
            aria-label={`${id} minimum visibility`}
            onChange={set("minVisibility")}
          />
          <FieldError msg={errs[`${keyPrefix}min_visibility`]} />
        </label>
        <label style={{ display: "grid", gap: 3 }}>
          <span className="fact-line">Collectors that must agree</span>
          <input
            className="ccw-input mono"
            type="text"
            inputMode="numeric"
            style={{ width: 110 }}
            value={cfg.minVantages}
            disabled={disabled}
            aria-label={`${id} minimum vantage points`}
            onChange={set("minVantages")}
          />
          <FieldError msg={errs[`${keyPrefix}min_vantages`]} />
        </label>
      </div>
    </div>
  );
}

export function AlertPolicyPanel({ status }: { status?: BgpAlertStatus }) {
  const [resp, setResp] = useState<BgpAlertConfigResp | null>(null);
  const [form, setForm] = useState<PolicyForm>(EMPTY_FORM);
  const [original, setOriginal] = useState<PolicyForm>(EMPTY_FORM);
  const [errs, setErrs] = useState<PolicyFieldErrors>({});
  const [err, setErr] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const [busy, setBusy] = useState(true);
  const [readAt, setReadAt] = useState<number | null>(null);

  const adopt = useCallback((r: BgpAlertConfigResp) => {
    setResp(r);
    const f = policyForm(r);
    setForm(f);
    setOriginal(f);
    setReadAt(Date.now());
  }, []);

  const load = useCallback(async () => {
    setBusy(true);
    try {
      adopt(await api.bgpAlertConfig());
      setErr(null);
    } catch (e) {
      setErr(operatorError(e, "The alert policy could not be read."));
    } finally {
      setBusy(false);
    }
  }, [adopt]);

  useEffect(() => { void load(); }, [load]);

  const limits = policyLimits(resp);
  const dirty = policyDirty(form, original);

  const save = async () => {
    setSaved(false);
    setErr(null);
    const v = validatePolicy(form, limits);
    setErrs(v);
    if (Object.keys(v).length > 0) return;
    setBusy(true);
    try {
      const out = await api.setBgpAlertConfig(policyBody(form, limits));
      // Re-render from the STORED policy: the server dedupes, sorts and
      // canonicalizes, and showing the typed version would be a lie about what
      // the evaluator now holds.
      adopt({ ...(resp as BgpAlertConfigResp), ...out } as BgpAlertConfigResp);
      setSaved(true);
      setTimeout(() => setSaved(false), 2500);
    } catch (e) {
      // The typed policy stays on screen — a refusal must not cost the operator
      // the set they just entered.
      setErr(operatorError(e, "The alert policy was not saved."));
    } finally {
      setBusy(false);
    }
  };

  const addPrefix = () => {
    if (form.prefixes.length >= limits.maxPrefixes) {
      setErrs((e) => ({ ...e, prefixes: `At most ${limits.maxPrefixes} per-prefix policies are allowed.` }));
      return;
    }
    setForm((f) => ({ ...f, prefixes: [...f.prefixes, { key: "", cfg: { ...EMPTY_POLICY_CONFIG } }] }));
  };

  const removePrefix = (i: number) =>
    setForm((f) => ({ ...f, prefixes: f.prefixes.filter((_, n) => n !== i) }));

  return (
    <Section
      id="alert-policy"
      title="Alert rules"
      sub="What counts as a problem here"
      updatedAt={readAt}
      note={<span className="fact-line">your own rules</span>}
      actions={<AskIris topic="bgp.alert-rules" label="Alert rules" />}
    >
      <p className="mini-meta" style={{ marginTop: 0 }}>
        {policyEvaluationNote(status)}
      </p>

      {err && <p role="alert" className="fact-line fact-bad">{err}</p>}
      {saved && <p role="status" className="fact-line" style={{ color: "var(--ok)" }}>Saved.</p>}

      <ConfigFields
        id="Default"
        cfg={form.def}
        errs={errs}
        keyPrefix="default."
        disabled={busy}
        onChange={(def) => setForm((f) => ({ ...f, def }))}
      />

      <div style={{ marginTop: 12 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <span className="fact-line">
            Rules for one prefix — {form.prefixes.length} of {limits.maxPrefixes}
          </span>
          <button className="btn-ghost" style={{ fontSize: 13 }} disabled={busy} onClick={addPrefix}>
            Add a rule for one prefix
          </button>
        </div>
        <FieldError msg={errs.prefixes} />

        {form.prefixes.length === 0 && (
          <div className="empty">
            Every watched prefix uses the settings above. Add one to override them.
          </div>
        )}

        {form.prefixes.map((row, i) => (
          <div key={i} style={{ border: "1px solid var(--border)", borderRadius: 6, padding: 10, marginTop: 8 }}>
            <div style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 6 }}>
              <input
                className="ccw-input mono"
                type="text"
                value={row.key}
                disabled={busy}
                placeholder="193.0.0.0/21"
                aria-label={`Prefix ${i + 1}`}
                onChange={(e) =>
                  setForm((f) => ({
                    ...f,
                    prefixes: f.prefixes.map((r, n) => (n === i ? { ...r, key: e.target.value } : r)),
                  }))
                }
              />
              <button
                className="btn-ghost"
                style={{ fontSize: 13 }}
                disabled={busy}
                aria-label={`Remove the policy for ${row.key || `prefix ${i + 1}`}`}
                onClick={() => removePrefix(i)}
              >
                Remove
              </button>
            </div>
            <FieldError msg={errs[`${row.key.trim()}.key`]} />
            <ConfigFields
              id={row.key || `Prefix ${i + 1}`}
              cfg={row.cfg}
              errs={errs}
              keyPrefix={`${row.key.trim()}.`}
              disabled={busy}
              onChange={(cfg) =>
                setForm((f) => ({ ...f, prefixes: f.prefixes.map((r, n) => (n === i ? { ...r, cfg } : r)) }))
              }
            />
          </div>
        ))}
      </div>

      <div style={{ display: "flex", gap: 8, alignItems: "center", marginTop: 12 }}>
        <button className="btn-primary" disabled={busy || !dirty} onClick={() => void save()}>
          Save rules
        </button>
        {dirty && !busy && <span className="fact-line">Unsaved changes.</span>}
        <AskIris topic="policy.bgp-canonical" label="Save rules" />
        {resp?.updated_by && (
          <span className="fact-line" style={{ marginLeft: "auto" }}>
            Last set by {resp.updated_by}
            {resp.updated_at ? ` on ${new Date(resp.updated_at).toLocaleString()}` : ""}
          </span>
        )}
      </div>
    </Section>
  );
}

export default AlertPolicyPanel;
