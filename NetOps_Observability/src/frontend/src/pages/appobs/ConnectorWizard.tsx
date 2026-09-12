// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Cloud Connector onboarding wizard (backlog Wave 1 #3).
//
// A guided, multi-step flow over the DONE 7-step connector API (the domain model,
// RLS storage, live AWS/Azure/GCP token exchange and validate-with-findings are
// already built — this is the front-end over them). Steps mirror the API:
//   provider catalog → draft → auth method (federated dominant) → trust setup →
//   scope → validate-with-findings (LIVE trust proof) → activate.
//
// House rules honored here:
//  • Tenant isolation — the client NEVER sends a tenant; the backend stamps the
//    owner from the token and mints the AWS ExternalId itself. We only read/write
//    trust metadata, never a secret we don't submit.
//  • Honesty-first — the Validate step calls the real backend; activation is gated
//    on last_validation.ok (canActivate). We never paint a green we didn't earn.
//  • Design-system primitives — ao-*/var(--*) tokens, light+dark for free.
//  • Accessible — role="dialog" + aria-modal, ESC to close, a labelled stepper
//    with aria-current, keyboard-reachable controls.

import { ReactNode, useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  api, CloudProvider, CloudAuthMethod, CloudConnectorView, CloudProviderCatalogEntry,
  CloudCapabilityPack, CloudSetupBundle, CloudScope,
} from "../../services/api";
import { invalidateCloudInventory } from "./api";
import { providerIds, providerLabel, providerBlurb, providerDescriptor, ProviderIcon, OrgScopeField } from "./providers";
import {
  WizardStep, STEPS, STEP_LABEL, stepIndex,
  primaryScopeType, primaryScopeLabel, primaryScopePlaceholder,
  METHOD_LABEL, METHOD_BLURB, methodHoldsSecret, authFields, AuthFieldKey,
  secretConfig, buildAuthInput, authFieldsComplete, packFullId, packPermissions,
  findingTone, findingIcon, liveCheckDisplay, healthTone, healthLabel, canActivate, isActive,
  errText, resumeStep, resumePrimaryRef, resumeRegions, hydrateAuthValues,
} from "./connectorWizard";

// Red asterisk + legend for required fields (the admin.tsx config-form convention).
function ReqLegend() {
  return <p className="ccw-hint"><span className="ccw-req" aria-hidden="true">*</span> required field</p>;
}

export default function ConnectorWizard({ onClose, onCreated, resume }: {
  onClose: () => void;
  /** Called after a connector reaches ACTIVE so the caller reloads its accounts. */
  onCreated: (view: CloudConnectorView) => void;
  /** Re-open an incomplete connector at the first step that still needs work
   *  (state re-hydrated from the API's stored truth — never a secret). */
  resume?: CloudConnectorView;
}) {
  const [catalog, setCatalog] = useState<CloudProviderCatalogEntry[] | null>(null);
  const [catalogErr, setCatalogErr] = useState<string>("");

  const [step, setStep] = useState<WizardStep>(() => (resume ? resumeStep(resume) : "provider"));
  const [maxReached, setMaxReached] = useState<number>(() => (resume ? stepIndex(resumeStep(resume)) : 0));

  const [provider, setProvider] = useState<CloudProvider | null>(resume?.provider ?? null);
  const [connector, setConnector] = useState<CloudConnectorView | null>(resume ?? null);

  // draft form
  const [displayName, setDisplayName] = useState(resume?.display_name ?? "");
  const [accountId, setAccountId] = useState(
    () => (resume ? (resume.identity?.org?.ref || resumePrimaryRef(resume)) : ""),
  );

  // org-level (multi-account) mode — Wave 5 #17 slice 2. In org mode the
  // target field IS the org anchor ref (org / management-group / folder id).
  const [orgMode, setOrgMode] = useState(() => !!resume?.identity?.org);
  const [orgType, setOrgType] = useState<string>(() => resume?.identity?.org?.type ?? "");
  const [orgRole, setOrgRole] = useState(() => resume?.identity?.org?.role_template ?? "");

  // auth form
  const [method, setMethod] = useState<CloudAuthMethod | null>(resume?.auth_method || null);
  const [authValues, setAuthValues] = useState<Partial<Record<AuthFieldKey, string>>>(
    () => (resume ? hydrateAuthValues(resume) : {}),
  );
  const [secretHint, setSecretHint] = useState("");
  const [secretValue, setSecretValue] = useState("");
  // A stored (write-only) credential is never echoed back; the operator can keep
  // it or explicitly replace it. True only while "Replace" is active.
  const [replaceSecret, setReplaceSecret] = useState(false);

  // trust setup
  const [setup, setSetup] = useState<CloudSetupBundle | null>(null);

  // scope
  const [regions, setRegions] = useState<string>(() => (resume ? resumeRegions(resume) : ""));

  // validate
  const [validation, setValidation] = useState<CloudConnectorView["last_validation"] | null>(null);
  const [liveCheck, setLiveCheck] = useState<string>("");

  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>("");

  const dialogRef = useRef<HTMLDivElement>(null);

  // load provider catalog once (needs only infrastructure:read)
  useEffect(() => {
    let live = true;
    api.cloudProviderCatalog().then(
      (r) => { if (live) setCatalog(r.providers ?? []); },
      (e) => { if (live) setCatalogErr(errText(e)); },
    );
    return () => { live = false; };
  }, []);

  // ESC to close + focus the dialog on open (accessibility).
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKey);
    dialogRef.current?.focus();
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const entry = useMemo(
    () => catalog?.find((c) => c.provider === provider) ?? null,
    [catalog, provider],
  );
  const observerPack: CloudCapabilityPack | undefined = entry?.capability_packs?.[0];
  const methods = entry?.methods ?? [];

  // Org-mode surface (registry-driven): the provider's org anchor choices and
  // the effective target field (org anchor in org mode, else primary scope).
  const orgOptions = providerDescriptor(provider).orgScopes;
  const orgOption: OrgScopeField | undefined =
    orgOptions.find((o) => o.type === orgType) ?? orgOptions[0];
  const orgActive = orgMode && !!orgOption;
  const scopeLabel = orgActive ? orgOption.label : provider ? primaryScopeLabel(provider) : "";
  const scopePlaceholder = orgActive ? orgOption.placeholder : provider ? primaryScopePlaceholder(provider) : "";

  const goStep = useCallback((s: WizardStep) => {
    setError("");
    setStep(s);
    setMaxReached((m) => Math.max(m, stepIndex(s)));
  }, []);

  // ── step actions ──────────────────────────────────────────────────────────
  const createDraft = async () => {
    if (!provider) return;
    setBusy(true); setError("");
    try {
      let c = connector;
      if (!c) {
        c = await api.cloudCreateConnector(provider, displayName.trim());
      }
      // Bind the read-only observer capability pack so every downstream step
      // (setup templates, validate live-check, requested permissions) has it.
      if (observerPack && c.capability_pack !== packFullId(observerPack)) {
        c = await api.cloudConnectorCapabilities(c.id, packFullId(observerPack));
      }
      // Org mode: anchor the connector on the org container so the trust step
      // renders the org-level artifacts and discovery enumerates members. The
      // tenant is NEVER sent — member scopes inherit the connector's owner.
      if (orgActive) {
        c = await api.cloudConnectorOrg(c.id, {
          type: orgOption.type, ref: accountId.trim(), role_template: orgRole.trim(),
        });
      } else if (c.identity?.org) {
        c = await api.cloudConnectorOrg(c.id, { type: "" }); // back to single-account
      }
      setConnector(c);
      goStep("auth");
    } catch (e) { setError(errText(e)); }
    finally { setBusy(false); }
  };

  const submitAuth = async () => {
    if (!connector || !method) return;
    setBusy(true); setError("");
    try {
      let c = await api.cloudConnectorAuth(connector.id, buildAuthInput(method, authValues));
      // Legacy methods: encrypt-and-store the reusable secret (never re-shown).
      // A credential that is already stored (write-only) is kept unless the
      // operator explicitly typed a replacement.
      if (methodHoldsSecret(method) && secretValue.trim()) {
        const sc = secretConfig(provider!, method)!;
        c = await api.cloudConnectorSecret(c.id, {
          kind: sc.kind, key_hint: secretHint.trim(), secret: secretValue,
        });
        setSecretValue(""); // drop the plaintext from component state
        setReplaceSecret(false);
      }
      setConnector(c);
      setSetup(null);
      goStep("trust");
    } catch (e) { setError(errText(e)); }
    finally { setBusy(false); }
  };

  // fetch the trust setup templates when entering the trust step
  useEffect(() => {
    if (step !== "trust" || !connector || setup) return;
    let live = true;
    api.cloudConnectorSetup(connector.id).then(
      (b) => { if (live) setSetup(b); },
      (e) => { if (live) setError(errText(e)); },
    );
    return () => { live = false; };
  }, [step, connector, setup]);

  const submitScopes = async () => {
    if (!connector || !provider) return;
    setBusy(true); setError("");
    try {
      const regionList = regions.split(",").map((s) => s.trim()).filter(Boolean);
      const scopes: CloudScope[] = [{
        // Org mode: the collection scope is the org anchor itself; member
        // accounts arrive via Discover Scopes and operator selection.
        type: orgActive ? orgOption.type : primaryScopeType(provider),
        ref: accountId.trim(),
        ...(regionList.length ? { regions: regionList } : {}),
      }];
      const c = await api.cloudConnectorScopes(connector.id, scopes);
      setConnector(c);
      goStep("validate");
    } catch (e) { setError(errText(e)); }
    finally { setBusy(false); }
  };

  const runValidate = async () => {
    if (!connector) return;
    setBusy(true); setError("");
    try {
      // A resumed connector may predate the pack binding (the draft step binds
      // it) — bind the read-only observer pack before the live trust proof so
      // the exchanged credential is bounded to it.
      if (!connector.capability_pack && observerPack) {
        setConnector(await api.cloudConnectorCapabilities(connector.id, packFullId(observerPack)));
      }
      const r = await api.cloudConnectorValidate(connector.id);
      setConnector(r.connector);
      setValidation(r.validation);
      setLiveCheck(r.live_check);
    } catch (e) { setError(errText(e)); }
    finally { setBusy(false); }
  };

  const activate = async () => {
    if (!connector) return;
    setBusy(true); setError("");
    try {
      const c = await api.cloudConnectorActivate(connector.id);
      setConnector(c);
      invalidateCloudInventory(); // the accounts list must re-read the stored truth
      onCreated(c);
      goStep("activate");
    } catch (e) { setError(errText(e)); }
    finally { setBusy(false); }
  };

  // ── per-step gating for the primary button ─────────────────────────────────
  const draftValid = !!provider && displayName.trim() !== "" && accountId.trim() !== "";
  // A stored credential (write-only, has_legacy_secret) satisfies the secret
  // requirement unless the operator chose to replace it.
  const secretStored = !!connector?.identity?.has_legacy_secret && method === (connector?.auth_method || null);
  const authValid = !!method && authFieldsComplete(provider!, method, authValues) &&
    (!methodHoldsSecret(method) || secretValue.trim() !== "" || (secretStored && !replaceSecret));

  // UI-words sweep 5 (tracker 270): a heading is budgeted at four words, so the
  // three-way title is resolved here rather than inline in the <h2>.
  const headTitle = resume
    ? `Finish setting up ${resume.display_name || (provider ? providerLabel(provider) : "this connection")}`
    : provider ? `Connect ${providerLabel(provider)}` : "Connect a cloud account";

  return (
    <div className="ev-detail-scrim" onClick={onClose}>
      <aside
        className="ev-detail ccw"
        role="dialog"
        aria-modal="true"
        aria-labelledby="ccw-title"
        tabIndex={-1}
        ref={dialogRef}
        onClick={(e) => e.stopPropagation()}
      >
        <header className="ccw-head">
          <div>
            <div className="ccw-eyebrow">{resume ? "Resume cloud onboarding" : "Cloud onboarding"}</div>
            <h2 className="ccw-title" id="ccw-title">{headTitle}</h2>
          </div>
          <button className="ao-x" onClick={onClose} aria-label="Close wizard">×</button>
        </header>

        <Stepper current={step} maxReached={maxReached} onJump={(s) => goStep(s)} />

        <div className="ccw-body">
          {catalogErr && step === "provider" ? (
            <div className="ccw-error" role="alert">{catalogErr}</div>
          ) : (
            <>
              {step === "provider" && (
                <ProviderStep
                  catalog={catalog}
                  selected={provider}
                  onSelect={(p) => { if (p !== provider) { setProvider(p); setConnector(null); setMethod(null); setAuthValues({}); } }}
                />
              )}
              {step === "draft" && provider && (
                <DraftStep
                  provider={provider} nameLocked={!!connector}
                  displayName={displayName} onName={setDisplayName}
                  accountId={accountId} onAccount={setAccountId}
                  scopeLabel={scopeLabel} scopePlaceholder={scopePlaceholder}
                  orgOptions={orgOptions} orgMode={orgMode} onOrgMode={setOrgMode}
                  orgType={orgOption?.type ?? ""} onOrgType={setOrgType}
                  orgRole={orgRole} onOrgRole={setOrgRole}
                />
              )}
              {step === "auth" && provider && (
                <AuthStep
                  provider={provider} methods={methods}
                  method={method} onMethod={setMethod}
                  values={authValues} onValue={(k, v) => setAuthValues((s) => ({ ...s, [k]: v }))}
                  secretHint={secretHint} onSecretHint={setSecretHint}
                  secretValue={secretValue} onSecretValue={setSecretValue}
                  secretStored={secretStored} storedKeyHint={connector?.identity?.legacy_key_hint}
                  replaceSecret={replaceSecret} onReplaceSecret={setReplaceSecret}
                />
              )}
              {step === "trust" && (
                <TrustStep setup={setup} connector={connector} />
              )}
              {step === "scopes" && provider && (
                <ScopeStep
                  accountId={accountId} onAccount={setAccountId}
                  regions={regions} onRegions={setRegions}
                  pack={observerPack}
                  scopeLabel={scopeLabel} scopePlaceholder={scopePlaceholder}
                  orgActive={orgActive}
                />
              )}
              {step === "validate" && (
                <ValidateStep
                  connector={connector} validation={validation} liveCheck={liveCheck}
                  busy={busy} onRun={runValidate}
                />
              )}
              {step === "activate" && (
                <ActivateStep connector={connector} />
              )}
              {error && <div className="ccw-error" role="alert">{error}</div>}
            </>
          )}
        </div>

        <footer className="ccw-foot">
          <StepNav
            step={step} busy={busy}
            draftValid={draftValid} authValid={authValid} scopeValid={accountId.trim() !== ""}
            canValidateNext={canActivate(connector)}
            active={isActive(connector)}
            onBack={() => { const i = stepIndex(step); if (i > 0) goStep(STEPS[i - 1]); }}
            onProviderNext={() => provider && goStep("draft")}
            onDraftNext={createDraft}
            onAuthNext={submitAuth}
            onTrustNext={() => goStep("scopes")}
            onScopeNext={submitScopes}
            onActivate={activate}
            onClose={onClose}
          />
        </footer>
      </aside>
    </div>
  );
}

// ── Stepper ─────────────────────────────────────────────────────────────────
function Stepper({ current, maxReached, onJump }: {
  current: WizardStep; maxReached: number; onJump: (s: WizardStep) => void;
}) {
  const curIdx = stepIndex(current);
  return (
    <ol className="ccw-steps" aria-label="Onboarding progress">
      {STEPS.map((s, i) => {
        const state = i < curIdx ? "done" : i === curIdx ? "current" : "todo";
        const reachable = i <= maxReached && i !== curIdx;
        return (
          <li key={s} className={`ccw-step is-${state}`} aria-current={state === "current" ? "step" : undefined}>
            <button
              className="ccw-step-btn" disabled={!reachable}
              onClick={() => reachable && onJump(s)}
              aria-label={`Step ${i + 1}: ${STEP_LABEL[s]}${state === "done" ? " (completed)" : ""}`}
            >
              <span className="ccw-step-dot" aria-hidden="true">{i < curIdx ? "✓" : i + 1}</span>
              <span className="ccw-step-l">{STEP_LABEL[s]}</span>
            </button>
          </li>
        );
      })}
    </ol>
  );
}

// ── Step 1: provider catalog ──────────────────────────────────────────────────
function ProviderStep({ catalog, selected, onSelect }: {
  catalog: CloudProviderCatalogEntry[] | null; selected: CloudProvider | null;
  onSelect: (p: CloudProvider) => void;
}) {
  const available = new Set((catalog ?? []).map((c) => c.provider));
  // Registry ∪ catalog: every registered descriptor renders a tile, and a
  // provider the BACKEND offers renders even without a frontend descriptor
  // (generic label fallback) — adding a provider needs zero edits here.
  const tiles = [...providerIds()];
  for (const p of available) if (!tiles.includes(p)) tiles.push(p);
  return (
    <div className="ccw-stack">
      <p className="ccw-lead">Pick the cloud you want Correlix to observe. Every connector is read-only and least-privilege.</p>
      <div className="ccw-tiles" role="radiogroup" aria-label="Cloud provider">
        {tiles.map((p) => {
          const ready = catalog === null || available.has(p);
          return (
            <button
              key={p} role="radio" aria-checked={selected === p}
              className={`ccw-tile${selected === p ? " is-sel" : ""}`}
              disabled={!ready}
              onClick={() => onSelect(p)}
            >
              <ProviderIcon provider={p} size={44} />
              <span className="ccw-tile-t">{providerLabel(p)}</span>
              <span className="ccw-tile-d">{providerBlurb(p)}</span>
            </button>
          );
        })}
      </div>
    </div>
  );
}

// ── Step 2: draft ─────────────────────────────────────────────────────────────
function DraftStep({ provider, nameLocked, displayName, onName, accountId, onAccount,
  scopeLabel, scopePlaceholder, orgOptions, orgMode, onOrgMode, orgType, onOrgType, orgRole, onOrgRole }: {
  provider: CloudProvider; nameLocked: boolean; displayName: string; onName: (v: string) => void;
  accountId: string; onAccount: (v: string) => void;
  scopeLabel: string; scopePlaceholder: string;
  orgOptions: OrgScopeField[]; orgMode: boolean; onOrgMode: (v: boolean) => void;
  orgType: string; onOrgType: (v: string) => void;
  orgRole: string; onOrgRole: (v: string) => void;
}) {
  const orgAvailable = orgOptions.length > 0;
  const orgActive = orgMode && orgAvailable;
  const selected = orgOptions.find((o) => o.type === orgType) ?? orgOptions[0];
  return (
    <div className="ccw-stack">
      <p className="ccw-lead">Name this connection and tell us what it targets.</p>
      <label className="ccw-field">
        <span className="ccw-label">Connection name <span className="ccw-req" aria-hidden="true">*</span></span>
        <input className="ccw-input" value={displayName} maxLength={128}
          placeholder="e.g. Production — us-east" disabled={nameLocked}
          onChange={(e) => onName(e.target.value)} aria-required="true" />
        {nameLocked && <span className="ccw-hint">The name was set when this connection was created and can't be changed here.</span>}
      </label>

      {orgAvailable && (
        <div className="ccw-field" role="radiogroup" aria-label="Enrollment mode">
          <span className="ccw-label">Enrollment mode</span>
          <div className="ccw-methods">
            <button type="button" role="radio" aria-checked={!orgActive}
              className={`ccw-method${!orgActive ? " is-sel" : ""}`}
              onClick={() => onOrgMode(false)}>
              <span className="ccw-method-h"><span className="ccw-method-t">Single {primaryScopeLabel(provider).replace(/ ID$/, "").toLowerCase()}</span></span>
              <span className="ccw-method-d">Observe one {primaryScopeLabel(provider).toLowerCase().replace(/ id$/, "")}.</span>
            </button>
            <button type="button" role="radio" aria-checked={orgActive}
              className={`ccw-method${orgActive ? " is-sel" : ""}`}
              onClick={() => onOrgMode(true)}>
              <span className="ccw-method-h"><span className="ccw-method-t">Organization (multi-account)</span></span>
              <span className="ccw-method-d">Deploy trust once at the org level; member accounts are enumerated for selection and inherit this connection's workspace.</span>
            </button>
          </div>
        </div>
      )}

      {orgActive && orgOptions.length > 1 && (
        <label className="ccw-field">
          <span className="ccw-label">Enroll at</span>
          <select className="ccw-input" value={selected?.type ?? ""} onChange={(e) => onOrgType(e.target.value)} aria-label="Org anchor kind">
            {orgOptions.map((o) => <option key={o.type} value={o.type}>{o.label}</option>)}
          </select>
        </label>
      )}

      <label className="ccw-field">
        <span className="ccw-label">{scopeLabel} <span className="ccw-req" aria-hidden="true">*</span></span>
        <input className="ccw-input ccw-mono" value={accountId} maxLength={200}
          placeholder={scopePlaceholder}
          onChange={(e) => onAccount(e.target.value)} aria-required="true" />
        <span className="ccw-hint">
          {orgActive
            ? (selected?.hint ?? "The org-level container Correlix anchors trust on.")
            : "The primary collection scope. You can narrow to regions on the Scope step."}
        </span>
      </label>

      {orgActive && (
        <label className="ccw-field">
          <span className="ccw-label">Member role name (optional)</span>
          <input className="ccw-input ccw-mono" value={orgRole} maxLength={64}
            placeholder="correlix-observer"
            onChange={(e) => onOrgRole(e.target.value)} />
          <span className="ccw-hint">The read-only observer role the org-level deployment creates in every member account.</span>
        </label>
      )}
      <ReqLegend />
    </div>
  );
}

// ── Step 3: auth method ───────────────────────────────────────────────────────
function AuthStep({ provider, methods, method, onMethod, values, onValue, secretHint, onSecretHint, secretValue, onSecretValue, secretStored, storedKeyHint, replaceSecret, onReplaceSecret }: {
  provider: CloudProvider;
  methods: CloudProviderCatalogEntry["methods"];
  method: CloudAuthMethod | null; onMethod: (m: CloudAuthMethod) => void;
  values: Partial<Record<AuthFieldKey, string>>; onValue: (k: AuthFieldKey, v: string) => void;
  secretHint: string; onSecretHint: (v: string) => void;
  secretValue: string; onSecretValue: (v: string) => void;
  /** A credential is already stored for this method (write-only — never shown). */
  secretStored: boolean; storedKeyHint?: string;
  replaceSecret: boolean; onReplaceSecret: (v: boolean) => void;
}) {
  const fields = method ? authFields(provider, method) : [];
  const sc = method ? secretConfig(provider, method) : null;
  // Write-only credential already on file → show the configured state instead of
  // an input; the stored value is NEVER echoed back into the form.
  const showConfigured = !!sc && secretStored && !replaceSecret;
  return (
    <div className="ccw-stack">
      <p className="ccw-lead">How should Correlix authenticate? <strong>Federated (secretless)</strong> is recommended — nothing to store or rotate.</p>
      <div className="ccw-methods" role="radiogroup" aria-label="Authentication method">
        {methods.map((m) => (
          <button
            key={m.method} role="radio" aria-checked={method === m.method}
            className={`ccw-method${method === m.method ? " is-sel" : ""}${m.legacy ? " is-legacy" : ""}`}
            onClick={() => onMethod(m.method)}
          >
            <span className="ccw-method-h">
              <span className="ccw-method-t">{METHOD_LABEL[m.method]}</span>
              {m.recommended && <span className="ccw-tag ccw-tag--rec">Recommended</span>}
              {m.federated && !m.recommended && <span className="ccw-tag ccw-tag--fed">Secretless</span>}
              {m.legacy && <span className="ccw-tag ccw-tag--legacy">Legacy</span>}
            </span>
            <span className="ccw-method-d">{METHOD_BLURB[m.method]}</span>
          </button>
        ))}
      </div>

      {method && (
        <div className="ccw-panel">
          <div className="ccw-panel-h">Trust details</div>
          {fields.length === 0 && !sc && (
            <p className="ccw-hint">No identifiers needed here — you'll deploy the trust and prove it on the next steps.</p>
          )}
          {fields.map((f) => (
            <label className="ccw-field" key={f.key}>
              <span className="ccw-label">{f.label}{f.required && <span className="ccw-req" aria-hidden="true"> *</span>}</span>
              <input
                className={`ccw-input${f.mono ? " ccw-mono" : ""}`}
                value={values[f.key] ?? ""} placeholder={f.placeholder}
                onChange={(e) => onValue(f.key, e.target.value)}
                aria-required={f.required || undefined}
              />
              {f.hint && <span className="ccw-hint">{f.hint}</span>}
            </label>
          ))}
          {sc && showConfigured && (
            <div className="ccw-field">
              <span className="ccw-label">{sc.secretLabel}</span>
              <div className="ccw-secretset">
                <span className="ccw-secretset-dot" aria-hidden="true" />
                <span>
                  Credential configured{storedKeyHint ? <> (<code className="ccw-mono">{storedKeyHint}</code>)</> : null} — stored encrypted, write-only, never displayed.
                </span>
                <button type="button" className="ao-btn ccw-copy" onClick={() => onReplaceSecret(true)}>Replace</button>
              </div>
            </div>
          )}
          {sc && !showConfigured && (
            <>
              <label className="ccw-field">
                <span className="ccw-label">{sc.keyHintLabel}</span>
                <input className="ccw-input ccw-mono" value={secretHint} placeholder={sc.keyHintPlaceholder}
                  onChange={(e) => onSecretHint(e.target.value)} />
              </label>
              <label className="ccw-field">
                <span className="ccw-label">{sc.secretLabel} <span className="ccw-req" aria-hidden="true">*</span></span>
                {sc.multiline ? (
                  <textarea className="ccw-input ccw-mono" rows={5} value={secretValue} placeholder={sc.secretPlaceholder}
                    onChange={(e) => onSecretValue(e.target.value)} aria-required="true" />
                ) : (
                  <input type="password" className="ccw-input ccw-mono" value={secretValue} placeholder={sc.secretPlaceholder}
                    onChange={(e) => onSecretValue(e.target.value)} aria-required="true" autoComplete="off" />
                )}
                <span className="ccw-hint">Encrypted immediately in the platform vault and never displayed again. Root/admin credentials are rejected.</span>
              </label>
              {secretStored && replaceSecret && (
                <button type="button" className="ao-btn ccw-copy" onClick={() => { onReplaceSecret(false); onSecretValue(""); }}>
                  Keep the stored credential
                </button>
              )}
            </>
          )}
          {(fields.some((f) => f.required) || (sc && !showConfigured)) && <ReqLegend />}
        </div>
      )}
    </div>
  );
}

// ── Step 4: trust setup templates ─────────────────────────────────────────────
function TrustStep({ setup, connector }: { setup: CloudSetupBundle | null; connector: CloudConnectorView | null }) {
  const extId = connector?.identity?.external_id;
  if (!setup) return <div className="ccw-stack"><p className="ccw-lead ao-muted">Loading trust setup…</p></div>;
  return (
    <div className="ccw-stack">
      <p className="ccw-lead">{setup.summary}</p>
      {extId && (
        <div className="ccw-callout">
          <span className="ccw-callout-l">External ID (minted for this connector)</span>
          <CopyLine text={extId} />
        </div>
      )}
      <ol className="ccw-steplist">
        {setup.steps.map((s, i) => <li key={i}>{s}</li>)}
      </ol>
      {setup.artifacts.map((a) => (
        <CopyBlock key={a.kind} title={a.title} content={a.content} />
      ))}
    </div>
  );
}

// ── Step 5: scope + requested permissions ─────────────────────────────────────
function ScopeStep({ accountId, onAccount, regions, onRegions, pack, scopeLabel, scopePlaceholder, orgActive }: {
  accountId: string; onAccount: (v: string) => void;
  regions: string; onRegions: (v: string) => void;
  pack: CloudCapabilityPack | undefined;
  scopeLabel: string; scopePlaceholder: string; orgActive: boolean;
}) {
  const perms = packPermissions(pack);
  return (
    <div className="ccw-stack">
      <p className="ccw-lead">Confirm what Correlix will collect from — and exactly what it's allowed to read.</p>
      <div className="ccw-panel">
        <div className="ccw-panel-h">Collection scope</div>
        <label className="ccw-field">
          <span className="ccw-label">{scopeLabel} <span className="ccw-req" aria-hidden="true">*</span></span>
          <input className="ccw-input ccw-mono" value={accountId} maxLength={200}
            placeholder={scopePlaceholder}
            onChange={(e) => onAccount(e.target.value)} aria-required="true" />
          {orgActive && (
            <span className="ccw-hint">
              Organization mode: member accounts are enumerated after validation (Discover Scopes) and inherit this connection's workspace — enumeration never widens collection by itself.
            </span>
          )}
        </label>
        <label className="ccw-field">
          <span className="ccw-label">Regions (optional)</span>
          <input className="ccw-input ccw-mono" value={regions}
            placeholder="us-east-1, eu-west-1"
            onChange={(e) => onRegions(e.target.value)} />
          <span className="ccw-hint">Comma-separated. Leave blank to observe all regions in the {scopeLabel.toLowerCase()}.</span>
        </label>
        <ReqLegend />
      </div>
      <div className="ccw-panel">
        <div className="ccw-panel-h">
          Requested permissions
          {pack && <span className="ccw-panel-meta">{pack.title} · read-only</span>}
        </div>
        {perms.length === 0 ? (
          <p className="ccw-hint">Permissions are set by the provider’s capability pack.</p>
        ) : (
          <ul className="ccw-perms">
            {perms.map((p) => <li key={p} className="ccw-perm"><code>{p}</code></li>)}
          </ul>
        )}
      </div>
    </div>
  );
}

// ── Step 6: validate with findings (LIVE) ─────────────────────────────────────
function ValidateStep({ connector, validation, liveCheck, busy, onRun }: {
  connector: CloudConnectorView | null;
  validation: CloudConnectorView["last_validation"] | null;
  liveCheck: string; busy: boolean; onRun: () => void;
}) {
  const live = liveCheck ? liveCheckDisplay(liveCheck) : null;
  const idh = connector?.identity_health;
  const findings = validation?.findings ?? [];
  const ran = validation !== null;
  return (
    <div className="ccw-stack">
      <p className="ccw-lead">
        Prove the trust is real. This runs the configuration checks <strong>and a live credential exchange</strong> against
        the provider. Activation stays blocked until it passes.
      </p>
      <div className="ccw-cta-row">
        <button className="ao-btn ao-btn--primary" onClick={onRun} disabled={busy}>
          {busy ? "Validating…" : ran ? "Re-run validation" : "Run validation"}
        </button>
      </div>

      {ran && (
        <>
          <div className="ccw-verdict" style={{ borderColor: validation?.ok ? "var(--ok)" : "var(--crit)" }}>
            <span className="ccw-verdict-dot" style={{ background: validation?.ok ? "var(--ok)" : "var(--crit)" }} aria-hidden="true" />
            <span className="ccw-verdict-t">{validation?.ok ? "Configuration validated" : "Validation failed"}</span>
            {live && <span className="ccw-chip" style={{ color: live.tone, borderColor: live.tone }}>{live.label}</span>}
          </div>

          {idh && (
            <div className="ccw-kv">
              <span className="ccw-k">Identity health</span>
              <span style={{ color: healthTone(idh.state) }}>{healthLabel(idh.state)}{idh.detail ? ` — ${idh.detail}` : ""}</span>
            </div>
          )}

          {findings.length > 0 ? (
            <ul className="ccw-findings">
              {findings.map((f, i) => (
                <li key={i} className="ccw-finding">
                  <span className="ccw-finding-i" style={{ background: findingTone(f.severity) }} aria-hidden="true">{findingIcon(f.severity)}</span>
                  <div>
                    <div className="ccw-finding-m">{f.message}</div>
                    {f.remediation && <div className="ccw-finding-r">{f.remediation}</div>}
                  </div>
                </li>
              ))}
            </ul>
          ) : (
            <p className="ccw-hint">No blocking findings. {live?.ok ? "The provider issued a live scoped credential." : "The live trust check was deferred in this deployment."}</p>
          )}
        </>
      )}
    </div>
  );
}

// ── Step 7: activate ──────────────────────────────────────────────────────────
function ActivateStep({ connector }: { connector: CloudConnectorView | null }) {
  const active = isActive(connector);
  return (
    <div className="ccw-stack ccw-center">
      <div className="ccw-done-badge" style={{ borderColor: active ? "var(--ok)" : "var(--accent)" }} aria-hidden="true">
        {active ? "✓" : "→"}
      </div>
      <h3 className="ccw-done-t">{active ? "Connector is live" : "Ready to activate"}</h3>
      <p className="ccw-lead ccw-center-t">
        {active
          ? `${connector?.display_name} is active. Correlix will begin collecting on its next poll — identity health is proven, telemetry health follows as data arrives.`
          : "Activate to start collection. You can pause or revoke the connector at any time."}
      </p>
    </div>
  );
}

// ── footer nav ────────────────────────────────────────────────────────────────
function StepNav(props: {
  step: WizardStep; busy: boolean; draftValid: boolean; authValid: boolean; scopeValid: boolean;
  canValidateNext: boolean; active: boolean;
  onBack: () => void; onProviderNext: () => void; onDraftNext: () => void;
  onAuthNext: () => void; onTrustNext: () => void; onScopeNext: () => void;
  onActivate: () => void; onClose: () => void;
}) {
  const { step, busy } = props;
  const backBtn = step !== "provider" && step !== "activate" && (
    <button className="ao-btn" onClick={props.onBack} disabled={busy}>Back</button>
  );
  let primary: ReactNode = null;
  switch (step) {
    case "provider": primary = <button className="ao-btn ao-btn--primary" onClick={props.onProviderNext} disabled={busy}>Continue</button>; break;
    case "draft": primary = <button className="ao-btn ao-btn--primary" onClick={props.onDraftNext} disabled={busy || !props.draftValid}>{busy ? "Creating…" : "Create draft"}</button>; break;
    case "auth": primary = <button className="ao-btn ao-btn--primary" onClick={props.onAuthNext} disabled={busy || !props.authValid}>{busy ? "Saving…" : "Save & continue"}</button>; break;
    case "trust": primary = <button className="ao-btn ao-btn--primary" onClick={props.onTrustNext} disabled={busy}>I've deployed the trust</button>; break;
    case "scopes": primary = (
      <button className="ao-btn ao-btn--primary" onClick={props.onScopeNext} disabled={busy || !props.scopeValid}
        title={props.scopeValid ? undefined : "Enter the collection target to continue"}>
        {busy ? "Saving…" : "Save scope"}
      </button>
    ); break;
    // validate: the activation gate — enabled ONLY once the backend validation passed.
    case "validate": primary = (
      <button className="ao-btn ao-btn--primary" onClick={props.onActivate} disabled={busy || !props.canValidateNext}
        title={props.canValidateNext ? undefined : "Run validation and clear all blocking findings first"}>
        {busy ? "Activating…" : "Activate connector"}
      </button>
    ); break;
    case "activate": primary = <button className="ao-btn ao-btn--primary" onClick={props.onClose}>Done</button>; break;
  }
  return (
    <div className="ccw-nav">
      <button className="ao-btn ccw-cancel" onClick={props.onClose} disabled={busy}>Cancel</button>
      <div className="ccw-nav-r">
        {backBtn}
        {primary}
      </div>
    </div>
  );
}

// ── copy helpers ──────────────────────────────────────────────────────────────
function copy(text: string): void {
  try { navigator.clipboard?.writeText(text); } catch { /* clipboard unavailable */ }
}

function CopyLine({ text }: { text: string }) {
  const [done, setDone] = useState(false);
  return (
    <span className="ccw-copyline">
      <code className="ccw-mono">{text}</code>
      <button className="ao-btn ccw-copy" onClick={() => { copy(text); setDone(true); setTimeout(() => setDone(false), 1400); }}
        aria-label="Copy value">{done ? "Copied" : "Copy"}</button>
    </span>
  );
}

function CopyBlock({ title, content }: { title: string; content: string }) {
  const [done, setDone] = useState(false);
  return (
    <div className="ccw-code">
      <div className="ccw-code-h">
        <span>{title}</span>
        <button className="ao-btn ccw-copy" onClick={() => { copy(content); setDone(true); setTimeout(() => setDone(false), 1400); }}
          aria-label={`Copy ${title}`}>{done ? "Copied" : "Copy"}</button>
      </div>
      <pre className="ccw-pre"><code>{content}</code></pre>
    </div>
  );
}
