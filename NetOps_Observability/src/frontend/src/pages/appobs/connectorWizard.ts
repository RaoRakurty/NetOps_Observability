// Cloud Connector onboarding — pure logic for the wizard (backlog Wave 1 #3).
//
// Everything here is provider/API-shaped and side-effect-free so the wizard's
// step model, per-method field sets, and honesty gates are unit-testable without
// a DOM. The wizard component (ConnectorWizard.tsx) is the thin React shell over
// these helpers and the done 7-step connector API (services/api.ts).
//
// Honesty-first: the ACTIVATE gate is derived ONLY from the backend's real
// validation result (last_validation.ok) — never from client optimism. Federated
// (secretless) auth is the dominant/recommended path and is ordered first.

import type {
  CloudProvider, CloudAuthMethod, CloudAuthInput, CloudConnectorView,
  CloudCapabilityPack, CloudConnFinding,
} from "../../services/api";
import {
  providerDescriptor, providerIds,
  type AuthField, type AuthFieldKey, type SecretConfig,
} from "./providers";

// Re-exported so existing importers keep one import site for the field model.
export type { AuthField, AuthFieldKey, SecretConfig };

// Customer-facing text for an API error thrown by services/api's request()
// ("<status> <text>: <body>"). The 501 case is the honest "this deployment has
// no connector store" message — no backend vendor names.
export function errText(e: unknown): string {
  const m = (e as Error)?.message ?? String(e);
  if (m.startsWith("501")) return "Cloud connectors are not available on this deployment.";
  return m;
}

// ── Steps ─────────────────────────────────────────────────────────────────────
export type WizardStep =
  | "provider" | "draft" | "auth" | "trust" | "scopes" | "validate" | "activate";

export const STEPS: WizardStep[] = [
  "provider", "draft", "auth", "trust", "scopes", "validate", "activate",
];

export const STEP_LABEL: Record<WizardStep, string> = {
  provider: "Provider",
  draft: "Account",
  auth: "Authentication",
  trust: "Trust setup",
  scopes: "Scope",
  validate: "Validate",
  activate: "Activate",
};

export function stepIndex(step: WizardStep): number {
  return STEPS.indexOf(step);
}

// ── Providers ───────────────────────────────────────────────────────────────
// Registry-driven (providers.tsx): the id list, labels, blurbs, scope fields
// and per-method auth fields all come from the ONE descriptor module. Adding a
// provider is a registerProvider() call — nothing here changes.
// NOTE: PROVIDERS is a snapshot taken at module import (compat export); live
// surfaces (the wizard tile list) call providerIds() directly so providers
// registered later still render.
export const PROVIDERS: CloudProvider[] = providerIds();

// The provider-native id an operator names first (the primary collection scope).
export function primaryScopeType(p: CloudProvider): string {
  return providerDescriptor(p).primaryScope.type;
}
export function primaryScopeLabel(p: CloudProvider): string {
  return providerDescriptor(p).primaryScope.label;
}
export function primaryScopePlaceholder(p: CloudProvider): string {
  return providerDescriptor(p).primaryScope.placeholder;
}

// ── Auth methods ──────────────────────────────────────────────────────────────
export const METHOD_LABEL: Record<CloudAuthMethod, string> = {
  workload_identity_federation: "Workload Identity Federation",
  cloud_role: "Cross-account role",
  certificate: "Certificate",
  client_secret: "Client secret",
  static_key: "Static access key",
  admin_password: "Admin password",
};

export const METHOD_BLURB: Record<CloudAuthMethod, string> = {
  workload_identity_federation:
    "Secretless. Correlix presents its own signed workload identity and receives short-lived tokens. Nothing to store or rotate.",
  cloud_role:
    "Secretless. Correlix assumes a role you create, gated by a per-connector external ID (confused-deputy protection).",
  certificate:
    "A certificate you register on the app; Correlix holds only the thumbprint reference.",
  client_secret:
    "Legacy. A reusable secret Correlix must store (encrypted) and you must rotate. Prefer federation.",
  static_key:
    "Legacy. A long-lived key Correlix must store (encrypted). Root/admin keys are rejected. Prefer federation.",
  admin_password: "Never a connector credential.",
};

// A legacy method means Correlix must store a reusable secret (Vault-encrypted).
export function methodHoldsSecret(m: CloudAuthMethod): boolean {
  return m === "client_secret" || m === "static_key";
}

// ── Identity fields per provider × method (mirrors cloudconn ValidateConfiguration) ──
// Both surfaces resolve through the provider descriptor (providers.tsx).
export function authFields(provider: CloudProvider, method: CloudAuthMethod): AuthField[] {
  return providerDescriptor(provider).authFields(method);
}

export function secretConfig(provider: CloudProvider, method: CloudAuthMethod): SecretConfig | null {
  if (!methodHoldsSecret(method)) return null;
  return providerDescriptor(provider).secretConfig(method);
}

// buildAuthInput assembles the auth POST body from the collected values. The
// TENANT is never included (server stamps the owner); the AWS ExternalId is minted
// server-side, never sent from the client.
export function buildAuthInput(method: CloudAuthMethod, values: Partial<Record<AuthFieldKey, string>>): CloudAuthInput {
  const trim = (v?: string) => (v ?? "").trim();
  return {
    method,
    role_arn: trim(values.role_arn),
    azure_tenant_id: trim(values.azure_tenant_id),
    client_id: trim(values.client_id),
    audience: trim(values.audience),
    issuer: trim(values.issuer),
    federated_subject: trim(values.federated_subject),
    cert_thumbprint: trim(values.cert_thumbprint),
    project_number: trim(values.project_number),
    workload_pool: trim(values.workload_pool),
    workload_provider: trim(values.workload_provider),
    service_account: trim(values.service_account),
  };
}

// Every non-secret required field present? (client-side pre-check; the backend
// remains the authority — this only avoids a round-trip on obviously-empty forms).
export function authFieldsComplete(
  provider: CloudProvider, method: CloudAuthMethod, values: Partial<Record<AuthFieldKey, string>>,
): boolean {
  return authFields(provider, method).every((f) => !f.required || (values[f.key] ?? "").trim() !== "");
}

// ── Capability pack helpers ───────────────────────────────────────────────────
export function packFullId(p: CloudCapabilityPack): string {
  return `${p.id}-${p.version}`;
}
// The flat, de-duplicated, sorted permission set the setup templates + validator
// use — the exact "what Correlix will be able to read" answer for the Scope step.
export function packPermissions(p: CloudCapabilityPack | undefined): string[] {
  if (!p) return [];
  const seen = new Set<string>();
  for (const c of p.capabilities ?? []) for (const perm of c.permissions ?? []) seen.add(perm);
  return [...seen].sort();
}

// ── Finding / health presentation ─────────────────────────────────────────────
export function findingTone(sev: CloudConnFinding["severity"]): string {
  return sev === "error" ? "var(--crit)" : sev === "warning" ? "var(--warn)" : "var(--accent)";
}
export function findingIcon(sev: CloudConnFinding["severity"]): string {
  return sev === "error" ? "✕" : sev === "warning" ? "!" : "i";
}

export interface LiveCheckDisplay { label: string; tone: string; ok: boolean; }
export function liveCheckDisplay(marker: string): LiveCheckDisplay {
  switch (marker) {
    case "ok": return { label: "Live trust proven", tone: "var(--ok)", ok: true };
    case "deferred": return { label: "Live check deferred", tone: "var(--warn)", ok: false };
    case "failed": return { label: "Live trust failed", tone: "var(--crit)", ok: false };
    default: return { label: marker || "—", tone: "var(--fg-subtle)", ok: false };
  }
}

export function healthTone(state: string): string {
  switch (state) {
    case "live_verified": case "healthy": return "var(--ok)";
    case "config_validated": return "var(--accent)";
    case "degraded": case "unverified": return "var(--warn)";
    case "failed": return "var(--crit)";
    default: return "var(--fg-subtle)";
  }
}
export function healthLabel(state: string): string {
  switch (state) {
    case "live_verified": return "Live verified";
    case "config_validated": return "Config validated";
    case "healthy": return "Healthy";
    case "degraded": return "Degraded";
    case "failed": return "Failed";
    case "unverified": return "Unverified";
    case "unknown": case "": return "Not checked";
    default: return state;
  }
}

// The single honesty gate: activation is allowed ONLY when the backend's own
// configuration validation passed. Live-trust "deferred" (platform identity not
// configured in this deployment) still allows activation — but a live FAILURE
// records a blocking finding, so last_validation.ok is false and this returns false.
export function canActivate(view: CloudConnectorView | null): boolean {
  return !!view?.last_validation?.ok;
}

// The connector already reached ACTIVE.
export function isActive(view: CloudConnectorView | null): boolean {
  return view?.state === "ACTIVE";
}

// ── Resume (pick an incomplete connector back up where it left off) ───────────
// The API keeps the full connector state (GET by id / list), so the wizard can
// re-open at the first step that still needs work. Derivation is conservative:
// we only skip a step when the API's stored truth proves it was completed.

// The step an existing connector should re-open at.
export function resumeStep(v: CloudConnectorView): WizardStep {
  if (v.state === "ACTIVE" || v.state === "DEGRADED") return "activate";
  // Backend validation already passed → only activation remains.
  if (v.last_validation?.ok) return "validate";
  // Scopes saved → auth + trust were completed; validation is the open step.
  if ((v.scopes?.length ?? 0) > 0) return "validate";
  // Auth method chosen and its trust metadata saved → deploy/confirm the trust.
  if (v.auth_method) return "trust";
  // Draft exists but nothing else — re-confirm the name/target and continue.
  return "draft";
}

// Setup states an operator can resume in the wizard. Paused (DISABLED) and
// revoked connectors are lifecycle actions, not onboarding resumes.
export function isResumable(v: CloudConnectorView): boolean {
  return v.state === "DRAFT" || v.state === "DEPLOYING" || v.state === "VALIDATING"
    || v.state === "REAUTHORIZATION_REQUIRED";
}

// The primary (non-region) collection scope ref stored on the connector — the
// account / subscription / project id the draft step captured.
export function resumePrimaryRef(v: CloudConnectorView): string {
  const sc = (v.scopes ?? []).find((s) => s.type !== "region");
  return sc?.ref ?? "";
}

// The saved region narrowing, re-flattened to the wizard's comma-separated field.
export function resumeRegions(v: CloudConnectorView): string {
  const scopes = v.scopes ?? [];
  const primary = scopes.find((s) => s.type !== "region");
  const regionRefs = scopes.filter((s) => s.type === "region").map((s) => s.ref);
  return [...(primary?.regions ?? []), ...regionRefs].filter(Boolean).join(", ");
}

// Re-hydrate the auth form from the connector's stored trust metadata. Only
// NON-secret identity fields exist on the view (the API never echoes a secret),
// so this is safe by construction.
export function hydrateAuthValues(v: CloudConnectorView): Partial<Record<AuthFieldKey, string>> {
  const i = v.identity ?? ({} as CloudConnectorView["identity"]);
  const out: Partial<Record<AuthFieldKey, string>> = {};
  const put = (k: AuthFieldKey, val?: string) => { if (val && val.trim() !== "") out[k] = val; };
  put("role_arn", i.role_arn);
  put("azure_tenant_id", i.azure_tenant_id);
  put("client_id", i.client_id);
  put("audience", i.audience);
  put("issuer", i.issuer);
  put("federated_subject", i.federated_subject);
  put("cert_thumbprint", i.cert_thumbprint);
  put("project_number", i.project_number);
  put("workload_pool", i.workload_pool);
  put("workload_provider", i.workload_provider);
  put("service_account", i.service_account);
  return out;
}

// ── Honest connector status (list view) ──────────────────────────────────────
// One customer-facing status per connector, derived ONLY from the API's stored
// truth (lifecycle state + the backend's own validation result). VALIDATING with
// a failed last_validation reads as failed — we never paint a green (or a blue)
// the backend didn't earn.
export interface ConnectorStatus { label: string; tone: string; }

export function connectorStatus(v: CloudConnectorView): ConnectorStatus {
  switch (v.state) {
    case "ACTIVE": return { label: "Enabled", tone: "var(--ok)" };
    case "DEGRADED": return { label: "Enabled — degraded", tone: "var(--warn)" };
    case "DISABLED": return { label: "Paused", tone: "var(--fg-subtle)" };
    case "REVOKED": return { label: "Revoked", tone: "var(--crit)" };
    case "REAUTHORIZATION_REQUIRED": return { label: "Needs re-authorization", tone: "var(--crit)" };
    case "DELETING": return { label: "Removing", tone: "var(--fg-subtle)" };
    case "VALIDATING":
      return v.last_validation?.ok
        ? { label: "Validated — not enabled", tone: "var(--accent)" }
        : { label: "Validation failed", tone: "var(--crit)" };
    default: { // DRAFT / DEPLOYING / ""
      const failed = v.identity_health?.state === "failed"
        || (!v.last_validation?.ok && (v.last_validation?.findings?.length ?? 0) > 0);
      if (failed) return { label: "Validation failed", tone: "var(--crit)" };
      return v.state === "DEPLOYING"
        ? { label: "Deploying trust", tone: "var(--warn)" }
        : { label: "Setup incomplete", tone: "var(--warn)" };
    }
  }
}

// Short scope summary for the list ("123456789012 · 2 regions").
export function scopeSummary(v: CloudConnectorView): string {
  const primary = resumePrimaryRef(v);
  if (!primary) return "—";
  const regions = resumeRegions(v).split(",").map((s) => s.trim()).filter(Boolean);
  return regions.length ? `${primary} · ${regions.length} region${regions.length > 1 ? "s" : ""}` : primary;
}
