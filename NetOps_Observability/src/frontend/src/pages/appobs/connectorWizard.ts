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
export const PROVIDERS: CloudProvider[] = ["aws", "azure", "gcp"];

export const PROVIDER_LABEL: Record<CloudProvider, string> = {
  aws: "Amazon Web Services",
  azure: "Microsoft Azure",
  gcp: "Google Cloud",
};

export const PROVIDER_BLURB: Record<CloudProvider, string> = {
  aws: "Cross-account IAM role, read-only. Inventory, CloudWatch, CloudTrail and VPC flow logs.",
  azure: "Entra workload identity, read-only. Resource inventory, Azure Monitor and activity logs.",
  gcp: "Workload Identity Federation, read-only. Compute inventory, Cloud Monitoring and flow logs.",
};

// The provider-native id an operator names first (the primary collection scope).
export function primaryScopeType(p: CloudProvider): string {
  return p === "aws" ? "account" : p === "azure" ? "subscription" : "project";
}
export function primaryScopeLabel(p: CloudProvider): string {
  return p === "aws" ? "Account ID" : p === "azure" ? "Subscription ID" : "Project ID";
}
export function primaryScopePlaceholder(p: CloudProvider): string {
  return p === "aws" ? "123456789012" : p === "azure"
    ? "00000000-0000-0000-0000-000000000000" : "my-project-123";
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
export type AuthFieldKey =
  | "role_arn" | "azure_tenant_id" | "client_id" | "audience"
  | "issuer" | "federated_subject" | "cert_thumbprint"
  | "project_number" | "workload_pool" | "workload_provider" | "service_account";

export interface AuthField {
  key: AuthFieldKey;
  label: string;
  placeholder: string;
  required: boolean;
  mono?: boolean;
  hint?: string;
}

const F = {
  role_arn: (required: boolean): AuthField => ({
    key: "role_arn", label: "Role ARN", required, mono: true,
    placeholder: "arn:aws:iam::123456789012:role/correlix-observer",
    hint: "Deploy the trust setup on the next step, then paste the created role ARN here.",
  }),
  azure_tenant_id: (): AuthField => ({
    key: "azure_tenant_id", label: "Directory (tenant) ID", required: true, mono: true,
    placeholder: "00000000-0000-0000-0000-000000000000",
  }),
  client_id: (): AuthField => ({
    key: "client_id", label: "Application (client) ID", required: true, mono: true,
    placeholder: "00000000-0000-0000-0000-000000000000",
  }),
  audience: (): AuthField => ({
    key: "audience", label: "Audience", required: false, mono: true,
    placeholder: "api://AzureADTokenExchange",
    hint: "Optional — Entra's default is used when blank.",
  }),
  issuer: (): AuthField => ({
    key: "issuer", label: "Federation issuer", required: true, mono: true,
    placeholder: "https://token.correlix…/oidc",
    hint: "From the trust setup — the Correlix issuer your federated credential trusts.",
  }),
  federated_subject: (): AuthField => ({
    key: "federated_subject", label: "Federation subject", required: true, mono: true,
    placeholder: "correlix:connector:…",
    hint: "From the trust setup — the subject your federated credential trusts.",
  }),
  cert_thumbprint: (): AuthField => ({
    key: "cert_thumbprint", label: "Certificate thumbprint", required: true, mono: true,
    placeholder: "A1B2C3…",
  }),
  project_number: (): AuthField => ({
    key: "project_number", label: "Project number", required: true, mono: true,
    placeholder: "123456789012",
    hint: "The numeric project number (not the project ID).",
  }),
  workload_pool: (): AuthField => ({
    key: "workload_pool", label: "Workload identity pool", required: true, mono: true,
    placeholder: "correlix-pool",
    hint: "From the trust setup — created by the deployed template.",
  }),
  workload_provider: (): AuthField => ({
    key: "workload_provider", label: "Pool provider", required: true, mono: true,
    placeholder: "correlix-provider",
  }),
  service_account_opt: (): AuthField => ({
    key: "service_account", label: "Impersonated service account", required: false, mono: true,
    placeholder: "observer@my-project.iam.gserviceaccount.com",
    hint: "Optional — the least-privilege SA Correlix impersonates.",
  }),
  service_account_req: (): AuthField => ({
    key: "service_account", label: "Service account", required: true, mono: true,
    placeholder: "observer@my-project.iam.gserviceaccount.com",
  }),
};

export function authFields(provider: CloudProvider, method: CloudAuthMethod): AuthField[] {
  if (provider === "aws") {
    if (method === "workload_identity_federation" || method === "cloud_role") return [F.role_arn(true)];
    return []; // static_key → only the stored secret
  }
  if (provider === "azure") {
    const base = [F.azure_tenant_id(), F.client_id()];
    if (method === "workload_identity_federation") return [...base, F.issuer(), F.federated_subject(), F.audience()];
    if (method === "certificate") return [...base, F.cert_thumbprint()];
    return base; // client_secret → base + stored secret
  }
  // gcp
  if (method === "workload_identity_federation") {
    return [F.project_number(), F.workload_pool(), F.workload_provider(), F.service_account_opt()];
  }
  return [F.project_number(), F.service_account_req()]; // static_key → + stored secret
}

// The stored-secret input shown only for legacy methods.
export interface SecretConfig {
  kind: string;
  keyHintLabel: string;
  keyHintPlaceholder: string;
  secretLabel: string;
  secretPlaceholder: string;
  multiline: boolean;
}
export function secretConfig(provider: CloudProvider, method: CloudAuthMethod): SecretConfig | null {
  if (!methodHoldsSecret(method)) return null;
  if (provider === "aws" && method === "static_key") {
    return {
      kind: "access_key",
      keyHintLabel: "Access key ID", keyHintPlaceholder: "AKIA…",
      secretLabel: "Secret access key", secretPlaceholder: "…", multiline: false,
    };
  }
  if (provider === "azure" && method === "client_secret") {
    return {
      kind: "client_secret",
      keyHintLabel: "Secret name / ID", keyHintPlaceholder: "correlix-observer-secret",
      secretLabel: "Client secret value", secretPlaceholder: "…", multiline: false,
    };
  }
  // gcp static_key
  return {
    kind: "sa_key",
    keyHintLabel: "Key ID (optional)", keyHintPlaceholder: "key-1",
    secretLabel: "Service-account JSON key", secretPlaceholder: "{ \"type\": \"service_account\", … }",
    multiline: true,
  };
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
