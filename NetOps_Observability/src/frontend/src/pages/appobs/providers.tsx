// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// providers.tsx — the ONE frontend cloud-provider descriptor module
// (backlog Wave 5 #17: extensibility). Labels, icons, blurbs, console names,
// wizard scope fields and per-method auth-field sets all live HERE, keyed by
// provider id. UI surfaces (ConnectorWizard, Connections, badges, CloudLogs)
// consult this registry instead of branching on "aws"/"azure"/"gcp" — so
// adding Oracle/Alibaba/vSphere is one registerProvider() call from the new
// provider's module, with ZERO edits to the wizard or the cloud pages
// (proven by providers.test.tsx, which registers a fake provider and asserts
// the wizard renders it).
//
// Unknown providers never crash a surface: providerDescriptor() falls back to
// an honest generic descriptor (id as label, no brand mark, no field help).

import type { ReactNode } from "react";
import { AwsLogo, AzureLogo, GcpLogo } from "../../components/ConnectorLogos";

// ── auth-field model (moved here from connectorWizard.ts so descriptors own it) ──
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

// The stored-secret input shown only for legacy methods.
export interface SecretConfig {
  kind: string;
  keyHintLabel: string;
  keyHintPlaceholder: string;
  secretLabel: string;
  secretPlaceholder: string;
  multiline: boolean;
}

// The provider-native id an operator names first (the primary collection scope).
export interface ScopeField {
  type: string;        // backend ScopeType token ("account" | "subscription" | …)
  label: string;       // "Account ID"
  placeholder: string; // "123456789012"
}

// One org-level (multi-account) anchor choice — Wave 5 #17 slice 2 renders
// these as the "Organization (multi-account)" mode options.
export interface OrgScopeField extends ScopeField {
  hint?: string;
}

export interface ProviderUiDescriptor {
  id: string;
  /** Customer-facing full name ("Amazon Web Services"). */
  label: string;
  /** Compact label for dense cells ("AWS"). */
  short: string;
  /** Wizard provider-tile blurb. */
  blurb: string;
  /** Deep-link name ("AWS Console"). */
  consoleName: string;
  /** Brand mark; null = no mark (text carries the identity). */
  icon: (size: number) => ReactNode;
  primaryScope: ScopeField;
  /** Org-anchor choices; empty = provider has no org onboarding mode. */
  orgScopes: OrgScopeField[];
  /** Non-secret identity fields the auth step collects for a method. */
  authFields: (method: string) => AuthField[];
  /** Stored-secret input config for legacy methods; null = secretless method. */
  secretConfig: (method: string) => SecretConfig | null;
}

// ── field catalog (shared building blocks for descriptors) ────────────────────
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

// ── registry ──────────────────────────────────────────────────────────────────
// Registration order is presentation order (the wizard tile order).
const registry = new Map<string, ProviderUiDescriptor>();

/** Register a provider descriptor. Adding a provider = calling this from the
 *  new provider's module — no UI file edits. Duplicate ids are a programmer
 *  error and throw (fail fast, never silently shadow a provider). */
export function registerProvider(d: ProviderUiDescriptor): void {
  const id = d.id.trim().toLowerCase();
  if (!id) throw new Error("registerProvider: empty provider id");
  if (registry.has(id)) throw new Error(`registerProvider: duplicate provider ${id}`);
  registry.set(id, { ...d, id });
}

/** Every registered descriptor, in registration order. */
export function listProviders(): ProviderUiDescriptor[] {
  return [...registry.values()];
}

/** Registered provider ids, in registration order (the wizard tile order). */
export function providerIds(): string[] {
  return [...registry.keys()];
}

/** The descriptor for a provider id — an HONEST generic fallback when the id
 *  is unknown (raw id as label, no brand mark, no field help). Surfaces never
 *  crash on a provider the frontend has no descriptor for. */
export function providerDescriptor(id: string | null | undefined): ProviderUiDescriptor {
  const key = (id ?? "").trim().toLowerCase();
  const d = registry.get(key);
  if (d) return d;
  return {
    id: key,
    label: key || "—",
    short: key ? key.toUpperCase() : "—",
    blurb: "",
    consoleName: "cloud console",
    icon: () => null,
    primaryScope: { type: "account", label: "Account ID", placeholder: "" },
    orgScopes: [],
    authFields: () => [],
    secretConfig: () => null,
  };
}

// ── convenience lookups (what the UI surfaces actually call) ──────────────────
export const providerLabel = (id: string | null | undefined): string => providerDescriptor(id).label;
export const providerShort = (id: string | null | undefined): string => providerDescriptor(id).short;
export const providerBlurb = (id: string | null | undefined): string => providerDescriptor(id).blurb;
export const providerConsoleName = (id: string | null | undefined): string => providerDescriptor(id).consoleName;

/** The provider's brand mark (or null — callers render text alongside, so a
 *  markless provider is still fully identified). */
export function ProviderIcon({ provider, size = 14 }: { provider: string | null | undefined; size?: number }) {
  return <>{providerDescriptor(provider).icon(size)}</>;
}

// ── built-in descriptors ──────────────────────────────────────────────────────
registerProvider({
  id: "aws",
  label: "Amazon Web Services",
  short: "AWS",
  blurb: "Cross-account IAM role, read-only. Inventory, CloudWatch, CloudTrail and VPC flow logs.",
  consoleName: "AWS Console",
  icon: (size) => <AwsLogo size={size} />,
  primaryScope: { type: "account", label: "Account ID", placeholder: "123456789012" },
  orgScopes: [
    { type: "org", label: "Organization ID", placeholder: "o-a1b2c3d4e5", hint: "The AWS Organizations id (management account required for enumeration)." },
    { type: "ou", label: "Organizational Unit ID", placeholder: "ou-a1b2-c3d4e5f6", hint: "Narrow enrollment to one OU of the organization." },
  ],
  authFields: (method) => {
    if (method === "workload_identity_federation" || method === "cloud_role") return [F.role_arn(true)];
    return []; // static_key → only the stored secret
  },
  secretConfig: (method) => method === "static_key" ? {
    kind: "access_key",
    keyHintLabel: "Access key ID", keyHintPlaceholder: "AKIA…",
    secretLabel: "Secret access key", secretPlaceholder: "…", multiline: false,
  } : null,
});

registerProvider({
  id: "azure",
  label: "Microsoft Azure",
  short: "Azure",
  blurb: "Entra workload identity, read-only. Resource inventory, Azure Monitor and activity logs.",
  consoleName: "Azure Portal",
  icon: (size) => <AzureLogo size={size} />,
  primaryScope: { type: "subscription", label: "Subscription ID", placeholder: "00000000-0000-0000-0000-000000000000" },
  orgScopes: [
    { type: "mgmt_group", label: "Management group ID", placeholder: "mg-production", hint: "Role assignments at the management group inherit to every member subscription." },
    { type: "org", label: "Tenant root group", placeholder: "00000000-0000-0000-0000-000000000000", hint: "The Entra tenant root management group — enrolls every subscription." },
  ],
  authFields: (method) => {
    const base = [F.azure_tenant_id(), F.client_id()];
    if (method === "workload_identity_federation") return [...base, F.issuer(), F.federated_subject(), F.audience()];
    if (method === "certificate") return [...base, F.cert_thumbprint()];
    return base; // client_secret → base + stored secret
  },
  secretConfig: (method) => method === "client_secret" ? {
    kind: "client_secret",
    keyHintLabel: "Secret name / ID", keyHintPlaceholder: "correlix-observer-secret",
    secretLabel: "Client secret value", secretPlaceholder: "…", multiline: false,
  } : null,
});

registerProvider({
  id: "gcp",
  label: "Google Cloud",
  short: "GCP",
  blurb: "Workload Identity Federation, read-only. Compute inventory, Cloud Monitoring and flow logs.",
  consoleName: "Google Cloud Console",
  icon: (size) => <GcpLogo size={size} />,
  primaryScope: { type: "project", label: "Project ID", placeholder: "my-project-123" },
  orgScopes: [
    { type: "folder", label: "Folder ID", placeholder: "123456789012", hint: "The numeric folder id — enrolls every project under the folder." },
    { type: "org", label: "Organization ID", placeholder: "123456789012", hint: "The numeric organization id — enrolls every project in the org." },
  ],
  authFields: (method) => {
    if (method === "workload_identity_federation") {
      return [F.project_number(), F.workload_pool(), F.workload_provider(), F.service_account_opt()];
    }
    return [F.project_number(), F.service_account_req()]; // static_key → + stored secret
  },
  secretConfig: (method) => method === "static_key" ? {
    kind: "sa_key",
    keyHintLabel: "Key ID (optional)", keyHintPlaceholder: "key-1",
    secretLabel: "Service-account JSON key", secretPlaceholder: "{ \"type\": \"service_account\", … }",
    multiline: true,
  } : null,
});
