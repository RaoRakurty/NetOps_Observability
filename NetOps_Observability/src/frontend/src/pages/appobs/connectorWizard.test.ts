// connectorWizard.test.ts — the pure logic behind the Cloud Connector onboarding
// wizard (backlog Wave 1 #3). The load-bearing guarantees:
//  • per-provider × method identity fields match the backend validator's required
//    fields (no field the backend wants is missing; no field it rejects is offered);
//  • the auth body NEVER carries a tenant (owner is stamped server-side) and never
//    the AWS external id (minted server-side, confused-deputy protection);
//  • activation is gated ONLY on the backend's real validation result (honesty).

import { describe, it, expect } from "vitest";
import type { CloudConnectorView, CloudCapabilityPack } from "../../services/api";
import {
  STEPS, stepIndex, PROVIDERS, primaryScopeType, primaryScopeLabel,
  authFields, methodHoldsSecret, secretConfig, buildAuthInput, authFieldsComplete,
  packFullId, packPermissions, findingTone, liveCheckDisplay, healthLabel,
  canActivate, isActive,
} from "./connectorWizard";

describe("wizard step model", () => {
  it("orders the 7 API steps", () => {
    expect(STEPS).toEqual(["provider", "draft", "auth", "trust", "scopes", "validate", "activate"]);
    expect(stepIndex("validate")).toBe(5);
    expect(stepIndex("activate")).toBe(6);
  });
});

describe("provider → primary scope", () => {
  it("maps each provider to its native primary scope", () => {
    expect(PROVIDERS).toEqual(["aws", "azure", "gcp"]);
    expect(primaryScopeType("aws")).toBe("account");
    expect(primaryScopeType("azure")).toBe("subscription");
    expect(primaryScopeType("gcp")).toBe("project");
    expect(primaryScopeLabel("gcp")).toBe("Project ID");
  });
});

describe("auth fields match the backend validator", () => {
  it("AWS federated/role require a role ARN; static key needs no identity field", () => {
    expect(authFields("aws", "workload_identity_federation").map((f) => f.key)).toEqual(["role_arn"]);
    expect(authFields("aws", "cloud_role").map((f) => f.key)).toEqual(["role_arn"]);
    expect(authFields("aws", "static_key")).toEqual([]);
  });
  it("Azure always needs tenant + client id, plus method extras", () => {
    expect(authFields("azure", "workload_identity_federation").map((f) => f.key))
      .toEqual(["azure_tenant_id", "client_id", "issuer", "federated_subject", "audience"]);
    expect(authFields("azure", "certificate").map((f) => f.key))
      .toEqual(["azure_tenant_id", "client_id", "cert_thumbprint"]);
    expect(authFields("azure", "client_secret").map((f) => f.key))
      .toEqual(["azure_tenant_id", "client_id"]);
  });
  it("GCP always needs the project number, plus method extras", () => {
    expect(authFields("gcp", "workload_identity_federation").map((f) => f.key))
      .toEqual(["project_number", "workload_pool", "workload_provider", "service_account"]);
    expect(authFields("gcp", "static_key").map((f) => f.key))
      .toEqual(["project_number", "service_account"]);
  });
  it("marks audience + impersonated SA optional, everything else required", () => {
    const azFed = authFields("azure", "workload_identity_federation");
    expect(azFed.find((f) => f.key === "audience")?.required).toBe(false);
    expect(azFed.find((f) => f.key === "issuer")?.required).toBe(true);
    const gcpFed = authFields("gcp", "workload_identity_federation");
    expect(gcpFed.find((f) => f.key === "service_account")?.required).toBe(false);
  });
});

describe("legacy secret handling", () => {
  it("only client_secret + static_key hold a stored secret", () => {
    expect(methodHoldsSecret("workload_identity_federation")).toBe(false);
    expect(methodHoldsSecret("cloud_role")).toBe(false);
    expect(methodHoldsSecret("certificate")).toBe(false);
    expect(methodHoldsSecret("client_secret")).toBe(true);
    expect(methodHoldsSecret("static_key")).toBe(true);
  });
  it("returns a secret config only for legacy methods, with a provider-correct kind", () => {
    expect(secretConfig("aws", "workload_identity_federation")).toBeNull();
    expect(secretConfig("aws", "static_key")?.kind).toBe("access_key");
    expect(secretConfig("azure", "client_secret")?.kind).toBe("client_secret");
    expect(secretConfig("gcp", "static_key")?.kind).toBe("sa_key");
    expect(secretConfig("gcp", "static_key")?.multiline).toBe(true);
  });
});

describe("buildAuthInput — tenant/external-id isolation", () => {
  it("carries the method + supplied fields but never a tenant or external id", () => {
    const body = buildAuthInput("cloud_role", { role_arn: "  arn:aws:iam::123:role/x  " });
    expect(body.method).toBe("cloud_role");
    expect(body.role_arn).toBe("arn:aws:iam::123:role/x"); // trimmed
    // the wire contract has no tenant / external_id keys at all
    expect(Object.keys(body)).not.toContain("tenant");
    expect(Object.keys(body)).not.toContain("tenant_id");
    expect(Object.keys(body)).not.toContain("external_id");
  });
});

describe("authFieldsComplete", () => {
  it("requires every required field but tolerates blank optionals", () => {
    expect(authFieldsComplete("aws", "cloud_role", {})).toBe(false);
    expect(authFieldsComplete("aws", "cloud_role", { role_arn: "arn:aws:iam::1:role/x" })).toBe(true);
    // audience optional → complete without it
    expect(authFieldsComplete("azure", "workload_identity_federation", {
      azure_tenant_id: "t", client_id: "c", issuer: "i", federated_subject: "s",
    })).toBe(true);
  });
});

describe("capability pack helpers", () => {
  const pack: CloudCapabilityPack = {
    id: "aws-observer", version: "v1", provider: "aws", title: "AWS Observer",
    summary: "", read_only: true,
    capabilities: [
      { key: "a", title: "", apis: [], permissions: ["ec2:Describe*", "s3:GetObject"], read_only: true, data_collected: "", rca_value: "" },
      { key: "b", title: "", apis: [], permissions: ["s3:GetObject", "cloudwatch:ListMetrics"], read_only: true, data_collected: "", rca_value: "" },
    ],
  };
  it("builds the immutable full id", () => {
    expect(packFullId(pack)).toBe("aws-observer-v1");
  });
  it("flattens, de-dupes and sorts the permission set", () => {
    expect(packPermissions(pack)).toEqual(["cloudwatch:ListMetrics", "ec2:Describe*", "s3:GetObject"]);
    expect(packPermissions(undefined)).toEqual([]);
  });
});

describe("presentation helpers", () => {
  it("tones findings by severity", () => {
    expect(findingTone("error")).toBe("var(--crit)");
    expect(findingTone("warning")).toBe("var(--warn)");
    expect(findingTone("info")).toBe("var(--accent)");
  });
  it("labels the live-trust markers honestly", () => {
    expect(liveCheckDisplay("ok").ok).toBe(true);
    expect(liveCheckDisplay("deferred").ok).toBe(false);
    expect(liveCheckDisplay("failed").tone).toBe("var(--crit)");
  });
  it("labels identity-health states", () => {
    expect(healthLabel("live_verified")).toBe("Live verified");
    expect(healthLabel("config_validated")).toBe("Config validated");
    expect(healthLabel("unknown")).toBe("Not checked");
  });
});

describe("activation honesty gate", () => {
  const base: CloudConnectorView = {
    id: "ccn_1", provider: "aws", display_name: "x", auth_method: "cloud_role",
    auth_federated: false, auth_legacy: false, capability_pack: "aws-observer-v1",
    state: "VALIDATING", collecting: false,
    identity: { has_legacy_secret: false }, scopes: [],
    identity_health: { state: "config_validated" }, telemetry_health: { state: "unknown" },
    last_validation: { ok: false, findings: [] }, version: 1,
    created_at: "", updated_at: "",
  };
  it("blocks activation until the BACKEND validation passed", () => {
    expect(canActivate(null)).toBe(false);
    expect(canActivate({ ...base, last_validation: { ok: false, findings: [] } })).toBe(false);
    expect(canActivate({ ...base, last_validation: { ok: true, findings: [] } })).toBe(true);
  });
  it("reports ACTIVE state", () => {
    expect(isActive({ ...base, state: "ACTIVE" })).toBe(true);
    expect(isActive({ ...base, state: "VALIDATING" })).toBe(false);
  });
});
