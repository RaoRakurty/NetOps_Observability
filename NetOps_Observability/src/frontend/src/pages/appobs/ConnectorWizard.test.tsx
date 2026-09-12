// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// ConnectorWizard.test.tsx — the onboarding wizard drives the DONE 7-step API in
// order and, critically, NEVER lets a connector activate until the BACKEND
// validation passed (honesty-first). We mock services/api so the flow is
// deterministic and assert the gate + the call sequence.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, fireEvent, waitFor, cleanup } from "@testing-library/react";
import type {
  CloudConnectorView, CloudProviderCatalogEntry, CloudCapabilityPack,
  CloudSetupBundle, CloudConnValidateResult,
} from "../../services/api";

// ── api mock (hoisted so the vi.mock factory can reference it) ────────────────
const h = vi.hoisted(() => {
  const draft = (over: Partial<CloudConnectorView> = {}): CloudConnectorView => ({
    id: "ccn_1", provider: "aws", display_name: "Prod", auth_method: "",
    auth_federated: false, auth_legacy: false, capability_pack: "", state: "DRAFT",
    collecting: false, identity: { has_legacy_secret: false }, scopes: [],
    identity_health: { state: "unknown" }, telemetry_health: { state: "unknown" },
    last_validation: { ok: false, findings: [] }, version: 1, created_at: "", updated_at: "",
    ...over,
  });
  const pack: CloudCapabilityPack = {
    id: "aws-observer", version: "v1", provider: "aws", title: "AWS Observer (read-only)",
    summary: "", read_only: true,
    capabilities: [{ key: "inv", title: "", apis: [], permissions: ["ec2:Describe*"], read_only: true, data_collected: "", rca_value: "" }],
  };
  const catalog: CloudProviderCatalogEntry[] = [{
    provider: "aws",
    methods: [
      { method: "workload_identity_federation", rank: 1, federated: true, legacy: false, recommended: true },
      { method: "cloud_role", rank: 2, federated: false, legacy: false, recommended: false },
      { method: "static_key", rank: 5, federated: false, legacy: true, recommended: false },
    ],
    scope_types: ["account", "region"],
    capability_packs: [pack],
  }];
  const setupBundle: CloudSetupBundle = {
    provider: "aws", method: "cloud_role", summary: "Create a read-only cross-account role.",
    steps: ["Deploy the template", "Paste the role ARN back"],
    artifacts: [{ kind: "terraform", title: "Terraform", format: "hcl", content: "resource {}" }],
  };
  const mock = {
    cloudProviderCatalog: vi.fn(async () => ({ providers: catalog })),
    cloudCreateConnector: vi.fn(async () => draft()),
    cloudConnectorCapabilities: vi.fn(async () => draft({ capability_pack: "aws-observer-v1" })),
    cloudConnectorAuth: vi.fn(async () => draft({ auth_method: "cloud_role", identity: { has_legacy_secret: false, external_id: "ext-abc123" } })),
    cloudConnectorSecret: vi.fn(async () => draft({ auth_method: "static_key", identity: { has_legacy_secret: true } })),
    cloudConnectorSetup: vi.fn(async () => setupBundle),
    cloudConnectorScopes: vi.fn(async () => draft({ state: "DRAFT" })),
    cloudConnectorValidate: vi.fn(async (): Promise<CloudConnValidateResult> => ({
      connector: draft({ state: "VALIDATING", last_validation: { ok: true, findings: [] }, identity_health: { state: "live_verified" } }),
      validation: { ok: true, findings: [] },
      live_check: "ok",
    })),
    cloudConnectorActivate: vi.fn(async () => draft({ state: "ACTIVE", last_validation: { ok: true, findings: [] } })),
  };
  return { draft, mock };
});
const mock = h.mock;
const draft = h.draft;

vi.mock("../../services/api", () => ({ api: h.mock }));

import ConnectorWizard from "./ConnectorWizard";

beforeEach(() => { Object.values(mock).forEach((m) => m.mockClear()); });
afterEach(cleanup);

async function advanceToValidate() {
  // provider
  fireEvent.click(await screen.findByText("Amazon Web Services"));
  fireEvent.click(screen.getByRole("button", { name: "Continue" }));
  // draft
  fireEvent.change(await screen.findByPlaceholderText("e.g. Production — us-east"), { target: { value: "Prod" } });
  fireEvent.change(screen.getByPlaceholderText("123456789012"), { target: { value: "123456789012" } });
  fireEvent.click(screen.getByRole("button", { name: "Create draft" }));
  // auth
  fireEvent.click(await screen.findByText("Cross-account role"));
  fireEvent.change(await screen.findByPlaceholderText("arn:aws:iam::123456789012:role/correlix-observer"), {
    target: { value: "arn:aws:iam::123456789012:role/correlix-observer" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Save & continue" }));
  // trust
  fireEvent.click(await screen.findByRole("button", { name: "I've deployed the trust" }));
  // scopes
  fireEvent.click(await screen.findByRole("button", { name: "Save scope" }));
  // validate step reached
  await screen.findByRole("button", { name: "Activate connector" });
}

describe("ConnectorWizard", () => {
  it("renders the three-step provider catalog from the API", async () => {
    render(<ConnectorWizard onClose={() => {}} onCreated={() => {}} />);
    expect(await screen.findByText("Amazon Web Services")).toBeTruthy();
    expect(mock.cloudProviderCatalog).toHaveBeenCalledOnce();
  });

  it("cancels via the footer button", async () => {
    const onClose = vi.fn();
    render(<ConnectorWizard onClose={onClose} onCreated={() => {}} />);
    fireEvent.click(await screen.findByRole("button", { name: "Cancel" }));
    expect(onClose).toHaveBeenCalled();
  });

  it("walks the 7 steps and binds the observer capability pack on draft", async () => {
    render(<ConnectorWizard onClose={() => {}} onCreated={() => {}} />);
    await advanceToValidate();
    expect(mock.cloudCreateConnector).toHaveBeenCalledWith("aws", "Prod");
    expect(mock.cloudConnectorCapabilities).toHaveBeenCalledWith("ccn_1", "aws-observer-v1");
    // auth body carries the method + role ARN, never a tenant
    const authBody = mock.cloudConnectorAuth.mock.calls[0][1];
    expect(authBody.method).toBe("cloud_role");
    expect(authBody.role_arn).toBe("arn:aws:iam::123456789012:role/correlix-observer");
    expect(authBody).not.toHaveProperty("tenant");
    // scope submitted with the account ref
    expect(mock.cloudConnectorScopes).toHaveBeenCalledWith("ccn_1", [{ type: "account", ref: "123456789012" }]);
  });

  it("blocks activation until the backend validation passes, then activates", async () => {
    const onCreated = vi.fn();
    render(<ConnectorWizard onClose={() => {}} onCreated={onCreated} />);
    await advanceToValidate();

    // HONESTY GATE: activate is disabled before any validation ran.
    const activateBtn = screen.getByRole("button", { name: "Activate connector" }) as HTMLButtonElement;
    expect(activateBtn.disabled).toBe(true);
    expect(mock.cloudConnectorActivate).not.toHaveBeenCalled();

    // run the real validation → backend returns ok
    fireEvent.click(screen.getByRole("button", { name: "Run validation" }));
    await waitFor(() => expect(mock.cloudConnectorValidate).toHaveBeenCalledWith("ccn_1"));
    await waitFor(() => expect((screen.getByRole("button", { name: "Activate connector" }) as HTMLButtonElement).disabled).toBe(false));
    expect(await screen.findByText("Configuration validated")).toBeTruthy();
    expect(screen.getByText("Live trust proven")).toBeTruthy();

    // activate
    fireEvent.click(screen.getByRole("button", { name: "Activate connector" }));
    await waitFor(() => expect(mock.cloudConnectorActivate).toHaveBeenCalledWith("ccn_1"));
    expect(onCreated).toHaveBeenCalled();
    expect(await screen.findByText("Connector is live")).toBeTruthy();
  });

  it("resumes an incomplete connector at the first step that still needs work", async () => {
    // auth chosen + scopes saved → validation is the open step.
    const resume = draft({
      auth_method: "cloud_role",
      identity: { has_legacy_secret: false, role_arn: "arn:aws:iam::1:role/x", external_id: "ext-1" },
      scopes: [{ type: "account", ref: "123456789012" }],
    });
    render(<ConnectorWizard onClose={() => {}} onCreated={() => {}} resume={resume} />);
    // lands on Validate without re-walking earlier steps; no new draft created.
    expect(await screen.findByRole("button", { name: "Run validation" })).toBeTruthy();
    expect(mock.cloudCreateConnector).not.toHaveBeenCalled();
    // the header names the resumed connection.
    expect(screen.getByText(/Finish setting up Prod/)).toBeTruthy();
  });

  it("resumes at trust when auth is saved but no scope exists yet", async () => {
    const resume = draft({
      auth_method: "cloud_role",
      identity: { has_legacy_secret: false, role_arn: "arn:aws:iam::1:role/x" },
    });
    render(<ConnectorWizard onClose={() => {}} onCreated={() => {}} resume={resume} />);
    // the trust step fetches the setup bundle for THIS connector.
    await waitFor(() => expect(mock.cloudConnectorSetup).toHaveBeenCalledWith("ccn_1"));
    expect(await screen.findByRole("button", { name: "I've deployed the trust" })).toBeTruthy();
  });

  it("treats a stored credential as configured — write-only, never echoed, no re-entry required", async () => {
    const resume = draft({
      auth_method: "static_key",
      identity: { has_legacy_secret: true, legacy_key_hint: "AKIA-hint" },
    });
    render(<ConnectorWizard onClose={() => {}} onCreated={() => {}} resume={resume} />);
    // opens at trust (auth saved); step Back into Authentication.
    await screen.findByRole("button", { name: "I've deployed the trust" });
    fireEvent.click(screen.getByRole("button", { name: "Back" }));
    // configured state shown instead of a secret input; the value is never present.
    expect(await screen.findByText(/Credential configured/)).toBeTruthy();
    expect(screen.queryByPlaceholderText("…")).toBeNull();
    // Save & continue is enabled WITHOUT re-typing the secret…
    const save = screen.getByRole("button", { name: "Save & continue" }) as HTMLButtonElement;
    expect(save.disabled).toBe(false);
    // …and saving does NOT re-store a secret (the stored one is kept).
    fireEvent.click(save);
    await waitFor(() => expect(mock.cloudConnectorAuth).toHaveBeenCalled());
    expect(mock.cloudConnectorSecret).not.toHaveBeenCalled();
  });

  it("keeps activation blocked when the backend reports a blocking finding", async () => {
    mock.cloudConnectorValidate.mockResolvedValueOnce({
      connector: draft({ last_validation: { ok: false, findings: [{ severity: "error", code: "role_arn_missing", message: "role ARN is required", remediation: "paste the role ARN" }] } }),
      validation: { ok: false, findings: [{ severity: "error", code: "role_arn_missing", message: "role ARN is required", remediation: "paste the role ARN" }] },
      live_check: "failed",
    });
    render(<ConnectorWizard onClose={() => {}} onCreated={() => {}} />);
    await advanceToValidate();
    fireEvent.click(screen.getByRole("button", { name: "Run validation" }));
    await screen.findByText("Validation failed");
    expect(screen.getByText("role ARN is required")).toBeTruthy();
    expect((screen.getByRole("button", { name: "Activate connector" }) as HTMLButtonElement).disabled).toBe(true);
    expect(mock.cloudConnectorActivate).not.toHaveBeenCalled();
  });
});
