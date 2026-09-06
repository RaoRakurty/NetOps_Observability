// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// ConnectorWizardOrg.test.tsx — Wave 5 #17 slice 2: the "Organization
// (multi-account)" wizard mode. Asserts the toggle renders from the provider
// descriptor's orgScopes, the org anchor POST carries type/ref/role_template
// (and NEVER a tenant), and the saved collection scope is the org anchor
// itself — member accounts arrive only via discovery + operator selection.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, fireEvent, waitFor, cleanup } from "@testing-library/react";
import type { CloudConnectorView, CloudProviderCatalogEntry } from "../../services/api";

const h = vi.hoisted(() => {
  const view = (over: Partial<CloudConnectorView> = {}): CloudConnectorView => ({
    id: "ccn_org1", provider: "aws", display_name: "Org prod", auth_method: "",
    auth_federated: false, auth_legacy: false, capability_pack: "", state: "DRAFT",
    collecting: false, identity: { has_legacy_secret: false }, scopes: [],
    identity_health: { state: "unknown" }, telemetry_health: { state: "unknown" },
    last_validation: { ok: false, findings: [] }, version: 1, created_at: "", updated_at: "",
    ...over,
  });
  const catalog: CloudProviderCatalogEntry[] = [{
    provider: "aws",
    display_name: "Amazon Web Services",
    methods: [{ method: "cloud_role", rank: 2, federated: false, legacy: false, recommended: true }],
    scope_types: ["org", "ou", "account", "region"],
    org_scope_types: ["org", "ou"],
    member_scope_type: "account",
    capability_packs: [],
  }];
  const mock = {
    cloudProviderCatalog: vi.fn(async () => ({ providers: catalog })),
    cloudCreateConnector: vi.fn(async () => view()),
    cloudConnectorCapabilities: vi.fn(async () => view()),
    cloudConnectorOrg: vi.fn(async (_id: string, org: { type: string; ref?: string; role_template?: string }) =>
      view({ identity: { has_legacy_secret: false, org: { type: org.type, ref: org.ref ?? "", role_template: org.role_template } } })),
    cloudConnectorAuth: vi.fn(async () => view()),
    cloudConnectorScopes: vi.fn(async () => view()),
    cloudConnectorSetup: vi.fn(async () => ({ provider: "aws", method: "cloud_role", summary: "", steps: [], artifacts: [] })),
  };
  return { view, mock };
});
vi.mock("../../services/api", () => ({ api: h.mock }));

import ConnectorWizard from "./ConnectorWizard";

beforeEach(() => { Object.values(h.mock).forEach((m) => m.mockClear()); });
afterEach(cleanup);

async function toDraftStep() {
  render(<ConnectorWizard onClose={() => {}} onCreated={() => {}} />);
  fireEvent.click(await screen.findByText("Amazon Web Services"));
  fireEvent.click(screen.getByRole("button", { name: "Continue" }));
  await screen.findByPlaceholderText("e.g. Production — us-east");
}

describe("ConnectorWizard org (multi-account) mode", () => {
  it("offers the descriptor-driven org toggle and anchors the connector on the org", async () => {
    await toDraftStep();

    // The toggle comes from the registry descriptor (orgScopes non-empty).
    const orgRadio = screen.getByRole("radio", { name: /Organization \(multi-account\)/ });
    fireEvent.click(orgRadio);

    // Anchor-kind select (aws: Organization ID / Organizational Unit ID) and
    // the descriptor's org field replace the single-account field.
    fireEvent.change(screen.getByLabelText("Org anchor kind"), { target: { value: "ou" } });

    fireEvent.change(screen.getByPlaceholderText("e.g. Production — us-east"), { target: { value: "Org prod" } });
    // The target field switched to the descriptor's OU anchor (label+placeholder).
    fireEvent.change(await screen.findByPlaceholderText("ou-a1b2-c3d4e5f6"), { target: { value: "ou-a1b2-c3d4e5f6" } });
    fireEvent.change(screen.getByPlaceholderText("correlix-observer"), { target: { value: "acme-observer" } });
    fireEvent.click(screen.getByRole("button", { name: "Create draft" }));

    await waitFor(() => expect(h.mock.cloudConnectorOrg).toHaveBeenCalledTimes(1));
    const [id, org] = h.mock.cloudConnectorOrg.mock.calls[0];
    expect(id).toBe("ccn_org1");
    expect(org).toEqual({ type: "ou", ref: "ou-a1b2-c3d4e5f6", role_template: "acme-observer" });
    // §3a: no tenant field ever leaves the client.
    expect(JSON.stringify(org)).not.toMatch(/tenant/i);
  });

  it("saves the org anchor itself as the collection scope", async () => {
    await toDraftStep();
    fireEvent.click(screen.getByRole("radio", { name: /Organization \(multi-account\)/ }));
    fireEvent.change(screen.getByPlaceholderText("e.g. Production — us-east"), { target: { value: "Org prod" } });
    // Default anchor kind is the first descriptor option (org → Organization ID).
    fireEvent.change(screen.getByPlaceholderText("o-a1b2c3d4e5"), { target: { value: "o-a1b2c3d4e5" } });
    fireEvent.click(screen.getByRole("button", { name: "Create draft" }));
    await waitFor(() => expect(h.mock.cloudConnectorOrg).toHaveBeenCalled());

    // Jump to the scope step (auth step is now current; the org scope value
    // carried over) — walk: auth requires a method, so drive scopes directly
    // through the exposed submit by navigating the stepper is not possible;
    // instead assert the scope step renders the org label after trust.
    // Minimal honest check: the wizard's saved scope uses the org type.
    fireEvent.click(await screen.findByText("Cross-account role"));
    fireEvent.change(await screen.findByPlaceholderText("arn:aws:iam::123456789012:role/correlix-observer"), {
      target: { value: "arn:aws:iam::111122223333:role/acme-observer" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save & continue" }));
    fireEvent.click(await screen.findByRole("button", { name: "I've deployed the trust" }));

    // Scope step shows the ORG anchor field, not the single-account field.
    expect(await screen.findByText(/Organization ID/)).toBeTruthy();
    expect(screen.getByText(/member accounts are enumerated after validation/i)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Save scope" }));
    await waitFor(() => expect(h.mock.cloudConnectorScopes).toHaveBeenCalledTimes(1));
    const [, scopes] = h.mock.cloudConnectorScopes.mock.calls[0];
    expect(scopes).toEqual([{ type: "org", ref: "o-a1b2c3d4e5" }]);
  });

  it("stays in single-account mode by default (no org POST, primary scope type)", async () => {
    await toDraftStep();
    fireEvent.change(screen.getByPlaceholderText("e.g. Production — us-east"), { target: { value: "Prod" } });
    fireEvent.change(screen.getByPlaceholderText("123456789012"), { target: { value: "123456789012" } });
    fireEvent.click(screen.getByRole("button", { name: "Create draft" }));
    await waitFor(() => expect(h.mock.cloudCreateConnector).toHaveBeenCalled());
    expect(h.mock.cloudConnectorOrg).not.toHaveBeenCalled();
  });
});
