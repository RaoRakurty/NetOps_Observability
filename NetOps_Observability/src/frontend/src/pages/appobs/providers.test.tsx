// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// providers.test.tsx — Wave 5 #17 slice 1: the frontend provider registry is
// the ONE provider descriptor module. The success criterion under test:
// REGISTERING A 4TH PROVIDER REQUIRES ZERO UI FILE EDITS — the wizard tile,
// step labels/placeholders, per-method auth fields, badges and console naming
// all render the new provider straight from its descriptor.

import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, fireEvent, cleanup } from "@testing-library/react";
import type { CloudProviderCatalogEntry } from "../../services/api";

// ── api mock: the backend catalog OFFERS the 4th provider (its own registry
// would, once the Go descriptor is registered) ────────────────────────────────
const h = vi.hoisted(() => {
  const catalog: CloudProviderCatalogEntry[] = [
    {
      provider: "aws",
      methods: [{ method: "workload_identity_federation", rank: 1, federated: true, legacy: false, recommended: true }],
      scope_types: ["account", "region"],
      capability_packs: [],
    },
    {
      provider: "oracle", // the 4th provider — NO UI file mentions it anywhere
      methods: [
        { method: "workload_identity_federation", rank: 1, federated: true, legacy: false, recommended: true },
        { method: "static_key", rank: 5, federated: false, legacy: true, recommended: false },
      ],
      scope_types: ["compartment", "region"],
      capability_packs: [],
    },
  ];
  return {
    mock: {
      cloudProviderCatalog: vi.fn(async () => ({ providers: catalog })),
      cloudCreateConnector: vi.fn(async () => { throw new Error("not under test"); }),
    },
  };
});
vi.mock("../../services/api", () => ({ api: h.mock }));

import {
  registerProvider, providerDescriptor, providerIds, listProviders,
  providerLabel, providerShort, providerBlurb, providerConsoleName,
} from "./providers";
import { primaryScopeType, primaryScopeLabel, primaryScopePlaceholder, authFields, secretConfig } from "./connectorWizard";
import { ProviderBadge, consoleName } from "./badges";
import ConnectorWizard from "./ConnectorWizard";

afterEach(cleanup);

// Register once for the whole file (module registry is process-wide; the id is
// fake and collides with nothing real).
registerProvider({
  id: "oracle",
  label: "Oracle Cloud",
  short: "OCI",
  blurb: "Read-only tenancy observer for Oracle Cloud Infrastructure.",
  consoleName: "OCI Console",
  icon: () => null, // no brand mark — the text carries the identity
  primaryScope: { type: "compartment", label: "Compartment OCID", placeholder: "ocid1.compartment.oc1…" },
  orgScopes: [{ type: "org", label: "Tenancy OCID", placeholder: "ocid1.tenancy.oc1…" }],
  authFields: (method) =>
    method === "workload_identity_federation"
      ? [{ key: "issuer", label: "Federation issuer", placeholder: "https://…", required: true, mono: true }]
      : [],
  secretConfig: (method) => method === "static_key" ? {
    kind: "api_key", keyHintLabel: "Key fingerprint", keyHintPlaceholder: "aa:bb…",
    secretLabel: "API private key", secretPlaceholder: "-----BEGIN…", multiline: true,
  } : null,
});

describe("provider registry (module surface)", () => {
  it("serves registered descriptors and an honest generic fallback", () => {
    expect(providerIds()).toEqual(["aws", "azure", "gcp", "oracle"]);
    expect(listProviders().map((d) => d.id)).toContain("oracle");
    expect(providerLabel("oracle")).toBe("Oracle Cloud");
    expect(providerShort("oracle")).toBe("OCI");
    expect(providerBlurb("oracle")).toMatch(/tenancy observer/);
    expect(providerConsoleName("oracle")).toBe("OCI Console");
    // Unknown provider: never crash, honest raw-token fallback.
    const g = providerDescriptor("alibabacloud");
    expect(g.label).toBe("alibabacloud");
    expect(g.short).toBe("ALIBABACLOUD");
    expect(g.consoleName).toBe("cloud console");
    expect(g.authFields("static_key")).toEqual([]);
  });

  it("rejects duplicate registration (fail fast, never shadow)", () => {
    expect(() => registerProvider(providerDescriptor("oracle"))).toThrow(/duplicate/);
  });

  it("drives the wizard logic helpers with zero edits", () => {
    // providerIds() is the live list the wizard renders tiles from (PROVIDERS
    // is a compat snapshot taken at module import, before this registration).
    expect(providerIds()).toContain("oracle");
    expect(primaryScopeType("oracle")).toBe("compartment");
    expect(primaryScopeLabel("oracle")).toBe("Compartment OCID");
    expect(primaryScopePlaceholder("oracle")).toBe("ocid1.compartment.oc1…");
    expect(authFields("oracle", "workload_identity_federation").map((f) => f.key)).toEqual(["issuer"]);
    expect(secretConfig("oracle", "static_key")?.kind).toBe("api_key");
    expect(secretConfig("oracle", "workload_identity_federation")).toBeNull();
  });

  it("drives the badge + console surfaces with zero edits", () => {
    render(<ProviderBadge provider="oracle" />);
    expect(screen.getByText("OCI")).toBeTruthy();
    expect(consoleName("oracle")).toBe("OCI Console");
  });
});

describe("ConnectorWizard renders a 4th provider from its descriptor", () => {
  it("shows the oracle tile (label + blurb) and its draft-step scope field", async () => {
    render(<ConnectorWizard onClose={() => {}} onCreated={() => {}} />);

    // The tile comes from registry ∪ catalog — no wizard edit names "oracle".
    const tile = await screen.findByRole("radio", { name: /Oracle Cloud/ });
    expect(tile.textContent).toContain("Read-only tenancy observer");
    // Catalog offers it → selectable.
    fireEvent.click(tile);
    fireEvent.click(screen.getByRole("button", { name: "Continue" }));

    // Draft step renders the descriptor's scope label + placeholder.
    expect(await screen.findByText(/Compartment OCID/)).toBeTruthy();
    expect(screen.getByPlaceholderText("ocid1.compartment.oc1…")).toBeTruthy();
    // The header names the provider through the registry.
    expect(screen.getByText("Connect Oracle Cloud")).toBeTruthy();
  });

  it("keeps a catalog-only provider selectable with the honest generic fallback", async () => {
    // Backend one day offers a provider the frontend has NO descriptor for:
    h.mock.cloudProviderCatalog.mockResolvedValueOnce({
      providers: [{
        provider: "alibaba",
        methods: [{ method: "static_key", rank: 5, federated: false, legacy: true, recommended: true }],
        scope_types: ["account"],
        capability_packs: [],
      }],
    });
    render(<ConnectorWizard onClose={() => {}} onCreated={() => {}} />);
    // Falls back to the raw token as the label — visible and selectable, never a crash.
    const tile = await screen.findByRole("radio", { name: /alibaba/ });
    expect(tile).toBeTruthy();
  });
});
