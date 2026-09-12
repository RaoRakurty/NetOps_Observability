// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// ApiAccessAdmin — the API-key wizard when its permission grid does not load.
//
// `api.permissions()` tells the wizard which scopes THIS caller may mint. A
// failed read used to be mapped to an empty grid with no error: the picker said
// "Checking which scopes your role may issue…" for ever, and the scopes step
// still reported itself valid — so Next advanced and Generate key minted a
// credential carrying the wizard's DEFAULT scope set, which the operator had
// never been shown. The server re-authorises every scope on mint, so nothing
// escalated; what was lost was the operator's sight of the authority they were
// issuing, and an API key is exactly the artefact where that matters.
//
// This drives the real component through the real wizard.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, cleanup, waitFor, fireEvent } from "@testing-library/react";

const permissions = vi.fn();
const listApiKeys = vi.fn();
const createApiKey = vi.fn();
const revokeApiKey = vi.fn();

vi.mock("../services/api", () => ({
  api: {
    permissions: (...a: unknown[]) => permissions(...a),
    listApiKeys: (...a: unknown[]) => listApiKeys(...a),
    createApiKey: (...a: unknown[]) => createApiKey(...a),
    revokeApiKey: (...a: unknown[]) => revokeApiKey(...a),
  },
}));
vi.mock("../hooks/useAuth", () => ({
  useAuth: () => ({ user: { username: "root", platform_admin: false }, loading: false }),
}));

import { ApiAccessAdmin } from "./admin";

const GRID = {
  overview: 3, explore: 3, alerts: 3, infrastructure: 3,
  topology: 3, reports: 3, administration: 3, sensitive_data: 3,
};

/** Open the wizard modal and walk the Identity step. */
async function openWizardAtScopes() {
  window.location.hash = "#/admin/api/keys";
  render(<ApiAccessAdmin />);
  await screen.findByRole("heading", { name: "Generate API key" });
  fireEvent.change(screen.getByLabelText(/Label/), { target: { value: "ci-pipeline" } });
  fireEvent.click(screen.getByRole("button", { name: "Next" }));
  await screen.findByRole("heading", { name: "Grant types" });
}

beforeEach(() => {
  vi.clearAllMocks();
  listApiKeys.mockResolvedValue([]);
  createApiKey.mockResolvedValue({ secret: "s3cret" });
  revokeApiKey.mockResolvedValue(undefined);
  window.location.hash = "";
});
afterEach(() => { cleanup(); window.location.hash = ""; });

describe("ApiAccessAdmin — a permission grid that did not load", () => {
  it("says the scopes could not be read, and will not let the key be minted", async () => {
    permissions.mockRejectedValue(new Error(
      '502 Bad Gateway: {"error":"Get http://api:8080/auth/permissions: ' +
      'dial tcp 172.18.0.9:8080: connect: connection refused"}',
    ));
    await openWizardAtScopes();
    await waitFor(() => expect(permissions).toHaveBeenCalled());

    // FIRST, the thing that actually mattered: the wizard must not walk on past
    // a scope grid the operator never saw. On the old code Next stayed enabled,
    // advanced, and Generate key minted with the DEFAULT scope set.
    expect(
      screen.getByRole("button", { name: "Next" }),
      "Next is still live on an unread scope grid — the wizard will mint a key whose scopes were never shown",
    ).toBeDisabled();
    fireEvent.click(screen.getByRole("button", { name: "Next" }));
    await waitFor(() => expect(screen.getByRole("heading", { name: "Grant types" })).toBeTruthy());
    expect(createApiKey).not.toHaveBeenCalled();

    // SECOND, the failure is SAID, not swallowed into a forever-loading picker
    // — and said in operator words, not as the api.ts envelope.
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toMatch(/no key can be issued yet/);
    expect(alert.textContent).not.toMatch(/dial tcp|172\.18\.0\.9|api:8080/);
    expect(screen.queryByText(/Checking which scopes your role may issue/)).toBeNull();
  });

  it("recovers on retry: the grid arrives, the scopes appear, the step opens", async () => {
    permissions
      .mockRejectedValueOnce(new Error("503 Service Unavailable: permission store down"))
      .mockResolvedValueOnce({ permissions: GRID });
    await openWizardAtScopes();
    await screen.findByRole("alert");
    expect(screen.getByRole("button", { name: "Next" })).toBeDisabled();

    fireEvent.click(screen.getByRole("button", { name: "Try again" }));

    await screen.findByLabelText(/read:metrics/);
    expect(screen.queryByRole("alert")).toBeNull();
    expect(screen.getByRole("button", { name: "Next" })).not.toBeDisabled();
  });

  it("a grid that DID load lets the wizard run as before", async () => {
    permissions.mockResolvedValue({ permissions: GRID });
    await openWizardAtScopes();
    await screen.findByLabelText(/read:metrics/);
    expect(screen.getByRole("button", { name: "Next" })).not.toBeDisabled();
  });
});

// A refused revocation is a security-relevant failure the operator must be able
// to read. It used to render `(e as Error).message` — the api.ts envelope, with
// the upstream's internal host and container IP in it.
describe("ApiAccessAdmin — a revocation that is refused", () => {
  it("says it in operator words, not as the api.ts envelope", async () => {
    permissions.mockResolvedValue({ permissions: GRID });
    listApiKeys.mockResolvedValue([
      { id: "k-1", label: "ci-pipeline", prefix: "ck_abc", scopes: ["read:metrics"], window_used: 0 },
    ]);
    revokeApiKey.mockRejectedValue(new Error(
      '502 Bad Gateway: {"error":"Post http://api:8080/keys/k-1/revoke: ' +
      'dial tcp 172.18.0.9:8080: connect: connection refused"}',
    ));
    const { container } = render(<ApiAccessAdmin />);

    fireEvent.click(await screen.findByRole("button", { name: "Revoke" }));
    await waitFor(() => expect(revokeApiKey).toHaveBeenCalledWith("k-1"));
    await screen.findByText("The service did not answer.");

    const text = container.textContent ?? "";
    expect(text).not.toMatch(/dial tcp|172\.18\.0\.9|api:8080|Bad Gateway/);
  });
});
