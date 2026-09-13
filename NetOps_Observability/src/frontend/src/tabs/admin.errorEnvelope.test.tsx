// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Administration — what an operator reads when the API refuses (tracker 293).
//
// Every one of these screens used to render `(e as Error).message`: the raw
// api.ts envelope, which is
//
//     502 Bad Gateway: {"error":"Get http://api:8080/tenants: dial tcp
//     172.18.0.9:8080: connect: connection refused"}
//
// — an internal hostname, a container IP and a Go wrap chain, on an admin's
// screen, saying nothing they can act on. 52 sites in this one file did it.
//
// These drive the real components through the real failure path. Each asserts
// BOTH halves, because either alone can pass while the bug is present:
//   - the operator sentence IS shown (not a silent failure, §10);
//   - no part of the envelope is anywhere in the rendered output.
//
// The file-wide ratchet that stops a 53rd site being written is
// src/errorEnvelope.test.ts; this is the behavioural half.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, cleanup, waitFor, fireEvent } from "@testing-library/react";

const listUsers = vi.fn();
const listRoles = vi.fn();
const listTenants = vi.fn();
const listOrgs = vi.fn();
const listRegions = vi.fn();
const listSessions = vi.fn();
const revokeSession = vi.fn();
const createTenant = vi.fn();
const deleteTenant = vi.fn();
const getSecuritySettings = vi.fn();

vi.mock("../services/api", () => ({
  api: {
    listUsers: (...a: unknown[]) => listUsers(...a),
    listRoles: (...a: unknown[]) => listRoles(...a),
    listTenants: (...a: unknown[]) => listTenants(...a),
    listOrgs: (...a: unknown[]) => listOrgs(...a),
    listRegions: (...a: unknown[]) => listRegions(...a),
    listSessions: (...a: unknown[]) => listSessions(...a),
    revokeSession: (...a: unknown[]) => revokeSession(...a),
    createTenant: (...a: unknown[]) => createTenant(...a),
    deleteTenant: (...a: unknown[]) => deleteTenant(...a),
    getSecuritySettings: (...a: unknown[]) => getSecuritySettings(...a),
  },
}));
vi.mock("../hooks/useAuth", () => ({
  useAuth: () => ({ user: { username: "root", platform_admin: true }, loading: false }),
}));

import { UsersAdmin, TenantsAdmin, SessionsAdmin } from "./admin";

const DIAL = "Get http://api:8080/tenants: dial tcp 172.18.0.9:8080: connect: connection refused";

/** The exact shape services/api.ts throws. */
const envelope = (status: number, statusText: string, goErr: string) =>
  new Error(`${status} ${statusText}: {"error":${JSON.stringify(goErr)}}`);

/** Nothing from the envelope may survive into the DOM. */
function expectNoEnvelope(container: HTMLElement): void {
  const text = container.textContent ?? "";
  expect(text, "the api.ts envelope reached the screen").not.toMatch(
    /dial tcp|172\.18\.0\.9|api:8080|Bad Gateway|Gateway Timeout|connection refused|\{"error"|\bpq:/,
  );
}

const TENANT = { id: "t-1", name: "acme", slug: "acme", status: "active", org_id: "global" };

beforeEach(() => {
  vi.clearAllMocks();
  listUsers.mockResolvedValue([]);
  listRoles.mockResolvedValue({ roles: [] });
  listTenants.mockResolvedValue([]);
  listOrgs.mockResolvedValue([{ id: "global", name: "Provider" }]);
  listRegions.mockResolvedValue([]);
  listSessions.mockResolvedValue([]);
  getSecuritySettings.mockResolvedValue(null);
  window.location.hash = "";
});
afterEach(() => { cleanup(); vi.restoreAllMocks(); window.location.hash = ""; });

describe("a list read that failed", () => {
  it("falls back to what WE were doing when the failure explains nothing", async () => {
    // A browser-level fetch failure carries no sentence for a person, so the
    // caller's own description is what the operator gets. This is the fallback
    // the sweep had to supply at each of ten shared-loader call sites; before
    // it, the screen said "TypeError: NetworkError when attempting to fetch".
    listUsers.mockRejectedValue(new Error("TypeError: NetworkError when attempting to fetch resource."));
    const { container } = render(<UsersAdmin />);
    await screen.findByText("The user list could not be read.");
    expect(container.textContent ?? "").not.toMatch(/TypeError|NetworkError/);
  });

  it("maps the api envelope to a status sentence and drops the internals", async () => {
    listUsers.mockRejectedValue(envelope(502, "Bad Gateway", DIAL));
    const { container } = render(<UsersAdmin />);
    await screen.findByText("The service did not answer.");
    expectNoEnvelope(container);
  });

  it("keeps a server sentence that IS worth reading", async () => {
    // operatorError never throws away wording the backend wrote for a person.
    listSessions.mockRejectedValue(envelope(403, "Forbidden", "session listing is disabled for this tenant"));
    const { container } = render(<SessionsAdmin />);
    await screen.findByText("Session listing is disabled for this tenant.");
    expectNoEnvelope(container);
  });
});

describe("a write that was refused", () => {
  it("does not quote the database driver at the operator", async () => {
    createTenant.mockRejectedValue(
      envelope(500, "Internal Server Error", 'pq: duplicate key value violates unique constraint "tenants_pkey"'),
    );
    const { container } = render(<TenantsAdmin />);
    fireEvent.click(await screen.findByRole("button", { name: /Create tenant/ }));
    fireEvent.change(await screen.findByPlaceholderText("e.g. acme"), { target: { value: "acme" } });
    fireEvent.click(screen.getAllByRole("button", { name: "Create tenant" }).slice(-1)[0]);

    await waitFor(() => expect(createTenant).toHaveBeenCalled());
    await screen.findByText("The service did not answer.");
    expect(container.textContent ?? "", "a pq: driver error reached the screen")
      .not.toMatch(/pq:|tenants_pkey|unique constraint/);
  });

  it("a refused session revocation is readable, and the envelope is gone", async () => {
    listSessions.mockResolvedValue([
      { id: "s-1", user_id: "amy", display_name: "Amy", status: "active", issued_ip: "10.1.1.1", tenant_id: "global" },
    ]);
    revokeSession.mockRejectedValue(envelope(504, "Gateway Timeout", "context deadline exceeded"));
    vi.spyOn(window, "confirm").mockReturnValue(true);

    const { container } = render(<SessionsAdmin />);
    fireEvent.click(await screen.findByRole("button", { name: "Revoke" }));
    await waitFor(() => expect(revokeSession).toHaveBeenCalledWith("s-1"));
    await screen.findByText("The service did not answer.");
    expectNoEnvelope(container);
  });
});

describe("a failure the form has to BRANCH on, not just print", () => {
  it("reveals the force option on a 409 without printing the 409", async () => {
    // The status is a CONTRACT the form branches on (httpFailure); the sentence
    // shown is not (operatorError). Reading one string for both is what put
    // "409 Conflict: {\"error\":\"tenant still has 3 users\"}" on the screen.
    listTenants.mockResolvedValue([TENANT]);
    deleteTenant.mockRejectedValue(envelope(409, "Conflict", "tenant still has 3 users"));

    const { container } = render(<TenantsAdmin />);
    fireEvent.click(await screen.findByRole("button", { name: "Delete" }));
    fireEvent.change(await screen.findByPlaceholderText("acme"), { target: { value: "acme" } });
    fireEvent.click(await screen.findByRole("button", { name: "Delete tenant" }));

    await waitFor(() => expect(deleteTenant).toHaveBeenCalled());
    // The branch still happened: the force checkbox is now offered…
    await screen.findByText(/force delete anyway/);
    // …and the reason is said in the server's own words, not as an envelope.
    await screen.findByText("Tenant still has 3 users.");
    expect(container.textContent ?? "", "the status code was printed as if it were copy")
      .not.toMatch(/409 Conflict|\{"error"/);
  });
});
