// Connections.test.tsx — the connector list renders ONLY what the tenant-scoped
// API returns, with honest lifecycle states (no green the backend didn't earn),
// a resume action for incomplete connectors, and the API's REAL error message on
// failure (including the 501 no-store deployment).

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, fireEvent, waitFor, cleanup } from "@testing-library/react";
import type { CloudConnectorView } from "../../services/api";

const h = vi.hoisted(() => {
  const conn = (over: Partial<CloudConnectorView> = {}): CloudConnectorView => ({
    id: "ccn_a", provider: "aws", display_name: "Prod", auth_method: "cloud_role",
    auth_federated: false, auth_legacy: false, capability_pack: "aws-observer-v1",
    state: "DRAFT", collecting: false,
    identity: { has_legacy_secret: false }, scopes: [],
    identity_health: { state: "unknown" }, telemetry_health: { state: "unknown" },
    last_validation: { ok: false, findings: null }, version: 1,
    created_at: "2026-07-01T00:00:00Z", updated_at: "2026-07-15T00:00:00Z",
    ...over,
  });
  return {
    conn,
    mock: {
      cloudConnectors: vi.fn(async () => ({ connectors: [conn()] })),
      cloudDeleteConnector: vi.fn(async () => ({ deleted: "ccn_a" })),
    },
  };
});
vi.mock("../../services/api", () => ({ api: h.mock }));

import Connections from "./Connections";

const conn = h.conn;
const mock = h.mock;

beforeEach(() => { Object.values(mock).forEach((m) => m.mockClear()); });
afterEach(cleanup);

describe("Connections list", () => {
  it("renders honest per-connector states from the API", async () => {
    mock.cloudConnectors.mockResolvedValueOnce({
      connectors: [
        conn({ id: "ccn_1", display_name: "Prod", state: "ACTIVE", collecting: true }),
        conn({ id: "ccn_2", display_name: "Stage", state: "VALIDATING", last_validation: { ok: true, findings: [] } }),
        conn({
          id: "ccn_3", display_name: "Broken", state: "VALIDATING",
          last_validation: { ok: false, findings: [{ severity: "error", code: "x", message: "m" }] },
        }),
        conn({ id: "ccn_4", display_name: "Half", state: "DRAFT" }),
      ],
    });
    render(<Connections nonce={0} onConnect={() => {}} onResume={() => {}} />);
    expect(await screen.findByText("Enabled")).toBeTruthy();
    expect(screen.getByText("Validated — not enabled")).toBeTruthy();
    expect(screen.getByText("Validation failed")).toBeTruthy();
    expect(screen.getByText("Setup incomplete")).toBeTruthy();
  });

  it("offers Resume setup only for incomplete connectors and passes the stored view through", async () => {
    const onResume = vi.fn();
    mock.cloudConnectors.mockResolvedValueOnce({
      connectors: [
        conn({ id: "ccn_live", display_name: "Live", state: "ACTIVE", collecting: true }),
        conn({ id: "ccn_wip", display_name: "WIP", state: "DRAFT" }),
      ],
    });
    render(<Connections nonce={0} onConnect={() => {}} onResume={onResume} />);
    const resumes = await screen.findAllByRole("button", { name: "Resume setup" });
    expect(resumes.length).toBe(1); // ACTIVE row gets none
    fireEvent.click(resumes[0]);
    expect(onResume).toHaveBeenCalledWith(expect.objectContaining({ id: "ccn_wip" }));
  });

  it("shows the API's real error message — no fake empty state", async () => {
    mock.cloudConnectors.mockRejectedValueOnce(new Error("501 Not Implemented: store off"));
    render(<Connections nonce={0} onConnect={() => {}} onResume={() => {}} />);
    expect(await screen.findByText("Unable to load cloud connections")).toBeTruthy();
    expect(screen.getByText(/platform database backend/)).toBeTruthy();
  });

  it("empty tenant → honest empty state with the connect action", async () => {
    const onConnect = vi.fn();
    mock.cloudConnectors.mockResolvedValueOnce({ connectors: [] });
    render(<Connections nonce={0} onConnect={onConnect} onResume={() => {}} />);
    expect(await screen.findByText("No cloud connections yet")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Connect a cloud account" }));
    expect(onConnect).toHaveBeenCalled();
  });

  it("removes a setup-stage connector via the real DELETE after confirmation", async () => {
    const confirmSpy = vi.spyOn(window, "confirm").mockReturnValue(true);
    render(<Connections nonce={0} onConnect={() => {}} onResume={() => {}} />);
    fireEvent.click(await screen.findByRole("button", { name: "Remove" }));
    await waitFor(() => expect(mock.cloudDeleteConnector).toHaveBeenCalledWith("ccn_a"));
    confirmSpy.mockRestore();
  });
});
