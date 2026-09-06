// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Discovery audience contract. The Subnet Discovery pane has two honest
// states — the platform operator's config card, and the tenant explanation —
// and which one renders is decided by WHO is looking. That decision must wait
// for auth to RESOLVE: rendering the tenant copy while /api/auth/me is still
// in flight flashes wrong-audience content at the platform operator (and
// sticks if the duplicate me() call fails).
import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, cleanup } from "@testing-library/react";

const mockUseAuth = vi.fn();
vi.mock("../hooks/useAuth", () => ({ useAuth: (...a: unknown[]) => mockUseAuth(...a) }));
vi.mock("../tabs/Collectors", () => ({ DiscoveryCard: () => <div>PLATFORM DISCOVERY CARD</div> }));

import Discovery from "./Discovery";

const TENANT_COPY = /nothing\s+to configure here for a tenant account/i;

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  location.hash = "";
});

describe("Discovery auth-audience gate", () => {
  it("renders NEITHER audience's content while auth is still resolving", () => {
    mockUseAuth.mockReturnValue({ user: null, loading: true });
    render(<Discovery />);
    expect(screen.queryByText(TENANT_COPY)).toBeNull();
    expect(screen.queryByText("PLATFORM DISCOVERY CARD")).toBeNull();
  });

  it("shows the config card to the resolved platform operator", async () => {
    mockUseAuth.mockReturnValue({ user: { username: "root", platform_admin: true }, loading: false });
    render(<Discovery />);
    expect(await screen.findByText("PLATFORM DISCOVERY CARD")).toBeTruthy();
    expect(screen.queryByText(TENANT_COPY)).toBeNull();
  });

  it("shows the honest tenant explanation to a resolved tenant user", async () => {
    mockUseAuth.mockReturnValue({ user: { username: "t-user", platform_admin: false }, loading: false });
    render(<Discovery />);
    expect(await screen.findByText(TENANT_COPY)).toBeTruthy();
    expect(screen.queryByText("PLATFORM DISCOVERY CARD")).toBeNull();
  });
});
