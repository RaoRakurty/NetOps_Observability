// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// AdminSsoIdp — the group→role mapping table (ordering is the contract: the
// backend applies rows first-match-wins, so the UI must preserve and expose
// order), the pinned amber default-role row, the SP-value derivation, and the
// cert-expiry banner rendering.

import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, cleanup, fireEvent } from "@testing-library/react";
import {
  moveRow,
  blankIdp,
  spValues,
  idpIsValid,
  DEFAULT_ATTR_MAPPINGS,
  RoleMappingTable,
  AttrMappingTable,
  CertExpiryBanner,
} from "./AdminSsoIdp";
import type { SsoIdpRoleMapping } from "../services/api";

afterEach(cleanup);

const ROLES = ["super-admin", "operator", "read-only"];
const ROWS: SsoIdpRoleMapping[] = [
  { value: "cn=netops-admins,ou=groups,dc=corp", role: "super-admin" },
  { value: "cn=noc,ou=groups,dc=corp", role: "operator" },
];

describe("moveRow", () => {
  const rows = ["a", "b", "c"];
  it("moves a row up/down by one and preserves the others' order", () => {
    expect(moveRow(rows, 1, -1)).toEqual(["b", "a", "c"]);
    expect(moveRow(rows, 1, 1)).toEqual(["a", "c", "b"]);
  });
  it("is a no-op at the edges and out of range", () => {
    expect(moveRow(rows, 0, -1)).toEqual(rows);
    expect(moveRow(rows, 2, 1)).toEqual(rows);
    expect(moveRow(rows, -1, 1)).toEqual(rows);
    expect(moveRow(rows, 3, -1)).toEqual(rows);
  });
  it("does not mutate the input", () => {
    moveRow(rows, 1, -1);
    expect(rows).toEqual(["a", "b", "c"]);
  });
});

describe("RoleMappingTable", () => {
  it("renders rows in order with first-match-wins helper text", () => {
    render(<RoleMappingTable rows={ROWS} roleIds={ROLES} defaultRole="read-only" onChange={() => {}} />);
    const inputs = screen.getAllByLabelText(/Group or claim value/);
    expect(inputs.map((i) => (i as HTMLInputElement).value)).toEqual([ROWS[0].value, ROWS[1].value]);
    expect(screen.getByText(/first match wins/i)).toBeInTheDocument();
  });

  it("reorders via the up/down buttons (first-match precedence is editable)", () => {
    const onChange = vi.fn();
    render(<RoleMappingTable rows={ROWS} roleIds={ROLES} defaultRole="read-only" onChange={onChange} />);
    fireEvent.click(screen.getByLabelText("Move mapping 2 up"));
    expect(onChange).toHaveBeenCalledWith([ROWS[1], ROWS[0]]);
    // Edge buttons are disabled — a row can't move past the ends.
    expect(screen.getByLabelText("Move mapping 1 up")).toBeDisabled();
    expect(screen.getByLabelText("Move mapping 2 down")).toBeDisabled();
  });

  it("adds and removes rows", () => {
    const onChange = vi.fn();
    render(<RoleMappingTable rows={ROWS} roleIds={ROLES} defaultRole="read-only" onChange={onChange} />);
    fireEvent.click(screen.getByText("+ Add mapping"));
    expect(onChange).toHaveBeenCalledWith([...ROWS, { value: "", role: "super-admin" }]);
    fireEvent.click(screen.getByLabelText("Remove mapping 1"));
    expect(onChange).toHaveBeenCalledWith([ROWS[1]]);
  });

  it("pins an amber default-role row explaining the no-match fallback", () => {
    render(<RoleMappingTable rows={ROWS} roleIds={ROLES} defaultRole="read-only" onChange={() => {}} />);
    const row = screen.getByTestId("default-role-row");
    expect(row).toHaveClass("default-row");
    expect(row).toHaveTextContent("read-only");
    // The CLAIM stays: no match means the default role, which is why a federated
    // login lands read-only when the mappings are wrong. The reasoning moved to
    // ai/skills/explain/sso.default-role.md and the (i) is asserted with it.
    expect(screen.getByText(/No match means the default role/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Ask Iris about the default role/ })).toBeInTheDocument();
  });
});

describe("AttrMappingTable", () => {
  it("new IdPs default to the email/firstName/lastName rows", () => {
    expect(blankIdp("saml").attr_mappings).toEqual(DEFAULT_ATTR_MAPPINGS);
    expect(DEFAULT_ATTR_MAPPINGS.map((m) => m.user_attr)).toEqual(["email", "firstName", "lastName"]);
  });

  it("adds and removes arbitrary rows", () => {
    const onChange = vi.fn();
    render(<AttrMappingTable rows={DEFAULT_ATTR_MAPPINGS} onChange={onChange} />);
    fireEvent.click(screen.getByText("+ Add attribute"));
    expect(onChange).toHaveBeenCalledWith([...DEFAULT_ATTR_MAPPINGS, { idp_attr: "", user_attr: "" }]);
    fireEvent.click(screen.getByLabelText("Remove attribute mapping 2"));
    expect(onChange).toHaveBeenCalledWith([DEFAULT_ATTR_MAPPINGS[0], DEFAULT_ATTR_MAPPINGS[2]]);
  });
});

describe("spValues", () => {
  it("derives the Keycloak broker endpoints from origin/realm/alias", () => {
    const saml = spValues("https://netops.corp", "correlix", "okta", "saml");
    expect(saml).toEqual([
      { label: "ACS URL (POST binding)", value: "https://netops.corp/auth/realms/correlix/broker/okta/endpoint" },
      { label: "Audience / SP Entity ID", value: "https://netops.corp/auth/realms/correlix" },
    ]);
    const oidc = spValues("https://netops.corp", "correlix", "azure", "oidc");
    expect(oidc[0]).toEqual({ label: "Redirect URI (callback)", value: "https://netops.corp/auth/realms/correlix/broker/azure/endpoint" });
  });
  it("shows placeholders while realm/alias are unknown", () => {
    const v = spValues("https://netops.corp", "", "", "saml");
    expect(v[0].value).toBe("https://netops.corp/auth/realms/<realm>/broker/<alias>/endpoint");
  });
});

describe("idpIsValid", () => {
  it("requires alias + display name + the protocol's connection fields", () => {
    const saml = { ...blankIdp("saml"), alias: "okta", display_name: "Okta" };
    expect(idpIsValid(saml)).toBe(false); // no metadata yet
    expect(idpIsValid({ ...saml, metadata_url: "https://idp/metadata.xml" })).toBe(true);
    expect(idpIsValid({ ...saml, metadata_xml: "<EntityDescriptor/>" })).toBe(true);
    expect(idpIsValid({ ...saml, alias: "bad alias!", metadata_url: "x" })).toBe(false);

    const oidc = { ...blankIdp("oidc"), alias: "azure", display_name: "Azure AD" };
    expect(idpIsValid(oidc)).toBe(false);
    expect(idpIsValid({ ...oidc, discovery_url: "https://idp/.well-known/openid-configuration" })).toBe(false); // still no client id
    expect(idpIsValid({ ...oidc, discovery_url: "https://idp/.well-known/openid-configuration", client_id: "correlix" })).toBe(true);
  });
});

describe("CertExpiryBanner", () => {
  const now = new Date("2026-08-04T12:00:00Z");
  const plusDays = (n: number) => new Date(now.getTime() + n * 86_400_000);

  it("renders nothing alarming when more than 30 days out", () => {
    render(<CertExpiryBanner notAfter={plusDays(90)} now={now} />);
    expect(screen.getByText(/valid until/)).toBeInTheDocument();
    expect(screen.queryByRole("status")).toBeNull();
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("warns at ≤30 days", () => {
    render(<CertExpiryBanner notAfter={plusDays(23)} now={now} />);
    const banner = screen.getByRole("status");
    expect(banner).toHaveClass("banner", "warn");
    expect(banner).toHaveTextContent("expires in 23 days");
    expect(banner).toHaveTextContent("Plan rotation");
  });

  it("goes critical at ≤7 days and when expired", () => {
    render(<CertExpiryBanner notAfter={plusDays(3)} now={now} />);
    expect(screen.getByRole("alert")).toHaveClass("banner", "crit");
    cleanup();
    render(<CertExpiryBanner notAfter={plusDays(-1)} now={now} />);
    expect(screen.getByRole("alert")).toHaveTextContent(/EXPIRED/);
  });

  it("renders nothing without a date", () => {
    const { container } = render(<CertExpiryBanner notAfter={null} />);
    expect(container).toBeEmptyDOMElement();
  });
});
