// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// tacRoutingModel.test.ts — the pure model behind Administration → Ticket
// delivery → TAC routing.
//
// Three things have to hold, and each of them is a bug that would only show up
// in production otherwise:
//
//   1. the save body NEVER carries a tenant, and folds its keys exactly the way
//      internal/ticketing/caseconn_routing.go folds them — a serial typed in
//      lower case must find the contract it was stored against;
//   2. an empty row is DROPPED, so a tenant that clears its last setting reads
//      afterwards exactly like a tenant that never made one;
//   3. the account-identifier label is the VENDOR's own word for it — an
//      operator with six vendor logins must not have to guess which one a
//      generic "Account id" wants.

import { describe, it, expect } from "vitest";
import type { TacConnectorInfo, TacRoutingConfig } from "../../services/api";
import {
  ACCOUNT_LABEL_FALLBACK,
  accountLabel,
  buildRoutingSave,
  captureFor,
  connectorChoiceLabel,
  connectorsForVendor,
  contractFor,
  contractIsEmpty,
  emptyRouting,
  overrideRows,
  routeFor,
  routingVendors,
  validateRouting,
  vendorDisplay,
} from "./tacRoutingModel";

const conn = (over: Partial<TacConnectorInfo>): TacConnectorInfo => ({
  id: "x", display: "X", capabilities: [], max_attachment_bytes: 0,
  profile: "link_only", configured: false, ...over,
});

const CONNECTORS: TacConnectorInfo[] = [
  conn({ id: "servicenow", display: "ServiceNow", vendor: "servicenow", configured: true }),
  conn({ id: "jira", display: "Jira", vendor: "jira", configured: false }),
  conn({ id: "email-arista", display: "Arista support mailbox", vendor: "arista", configured: true }),
  conn({ id: "cisco-cxd", display: "Cisco CXD", vendor: "cisco", configured: true }),
  conn({ id: "cisco-smart-bonding", display: "Cisco Smart Bonding", vendor: "cisco", configured: false }),
  conn({ id: "juniper", display: "Juniper Service Case", vendor: "juniper", configured: false }),
  conn({ id: "portal-nokia", display: "Nokia portal", vendor: "nokia", configured: true }),
  conn({ id: "portal-text", display: "Portal text", configured: true }),
];

describe("the vendors a tenant can route", () => {
  it("is derived from the connectors the SERVER sent, ITSM excluded", () => {
    expect(routingVendors(CONNECTORS)).toEqual(["arista", "cisco", "juniper", "nokia"]);
  });

  it("a deployment with no vendor path shows none, rather than a form per vendor", () => {
    expect(routingVendors([conn({ id: "portal-text", display: "Portal text" })])).toEqual([]);
    expect(routingVendors(undefined)).toEqual([]);
  });
});

describe("the connectors offered for one vendor's route", () => {
  it("offers the vendor's own paths, every ITSM path and the portal floor", () => {
    expect(connectorsForVendor(CONNECTORS, "cisco").map((c) => c.id))
      .toEqual(["servicenow", "jira", "cisco-cxd", "cisco-smart-bonding", "portal-text"]);
  });

  // A tenant route naming an unconfigured connector is HONOURED by the server
  // and then refused by name on the confirmation screen. Hiding the choice
  // would make that rule unreachable.
  it("offers an unconfigured connector, labelled as having no credentials", () => {
    const sb = CONNECTORS.find((c) => c.id === "cisco-smart-bonding")!;
    expect(connectorChoiceLabel(sb)).toBe("Cisco Smart Bonding — no credentials yet");
    expect(connectorChoiceLabel(CONNECTORS.find((c) => c.id === "cisco-cxd")!)).toBe("Cisco CXD");
  });
});

describe("the account identifier is labelled in the vendor's own words", () => {
  it.each([
    ["cisco", "Cisco CCO ID"],
    ["juniper", "Juniper CSP user"],
    ["arista", "Arista portal account"],
    ["nokia", "Nokia customer id"],
    ["paloalto", "Palo Alto support account"],
    ["fortinet", "Fortinet FortiCloud account"],
  ])("%s is called %s", (vendor, label) => {
    expect(accountLabel(vendor)).toBe(label);
    expect(accountLabel(vendor.toUpperCase())).toBe(label);
  });

  it("a vendor Correlix has not been taught gets the generic label, not an invented one", () => {
    expect(accountLabel("acme")).toBe(ACCOUNT_LABEL_FALLBACK);
    expect(accountLabel("")).toBe(ACCOUNT_LABEL_FALLBACK);
  });

  it("names a vendor it knows, and shows the id it does not", () => {
    expect(vendorDisplay("paloalto")).toBe("Palo Alto");
    expect(vendorDisplay("acme")).toBe("Acme");
    expect(vendorDisplay("")).toBe("");
  });
});

describe("reading one tenant's record", () => {
  const cfg: TacRoutingConfig = {
    contact: { name: "Jane Doe", email: "jane.doe@example.com", phone: "+1 555 0100" },
    route_by_vendor: { cisco: "cisco-cxd" },
    capture_by_dialect: { "cisco-iosxe": "tpl-9" },
    contract_by_vendor: { cisco: { vendor: "cisco", contract_id: "SVC-4411", account_id: "jdoe" } },
    contract_by_serial: {
      FDO222: { vendor: "cisco", contract_id: "SVC-9" },
      FDO111: { vendor: "cisco", contract_id: "SVC-1" },
    },
  };

  it("finds a route, a capture and a contract by their folded keys", () => {
    expect(routeFor(cfg, "CISCO")).toBe("cisco-cxd");
    expect(routeFor(cfg, "juniper")).toBe("");
    expect(captureFor(cfg, "Cisco-IOSXE")).toBe("tpl-9");
    expect(contractFor(cfg, "cisco").contract_id).toBe("SVC-4411");
    // A vendor with no contract gets an EMPTY row keyed to itself, so the form
    // opens on a blank field rather than on another vendor's contract.
    expect(contractFor(cfg, "juniper")).toEqual({ vendor: "juniper" });
  });

  it("lists the per-device overrides in a stable order", () => {
    expect(overrideRows(cfg).map((r) => r.serial)).toEqual(["FDO111", "FDO222"]);
    expect(overrideRows(emptyRouting())).toEqual([]);
  });
});

describe("the save body", () => {
  it("carries no tenant, folds every key and trims every value", () => {
    const body = buildRoutingSave({
      contact: { name: "  Jane Doe ", email: " jane@example.com ", phone: "" },
      route_by_vendor: { " CISCO ": " cisco-cxd " },
      capture_by_dialect: { "Cisco-IOSXE": " tpl-9 " },
      contract_by_vendor: { " Cisco ": { vendor: "ignored", contract_id: " SVC-4411 " } },
      contract_by_serial: { " fdo111 ": { vendor: " Cisco ", contract_id: " SVC-1 " } },
    });
    expect(JSON.stringify(body)).not.toContain("tenant");
    expect(body.contact).toEqual({ name: "Jane Doe", email: "jane@example.com", phone: "" });
    expect(body.route_by_vendor).toEqual({ cisco: "cisco-cxd" });
    expect(body.capture_by_dialect).toEqual({ "cisco-iosxe": "tpl-9" });
    expect(body.contract_by_vendor?.cisco.contract_id).toBe("SVC-4411");
    // The vendor is stamped from the KEY, never from the row a client sent.
    expect(body.contract_by_vendor?.cisco.vendor).toBe("cisco");
    // A serial is folded UP, because that is how the server stores and looks it
    // up — a serial typed in lower case must still find its contract.
    expect(Object.keys(body.contract_by_serial ?? {})).toEqual(["FDO111"]);
    expect(body.contract_by_serial?.FDO111.vendor).toBe("cisco");
  });

  it("drops every empty row, so a cleared record reads as one never made", () => {
    const body = buildRoutingSave({
      contact: { name: "", email: "", phone: "" },
      route_by_vendor: { cisco: "  " },
      capture_by_dialect: { "cisco-iosxe": "" },
      contract_by_vendor: { cisco: { vendor: "cisco" } },
      contract_by_serial: { FDO111: { vendor: "cisco", contract_id: "   " } },
    });
    expect(body.route_by_vendor).toBeUndefined();
    expect(body.capture_by_dialect).toBeUndefined();
    expect(body.contract_by_vendor).toBeUndefined();
    expect(body.contract_by_serial).toBeUndefined();
  });

  it("knows an empty contract from one carrying only a note", () => {
    expect(contractIsEmpty({ vendor: "cisco" })).toBe(true);
    expect(contractIsEmpty({ vendor: "cisco", note: "renewed via reseller" })).toBe(false);
    expect(contractIsEmpty(undefined)).toBe(true);
  });
});

describe("validation mirrors the server, in the same order", () => {
  it("accepts a complete record", () => {
    expect(validateRouting({
      contact: { name: "Jane Doe", email: "jane@example.com", phone: "+1 555 0100" },
      contract_by_vendor: { cisco: { vendor: "cisco", contract_id: "SVC-1", expires_on: "2027-03-31" } },
    })).toBe("");
    expect(validateRouting(emptyRouting())).toBe("");
  });

  it("refuses a contact email that is not an address", () => {
    expect(validateRouting({ contact: { email: "jane.example.com" } }))
      .toBe("The contact email must be an address.");
  });

  it("refuses a coverage date that is not YYYY-MM-DD, and names the vendor", () => {
    const bad = validateRouting({
      contact: {},
      contract_by_vendor: { cisco: { vendor: "cisco", expires_on: "31/03/2027" } },
    });
    expect(bad).toContain("Cisco");
    expect(bad).toContain("YYYY-MM-DD");
  });

  it("refuses an over-long field, and a serial key that is too long", () => {
    expect(validateRouting({ contact: { name: "x".repeat(201) } })).toContain("200 characters");
    expect(validateRouting({
      contact: {},
      contract_by_serial: { ["S".repeat(65)]: { vendor: "cisco", contract_id: "SVC-1" } },
    })).toContain("64 characters");
  });

  // The same bad record must report the same field every time, or an operator
  // fixing one at a time chases a moving error.
  it("reports the same field every time for the same record", () => {
    const cfg: TacRoutingConfig = {
      contact: {},
      contract_by_vendor: {
        juniper: { vendor: "juniper", expires_on: "nope" },
        cisco: { vendor: "cisco", expires_on: "nope" },
      },
    };
    const first = validateRouting(cfg);
    for (let i = 0; i < 5; i += 1) expect(validateRouting(cfg)).toBe(first);
    expect(first).toContain("Cisco");
  });
});
