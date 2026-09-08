// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// TacRoutingSection.test.tsx — Administration → Ticket delivery → TAC routing.
//
// What has to hold:
//   · the round trip: what the server sent is what the form shows, and what the
//     form saves is what the server gets — with NO tenant in the body;
//   · the account identifier carries the VENDOR's own label per vendor;
//   · an unconfigured connector is still offered as a route and SAYS it has no
//     credentials, because the server honours the choice and then refuses it by
//     name — hiding it would make that rule unreachable;
//   · a per-device override is keyed by serial, folded the way the server folds
//     it, and can be removed;
//   · a validation refusal names the field and sends nothing.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, cleanup, fireEvent, waitFor, act, within } from "@testing-library/react";
import type { TacConnectorInfo } from "../../services/api";

const tacRouting = vi.fn();
const tacRoutingSave = vi.fn();
const tacRoutingDelete = vi.fn();
const tacCaptures = vi.fn();

vi.mock("../../services/api", () => ({
  api: {
    tacRouting: (...a: unknown[]) => tacRouting(...a),
    tacRoutingSave: (...a: unknown[]) => tacRoutingSave(...a),
    tacRoutingDelete: (...a: unknown[]) => tacRoutingDelete(...a),
    tacCaptures: (...a: unknown[]) => tacCaptures(...a),
  },
}));

import TacRoutingSection from "./TacRoutingSection";

const conn = (over: Partial<TacConnectorInfo>): TacConnectorInfo => ({
  id: "x", display: "X", capabilities: [], max_attachment_bytes: 0,
  profile: "link_only", configured: false, ...over,
});

const CONNECTORS: TacConnectorInfo[] = [
  conn({ id: "servicenow", display: "ServiceNow", vendor: "servicenow", configured: true }),
  conn({ id: "cisco-cxd", display: "Cisco CXD", vendor: "cisco", configured: true }),
  conn({ id: "cisco-smart-bonding", display: "Cisco Smart Bonding", vendor: "cisco", configured: false }),
  conn({ id: "juniper", display: "Juniper Service Case", vendor: "juniper", configured: false }),
  conn({ id: "portal-text", display: "Portal text", configured: true }),
];

const DIALECTS = [
  { dialect: "cisco-iosxe", display: "Cisco IOS-XE" },
  { dialect: "juniper-junos", display: "Junos" },
];

const routingResponse = (over: Record<string, unknown> = {}) => ({
  routing: { contact: { name: "", email: "", phone: "" } },
  configured: false,
  connectors: CONNECTORS,
  dialects: DIALECTS,
  ...over,
});

beforeEach(() => {
  for (const m of [tacRouting, tacRoutingSave, tacRoutingDelete, tacCaptures]) m.mockReset();
  tacRouting.mockResolvedValue(routingResponse());
  tacCaptures.mockResolvedValue({
    captures: [
      { id: "tpl-9", name: "Our IOS-XE set", source: "template", dialect: "cisco-iosxe", commands: [] },
      { id: "tpl-3", name: "Our Junos set", source: "template", dialect: "juniper-junos", commands: [] },
    ],
    count: 2, limit: 200, formats: [], note: "",
  });
});
afterEach(() => cleanup());

const show = async () => {
  render(<TacRoutingSection />);
  await screen.findByTestId("tac-routing-contact");
};

describe("what the server sent is what the form shows", () => {
  it("opens on the stored contact, route, capture and contract", async () => {
    tacRouting.mockResolvedValue(routingResponse({
      configured: true,
      routing: {
        contact: { name: "Jane Doe", email: "jane.doe@example.com", phone: "+1 555 0100" },
        route_by_vendor: { cisco: "cisco-cxd" },
        capture_by_dialect: { "cisco-iosxe": "tpl-9" },
        contract_by_vendor: {
          cisco: { vendor: "cisco", contract_id: "SVC-4411", account_id: "jdoe", expires_on: "2027-03-31" },
        },
      },
    }));
    await show();
    expect((screen.getByLabelText("Name") as HTMLInputElement).value).toBe("Jane Doe");
    expect((screen.getByLabelText("Email") as HTMLInputElement).value).toBe("jane.doe@example.com");
    expect((screen.getByLabelText("Cisco") as HTMLSelectElement).value).toBe("cisco-cxd");
    expect((screen.getByLabelText("Cisco IOS-XE") as HTMLSelectElement).value).toBe("tpl-9");
    const cisco = screen.getByTestId("tac-contract-cisco");
    expect((within(cisco).getByLabelText("Cisco CCO ID") as HTMLInputElement).value).toBe("jdoe");
    expect((within(cisco).getByLabelText("Covered until") as HTMLInputElement).value).toBe("2027-03-31");
  });

  it("says so when nothing has been configured", async () => {
    await show();
    expect(screen.getByText("Nothing configured yet.")).toBeInTheDocument();
  });

  it("says what did not happen when the record cannot be read", async () => {
    tacRouting.mockRejectedValue(new Error("503 Service Unavailable: {}"));
    render(<TacRoutingSection />);
    expect(await screen.findByRole("alert")).toHaveTextContent(/./);
    expect(screen.queryByTestId("tac-routing-contact")).toBeNull();
  });
});

describe("the routes offered per vendor", () => {
  it("offers the vendor's own paths, the ITSM paths and the portal floor", async () => {
    await show();
    const sel = screen.getByLabelText("Cisco") as HTMLSelectElement;
    expect(Array.from(sel.options).map((o) => o.value))
      .toEqual(["", "servicenow", "cisco-cxd", "cisco-smart-bonding", "portal-text"]);
  });

  it("labels an unconfigured connector as choosable and credential-less", async () => {
    await show();
    const sel = screen.getByLabelText("Cisco") as HTMLSelectElement;
    const sb = Array.from(sel.options).find((o) => o.value === "cisco-smart-bonding")!;
    expect(sb.textContent).toBe("Cisco Smart Bonding — no credentials yet");
    expect(sb.disabled).toBe(false);
  });

  it("defaults every vendor to letting Correlix choose", async () => {
    await show();
    expect((screen.getByLabelText("Juniper") as HTMLSelectElement).value).toBe("");
  });
});

describe("the per-vendor contract labels", () => {
  it("names the account identifier the way each vendor names it", async () => {
    await show();
    expect(within(screen.getByTestId("tac-contract-cisco")).getByLabelText("Cisco CCO ID")).toBeInTheDocument();
    expect(within(screen.getByTestId("tac-contract-juniper")).getByLabelText("Juniper CSP user")).toBeInTheDocument();
  });
});

describe("the round trip", () => {
  it("saves what the form holds, with NO tenant in the body", async () => {
    tacRoutingSave.mockResolvedValue({
      routing: { contact: { name: "Jane Doe", email: "", phone: "" }, route_by_vendor: { cisco: "cisco-cxd" } },
      configured: true,
    });
    await show();
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: " Jane Doe " } });
    fireEvent.change(screen.getByLabelText("Cisco"), { target: { value: "cisco-cxd" } });
    fireEvent.change(
      within(screen.getByTestId("tac-contract-cisco")).getByLabelText("Cisco CCO ID"),
      { target: { value: "jdoe" } },
    );
    await act(async () => { fireEvent.click(screen.getByTestId("tac-routing-save")); });

    expect(tacRoutingSave).toHaveBeenCalledTimes(1);
    const body = tacRoutingSave.mock.calls[0][0];
    expect(JSON.stringify(body)).not.toContain("tenant");
    expect(body.contact.name).toBe("Jane Doe");
    expect(body.route_by_vendor).toEqual({ cisco: "cisco-cxd" });
    expect(body.contract_by_vendor.cisco.account_id).toBe("jdoe");
    expect(await screen.findByTestId("tac-routing-note")).toHaveTextContent("Saved.");
  });

  it("refuses an invalid record by naming the field, and sends nothing", async () => {
    await show();
    fireEvent.change(screen.getByLabelText("Email"), { target: { value: "jane.example.com" } });
    await act(async () => { fireEvent.click(screen.getByTestId("tac-routing-save")); });
    expect(tacRoutingSave).not.toHaveBeenCalled();
    expect(screen.getByTestId("tac-routing-error"))
      .toHaveTextContent("The contact email must be an address.");
  });

  it("refuses a coverage date that is not a date, and names the vendor", async () => {
    await show();
    fireEvent.change(
      within(screen.getByTestId("tac-contract-juniper")).getByLabelText("Covered until"),
      { target: { value: "31/03/2027" } },
    );
    await act(async () => { fireEvent.click(screen.getByTestId("tac-routing-save")); });
    expect(tacRoutingSave).not.toHaveBeenCalled();
    expect(screen.getByTestId("tac-routing-error")).toHaveTextContent("Juniper");
    expect(screen.getByTestId("tac-routing-error")).toHaveTextContent("YYYY-MM-DD");
  });

  it("says what did not happen when the save is refused server-side", async () => {
    tacRoutingSave.mockRejectedValue(new Error("400 Bad Request: {}"));
    await show();
    await act(async () => { fireEvent.click(screen.getByTestId("tac-routing-save")); });
    expect(await screen.findByTestId("tac-routing-error")).toHaveTextContent(/./);
  });

  it("clears the record only where there is one to clear", async () => {
    tacRouting.mockResolvedValue(routingResponse({ configured: true }));
    tacRoutingDelete.mockResolvedValue(undefined);
    await show();
    await act(async () => { fireEvent.click(screen.getByTestId("tac-routing-remove")); });
    expect(tacRoutingDelete).toHaveBeenCalledTimes(1);
    await waitFor(() => expect(screen.getByTestId("tac-routing-remove")).toBeDisabled());
  });
});

describe("per-device overrides", () => {
  it("adds a row keyed by the serial, folded the way the server folds it", async () => {
    await show();
    fireEvent.change(screen.getByLabelText("Serial"), { target: { value: "fdo111" } });
    fireEvent.change(screen.getByLabelText("Vendor for the new override"), { target: { value: "cisco" } });
    await act(async () => { fireEvent.click(screen.getByTestId("tac-override-add")); });
    expect(screen.getByTestId("tac-override-FDO111")).toBeInTheDocument();
  });

  it("saves the override with its own contract, under the vendor it names", async () => {
    tacRoutingSave.mockResolvedValue({ routing: { contact: {} }, configured: true });
    await show();
    fireEvent.change(screen.getByLabelText("Serial"), { target: { value: "FDO222" } });
    fireEvent.change(screen.getByLabelText("Vendor for the new override"), { target: { value: "cisco" } });
    await act(async () => { fireEvent.click(screen.getByTestId("tac-override-add")); });
    fireEvent.change(screen.getByLabelText("Contract for FDO222"), { target: { value: "SVC-9" } });
    await act(async () => { fireEvent.click(screen.getByTestId("tac-routing-save")); });
    const body = tacRoutingSave.mock.calls[0][0];
    expect(body.contract_by_serial.FDO222).toMatchObject({ vendor: "cisco", contract_id: "SVC-9" });
  });

  it("removes a row", async () => {
    tacRouting.mockResolvedValue(routingResponse({
      configured: true,
      routing: {
        contact: {},
        contract_by_serial: { FDO111: { vendor: "cisco", contract_id: "SVC-1" } },
      },
    }));
    await show();
    const row = screen.getByTestId("tac-override-FDO111");
    await act(async () => { fireEvent.click(within(row).getByRole("button", { name: "Remove" })); });
    expect(screen.queryByTestId("tac-override-FDO111")).toBeNull();
  });
});

describe("preferred captures", () => {
  it("offers this tenant's own sets for the platform they were written for", async () => {
    await show();
    const iosxe = screen.getByLabelText("Cisco IOS-XE") as HTMLSelectElement;
    expect(Array.from(iosxe.options).map((o) => o.textContent))
      .toEqual(["Correlix default", "Our IOS-XE set"]);
    const junos = screen.getByLabelText("Junos") as HTMLSelectElement;
    expect(Array.from(junos.options).map((o) => o.textContent))
      .toEqual(["Correlix default", "Our Junos set"]);
  });

  it("a tenant with no saved set still edits everything else", async () => {
    tacCaptures.mockRejectedValue(new Error("503 Service Unavailable: {}"));
    await show();
    const iosxe = screen.getByLabelText("Cisco IOS-XE") as HTMLSelectElement;
    expect(Array.from(iosxe.options).map((o) => o.value)).toEqual([""]);
  });
});
