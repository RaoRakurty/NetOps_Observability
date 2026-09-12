// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// tacRoutingModel — the pure model behind Administration → Ticket delivery →
// TAC routing.
//
// WHY IT IS ITS OWN FILE. Everything that DECIDES what a person types lives
// here: which vendors can be configured, what a vendor calls its account
// identifier, which connectors may carry a vendor's cases, and what a save
// actually sends. All of it is unit-testable without a DOM, and the one rule
// that matters — the wire body NEVER carries a tenant, because the server
// stamps the owner from the token (§3a.2) — is a single exported function
// rather than a condition spread across a form.
//
// THE RECORD THIS EDITS. internal/ticketing/caseconn_routing.go. It holds
// CHOICES and ENTITLEMENT IDENTIFIERS — a contract number, a CCO-ID, the name
// and phone number of the person the vendor calls back. None of it is a secret
// and all of it is echoed back to this screen, which is exactly why it is a
// different record from the connector CREDENTIALS the Configure form edits.
//
// WHY THE LABEL IS PER VENDOR. Every vendor spells "your account with us"
// differently — Cisco a CCO ID, Juniper a CSP user, Nokia a customer id — and a
// single generic label would leave an operator guessing which of their several
// vendor identifiers to paste. One shape with a per-vendor label beats six
// near-identical forms (caseconn_routing.go, VendorContract).

import type {
  TacConnectorInfo,
  TacRoutingConfig,
  TacVendorContract,
} from "../../services/api";

/** The vendor's own name for its account identifier. */
export const ACCOUNT_LABEL: Readonly<Record<string, string>> = Object.freeze({
  cisco: "Cisco CCO ID",
  juniper: "Juniper CSP user",
  arista: "Arista portal account",
  nokia: "Nokia customer id",
  paloalto: "Palo Alto support account",
  fortinet: "Fortinet FortiCloud account",
});

/** A vendor whose word for it Correlix has not been taught. The generic label
 *  is shown rather than one invented from the vendor id. */
export const ACCOUNT_LABEL_FALLBACK = "Support account";

export function accountLabel(vendor: string): string {
  return ACCOUNT_LABEL[(vendor || "").trim().toLowerCase()] ?? ACCOUNT_LABEL_FALLBACK;
}

/** Operator-facing vendor names. A vendor absent from the table is title-cased
 *  rather than replaced: showing the id the inventory actually holds beats
 *  inventing a brand name. */
export const VENDOR_DISPLAY: Readonly<Record<string, string>> = Object.freeze({
  cisco: "Cisco",
  juniper: "Juniper",
  arista: "Arista",
  nokia: "Nokia",
  paloalto: "Palo Alto",
  fortinet: "Fortinet",
  huawei: "Huawei",
});

export function vendorDisplay(vendor: string): string {
  const id = (vendor || "").trim().toLowerCase();
  if (id === "") return "";
  return VENDOR_DISPLAY[id] ?? id.charAt(0).toUpperCase() + id.slice(1);
}

/** The ITSM systems. They carry a tenant's own tickets for ANY device vendor,
 *  so they are a routing CHOICE everywhere and a contract subject nowhere. */
const ITSM_VENDORS = new Set(["servicenow", "jira"]);

/** The generic path, always present and always available. */
const PORTAL_TEXT_ID = "portal-text";

/**
 * The DEVICE vendors this deployment can route, sorted.
 *
 * Derived from the connectors the server sent rather than from a list held
 * here: a deployment that gains a vendor path gains its row without a client
 * release, and one that has none shows none instead of an empty form per
 * vendor Correlix happens to know about.
 */
export function routingVendors(connectors: TacConnectorInfo[] | undefined): string[] {
  const seen = new Set<string>();
  for (const c of connectors ?? []) {
    const v = (c.vendor || "").trim().toLowerCase();
    if (v === "" || ITSM_VENDORS.has(v)) continue;
    seen.add(v);
  }
  return [...seen].sort();
}

/**
 * The connectors offered for one vendor's route.
 *
 * Three things can carry a vendor's cases: the vendor's own path(s), the
 * tenant's ITSM connectors, and the generic portal path. An UNCONFIGURED one is
 * still offered — a tenant route naming it is honoured and then refused by name
 * on the confirmation screen, which is the server's own rule; hiding the choice
 * would make that rule unreachable.
 */
export function connectorsForVendor(
  connectors: TacConnectorInfo[] | undefined,
  vendor: string,
): TacConnectorInfo[] {
  const want = (vendor || "").trim().toLowerCase();
  return (connectors ?? []).filter((c) => {
    if (c.id === PORTAL_TEXT_ID) return true;
    const v = (c.vendor || "").trim().toLowerCase();
    if (ITSM_VENDORS.has(v)) return true;
    return v !== "" && v === want;
  });
}

/** How one connector reads in the route picker: its name, and whether this
 *  tenant has brought credentials for it. The label is the honesty: an
 *  operator choosing an unconfigured path must know that is what they chose. */
export function connectorChoiceLabel(c: TacConnectorInfo): string {
  return c.configured ? c.display : `${c.display} — no credentials yet`;
}

/** The route currently chosen for a vendor, or "" for "let Correlix decide". */
export function routeFor(routing: TacRoutingConfig, vendor: string): string {
  return (routing.route_by_vendor ?? {})[(vendor || "").trim().toLowerCase()] ?? "";
}

/** The preferred capture chosen for a dialect, or "" for the Correlix default. */
export function captureFor(routing: TacRoutingConfig, dialect: string): string {
  return (routing.capture_by_dialect ?? {})[(dialect || "").trim().toLowerCase()] ?? "";
}

/** The contract held for a vendor, as an editable row. */
export function contractFor(routing: TacRoutingConfig, vendor: string): TacVendorContract {
  const key = (vendor || "").trim().toLowerCase();
  return (routing.contract_by_vendor ?? {})[key] ?? { vendor: key };
}

/** The per-device overrides, keyed by SERIAL — what the vendor actually checks
 *  when it decides whether a chassis is covered. Sorted so the list reads the
 *  same on every open. */
export function overrideRows(routing: TacRoutingConfig): { serial: string; contract: TacVendorContract }[] {
  return Object.entries(routing.contract_by_serial ?? {})
    .map(([serial, contract]) => ({ serial, contract }))
    .sort((a, b) => (a.serial < b.serial ? -1 : a.serial > b.serial ? 1 : 0));
}

// ── bounds and validation (the server's own, mirrored so the UI refuses first) ─

/** internal/ticketing: at most 64 vendor routes / preferred captures / contracts. */
export const MAX_ROUTING_VENDORS = 64;
/** At most 2000 per-serial overrides. */
export const MAX_CONTRACT_OVERRIDES = 2000;
/** One free-text field is at most 200 characters. */
export const MAX_ROUTING_FIELD = 200;
/** A serial key is at most 64 characters. */
export const MAX_SERIAL = 64;

export const ROUTING_READ_FAILED = "Your TAC routing could not be read.";
export const ROUTING_SAVE_FAILED = "Your TAC routing could not be saved.";
export const ROUTING_SAVED = "Saved.";
export const ROUTING_EMPTY = "Nothing configured yet.";

/** A coverage date the server will accept. */
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;

/**
 * What is wrong with the record, in the operator's words, or "" when it is
 * saveable. It mirrors ValidateTACRoutingConfig field for field and in the same
 * ORDER, so the same bad record reports the same field every time — an operator
 * fixing one at a time must not chase a moving error.
 */
export function validateRouting(cfg: TacRoutingConfig): string {
  const email = (cfg.contact.email ?? "").trim();
  if (email !== "" && !email.includes("@")) return "The contact email must be an address.";
  for (const [what, value] of [
    ["contact name", cfg.contact.name],
    ["contact email", cfg.contact.email],
    ["contact phone", cfg.contact.phone],
  ] as [string, string | undefined][]) {
    if ((value ?? "").length > MAX_ROUTING_FIELD) {
      return `The ${what} must be at most ${MAX_ROUTING_FIELD} characters.`;
    }
  }
  for (const vendor of Object.keys(cfg.contract_by_vendor ?? {}).sort()) {
    const bad = validateContract(vendorDisplay(vendor), (cfg.contract_by_vendor ?? {})[vendor]);
    if (bad) return bad;
  }
  for (const serial of Object.keys(cfg.contract_by_serial ?? {}).sort()) {
    if (serial.length > MAX_SERIAL) return `A device serial must be at most ${MAX_SERIAL} characters.`;
    const bad = validateContract(serial, (cfg.contract_by_serial ?? {})[serial]);
    if (bad) return bad;
  }
  if (Object.keys(cfg.contract_by_serial ?? {}).length > MAX_CONTRACT_OVERRIDES) {
    return `At most ${MAX_CONTRACT_OVERRIDES} per-device overrides.`;
  }
  return "";
}

function validateContract(what: string, c: TacVendorContract | undefined): string {
  if (!c) return "";
  for (const value of [c.contract_id, c.account_id, c.site_id, c.support_level, c.note]) {
    if ((value ?? "").length > MAX_ROUTING_FIELD) {
      return `${what}: every field must be at most ${MAX_ROUTING_FIELD} characters.`;
    }
  }
  const on = (c.expires_on ?? "").trim();
  if (on !== "" && (!DATE_RE.test(on) || Number.isNaN(new Date(`${on}T00:00:00Z`).getTime()))) {
    return `${what}: the coverage end date must be YYYY-MM-DD.`;
  }
  return "";
}

/** True when a contract row carries nothing worth storing. */
export function contractIsEmpty(c: TacVendorContract | undefined): boolean {
  if (!c) return true;
  return [c.contract_id, c.account_id, c.site_id, c.support_level, c.expires_on, c.note]
    .every((v) => (v ?? "").trim() === "");
}

/**
 * The save body.
 *
 * It mirrors the server's own normalise so WHAT IS SHOWN IS WHAT IS STORED: keys
 * folded the way the server folds them (vendors and dialects lower-cased,
 * serials upper-cased, because that is what a lookup will use), every value
 * trimmed, and every empty entry dropped so a cleared row reads afterwards
 * exactly like a row that was never made.
 *
 * It carries NO tenant. The owner is stamped from the token server-side, and a
 * tenant here would be ignored (§3a.2).
 */
export function buildRoutingSave(cfg: TacRoutingConfig): TacRoutingConfig {
  const out: TacRoutingConfig = {
    contact: {
      name: (cfg.contact.name ?? "").trim(),
      email: (cfg.contact.email ?? "").trim(),
      phone: (cfg.contact.phone ?? "").trim(),
    },
  };
  const routes: Record<string, string> = {};
  for (const [k, v] of Object.entries(cfg.route_by_vendor ?? {})) {
    const key = k.trim().toLowerCase();
    const val = (v ?? "").trim();
    if (key && val) routes[key] = val;
  }
  if (Object.keys(routes).length) out.route_by_vendor = routes;

  const captures: Record<string, string> = {};
  for (const [k, v] of Object.entries(cfg.capture_by_dialect ?? {})) {
    const key = k.trim().toLowerCase();
    const val = (v ?? "").trim();
    if (key && val) captures[key] = val;
  }
  if (Object.keys(captures).length) out.capture_by_dialect = captures;

  const byVendor: Record<string, TacVendorContract> = {};
  for (const [k, v] of Object.entries(cfg.contract_by_vendor ?? {})) {
    const key = k.trim().toLowerCase();
    const row = normalizeContract(key, v);
    if (key && !contractIsEmpty(row)) byVendor[key] = row;
  }
  if (Object.keys(byVendor).length) out.contract_by_vendor = byVendor;

  const bySerial: Record<string, TacVendorContract> = {};
  for (const [k, v] of Object.entries(cfg.contract_by_serial ?? {})) {
    const key = k.trim().toUpperCase();
    const row = normalizeContract((v?.vendor ?? "").trim().toLowerCase(), v);
    if (key && !contractIsEmpty(row)) bySerial[key] = row;
  }
  if (Object.keys(bySerial).length) out.contract_by_serial = bySerial;
  return out;
}

function normalizeContract(vendor: string, c: TacVendorContract | undefined): TacVendorContract {
  return {
    vendor,
    contract_id: (c?.contract_id ?? "").trim(),
    account_id: (c?.account_id ?? "").trim(),
    site_id: (c?.site_id ?? "").trim(),
    support_level: (c?.support_level ?? "").trim(),
    expires_on: (c?.expires_on ?? "").trim(),
    note: (c?.note ?? "").trim(),
  };
}

/** An empty record, for a tenant that has configured nothing. */
export function emptyRouting(): TacRoutingConfig {
  return { contact: { name: "", email: "", phone: "" } };
}
