// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// connectorForms — the pure model behind Administration → Ticket delivery →
// Case connectors → Configure.
//
// WHY IT IS ITS OWN FILE. Everything that DECIDES what a person types lives
// here as data and pure functions: which fields a connector has, what each one
// is called in plain words, and — the part that is easy to get wrong — what a
// save actually sends for a secret. That makes all of it unit-testable without
// a DOM, and it makes the one rule that protects a stored credential a single
// exported function rather than a condition spread across a form component.
//
// THE SECRET RULE, stated once. The server never sends a stored secret back; it
// only says whether one is stored. So the form has three intentions and the
// wire has three shapes:
//
//	keep     → the field is OMITTED from the save   (the ordinary edit)
//	replace  → the new value is sent
//	clear    → an empty string is sent              (an explicit removal)
//
// A form that always sent its input box would wipe a stored credential every
// time someone edited the port number beside it. That is the bug this file
// exists to make impossible.
//
// The field lists mirror the server's own per-section forms
// (src/backend/internal/ticketing/caseconn_form.go). The server refuses a field
// it does not have, so a drift here is a refused save, never a silent write.

/** What a field is, which decides how it is rendered and how it is sent. */
export type FieldKind = "toggle" | "text" | "secret" | "select" | "number" | "map";

export type ConnectorField = {
  /** The wire field name — must match the server's form exactly. */
  name: string;
  /** What a person reads. Plain words, never the wire name. */
  label: string;
  kind: FieldKind;
  /** Choices for a select, in the order they are offered. */
  options?: readonly { value: string; label: string }[];
  /** A shape hint, shown in the empty box. Never an instruction. */
  placeholder?: string;
};

/**
 * The five settings blocks twelve connectors share. `section` comes from the
 * server (`config_section`), so the client never guesses which form a connector
 * takes — and a connector with no section has no form at all, which is the
 * honest state of every portal-only vendor.
 */
export const CONNECTOR_FORMS: Readonly<Record<string, readonly ConnectorField[]>> = Object.freeze({
  servicenow: [
    { name: "enabled", label: "Use ServiceNow for TAC cases", kind: "toggle" },
    { name: "max_attach_bytes", label: "Largest attachment, in bytes", kind: "number", placeholder: "1073741824" },
  ],
  jira: [
    { name: "enabled", label: "Use Jira for TAC cases", kind: "toggle" },
    {
      name: "deployment", label: "Which Jira", kind: "select",
      options: [
        { value: "cloud", label: "Jira Cloud" },
        { value: "datacenter", label: "Jira Data Center" },
      ],
    },
    { name: "max_attach_bytes", label: "Largest attachment, in bytes", kind: "number", placeholder: "1073741824" },
  ],
  email: [
    { name: "enabled", label: "Send cases by email", kind: "toggle" },
    { name: "host", label: "Mail relay, as host:port", kind: "text", placeholder: "smtp.example.com:587" },
    { name: "from", label: "Send from", kind: "text", placeholder: "noc@example.com" },
    { name: "user", label: "Sign-in name", kind: "text" },
    { name: "password", label: "Password", kind: "secret" },
    { name: "tls_on_connect", label: "Encrypt from the first byte, on port 465", kind: "toggle" },
    { name: "reply_to", label: "Reply goes to", kind: "text", placeholder: "jane.doe@example.com" },
  ],
  cisco: [
    { name: "enabled", label: "Use Cisco for TAC cases", kind: "toggle" },
    { name: "cco_id", label: "Cisco.com ID", kind: "text" },
    { name: "customer_source_id", label: "Customer source ID", kind: "text" },
    { name: "smart_bonding_enabled", label: "Open cases, not just attach", kind: "toggle" },
    { name: "client_id", label: "Client ID", kind: "text" },
    { name: "client_secret", label: "Client secret", kind: "secret" },
    { name: "token_url", label: "Sign-in address", kind: "text", placeholder: "https://id.cisco.com/oauth2/default/v1/token" },
    { name: "staging_host", label: "Test host, if you were given one", kind: "text" },
    { name: "field_map", label: "Field names, one per line as ours = theirs", kind: "map" },
  ],
  juniper: [
    { name: "enabled", label: "Use Juniper for TAC cases", kind: "toggle" },
    { name: "app_id", label: "App ID", kind: "text" },
    { name: "customer_source_id", label: "Customer source ID", kind: "text" },
    { name: "user_id", label: "Portal user ID", kind: "text" },
    { name: "account_id", label: "Account ID", kind: "text" },
    { name: "default_contact_email", label: "Person Juniper replies to", kind: "text", placeholder: "jane.doe@example.com" },
    {
      name: "auth_mode", label: "How we sign in", kind: "select",
      options: [
        { value: "oauth", label: "Client ID and secret" },
        { value: "apikey", label: "API key" },
      ],
    },
    { name: "client_id", label: "Client ID", kind: "text" },
    { name: "client_secret", label: "Client secret", kind: "secret" },
    { name: "api_key", label: "API key", kind: "secret" },
  ],
});

/** The fields of one section, or an empty list when there is no form. */
export function fieldsFor(section: string | undefined): readonly ConnectorField[] {
  return CONNECTOR_FORMS[(section ?? "").trim()] ?? [];
}

/** What the person has decided about one stored secret. */
export type SecretMode = "keep" | "replace" | "clear";

export type SecretState = { mode: SecretMode; value: string };

/** The whole form: plain values plus one state per secret. */
export type FormState = {
  values: Record<string, string | boolean>;
  secrets: Record<string, SecretState>;
};

/** The settings blocks as they arrive, keyed by section. */
type ViewBlocks = {
  section?: string;
  secrets?: Record<string, boolean>;
  servicenow?: Record<string, unknown>;
  jira?: Record<string, unknown>;
  email?: Record<string, unknown>;
  cisco?: Record<string, unknown>;
  juniper?: Record<string, unknown>;
};

/** The block the server populated for this connector. */
export function blockOf(view: ViewBlocks): Record<string, unknown> {
  const section = (view.section ?? "").trim();
  const block = (view as Record<string, unknown>)[section];
  return block && typeof block === "object" ? (block as Record<string, unknown>) : {};
}

/**
 * Opens the form on what is stored. A secret starts in "keep": nothing the
 * person has not touched can be sent, so simply opening and saving the form
 * cannot lose a credential.
 */
export function formStateFromView(view: ViewBlocks): FormState {
  const block = blockOf(view);
  const values: Record<string, string | boolean> = {};
  const secrets: Record<string, SecretState> = {};
  for (const f of fieldsFor(view.section)) {
    if (f.kind === "secret") {
      secrets[f.name] = { mode: "keep", value: "" };
      continue;
    }
    const raw = block[f.name];
    if (f.kind === "toggle") {
      values[f.name] = raw === true;
    } else if (f.kind === "map") {
      values[f.name] = mapToText(raw);
    } else if (f.kind === "number") {
      values[f.name] = typeof raw === "number" && raw > 0 ? String(raw) : "";
    } else {
      values[f.name] = typeof raw === "string" ? raw : "";
    }
  }
  return { values, secrets };
}

/** "ours = theirs" lines, sorted, so the box reads the same on every open. */
export function mapToText(raw: unknown): string {
  if (!raw || typeof raw !== "object") return "";
  return Object.entries(raw as Record<string, unknown>)
    .map(([k, v]) => `${k} = ${String(v ?? "")}`)
    .sort()
    .join("\n");
}

/** Parses those lines back. A line with no `=` is skipped rather than guessed. */
export function textToMap(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of (text || "").split("\n")) {
    const at = line.indexOf("=");
    if (at <= 0) continue;
    const k = line.slice(0, at).trim();
    const v = line.slice(at + 1).trim();
    if (k) out[k] = v;
  }
  return out;
}

/**
 * The save body: this connector's own fields, and NEVER a tenant — the server
 * stamps the owner from the token, and a tenant here would be refused anyway.
 *
 * A secret appears only when the person decided something about it:
 * "replace" sends the new value, "clear" sends the empty string that removes
 * the stored one, and "keep" sends nothing at all.
 */
export function payloadFromState(section: string | undefined, state: FormState): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const f of fieldsFor(section)) {
    if (f.kind === "secret") {
      const s = state.secrets[f.name] ?? { mode: "keep", value: "" };
      if (s.mode === "replace") out[f.name] = s.value;
      else if (s.mode === "clear") out[f.name] = "";
      continue;
    }
    const v = state.values[f.name];
    if (f.kind === "toggle") {
      out[f.name] = v === true;
    } else if (f.kind === "number") {
      const n = Number.parseInt(String(v ?? "").trim(), 10);
      out[f.name] = Number.isFinite(n) && n > 0 ? n : 0;
    } else if (f.kind === "map") {
      out[f.name] = textToMap(String(v ?? ""));
    } else {
      out[f.name] = String(v ?? "").trim();
    }
  }
  return out;
}

/** What the secret field shows when nothing has been touched yet. */
export const SECRET_STORED = "stored";
export const SECRET_NONE = "not set";

/** The word beside a secret field: stored, being replaced, or about to go. */
export function secretLabel(stored: boolean, mode: SecretMode): string {
  if (mode === "clear") return "will be removed";
  if (mode === "replace") return "will be replaced";
  return stored ? SECRET_STORED : SECRET_NONE;
}

/** One sentence per probe outcome. The server's own note follows it. */
export const PROBE_SENTENCE: Readonly<Record<string, string>> = Object.freeze({
  ok: "The vendor answered.",
  not_configured: "Nothing to test yet.",
  refused: "The vendor refused these credentials.",
  unreachable: "The vendor could not be reached.",
  timed_out: "The vendor did not answer in time.",
  unsupported: "This path has no test.",
});

/** Chip tone for an outcome. Only a real refusal or outage is bad news. */
export function probeTone(outcome: string): string {
  if (outcome === "ok") return "chip-ok";
  if (outcome === "refused" || outcome === "unreachable" || outcome === "timed_out") return "chip-crit";
  return "";
}

/** What removing a connector's settings actually costs, in one line. */
export const REMOVE_CONSEQUENCE = "Escalations stop offering this path.";

/** The save/remove/test failures, in the operator's words. */
export const CONFIG_READ_FAILED = "Those settings could not be read.";
export const CONFIG_SAVE_FAILED = "Those settings could not be saved.";
export const CONFIG_REMOVE_FAILED = "Those settings could not be removed.";
export const CONFIG_TEST_FAILED = "The test could not be run.";
