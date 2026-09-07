// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// connectorForms.test.ts — the rule that protects a stored credential.
//
// The bug this file exists to prevent: a form that always sends its password box
// wipes a stored secret every time someone edits the port number beside it. The
// server cannot help — an empty string is a legitimate "remove it" — so the
// distinction has to be made here, and proven here.

import { describe, it, expect } from "vitest";
import {
  CONNECTOR_FORMS,
  blockOf,
  fieldApplies,
  fieldsFor,
  formStateFromView,
  mapToText,
  payloadFromState,
  probeTone,
  secretLabel,
  textToMap,
  visibleFields,
} from "./connectorForms";

const EMAIL_VIEW = {
  id: "email-arista",
  display: "Arista support email",
  section: "email",
  editable: true,
  configured: true,
  secrets: { password: true },
  email: {
    enabled: true,
    host: "smtp.acme.example:587",
    from: "noc@acme.example",
    user: "acme-relay",
    tls_on_connect: false,
    reply_to: "jane.doe@acme.example",
  },
};

describe("the form opens on what is stored", () => {
  it("fills every field of the connector's own block", () => {
    const s = formStateFromView(EMAIL_VIEW);
    expect(s.values.host).toBe("smtp.acme.example:587");
    expect(s.values.enabled).toBe(true);
    expect(s.values.tls_on_connect).toBe(false);
    expect(s.values.reply_to).toBe("jane.doe@acme.example");
  });

  it("starts every secret in 'keep' — an untouched form cannot lose one", () => {
    const s = formStateFromView(EMAIL_VIEW);
    expect(s.secrets.password).toEqual({ mode: "keep", value: "" });
    expect(payloadFromState("email", s)).not.toHaveProperty("password");
  });

  it("never carries a secret VALUE, because the server never sends one", () => {
    const s = formStateFromView(EMAIL_VIEW);
    expect(JSON.stringify(s)).not.toContain("password\":\"s");
    expect(s.values.password).toBeUndefined();
  });

  it("reads only the block the server populated", () => {
    expect(blockOf(EMAIL_VIEW)).toHaveProperty("host");
    expect(blockOf({ section: "jira" })).toEqual({});
  });
});

describe("a save says exactly what was decided about each secret", () => {
  it("omits a secret nobody touched", () => {
    const s = formStateFromView(EMAIL_VIEW);
    s.values.host = "smtp.acme.example:465";
    const body = payloadFromState("email", s);
    expect(body).not.toHaveProperty("password");
    expect(body.host).toBe("smtp.acme.example:465");
  });

  it("sends the new value when it is replaced", () => {
    const s = formStateFromView(EMAIL_VIEW);
    s.secrets.password = { mode: "replace", value: "rotated" };
    expect(payloadFromState("email", s).password).toBe("rotated");
  });

  it("sends the empty string that REMOVES it when it is cleared", () => {
    const s = formStateFromView(EMAIL_VIEW);
    s.secrets.password = { mode: "clear", value: "" };
    expect(payloadFromState("email", s).password).toBe("");
  });

  it("never sends a tenant, under any name", () => {
    const body = payloadFromState("email", formStateFromView(EMAIL_VIEW));
    for (const k of Object.keys(body)) expect(k).not.toMatch(/tenant/i);
  });

  it("sends numbers as numbers and a blank ceiling as zero", () => {
    const s = formStateFromView({ section: "jira", jira: { enabled: true, deployment: "cloud" } });
    expect(payloadFromState("jira", s).max_attach_bytes).toBe(0);
    s.values.max_attach_bytes = "10485760";
    expect(payloadFromState("jira", s).max_attach_bytes).toBe(10485760);
  });
});

describe("the Cisco field map survives a round trip", () => {
  it("renders one sorted line per binding and parses it back", () => {
    const text = mapToText({ synopsis: "Field10", serial: "Field20" });
    expect(text).toBe("serial = Field20\nsynopsis = Field10");
    expect(textToMap(text)).toEqual({ synopsis: "Field10", serial: "Field20" });
  });

  it("skips a line it cannot read rather than guessing at it", () => {
    expect(textToMap("synopsis = Field10\nnonsense\n= orphan\n")).toEqual({ synopsis: "Field10" });
  });

  it("carries the stored map back on a save, so an edit cannot wipe it", () => {
    const s = formStateFromView({
      section: "cisco",
      secrets: { client_secret: false },
      cisco: { enabled: true, cco_id: "CCO-1", field_map: { synopsis: "Field10" } },
    });
    s.values.cco_id = "CCO-2";
    expect(payloadFromState("cisco", s).field_map).toEqual({ synopsis: "Field10" });
  });
});

describe("what a person reads", () => {
  it("says whether a secret is stored, and what is about to happen to it", () => {
    expect(secretLabel(true, "keep")).toBe("stored");
    expect(secretLabel(false, "keep")).toBe("not set");
    expect(secretLabel(true, "replace")).toBe("will be replaced");
    expect(secretLabel(true, "clear")).toBe("will be removed");
  });

  it("keeps a probe outcome honest: only a refusal or an outage is bad news", () => {
    expect(probeTone("ok")).toBe("chip-ok");
    expect(probeTone("refused")).toBe("chip-crit");
    expect(probeTone("unreachable")).toBe("chip-crit");
    expect(probeTone("timed_out")).toBe("chip-crit");
    expect(probeTone("not_configured")).toBe("");
    expect(probeTone("unsupported")).toBe("");
  });

  it("gives every field a plain-words label and no wire name", () => {
    for (const [section, fields] of Object.entries(CONNECTOR_FORMS)) {
      for (const f of fields) {
        expect(f.label, `${section}.${f.name}`).not.toContain("_");
        expect(f.label.length, `${section}.${f.name}`).toBeGreaterThan(2);
      }
    }
  });

  it("offers no form for a connector with no settings block", () => {
    expect(fieldsFor(undefined)).toEqual([]);
    expect(fieldsFor("")).toEqual([]);
    expect(payloadFromState(undefined, { values: { x: "y" }, secrets: {} })).toEqual({});
  });
});

// ── the mailbox sign-in mode ────────────────────────────────────────────────
//
// The email block covers four ways of reaching a mailbox and a customer is on
// exactly one. Two things have to hold: the form shows only that one's fields,
// and a save carries only that one's settings — including CLEARING a credential
// the chosen mode cannot use, because a relay password sitting invisibly behind
// a Microsoft 365 mailbox is one nobody can see and nobody meant to keep.

const GRAPH_VIEW = {
  id: "email-arista",
  section: "email",
  editable: true,
  configured: true,
  secrets: { password: false, oauth_client_secret: true, service_account_key: false },
  email: {
    enabled: true,
    auth_mode: "microsoft365",
    mailbox: "noc@acme.example",
    entra_tenant_id: "11111111-2222-3333-4444-555555555555",
    oauth_client_id: "app-client-id",
    reply_to: "jane.doe@acme.example",
  },
};

describe("one sign-in mode's fields at a time", () => {
  it("opens a legacy relay record on the password mode", () => {
    const s = formStateFromView(EMAIL_VIEW);
    expect(s.values.auth_mode).toBe("password");
    const names = visibleFields("email", s.values).map((f) => f.name);
    expect(names).toContain("host");
    expect(names).toContain("password");
    expect(names).not.toContain("entra_tenant_id");
    expect(names).not.toContain("service_account_key");
  });

  it("shows the Microsoft fields and no relay boxes on Microsoft 365", () => {
    const names = visibleFields("email", formStateFromView(GRAPH_VIEW).values).map((f) => f.name);
    expect(names).toEqual([
      "enabled", "auth_mode", "mailbox",
      "entra_tenant_id", "oauth_client_id", "oauth_client_secret",
      "read_replies", "reply_to",
    ]);
  });

  it("shows the Google fields and no Microsoft ones on Google Workspace", () => {
    const values = { auth_mode: "google_workspace" };
    const names = visibleFields("email", values).map((f) => f.name);
    expect(names).toContain("service_account_email");
    expect(names).toContain("service_account_key");
    expect(names).not.toContain("oauth_client_secret");
    expect(names).not.toContain("host");
  });

  it("asks who issues the token before it asks for one on SMTP with OAuth", () => {
    const undecided = { auth_mode: "smtp_oauth" };
    const names = visibleFields("email", undecided).map((f) => f.name);
    expect(names).toContain("oauth_provider");
    expect(names).not.toContain("entra_tenant_id");
    expect(names).not.toContain("service_account_key");

    const microsoft = { auth_mode: "smtp_oauth", oauth_provider: "microsoft" };
    const msNames = visibleFields("email", microsoft).map((f) => f.name);
    expect(msNames).toContain("host");
    expect(msNames).toContain("entra_tenant_id");
    expect(msNames).not.toContain("service_account_key");
    expect(msNames).not.toContain("password");

    const google = { auth_mode: "smtp_oauth", oauth_provider: "google" };
    const gNames = visibleFields("email", google).map((f) => f.name);
    expect(gNames).toContain("service_account_key");
    expect(gNames).not.toContain("entra_tenant_id");
  });

  it("leaves every other connector's form untouched", () => {
    for (const section of ["servicenow", "jira", "cisco", "juniper"]) {
      expect(visibleFields(section, {})).toEqual(fieldsFor(section));
    }
  });

  it("treats a field with no mode as belonging to all of them", () => {
    const enabled = fieldsFor("email").find((f) => f.name === "enabled")!;
    for (const mode of ["password", "microsoft365", "google_workspace", "smtp_oauth"]) {
      expect(fieldApplies(enabled, { auth_mode: mode })).toBe(true);
    }
  });

  it("puts the (i) on the mode selector, because that is the choice to explain", () => {
    const mode = fieldsFor("email").find((f) => f.name === "auth_mode")!;
    expect(mode.topic).toBe("tac.mailbox-oauth");
    expect(mode.options?.map((o) => o.value)).toEqual([
      "password", "microsoft365", "google_workspace", "smtp_oauth",
    ]);
  });
});

describe("a save carries one mode's settings and clears the rest", () => {
  it("sends the Microsoft fields and none of the relay ones", () => {
    const body = payloadFromState("email", formStateFromView(GRAPH_VIEW));
    expect(body.auth_mode).toBe("microsoft365");
    expect(body.mailbox).toBe("noc@acme.example");
    expect(body.entra_tenant_id).toBe("11111111-2222-3333-4444-555555555555");
    expect(body).not.toHaveProperty("host");
    expect(body).not.toHaveProperty("user");
  });

  it("CLEARS a credential the chosen mode cannot use", () => {
    const body = payloadFromState("email", formStateFromView(GRAPH_VIEW));
    // The relay password and the Google key belong to modes this mailbox is not
    // on, so they are removed rather than left stored where nobody can see them.
    expect(body.password).toBe("");
    expect(body.service_account_key).toBe("");
    // The credential this mode DOES use was not touched, so it is not sent.
    expect(body).not.toHaveProperty("oauth_client_secret");
  });

  it("still never sends OUR tenant, in any mode", () => {
    // `entra_tenant_id` is Microsoft's DIRECTORY id — a credential field, named
    // so it cannot be mistaken for the Correlix tenant the server stamps from
    // the token. Nothing else may carry the word at all.
    for (const view of [EMAIL_VIEW, GRAPH_VIEW]) {
      const body = payloadFromState("email", formStateFromView(view));
      for (const k of Object.keys(body)) {
        if (k === "entra_tenant_id") continue;
        expect(k).not.toMatch(/tenant/i);
      }
      expect(body).not.toHaveProperty("tenant");
      expect(body).not.toHaveProperty("tenant_id");
      expect(body).not.toHaveProperty("as_tenant");
    }
  });

  it("opens a select on its first choice so the box shows what a save sends", () => {
    const s = formStateFromView({ section: "jira", jira: { enabled: true } });
    expect(s.values.deployment).toBe("cloud");
    expect(payloadFromState("jira", s).deployment).toBe("cloud");
  });
});
