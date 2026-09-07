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
  fieldsFor,
  formStateFromView,
  mapToText,
  payloadFromState,
  probeTone,
  secretLabel,
  textToMap,
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
