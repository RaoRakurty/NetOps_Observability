// Registries sub-tab: pure-helper contracts.
//
// The load-bearing ones are specAttributes/describeSpec — the client-side mirror
// of servicecat.BuildSelectorCondition. A spec the engine cannot use must read as
// "nothing attributed", which is the `attributed:false` the flow view reports.

import { describe, expect, it } from "vitest";
import type { CatalogServiceSelector } from "../../services/api";
import {
  BINDING_KIND_LABELS, EMPTY_SELECTOR_DRAFT, REGISTRY_NAME_MAX, archivePrompt,
  backendLabel, describeSpec, ignoredSpecKeys, isArchived, isStoreUnavailable, latestSelector,
  nextSelectorVersion, parseSelectorDraft, specAttributes, storageBadge, validateBinding,
  validateRegistryName,
} from "./registries";

describe("validateRegistryName (mirror of both servers' name rule)", () => {
  it("requires a name and bounds it at 120", () => {
    expect(validateRegistryName("payments", "service")).toBe("");
    expect(validateRegistryName("  ", "service")).toMatch(/service name is required/);
    expect(validateRegistryName("  ", "application")).toBe("an application name is required");
    expect(validateRegistryName("  ", "service")).toBe("a service name is required");
    expect(validateRegistryName("x".repeat(REGISTRY_NAME_MAX), "service")).toBe("");
    expect(validateRegistryName("x".repeat(REGISTRY_NAME_MAX + 1), "service")).toMatch(/120 characters or fewer/);
  });
});

describe("parseSelectorDraft (only what the engine understands)", () => {
  it("parses ports, prefixes and protocols into the stored spec", () => {
    const r = parseSelectorDraft({ ports: "443, 8443", prefixes: "10.0.0.0/8", protocols: "6" });
    expect(r.error).toBe("");
    expect(r.spec).toEqual({ ports: [443, 8443], dst_prefixes: ["10.0.0.0/8"], protocols: [6] });
  });
  it("accepts whitespace- and comma-separated lists alike", () => {
    expect(parseSelectorDraft({ ...EMPTY_SELECTOR_DRAFT, ports: "80 443\n8080" }).spec)
      .toEqual({ ports: [80, 443, 8080] });
  });
  it("refuses an unusable token rather than dropping it silently", () => {
    expect(parseSelectorDraft({ ...EMPTY_SELECTOR_DRAFT, ports: "70000" }).error).toMatch(/0 to 65535/);
    expect(parseSelectorDraft({ ...EMPTY_SELECTOR_DRAFT, protocols: "300" }).error).toMatch(/0 to 255/);
    expect(parseSelectorDraft({ ...EMPTY_SELECTOR_DRAFT, prefixes: "10.0.0.0/33" }).error).toMatch(/IPv4 address or CIDR/);
    expect(parseSelectorDraft({ ...EMPTY_SELECTOR_DRAFT, prefixes: "10.0.0.0/33" }).spec).toEqual({});
  });
  it("an all-empty draft parses to an empty spec (which attributes nothing)", () => {
    const r = parseSelectorDraft(EMPTY_SELECTOR_DRAFT);
    expect(r).toEqual({ spec: {}, error: "" });
    expect(specAttributes(r.spec)).toBe(false);
  });
});

describe("specAttributes (mirror of servicecat.BuildSelectorCondition)", () => {
  it("is true when any understood predicate is present", () => {
    expect(specAttributes({ ports: [443] })).toBe(true);
    expect(specAttributes({ dst_prefixes: ["10.0.0.0/8"] })).toBe(true);
    expect(specAttributes({ protocols: [6] })).toBe(true);
  });
  it("is false for an empty spec and for one the engine cannot act on", () => {
    expect(specAttributes({})).toBe(false);
    expect(specAttributes(null)).toBe(false);
    // keys the server's condition builder does not read
    expect(specAttributes({ remote_asns: [8075], domains: ["example.com"], tags: { app: "x" } })).toBe(false);
    // right key, unusable values
    expect(specAttributes({ ports: [70000] })).toBe(false);
    expect(specAttributes({ protocols: [999] })).toBe(false);
    expect(specAttributes({ dst_prefixes: ["not-a-prefix"] })).toBe(false);
    expect(specAttributes({ ports: "443" })).toBe(false);
  });
});

describe("describeSpec / ignoredSpecKeys", () => {
  it("reads a spec back as one line", () => {
    expect(describeSpec({ ports: [443, 8443], dst_prefixes: ["10.0.0.0/8"], protocols: [6] }))
      .toBe("ports 443, 8443 · destinations 10.0.0.0/8 · protocols 6");
    expect(describeSpec({})).toBe("");
  });
  it("names the keys the engine ignores, so a full-looking spec is not mistaken for a working one", () => {
    expect(ignoredSpecKeys({ ports: [443], domains: ["x"], remote_asns: [1] })).toEqual(["domains", "remote_asns"]);
    expect(ignoredSpecKeys({ ports: [443] })).toEqual([]);
  });
});

describe("selector versioning (append-only)", () => {
  const sel = (version: number): CatalogServiceSelector => ({
    service_id: "s1", version, effective_from: "2026-09-01T00:00:00Z",
    spec: { ports: [443] }, created_by: "u", created_at: "2026-09-01T00:00:00Z",
  });
  it("uses the highest version, whatever order the list arrives in", () => {
    expect(latestSelector([sel(1), sel(3), sel(2)])?.version).toBe(3);
    expect(latestSelector([])).toBeNull();
  });
  it("a save creates the next version, never an edit in place", () => {
    expect(nextSelectorVersion([sel(1), sel(2)])).toBe(3);
    expect(nextSelectorVersion([])).toBe(1);
  });
});

describe("validateBinding (mirror of the server's kind/ref guard)", () => {
  it("accepts the three kinds the server accepts, and no others", () => {
    expect(Object.keys(BINDING_KIND_LABELS).sort()).toEqual(["path", "probe", "seam"]);
    expect(validateBinding("probe", "http-checkout")).toBe("");
    expect(validateBinding("device", "x")).toMatch(/kind of attachment/);
  });
  it("requires a reference", () => {
    expect(validateBinding("seam", "   ")).toMatch(/reference is required/);
  });
});

describe("store availability and archive semantics", () => {
  it("recognizes the 501 no-store answer, and only that", () => {
    expect(isStoreUnavailable(new Error('501 Not Implemented: {"error":"service catalog requires the PostgreSQL backend"}'))).toBe(true);
    expect(isStoreUnavailable(new Error("500 Internal Server Error: boom"))).toBe(false);
    expect(isStoreUnavailable(new Error("network down"))).toBe(false);
  });
  it("says archive, never delete, and says what survives", () => {
    expect(archivePrompt("service", "payments")).toMatch(/Archive the service "payments"\?/);
    expect(archivePrompt("service", "payments")).toMatch(/selector versions and past attribution are kept/);
    expect(archivePrompt("application", "billing")).toMatch(/the record is kept/);
    expect(archivePrompt("service", "payments")).not.toMatch(/permanently|hard delete/i);
  });
  it("reads the archived marker off a row", () => {
    expect(isArchived({ archived_at: "2026-09-01T00:00:00Z" })).toBe(true);
    expect(isArchived({})).toBe(false);
  });
});

// ── tracker 245: the storage badge ─────────────────────────────────────────
//
// Four states that must never collapse into each other. The label is what an
// operator reads without knowing STORE_BACKEND exists.

describe("storageBadge", () => {
  const row = (over: Record<string, unknown> = {}) => ({
    registry: "applications", label: "Application registry",
    configured_backend: "postgres", active_backend: "postgres",
    persistence: "persistent", available: true, healthy: true, ...over,
  }) as Parameters<typeof storageBadge>[0];

  it("healthy persistent storage names the backend and its durability", () => {
    const b = storageBadge(row());
    expect(b?.label).toBe("PostgreSQL · Persistent");
    expect(b?.tone).toBe("var(--good)");
    expect(b?.title).toMatch(/survive an API restart/);
  });

  it("an ephemeral backend is labelled ephemeral and warned about", () => {
    const b = storageBadge(row({ configured_backend: "memory", active_backend: "memory", persistence: "ephemeral" }));
    expect(b?.label).toBe("Memory · Ephemeral");
    expect(b?.tone).toBe("var(--warn)");
    expect(b?.title).toMatch(/lost when the API restarts/);
  });

  it("an unhealthy backend keeps its identity — it is never relabelled as another backend", () => {
    const b = storageBadge(row({ available: false, healthy: false, reason: "database unavailable" }));
    expect(b?.label).toBe("PostgreSQL · Persistent · Unavailable");
    expect(b?.label).not.toMatch(/File|Memory/);
    expect(b?.tone).toBe("var(--bad)");
    expect(b?.title).toMatch(/nothing is written anywhere else/);
  });

  it("an unsupported backend names what is configured and claims no persistence", () => {
    const b = storageBadge(row({
      configured_backend: "file", active_backend: "", persistence: "",
      available: false, healthy: false, reason: "backend not supported for this registry",
    }));
    expect(b?.label).toBe("Unavailable · configured storage: File");
    expect(b?.label).not.toMatch(/Persistent/);
    expect(b?.tone).toBe("var(--bad)");
  });

  it("renders nothing when the posture is unknown — unknown is not healthy", () => {
    expect(storageBadge(undefined)).toBeNull();
  });

  it("prints an unrecognised backend kind verbatim rather than guessing", () => {
    expect(backendLabel("cassandra")).toBe("cassandra");
    expect(backendLabel("")).toBe("unknown");
  });
});

describe("isStoreUnavailable", () => {
  it("treats 501 (unsupported) and 503 (store down) as deployment facts, not empty registries", () => {
    expect(isStoreUnavailable(new Error("501 Not Implemented: {}"))).toBe(true);
    expect(isStoreUnavailable(new Error("503 Service Unavailable: {}"))).toBe(true);
    expect(isStoreUnavailable(new Error("403 Forbidden: {}"))).toBe(false);
    expect(isStoreUnavailable(new Error("500 Internal Server Error: {}"))).toBe(false);
  });
});
