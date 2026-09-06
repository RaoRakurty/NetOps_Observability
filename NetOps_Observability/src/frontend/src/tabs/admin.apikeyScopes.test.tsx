// API-key scope wizard (tracker 226) — the UI can now mint WRITE and
// ADMINISTRATIVE keys, and offers each caller only what the API will actually
// let it mint.
//
// Three things are pinned here:
//   1. the offered vocabulary does not drift from the backend's closed list
//      (internal/apikey.KnownScopes) — an option the API rejects is a broken
//      promise, and a missing one is the gap this row closed;
//   2. gating mirrors the server's rule (a key may not out-rank its minter),
//      default-closed while the caller's grid is still loading;
//   3. an administrative key cannot be issued without an explicit confirmation,
//      and the wording tells the truth about WHAT it administers.

import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, cleanup, fireEvent } from "@testing-library/react";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  SCOPE_OPTIONS,
  ScopePicker,
  allowedScopeOptions,
  isAdministrativeScope,
  scopeAllowed,
} from "./admin";

afterEach(cleanup);

// Permission grids, exactly as /api/auth/permissions returns them.
const ALL = (level: number) => ({
  overview: level, explore: level, alerts: level, infrastructure: level,
  topology: level, reports: level, administration: level, sensitive_data: level,
});
const SUPER_ADMIN = ALL(3);
const READ_ONLY = { ...ALL(1), administration: 0 };
const OPERATOR = { ...ALL(1), alerts: 2, infrastructure: 2, administration: 0 };
const ids = (opts: { id: string }[]) => opts.map((o) => o.id);

describe("scope vocabulary", () => {
  it("matches the backend's closed list exactly", () => {
    const here = dirname(fileURLToPath(import.meta.url));
    const go = readFileSync(join(here, "../../../backend/internal/apikey/store.go"), "utf-8");
    const body = go.match(/func KnownScopes\(\) \[\]string \{[\s\S]*?\n\}/)?.[0];
    expect(body, "KnownScopes() not found in internal/apikey/store.go").toBeTruthy();
    // Literals plus the exported constants the Go list uses by name.
    const constants: Record<string, string> = {
      ScopeReadAll: "read:*", ScopeWriteAll: "write:*",
      ScopeIngestCloud: "ingest:cloud", ScopeAdminAll: "admin:*",
    };
    const backend = [
      ...(body!.match(/"[a-z]+:[a-z*]+"/g) ?? []).map((s) => s.replace(/"/g, "")),
      ...Object.keys(constants).filter((c) => body!.includes(c)).map((c) => constants[c]),
    ];
    expect([...backend].sort()).toEqual([...ids(SCOPE_OPTIONS)].sort());
  });

  it("describes every scope — a chip with no explanation is not a choice", () => {
    for (const o of SCOPE_OPTIONS) {
      expect(o.what.length, `${o.id} has no description`).toBeGreaterThan(20);
      expect(o.what.endsWith("."), `${o.id}: description should read as a sentence`).toBe(true);
    }
  });

  it("recognises the administrative scope, and only that one", () => {
    expect(isAdministrativeScope("admin:*")).toBe(true);
    for (const o of SCOPE_OPTIONS.filter((s) => s.id !== "admin:*")) {
      expect(isAdministrativeScope(o.id)).toBe(false);
    }
  });
});

describe("allowedScopeOptions", () => {
  it("offers nothing until the caller's own grid is known (default-closed)", () => {
    expect(allowedScopeOptions(null, false)).toEqual([]);
    expect(allowedScopeOptions({}, true)).toEqual([]);
  });

  it("gives a platform admin every scope, service credential included", () => {
    expect(ids(allowedScopeOptions(SUPER_ADMIN, true))).toEqual(ids(SCOPE_OPTIONS));
  });

  it("gives a tenant admin everything except the platform-realm service scope", () => {
    const got = ids(allowedScopeOptions(SUPER_ADMIN, false));
    expect(got).toContain("admin:*");
    expect(got).toContain("write:devices");
    expect(got).not.toContain("ingest:cloud");
  });

  it("stops an operator-grade caller short of administrative keys", () => {
    const got = ids(allowedScopeOptions(OPERATOR, false));
    expect(got).toContain("write:*");
    expect(got).not.toContain("admin:*");
    expect(got).not.toContain("ingest:cloud");
  });

  it("leaves a read-only caller with read scopes only", () => {
    expect(ids(allowedScopeOptions(READ_ONLY, false))).toEqual(
      ids(SCOPE_OPTIONS.filter((o) => o.kind === "read")),
    );
  });

  it("refuses an administrative key to an admin who cannot administer everything", () => {
    // administration:admin alone is NOT enough: admin:* derives the
    // administrator role on every module, so the caller must hold that much.
    const partial = { ...ALL(1), administration: 3 };
    expect(scopeAllowed(SCOPE_OPTIONS.find((o) => o.id === "admin:*")!, partial, false)).toBe(false);
    expect(scopeAllowed(SCOPE_OPTIONS.find((o) => o.id === "read:metrics")!, partial, false)).toBe(true);
  });
});

describe("ScopePicker", () => {
  const opts = allowedScopeOptions(SUPER_ADMIN, false);

  it("groups the offered scopes and explains each group", () => {
    render(<ScopePicker options={opts} selected={["read:metrics"]} onToggle={() => {}} platformAdmin={false} confirmed={false} onConfirm={() => {}} />);
    expect(screen.getByText("Read")).toBeInTheDocument();
    expect(screen.getByText("Write")).toBeInTheDocument();
    expect(screen.getByText("Administrative")).toBeInTheDocument();
    expect(screen.getByLabelText(/admin:\*/)).toBeInTheDocument();
    expect(screen.getByLabelText(/write:devices/)).toBeInTheDocument();
  });

  it("says nothing about administrative keys until one is selected", () => {
    render(<ScopePicker options={opts} selected={["write:devices"]} onToggle={() => {}} platformAdmin={false} confirmed={false} onConfirm={() => {}} />);
    expect(screen.queryByText(/Administrative key/)).not.toBeInTheDocument();
  });

  it("demands an explicit confirmation for an administrative key", () => {
    const onConfirm = vi.fn();
    render(<ScopePicker options={opts} selected={["admin:*"]} onToggle={() => {}} platformAdmin={false} confirmed={false} onConfirm={onConfirm} />);
    expect(screen.getByText(/Administrative key/)).toBeInTheDocument();
    const box = screen.getByLabelText(/I understand, and I am issuing an administrative key/);
    fireEvent.click(box);
    expect(onConfirm).toHaveBeenCalledWith(true);
  });

  it("tells a tenant admin its key is tenant-bound, and a platform admin that its key is not", () => {
    render(<ScopePicker options={opts} selected={["admin:*"]} onToggle={() => {}} platformAdmin={false} confirmed={false} onConfirm={() => {}} />);
    expect(screen.getByText(/administers your tenant/)).toBeInTheDocument();
    expect(screen.getByText(/never reach another tenant/)).toBeInTheDocument();
    cleanup();
    render(<ScopePicker options={opts} selected={["admin:*"]} onToggle={() => {}} platformAdmin={true} confirmed={false} onConfirm={() => {}} />);
    expect(screen.getByText(/administers the whole platform/)).toBeInTheDocument();
  });

  it("waits rather than showing an empty picker while the grid loads", () => {
    render(<ScopePicker options={[]} selected={[]} onToggle={() => {}} platformAdmin={false} confirmed={false} onConfirm={() => {}} />);
    expect(screen.getByText(/Checking which scopes your role may issue/)).toBeInTheDocument();
  });

  it("toggles a scope through the callback", () => {
    const onToggle = vi.fn();
    render(<ScopePicker options={opts} selected={[]} onToggle={onToggle} platformAdmin={false} confirmed={false} onConfirm={() => {}} />);
    fireEvent.click(screen.getByLabelText(/read:flows/));
    expect(onToggle).toHaveBeenCalledWith("read:flows");
  });
});
