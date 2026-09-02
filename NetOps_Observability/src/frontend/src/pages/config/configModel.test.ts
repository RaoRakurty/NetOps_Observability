// configModel.test.ts — the honesty rules of the configuration-backup surfaces,
// pinned as unit tests so no component can quietly re-invent them:
//  · an unrecognised or missing state collapses to "unknown", never to a pass
//  · "never captured" and "capture failed" are their own states
//  · the unified diff is turned into TAGGED LINE DATA — never markup
//  · a 404/501 is the feature-off product state, a 403/429 are their own

import { describe, it, expect } from "vitest";
import {
  BACKUP_BUSY_MESSAGE,
  DRIFT_FILTERS,
  DRIFT_LABEL,
  FEATURE_OFF_MESSAGE,
  NEVER_CAPTURED_HELP,
  NO_PERMISSION_MESSAGE,
  actionErrorMessage,
  classifyError,
  diffLines,
  driftOf,
  driftTone,
  fmtBytes,
  fmtChurn,
  shortSha,
  statusBadge,
} from "./configModel";
import type { ConfigStatus } from "../../services/api";

const status = (o: Partial<ConfigStatus>): ConfigStatus =>
  ({ device_id: "leaf1", state: "unknown", ...o }) as ConfigStatus;

describe("driftOf — untrusted wire values collapse to unknown", () => {
  it("passes the four contracted verdicts through", () => {
    expect(driftOf("in_sync")).toBe("in_sync");
    expect(driftOf("changed")).toBe("changed");
    expect(driftOf("drifted")).toBe("drifted");
    expect(driftOf("unknown")).toBe("unknown");
  });

  it("collapses anything else — including a hostile or absent value — to unknown", () => {
    expect(driftOf("compliant")).toBe("unknown");
    expect(driftOf("<script>")).toBe("unknown");
    expect(driftOf(undefined)).toBe("unknown");
    expect(driftOf(null)).toBe("unknown");
    expect(driftOf(7)).toBe("unknown");
  });

  it("never colours an unknown verdict green", () => {
    expect(driftTone("unknown")).toBe("");
    expect(driftTone("in_sync")).toBe("good");
    expect(driftTone("changed")).toBe("warn");
    expect(driftTone("drifted")).toBe("bad");
  });
});

describe("statusBadge — four states plus the two honest edges", () => {
  it("says 'Never captured' when no capture has ever landed", () => {
    const b = statusBadge(status({ state: "in_sync" }));
    expect(b.label).toBe("Never captured");
    expect(b.tone).toBe("");
    expect(b.help).toBe(NEVER_CAPTURED_HELP);
  });

  it("says 'Never captured' for a missing status object too", () => {
    expect(statusBadge(null).label).toBe("Never captured");
    expect(statusBadge(undefined).tone).toBe("");
  });

  it("renders in_sync / changed / drifted with their own tone", () => {
    const at = "2026-09-01T10:00:00Z";
    expect(statusBadge(status({ state: "in_sync", last_capture_at: at }))).toMatchObject({ label: DRIFT_LABEL.in_sync, tone: "good" });
    expect(statusBadge(status({ state: "changed", last_capture_at: at }))).toMatchObject({ label: DRIFT_LABEL.changed, tone: "warn" });
    expect(statusBadge(status({ state: "drifted", last_capture_at: at }))).toMatchObject({ label: DRIFT_LABEL.drifted, tone: "bad" });
  });

  it("keeps an unrecognised state as Unknown rather than showing it verbatim", () => {
    const b = statusBadge(status({ state: "totally-fine", last_capture_at: "2026-09-01T10:00:00Z" }));
    expect(b.label).toBe("Unknown");
    expect(b.tone).toBe("");
  });

  it("surfaces a failed capture as a failure carrying the backend reason", () => {
    const b = statusBadge(status({ state: "failed", last_capture_at: "2026-09-01T10:00:00Z", last_error: "ssh auth failed" }));
    expect(b.label).toBe("Capture failed");
    expect(b.tone).toBe("bad");
    expect(b.help).toBe("ssh auth failed");
  });

  it("offers All plus the four states as filter chips", () => {
    expect(DRIFT_FILTERS.map((f) => f.value)).toEqual(["", "in_sync", "changed", "drifted", "unknown"]);
  });
});

describe("diffLines — tagged data, never markup", () => {
  it("tags +/- / hunk / meta / context lines", () => {
    const unified = [
      "--- golden",
      "+++ current",
      "@@ -1,3 +1,3 @@",
      " hostname leaf1",
      "-ntp server 10.0.0.1",
      "+ntp server 10.0.0.2",
    ].join("\n");
    expect(diffLines(unified).map((l) => l.kind)).toEqual(["meta", "meta", "hunk", "ctx", "del", "add"]);
  });

  it("returns raw text so the renderer can escape it — it never produces HTML", () => {
    const lines = diffLines("+<script>alert(1)</script>");
    expect(lines).toEqual([{ kind: "add", text: "+<script>alert(1)</script>" }]);
  });

  it("normalises CRLF and drops the trailing empty line", () => {
    expect(diffLines("+a\r\n-b\r\n").map((l) => l.text)).toEqual(["+a", "-b"]);
  });

  it("treats an empty or absent diff as no lines", () => {
    expect(diffLines("")).toEqual([]);
    expect(diffLines(null)).toEqual([]);
    expect(diffLines(undefined)).toEqual([]);
  });
});

describe("formatting", () => {
  it("shortens a sha but never lengthens a short one", () => {
    expect(shortSha("0123456789abcdef0123")).toBe("0123456789ab");
    expect(shortSha("abc")).toBe("abc");
    expect(shortSha(null)).toBe("");
  });

  it("formats sizes and refuses to invent one", () => {
    expect(fmtBytes(512)).toBe("512 B");
    expect(fmtBytes(2048)).toBe("2.0 KB");
    expect(fmtBytes(undefined)).toBe("—");
  });

  it("shows churn only when the backend reported it", () => {
    expect(fmtChurn(3, 1)).toContain("+3");
    expect(fmtChurn(3, 1)).toContain("1");
    expect(fmtChurn(undefined, undefined)).toBe("—");
    expect(fmtChurn(4, undefined)).toContain("+4");
  });
});

describe("classifyError — which failures are product states", () => {
  it("treats 404 and 501 as 'the feature is off'", () => {
    expect(classifyError(new Error("404 Not Found: "))).toBe("off");
    expect(classifyError(new Error("501 Not Implemented: disabled"))).toBe("off");
    expect(actionErrorMessage(new Error("404 Not Found: "))).toContain(FEATURE_OFF_MESSAGE);
  });

  it("treats 403 as a permission answer and 429 as an overlapping backup", () => {
    expect(classifyError(new Error("403 Forbidden: "))).toBe("forbidden");
    expect(actionErrorMessage(new Error("403 Forbidden: "))).toBe(NO_PERMISSION_MESSAGE);
    expect(classifyError(new Error('429 Too Many Requests: {"error":"in progress"}'))).toBe("busy");
    expect(actionErrorMessage(new Error("429 Too Many Requests: "))).toBe(BACKUP_BUSY_MESSAGE);
  });

  it("passes anything else through as itself", () => {
    expect(classifyError(new Error("500 Internal Server Error: boom"))).toBe("other");
    expect(actionErrorMessage(new Error("500 Internal Server Error: boom"))).toContain("boom");
  });
});
