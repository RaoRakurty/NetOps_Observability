// dataProtection.model.test.ts — the RULES behind the Data Protection console.
//
// The rule this file exists to hold down is the honest-empty-state rule: an
// absent measurement must stay absent all the way to the screen. A regression
// that quietly turns `null` into 0 does not look like a bug in a screenshot —
// it looks like a healthy backup — so it is pinned here as arithmetic, not as
// rendered pixels. The second rule is the three-way one: "not measured",
// "never", and a real value are three different answers, and the model must
// never collapse them into two.

import { describe, it, expect } from "vitest";
import type {
  BackupCoverageView, EngineCoverage, SnapshotRepositoryView, SnapshotView,
} from "../services/api";
import {
  BACKUP_DOC,
  DEFAULT_RESTORE_PREFIX,
  NOT_MEASURED_FALLBACK,
  SCOPE_PLATFORM,
  SCOPE_UNTAGGED,
  ageSeconds,
  compressionRatio,
  confirmMatches,
  coverageLabel,
  coverageRank,
  coverageTone,
  engineLabel,
  fmtAgo,
  fmtBytes,
  fmtDuration,
  fmtHours,
  fmtRatio,
  fmtUntil,
  isDrill,
  isExternal,
  isRestorable,
  lastProvenRestore,
  measured,
  measuredTotalLabel,
  notMeasuredText,
  operationLabel,
  operationTone,
  parseRetention,
  posture,
  postureLabel,
  postureTone,
  prefixUsable,
  repositoryAdvice,
  repositoryState,
  repositoryStateFrom,
  restorableVerdict,
  restorePreview,
  retentionHint,
  retentionSentence,
  rpoVerdict,
  scopeLabel,
  shardSummary,
  snapshotStateLabel,
  snapshotTone,
  sortedEngines,
  storeLabel,
  targetMeaning,
  unmeasuredBytesText,
  verifyEvidence,
} from "./dataProtection.model";

const NOW = Date.parse("2026-09-04T12:00:00Z");

function engine(over: Partial<EngineCoverage> = {}): EngineCoverage {
  return {
    id: "opensearch", name: "Search snapshots",
    covered: "yes", covered_reason: "the daily policy has produced a successful copy",
    schedule: { enabled: true, cron: "30 1 * * *", governed_by_gui: true, detail: "" },
    last_attempt: { at: "2026-09-04T01:33:00Z", result: "success" },
    last_success_at: "2026-09-04T01:33:00Z",
    last_verified: { at: "2026-09-01T04:00:00Z", result: "pass" },
    size_bytes: 1610612736, size_detail: "",
    retention: { max_count: 14, max_age_days: 30, detail: "" },
    target: {
      kind: "offsite", immutable: true, immutable_detail: "", encrypted: true, encrypted_detail: "",
    },
    rpo_hours: 10.5, rpo_detail: "",
    ...over,
  };
}

function coverage(over: Partial<BackupCoverageView> = {}): BackupCoverageView {
  return { generated_at: "2026-09-04T12:00:00Z", engines: [engine()], external: [], ...over };
}

function snapshot(over: Partial<SnapshotView> = {}): SnapshotView {
  return {
    name: "netops-daily-20260904", state: "SUCCESS",
    indices: ["netops-syslog-2026.09.04"], index_count: 1,
    started_at: "2026-09-04T01:30:00Z", ended_at: "2026-09-04T01:33:00Z", duration_seconds: 180,
    shards: { total: 6, successful: 6, failed: 0 }, failures: [], failures_trimmed: 0,
    size_bytes: null, size_detail: "not measured on this read — pass ?sizes=1",
    restorable_verified: true, restorable_verified_at: "2026-09-01T04:00:00Z", restorable_detail: "",
    ...over,
  };
}

function repo(over: Partial<SnapshotRepositoryView> = {}): SnapshotRepositoryView {
  return { name: "netops-fs", registered: true, verified: true, verified_detail: "", ...over };
}

describe("measured — absence never becomes a number", () => {
  it("treats null and undefined as absent, carrying the server's detail", () => {
    expect(measured(null, "the volume is not mounted")).toEqual({
      measured: false, reason: "the volume is not mounted",
    });
    expect(measured(undefined)).toEqual({ measured: false, reason: NOT_MEASURED_FALLBACK });
  });

  it("keeps a real ZERO and a real FALSE as measured values (the whole point)", () => {
    expect(measured(0, "unused")).toEqual({ measured: true, value: 0 });
    expect(measured(false, "unused")).toEqual({ measured: true, value: false });
    expect(measured("", "unused")).toEqual({ measured: true, value: "" });
  });

  it("falls back to a generic reason when the server sent only whitespace", () => {
    expect(measured(null, "   ")).toEqual({ measured: false, reason: NOT_MEASURED_FALLBACK });
  });

  it("renders absence as a sentence that names the reason", () => {
    expect(notMeasuredText("no probe has run")).toBe("not measured — no probe has run");
  });
});

describe("formatting", () => {
  it("sizes in binary units", () => {
    expect(fmtBytes(512)).toBe("512 B");
    expect(fmtBytes(1536)).toBe("1.5 KiB");
    expect(fmtBytes(1610612736)).toBe("1.5 GiB");
  });

  it("durations step from seconds to days, and hours convert into them", () => {
    expect(fmtDuration(45)).toBe("45s");
    expect(fmtDuration(134)).toBe("2m 14s");
    expect(fmtDuration(11220)).toBe("3h 07m");
    expect(fmtDuration(367200)).toBe("4d 06h");
    expect(fmtHours(10.5)).toBe("10h 30m");
    expect(fmtHours(0)).toBe("0s");
  });

  it("ages and countdowns read from one supplied clock", () => {
    expect(ageSeconds("2026-09-04T11:00:00Z", NOW)).toBe(3600);
    expect(fmtAgo("2026-09-04T11:00:00Z", NOW)).toBe("1h 00m ago");
    expect(fmtUntil("2026-09-04T14:30:00Z", NOW)).toBe("in 2h 30m");
    expect(fmtUntil("2026-09-04T11:00:00Z", NOW)).toBe("now");
  });

  it("returns null rather than NaN for a stamp it cannot read", () => {
    expect(ageSeconds("not-a-time", NOW)).toBeNull();
    expect(fmtAgo(undefined, NOW)).toBeNull();
    expect(fmtUntil("", NOW)).toBeNull();
  });
});

describe("vocabulary — rows are named for the data, not the engine", () => {
  it("maps every shipped engine id to an operator label", () => {
    const labels = [
      "opensearch", "system_bundle", "clickhouse", "postgres",
      "victoriametrics", "secrets_tls", "device_configs",
    ].map((id) => engineLabel({ id }));
    expect(labels).toEqual([
      "Log & event search",
      "Correlix system bundle",
      "Flows & correlation history",
      "Application state",
      "Metrics history",
      "Secrets & TLS material",
      "Device configurations",
    ]);
    for (const l of labels) expect(l).not.toMatch(/ClickHouse|VictoriaMetrics|Postgre|Lucene/i);
  });

  it("falls back to the platform's own name for an id we do not know", () => {
    expect(engineLabel({ id: "future_store", name: "Ledger archive" })).toBe("Ledger archive");
    expect(engineLabel({ id: "future_store" })).toBe("future_store");
  });

  it("says what each destination class protects against, including none", () => {
    expect(targetMeaning("none")).toMatch(/no copy of this to restore from/);
    expect(targetMeaning("local")).toMatch(/one disk failure loses both/);
    expect(targetMeaning("remote")).toMatch(/off this host/);
    expect(targetMeaning("offsite")).toMatch(/separate failure domain/);
  });

  it("tones and labels the four coverage verdicts; unknown is never a pass", () => {
    expect([coverageTone("yes"), coverageLabel("yes")]).toEqual(["good", "Covered"]);
    expect([coverageTone("no"), coverageLabel("no")]).toEqual(["bad", "Not covered"]);
    expect([coverageTone("not_applicable"), coverageLabel("not_applicable")]).toEqual(["muted", "Not protected here"]);
    expect([coverageTone("unknown"), coverageLabel("unknown")]).toEqual(["warn", "Coverage unknown"]);
  });

  it("an engine the GUI does not govern is external", () => {
    expect(isExternal(engine())).toBe(false);
    expect(isExternal(engine({ schedule: { enabled: true, governed_by_gui: false, detail: "a host cron runs it" } }))).toBe(true);
    // No schedule at all is not the same as an external one.
    expect(isExternal(engine({ schedule: null }))).toBe(false);
  });
});

describe("bytes on disk — a figure nobody took never becomes a zero", () => {
  it("names a weighed store with the coverage matrix's own vocabulary", () => {
    expect([
      storeLabel("opensearch"), storeLabel("clickhouse"),
      storeLabel("victoriametrics"), storeLabel("postgres"),
    ]).toEqual([
      "Log & event search", "Flows & correlation history",
      "Metrics history", "Application state",
    ]);
    // The two stores the coverage matrix has no row for get their own names…
    expect(storeLabel("filestore")).toBe("Files kept on the platform host");
    expect(storeLabel("kafka")).toBe("Events queued on the bus");
    // …and an id we do not know appears under its own id rather than vanishing.
    expect(storeLabel("future_store")).toBe("future_store");
  });

  it("labels the platform scope, the shared untagged bucket and a tenant", () => {
    expect(scopeLabel(SCOPE_PLATFORM)).toBe("Platform");
    expect(scopeLabel(SCOPE_UNTAGGED)).toBe("Untagged (shared)");
    expect(scopeLabel("acme")).toBe("acme");
    expect(scopeLabel("  ")).toBe("Scope not reported");
  });

  it("a null byte count renders the server's reason, never 0 B and never a blank", () => {
    const detail = "not measured — the event bus does not expose its log directory to this service";
    const m = measured<number>(null, detail);
    expect(m.measured).toBe(false);
    const text = unmeasuredBytesText(detail);
    expect(text).toBe(detail);                       // verbatim, not doubled
    expect(text).not.toContain("0 B");
    expect(text.trim()).not.toBe("");
  });

  it("supplies the prefix for a reason that arrives without one, and never doubles it", () => {
    expect(unmeasuredBytesText("the search tier refused the size query: 403"))
      .toBe("not measured — the search tier refused the size query: 403");
    expect(unmeasuredBytesText("not measured — the probe deadline passed"))
      .toBe("not measured — the probe deadline passed");
    expect(unmeasuredBytesText("")).toBe(notMeasuredText(NOT_MEASURED_FALLBACK));
    expect(unmeasuredBytesText(null)).toBe(notMeasuredText(NOT_MEASURED_FALLBACK));
  });

  it("zero bytes IS a measurement and renders as 0 B", () => {
    const m = measured<number>(0, "read back from the store, which holds nothing yet");
    expect(m).toEqual({ measured: true, value: 0 });
    expect(fmtBytes(0)).toBe("0 B");
  });

  it("compression is null when the store reports no uncompressed size — never 1.0", () => {
    expect(compressionRatio({ bytes_on_disk: 1024, uncompressed_bytes: null })).toBeNull();
    expect(compressionRatio({ bytes_on_disk: 1024, uncompressed_bytes: undefined })).toBeNull();
    // A store that reports zero on either side has not measured a ratio either.
    expect(compressionRatio({ bytes_on_disk: 0, uncompressed_bytes: 4096 })).toBeNull();
    expect(compressionRatio({ bytes_on_disk: 1024, uncompressed_bytes: 0 })).toBeNull();
  });

  it("reports the measured ratio where both halves exist", () => {
    const r = compressionRatio({ bytes_on_disk: 1000, uncompressed_bytes: 4900 });
    expect(r).toBeCloseTo(4.9, 5);
    expect(fmtRatio(r as number)).toBe("4.9×");
  });

  it("calls the total a lower bound while any store contributes nothing", () => {
    expect(measuredTotalLabel(["kafka"])).toBe("measured total (lower bound)");
    expect(measuredTotalLabel(["kafka", "postgres"])).toBe("measured total (lower bound)");
    expect(measuredTotalLabel([])).toBe("measured total");
  });
});

describe("repository state — four states, four first actions", () => {
  it("derives the state from registration, verification and readability", () => {
    expect(repositoryState(repo(), false)).toBe("ok");
    expect(repositoryState(repo({ registered: false }), false)).toBe("unregistered");
    expect(repositoryState(repo({ verified: false }), false)).toBe("damaged");
    expect(repositoryState(repo({ verified: null }), false)).toBe("unverified");
    expect(repositoryState(repo(), true)).toBe("unreachable");
    expect(repositoryState(null, false)).toBe("unreachable");
  });

  it("prefers the more actionable fact when the two reads disagree", () => {
    // The list read failed, but the policy read still knows it is not registered.
    expect(repositoryStateFrom(null, repo({ registered: false }), true)).toBe("unregistered");
    // Nothing usable from either read is honestly "could not be read".
    expect(repositoryStateFrom(null, null, true)).toBe("unreachable");
    // A failed list read over a registered repository is still unreachable — a
    // policy read cannot prove the restore points are listable.
    expect(repositoryStateFrom(null, repo({ verified: null }), true)).toBe("unreachable");
    // A good list read decides on its own.
    expect(repositoryStateFrom(repo({ verified: false }), repo(), false)).toBe("damaged");
  });

  it("gives each broken state its own remedy and the procedure link", () => {
    expect(repositoryAdvice("unregistered", "")?.remedy).toMatch(/opensearch-init/);
    expect(repositoryAdvice("damaged", "")?.remedy).toMatch(/2026-08-27/);
    expect(repositoryAdvice("unverified", "")?.remedy).toMatch(/Registration is not restorability/);
    expect(repositoryAdvice("unregistered", "")?.doc).toBe(BACKUP_DOC);
    expect(repositoryAdvice("unverified", "")?.tone).toBe("warn");
    expect(repositoryAdvice("damaged", "")?.tone).toBe("bad");
  });

  it("passes the read failure through for an unreachable repository", () => {
    expect(repositoryAdvice("unreachable", "The service did not answer.")?.remedy)
      .toBe("The service did not answer.");
  });

  it("has nothing to say about a healthy repository", () => {
    expect(repositoryAdvice("ok", "")).toBeNull();
  });
});

describe("posture — the worst true statement wins, and the reason names it", () => {
  it("is unknown, never protected, when the coverage table could not be read", () => {
    const p = posture(null, "ok");
    expect(p.state).toBe("unknown");
    expect(p.reason).toMatch(/could not be read/);
  });

  it("a broken repository makes the whole platform unprotected", () => {
    for (const st of ["unregistered", "unreachable", "damaged"] as const) {
      expect(posture(coverage(), st).state).toBe("unprotected");
    }
  });

  it("names the uncovered engine rather than reporting a count", () => {
    const p = posture(coverage({
      engines: [engine(), engine({ id: "postgres", covered: "no", covered_reason: "no bundle has ever been written" })],
    }), "ok");
    expect(p.state).toBe("unprotected");
    expect(p.reason).toBe("Application state is not covered — no bundle has ever been written");
  });

  it("an unmeasurable engine is at risk, not protected", () => {
    const p = posture(coverage({
      engines: [engine({ id: "clickhouse", covered: "unknown", covered_reason: "the store did not answer" })],
    }), "ok");
    expect(p.state).toBe("at_risk");
    expect(p.reason).toMatch(/could not be measured — the store did not answer/);
  });

  it("a scheduled engine that never succeeded is at risk", () => {
    const p = posture(coverage({ engines: [engine({ last_success_at: undefined })] }), "ok");
    expect(p.state).toBe("at_risk");
    expect(p.reason).toMatch(/never produced a successful copy/);
  });

  it("recent copies with no PROVED restore are at risk, not protected", () => {
    expect(posture(coverage({ engines: [engine({ last_verified: null })] }), "ok").state).toBe("at_risk");
    expect(posture(coverage({ engines: [engine({ last_verified: { at: "x", result: "fail" } })] }), "ok").state).toBe("at_risk");
    // Registered but unverified repository is the same class of doubt.
    expect(posture(coverage(), "unverified").state).toBe("at_risk");
  });

  it("only a covered, recently-successful, PROVED platform is protected", () => {
    const p = posture(coverage(), "ok");
    expect(p.state).toBe("protected");
    expect(p.reason).toMatch(/at least one restore has been proved/);
  });

  it("a matrix of only not-applicable rows is unknown, not protected", () => {
    expect(posture(coverage({ engines: [engine({ covered: "not_applicable" })] }), "ok").state).toBe("unknown");
  });

  it("maps each state to a tone and a word", () => {
    expect([postureTone("protected"), postureLabel("protected")]).toEqual(["good", "Protected"]);
    expect([postureTone("at_risk"), postureLabel("at_risk")]).toEqual(["warn", "At risk"]);
    expect([postureTone("unprotected"), postureLabel("unprotected")]).toEqual(["bad", "Unprotected"]);
    expect([postureTone("unknown"), postureLabel("unknown")]).toEqual(["muted", "Posture unknown"]);
  });
});

describe("last proven restorable copy", () => {
  it("takes the newest PASS across engines and names which one", () => {
    const m = lastProvenRestore(coverage({
      engines: [
        engine({ id: "opensearch", last_verified: { at: "2026-09-01T04:00:00Z", result: "pass" } }),
        engine({ id: "postgres", last_verified: { at: "2026-09-03T04:00:00Z", result: "pass" } }),
      ],
    }));
    expect(m).toEqual({ measured: true, value: { at: "2026-09-03T04:00:00Z", engine: "Application state" } });
  });

  it("ignores a FAILED verification — a failed drill is not a proof", () => {
    const m = lastProvenRestore(coverage({ engines: [engine({ last_verified: { at: "2026-09-03T04:00:00Z", result: "fail" } })] }));
    expect(m).toEqual({ measured: false, reason: "no restore has ever been proved on this platform" });
  });
});

describe("recovery-point objective", () => {
  it("reports the achieved age and names the missing objective, never assuming one", () => {
    const v = rpoVerdict(engine({ rpo_hours: 10.5 }));
    expect(v.state).toBe("achieved_only");
    expect(v).toMatchObject({ text: "last good copy 10h 30m old" });
  });

  it("compares against the SCHEDULE-derived target, and says that is what it used", () => {
    expect(rpoVerdict(engine({ rpo_hours: 10, rpo_target_hours: 24 })))
      .toEqual({ state: "met", text: "10h 00m against a 1d 00h scheduled objective" });
    expect(rpoVerdict(engine({ rpo_hours: 48, rpo_target_hours: 24 })).state).toBe("missed");
  });

  // S4 (2026-09-04). The server now publishes TWO numbers and they are not the
  // same claim: rpo_target_hours is measured from a real cron, while
  // rpo_objective_hours is declared policy. Evidence beats intent, so the
  // schedule wins when it exists — and the rendered text has to NAME which one
  // was used, or an operator reads a platform-invented number as compliance.
  it("falls back to the DECLARED objective when no schedule is in force, and labels it", () => {
    expect(rpoVerdict(engine({ rpo_hours: 10, rpo_objective_hours: 24 })))
      .toEqual({ state: "met", text: "10h 00m against a 1d 00h declared objective" });
    expect(rpoVerdict(engine({ rpo_hours: 48, rpo_objective_hours: 24 })).state).toBe("missed");
  });

  it("prefers the schedule-derived target over the declared objective when both exist", () => {
    // Achieved 30h: inside the declared 48h, outside the scheduled 24h. The
    // verdict must be MISSED — measured cadence is the stronger claim, and
    // reporting "met" off the looser declared number would be exactly the
    // flattering arithmetic this page exists to remove.
    expect(rpoVerdict(engine({ rpo_hours: 30, rpo_target_hours: 24, rpo_objective_hours: 48 })))
      .toEqual({ state: "missed", text: "1d 06h against a 1d 00h scheduled objective" });
  });

  it("judges the 0h custody objective as met only at 0", () => {
    expect(rpoVerdict(engine({ rpo_hours: 0, rpo_objective_hours: 0 })))
      .toEqual({ state: "met", text: "0s against a 0s declared objective" });
    expect(rpoVerdict(engine({ rpo_hours: 1, rpo_objective_hours: 0 })).state).toBe("missed");
  });

  it("is unmeasured, never a pass, when there is no good copy to date", () => {
    expect(rpoVerdict(engine({ rpo_hours: null, rpo_detail: "no successful copy exists" })))
      .toEqual({ state: "unmeasured", reason: "no successful copy exists" });
  });

  it("counts an achieved 0 as measured", () => {
    expect(rpoVerdict(engine({ rpo_hours: 0, rpo_target_hours: 24 })).state).toBe("met");
  });
});

describe("restore points", () => {
  it("tones and sentence-cases each state", () => {
    expect([snapshotTone("SUCCESS"), snapshotStateLabel("SUCCESS")]).toEqual(["good", "Success"]);
    expect([snapshotTone("IN_PROGRESS"), snapshotStateLabel("IN_PROGRESS")]).toEqual(["muted", "In progress"]);
    expect([snapshotTone("PARTIAL"), snapshotStateLabel("PARTIAL")]).toEqual(["warn", "Partial"]);
    expect([snapshotTone("FAILED"), snapshotStateLabel("FAILED")]).toEqual(["bad", "Failed"]);
    expect(snapshotStateLabel("")).toBe("State not reported");
  });

  it("only a completed copy is restorable", () => {
    expect(isRestorable(snapshot())).toBe(true);
    expect(isRestorable(snapshot({ state: "PARTIAL" }))).toBe(true);
    expect(isRestorable(snapshot({ state: "IN_PROGRESS" }))).toBe(false);
    expect(isRestorable(snapshot({ state: "FAILED" }))).toBe(false);
  });

  it("restorability has THREE outcomes — never-probed is not a pass", () => {
    expect(restorableVerdict(snapshot()).state).toBe("verified");
    expect(restorableVerdict(snapshot({ restorable_verified: false })).state).toBe("failed");
    const never = restorableVerdict(snapshot({
      restorable_verified: null, restorable_detail: "no probe has ever run on this restore point",
    }));
    expect(never).toEqual({ state: "never", detail: "no probe has ever run on this restore point" });
  });

  it("summarises shard failures only when there are any", () => {
    expect(shardSummary(snapshot())).toBeNull();
    expect(shardSummary(snapshot({ shards: { total: 6, successful: 4, failed: 2 } })))
      .toBe("2 of 6 shards failed");
  });
});

describe("restore wizard rules", () => {
  it("the shipped default puts the copy beside the live data", () => {
    expect(DEFAULT_RESTORE_PREFIX).toBe("restored-");
    expect(restorePreview("netops-syslog-2026.09.01", DEFAULT_RESTORE_PREFIX))
      .toBe("restored-netops-syslog-2026.09.01");
  });

  it("refuses an empty prefix — that is an overwrite wearing a rename's clothes", () => {
    expect(restorePreview("abc", "")).toBeNull();
    expect(restorePreview("abc", "   ")).toBeNull();
    expect(prefixUsable(["a", "b"], "")).toBe(false);
  });

  it("refuses a prefix the engine itself would reject", () => {
    for (const bad of ["a b", "a/b", "a*b", "a?b", 'a"b', "a<b", "a|b", "a,b", "a#b", "a:b", "_x", "-x", "+x"]) {
      expect(restorePreview("idx", bad), bad).toBeNull();
    }
    expect(prefixUsable([], "restored-")).toBe(false);  // nothing selected is not usable either
    expect(prefixUsable(["idx"], "restored-")).toBe(true);
  });

  it("type-to-confirm is exact after trimming, and never satisfied by an empty target", () => {
    expect(confirmMatches("  netops-daily-01  ", "netops-daily-01")).toBe(true);
    expect(confirmMatches("netops-daily-0", "netops-daily-01")).toBe(false);
    expect(confirmMatches("NETOPS-DAILY-01", "netops-daily-01")).toBe(false);
    expect(confirmMatches("", "")).toBe(false);
  });
});

describe("operations feed", () => {
  it("names each kind in the operator's words and tones each state", () => {
    expect(operationLabel("snapshot_create")).toBe("Take restore point");
    expect(operationLabel("snapshot_delete")).toBe("Delete restore point");
    expect(operationLabel("snapshot_restore")).toBe("Restore");
    expect(operationLabel("snapshot_verify")).toBe("Restore drill");
    expect(operationLabel("something_new")).toBe("something_new");
    expect([operationTone("succeeded"), operationTone("failed"), operationTone("running")])
      .toEqual(["good", "bad", "warn"]);
    expect(isDrill("snapshot_verify")).toBe(true);
    expect(isDrill("snapshot_create")).toBe(false);
  });

  it("reports the drill's evidence as document counts, not as a claim", () => {
    expect(verifyEvidence({ verify: { source_docs: 1200, restored_docs: 1200, match: true, index: "netops-flows" } }))
      .toBe("1200 of 1200 documents matched on netops-flows");
    expect(verifyEvidence({ verify: { source_docs: 1200, restored_docs: 1198, match: false, index: "netops-flows" } }))
      .toMatch(/they do not match/);
    expect(verifyEvidence({})).toBeNull();
  });
});

describe("coverage ordering — gaps first, deliberate exclusions last", () => {
  it("ranks uncovered, unknown, never-succeeded, healthy, not-applicable", () => {
    expect(coverageRank(engine({ covered: "no" }))).toBe(0);
    expect(coverageRank(engine({ covered: "unknown" }))).toBe(1);
    expect(coverageRank(engine({ covered: "yes", last_success_at: undefined }))).toBe(2);
    expect(coverageRank(engine({ covered: "yes" }))).toBe(3);
    expect(coverageRank(engine({ covered: "not_applicable" }))).toBe(4);
  });

  it("sorts a mixed matrix into that order without mutating the input", () => {
    const input: EngineCoverage[] = [
      engine({ id: "secrets_tls" }),
      engine({ id: "device_configs", covered: "not_applicable" }),
      engine({ id: "clickhouse", covered: "no" }),
      engine({ id: "postgres", covered: "unknown" }),
    ];
    const frozen = input.map((e) => e.id);
    expect(sortedEngines(input).map((e) => e.id)).toEqual([
      "clickhouse", "postgres", "secrets_tls", "device_configs",
    ]);
    expect(input.map((e) => e.id)).toEqual(frozen);
  });
});

// ── bundle retention (the one control on this page that deletes copies) ─────
//
// Three states, never two. A blank box, a deliberate 0 and a chosen count mean
// three different things to the host, and the sentence under the field is the
// only place an operator learns which one is in force.

describe("retentionSentence", () => {
  it("names the host's own fallback when nothing is stored", () => {
    expect(retentionSentence(null)).toBe("Not set. The host keeps 7.");
    expect(retentionSentence(undefined)).toBe("Not set. The host keeps 7.");
  });

  it("says what 0 costs rather than rendering it as 'keep nothing'", () => {
    expect(retentionSentence(0)).toBe("Pruning off. Every copy kept.");
  });

  it("states the count for a chosen retention", () => {
    expect(retentionSentence(1)).toBe("The host keeps the newest copy only.");
    expect(retentionSentence(30)).toBe("The host keeps the 30 newest copies.");
  });

  it("never renders a stored 0 as unset, or unset as 0", () => {
    expect(retentionSentence(0)).not.toBe(retentionSentence(null));
  });
});

describe("parseRetention", () => {
  it("reads an empty box as not-set, never as 0", () => {
    expect(parseRetention("")).toEqual({ ok: true, value: null });
    expect(parseRetention("   ")).toEqual({ ok: true, value: null });
    expect(parseRetention("0")).toEqual({ ok: true, value: 0 });
  });

  it("accepts whole counts inside the server's range", () => {
    expect(parseRetention("7")).toEqual({ ok: true, value: 7 });
    expect(parseRetention("365")).toEqual({ ok: true, value: 365 });
  });

  it("rejects what the server would refuse, instead of sending it", () => {
    for (const bad of ["-1", "1.5", "366", "seven", "7d", "1e3"]) {
      expect(parseRetention(bad), bad).toEqual({ ok: false });
    }
  });
});

describe("retentionHint", () => {
  it("says plainly that clearing a stored retention does nothing", () => {
    expect(retentionHint(null, 21)).toBe("Clearing is not a change. Saving keeps 21.");
    expect(retentionHint(undefined, 0)).toBe("Clearing is not a change. Saving keeps 0.");
  });

  it("falls through to the plain sentence when nothing is stored either", () => {
    expect(retentionHint(null, null)).toBe("Not set. The host keeps 7.");
    expect(retentionHint(30, 21)).toBe("The host keeps the 30 newest copies.");
  });
});
