// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { join, dirname, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { stripComments } from "./lib/copyScan";

// ── THE RAW-ERROR LEAK RATCHET (tracker 293) ────────────────────────────────
//
// `services/api.ts` throws `new Error(\`${status} ${statusText}: ${body}\`)`.
// Rendering that value's `.message` puts the api envelope on an operator's
// screen verbatim:
//
//     502 Bad Gateway: {"error":"Get http://api:8080/auth/permissions:
//     dial tcp 172.18.0.9:8080: connect: connection refused"}
//
// It names internal hosts and container IPs, and it tells the operator nothing
// they can do. `lib/errors.ts` exists to convert it: `operatorError(e, fallback)`
// keeps a server sentence worth reading and replaces developer text with the
// caller's own description of what failed. `httpFailure(e)` is the other half,
// for the rare caller that must branch on the STATUS (a 409 is a contract, not
// a sentence) — status for the code, `operatorError` for the screen.
//
// WHY THIS FILE EXISTS AND NOT JUST A FIX. The class has been fixed three times
// (the BGP panels, RcaVerdictFeedback, the API-keys card) and came back each
// time, because nothing stopped the next one being written. Tracker 293 is
// explicit that the guard, not the sweep, is the deliverable. There is no
// ESLint in this project (package.json: vitest, tsc, ui:check), so the
// mechanism that actually runs in the gate is a structural test.
//
// HOW IT WORKS — a RATCHET, not a denylist. `DEBT` below is the exact number of
// unconverted sites left in each file on the day of the sweep. The three
// assertions are:
//
//   1. a file NOT in DEBT must have ZERO — this is what fails when someone
//      writes a new `setErr((e as Error).message)` in swept code;
//   2. a file in DEBT must not be ABOVE its number — this is what fails when
//      someone adds one to a file that still has debt;
//   3. a file in DEBT must not be BELOW its number — when you convert some,
//      lower the number (or delete the row at zero) in the same change.
//
// (3) is what makes the list shrink instead of rot. A stale entry is a lie
// about the size of the problem, which is how the 263 KB tracker happened.
//
// SCOPE IS CODE, NOT COPY. Comments are blanked first (via lib/copyScan, shared
// with copyVoice.test.ts) so the paragraph you are reading does not trip the
// scan. Test files are excluded: a test that constructs and inspects an Error
// is doing its job.

/**
 * The two shapes the class is written in. Both name a caught value and pull
 * `.message` straight off it, which is exactly the step `operatorError` exists
 * to replace.
 */
const RAW_MESSAGE: readonly RegExp[] = [
  // `(e as Error).message`, `(err as any).message`, `(ex as unknown).message`
  /\(\s*[A-Za-z_$][\w$]*\s+as\s+(?:Error|any|unknown)\s*\)\s*\.\s*message/g,
  // `e instanceof Error ? e.message : String(e)`
  /instanceof\s+Error\s*\?\s*[A-Za-z_$][\w$]*\s*\.\s*message/g,
];

/**
 * The ONE place allowed to read a raw `.message`: the converter itself. Every
 * other reader goes through it. An addition here needs a reason as good as
 * this one, which is to say: it must be the implementation of the rule, not an
 * exception to it.
 */
const CONVERTER = "lib/errors.ts";

/**
 * Unconverted sites per file, counted 2026-09-13 after the `tabs/admin.tsx`
 * (52 sites) and `components/Wizard.tsx` (1 site, the shared submit path for
 * every wizard in the product) sweep.
 *
 * These are DEBT, not exemptions. Each number may only go DOWN, and a file
 * leaves the list when it reaches zero. If you are touching one of these files
 * for another reason, converting its sites is a welcome part of the change —
 * lower the number here and the guard will agree with you.
 */
const DEBT: ReadonlyMap<string, number> = new Map([
  ["components/ChangePasswordCard.tsx", 1],
  ["components/board/panels.tsx", 1],
  ["components/rca/RcaAskAi.tsx", 1],
  ["pages/ActionQueue.tsx", 1],
  ["pages/CloudLogs.tsx", 1],
  ["pages/CommandCenter.tsx", 1],
  ["pages/ComplianceMonitoring.tsx", 1],
  ["pages/DataSources.tsx", 1],
  ["pages/DeviceMonitoring.tsx", 4],
  ["pages/Devices.tsx", 4],
  ["pages/Events.tsx", 1],
  ["pages/InterfacePerformance.tsx", 1],
  ["pages/Login.tsx", 2],
  ["pages/NetworkPath.tsx", 1],
  ["pages/NewMonitor.tsx", 1],
  ["pages/Quality.tsx", 1],
  ["pages/Reports.tsx", 8],
  ["pages/ResourceDetail.tsx", 1],
  ["pages/SystemNetwork.tsx", 2],
  ["pages/ThreatDetection.tsx", 2],
  ["pages/VulnerabilityManagement.tsx", 1],
  ["pages/WanCircuits.tsx", 1],
  ["pages/appobs/GovernanceSettings.tsx", 10],
  ["pages/appobs/MonitorsSettings.tsx", 2],
  ["pages/appobs/ResourceMetricsPanel.tsx", 1],
  ["pages/appobs/SloCard.tsx", 2],
  ["pages/appobs/assign.ts", 1],
  ["pages/bgp/LiveFeedPanel.tsx", 1],
  ["pages/config/ConfigDrift.tsx", 1],
  ["pages/config/DeviceConfigPanel.tsx", 1],
  ["pages/experience/ExperienceIncidentView.tsx", 1],
  ["pages/experience/state.ts", 1],
  ["pages/igp/igpModel.ts", 1],
  ["pages/licence.model.ts", 1],
  ["pages/security/Exposures.tsx", 1],
  ["pages/security/SavedViews.tsx", 2],
  ["pages/security/SecurityRules.tsx", 1],
  ["pages/telemetry/TelemetryCoverage.tsx", 3],
  ["pages/troubleshoot/InvestigationPage.tsx", 1],
  ["pages/troubleshoot/IrisLane.tsx", 1],
  ["services/api.debug.ts", 2],
  ["tabs/AccessExplorer.tsx", 1],
  ["tabs/AdminSsoIdp.tsx", 4],
  ["tabs/Collectors.tsx", 3],
  ["tabs/Flows.tsx", 6],
  ["tabs/Incidents.tsx", 3],
  ["tabs/Logs.tsx", 5],
  ["tabs/MetricsExplorer.tsx", 1],
  ["tabs/Opsis.tsx", 8],
  ["tabs/Rules.tsx", 1],
  ["tabs/SavedSearches.tsx", 2],
  ["tabs/Settings.tsx", 4],
  ["tabs/SnmpConfigGenerator.tsx", 1],
  ["tabs/SnmpCredentials.tsx", 3],
  ["tabs/SourceOfTruth.tsx", 3],
  ["tabs/TransportSecurity.tsx", 2],
  ["tabs/Tunnels.tsx", 1],
]);

/** The headline number, so a reviewer sees the size of the class at a glance. */
const DEBT_TOTAL = 120;

const HOW_TO_FIX =
  "Convert it: `setErr(operatorError(e, \"<what we were trying to do>.\"))` from lib/errors.ts. " +
  "If you need the STATUS to branch on, `httpFailure(e)` gives it to you — the status is for the " +
  "code, operatorError is for the screen.";

const SRC = dirname(fileURLToPath(import.meta.url));

function sourceFiles(dir: string, out: string[] = []): string[] {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, e.name);
    if (e.isDirectory()) {
      if (e.name === "node_modules") continue;
      if (e.name === "mock") continue;   // vendor JSON fixtures
      if (e.name === "test") continue;   // test factories, not shipped code
      sourceFiles(full, out);
      continue;
    }
    if (!/\.tsx?$/.test(e.name)) continue;
    if (e.name.includes(".test.")) continue;
    if (e.name === "vite-env.d.ts") continue;
    out.push(full);
  }
  return out;
}

/** file (relative to src/, "/"-joined) → the lines holding a raw read. */
function scan(): Map<string, string[]> {
  const found = new Map<string, string[]>();
  for (const file of sourceFiles(SRC)) {
    const rel = relative(SRC, file).split(sep).join("/");
    if (rel === CONVERTER) continue;
    const lines = stripComments(readFileSync(file, "utf8")).split("\n");
    const hits: string[] = [];
    lines.forEach((line, i) => {
      for (const re of RAW_MESSAGE) {
        re.lastIndex = 0;
        const n = (line.match(new RegExp(re.source, "g")) ?? []).length;
        for (let k = 0; k < n; k++) hits.push(`${rel}:${i + 1}  ${line.trim()}`);
      }
    });
    if (hits.length) found.set(rel, hits);
  }
  return found;
}

describe("the api envelope never reaches an operator's screen (tracker 293)", () => {
  const found = scan();

  it("a file with no raw-error debt has none — a new one cannot be written", () => {
    const fresh: string[] = [];
    for (const [rel, hits] of found) if (!DEBT.has(rel)) fresh.push(...hits);
    expect(
      fresh,
      `A raw error message is being rendered in a file that was clean.\n${HOW_TO_FIX}\n\n${fresh.join("\n")}`,
    ).toEqual([]);
  });

  it("no file adds to its existing debt", () => {
    const grew: string[] = [];
    for (const [rel, allowed] of DEBT) {
      const hits = found.get(rel) ?? [];
      if (hits.length > allowed) {
        grew.push(`${rel}: ${hits.length} raw reads, but this file is capped at ${allowed}`);
      }
    }
    expect(grew, `The raw-error debt grew.\n${HOW_TO_FIX}\n\n${grew.join("\n")}`).toEqual([]);
  });

  it("the debt list is not stale — a converted site is struck off", () => {
    const shrank: string[] = [];
    for (const [rel, allowed] of DEBT) {
      const n = (found.get(rel) ?? []).length;
      if (n < allowed) {
        shrank.push(
          n === 0
            ? `${rel} has none left — delete its row from DEBT in errorEnvelope.test.ts.`
            : `${rel} is down to ${n} — lower its DEBT number from ${allowed} to ${n}.`,
        );
      }
    }
    expect(
      shrank,
      `Good news, and the list has to say so: an out-of-date DEBT entry understates the fix and overstates the problem.\n\n${shrank.join("\n")}`,
    ).toEqual([]);
  });

  it("reports the size of the class, so shrinking it is visible", () => {
    let total = 0;
    for (const hits of found.values()) total += hits.length;
    expect(
      total,
      `The raw-error count moved. If you converted sites, lower DEBT_TOTAL to ${total} with the per-file numbers.`,
    ).toBe(DEBT_TOTAL);
  });
});

// A guard that cannot fail is worse than none, so the matcher is tested on the
// exact strings the sweep removed and on the shapes that must NOT trip it.
describe("the matcher itself", () => {
  const matches = (s: string): boolean => RAW_MESSAGE.some((re) => new RegExp(re.source).test(s));

  it("catches every shape the sweep removed", () => {
    expect(matches('setErr((e as Error).message);')).toBe(true);
    expect(matches('if (alive) setErr((e as Error).message);')).toBe(true);
    expect(matches('.catch((e) => setMsg((e as Error).message))')).toBe(true);
    expect(matches('setErr((e as Error).message.replace(/^\\d+[^:]*:\\s*/, ""));')).toBe(true);
    expect(matches('setMsg({ kind: "err", text: (err as Error).message });')).toBe(true);
    expect(matches('flash("cp", (e as Error).message);')).toBe(true);
    expect(matches('window.alert(`Save failed: ${(err as Error).message}`);')).toBe(true);
    expect(matches('setError(e instanceof Error ? e.message : String(e));')).toBe(true);
    expect(matches('const msg = (e as any).message;')).toBe(true);
  });

  it("leaves the fixed form and ordinary code alone", () => {
    expect(matches('setErr(operatorError(e, "That key was not revoked."));')).toBe(false);
    expect(matches('const f = httpFailure(e); if (f?.status === 409) setForce(true);')).toBe(false);
    expect(matches('setErr(result.message);')).toBe(false);
    expect(matches('const m = alert.message;')).toBe(false);
    expect(matches('type X = { message: string };')).toBe(false);
  });
});
