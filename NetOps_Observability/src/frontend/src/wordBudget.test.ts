import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync, existsSync } from "node:fs";
import { join, dirname, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { stripComments } from "./lib/copyScan";

// ── WORD BUDGET (the "fewer words, Iris explains" ratchet, 2026-09-06) ───────
//
// Programme: docs/design/UI_WORDS_IRIS_EXPLAINS_2026-09-06.md (tracker 270).
// Owner direction, verbatim: "make sure remove the jargon and lots of words
// across the site. Remove so much of explanation, instead train the Iris AI to
// answer those questions. Less words UI experience looks clean."
//
// A screen states facts and offers actions. It does not teach. This guard is the
// mechanical half of that: it counts the words in the four places prose creeps
// back in — headings, captions, explanatory notes and empty states — and fails
// when they exceed the design doc's budgets.
//
// SIBLING OF copyVoice.test.ts. That guard asks "is this the right WORD"; this
// one asks "are there too MANY". Both read through lib/copyScan so "what a
// person can read" means the same thing in both, and both are deliberately blind
// to identifiers, field names and comments.
//
// THE ALLOWLIST IS DEBT, NOT PERMISSION. Every entry is a file that was over
// budget on the day the guard landed and has not been swept yet. It records the
// EXACT number of breaches, so:
//   · adding one → the test fails (new debt cannot hide behind old debt);
//   · removing one → the test fails until the number is lowered (the ratchet);
//   · sweeping a file to zero → the entry must be DELETED (a stale-entry test).
// The sweep order is in the design doc. Done = no entry for the file.

const SRC = dirname(fileURLToPath(import.meta.url));

// ── budgets (docs/design/UI_WORDS_IRIS_EXPLAINS_2026-09-06.md §"Word budgets") ─
export const BUDGET = {
  /** Page / section heading — h1, h2. */
  heading: 4,
  /** Card heading — h3…h6. */
  cardHeading: 3,
  /** KPI / section caption under a number or a title. */
  caption: 3,
  /** Explanatory note (`mini-meta`, `*-note`, `*-sub`). */
  note: 12,
  /** Empty state (the action beside it is not counted — it is a control). */
  empty: 8,
} as const;

export type BudgetKind = keyof typeof BUDGET;

/**
 * At most ONE note per card. "Card" is not a thing a regex can see, so the
 * proxy is the region between two headings: every card in this codebase opens
 * with one. A second note inside the same region is a breach of its own.
 */
const MAX_NOTES_PER_REGION = 1;

// ── which classes and props carry which budget ───────────────────────────────
//
// Keyed on the conventions this codebase actually uses. `mini-meta` is the
// app-wide explanatory-note class; `-note`/`-sub` are the per-page spellings of
// the same thing; `-caption`/`-cap` sit under a number or a section title;
// `-empty` is the "nothing here" state.
const NOTE_CLASS = /(?:^|[\s"'`])(?:mini-meta|[a-z][a-z0-9]*(?:-[a-z0-9]+)*-(?:note|sub))(?=$|[\s"'`])/;
const CAPTION_CLASS = /(?:^|[\s"'`])[a-z][a-z0-9]*(?:-[a-z0-9]+)*-(?:caption|cap)(?=$|[\s"'`])/;
const EMPTY_CLASS = /(?:^|[\s"'`])[a-z][a-z0-9]*(?:-[a-z0-9]+)*-empty(?=$|[\s"'`])/;

/** Props that ARE a caption wherever they appear (`interp=`, `caption:`). */
const CAPTION_PROP = /\b(?:interp|caption)\s*[:=]/;

/**
 * Attributes whose value is never copy. Their values are removed before spans
 * are read, so a long className or href can never be counted as words — and so
 * `className="cc-kpi-i"` does not become its own three-word caption.
 */
const NON_COPY_ATTR = new RegExp(
  "\\b(?:className|class|key|id|htmlFor|href|src|to|style|role|type|name|value|data-testid|data-topic|data-lane|" +
  "aria-labelledby|aria-controls|aria-describedby|width|height|viewBox|d|fill|stroke|transform|" +
  "encType|method|autoComplete|inputMode|pattern|rel|target|as|hue)\\s*=\\s*(?:\"[^\"]*\"|'[^']*'|`[^`]*`|\\{[^{}]*\\})",
  "g",
);

/** Heading tags → their budget. */
const HEADING_RE = /<(h[1-6])\b[^>]*>([\s\S]*?)<\/\1>/g;

/**
 * The words a reader actually sees in a chunk of JSX/text: expressions are
 * dropped (they are code, and their rendered value is not knowable here),
 * entities and punctuation-only tokens do not count.
 */
export function copyWords(raw: string): string[] {
  const text = raw
    .replace(/\{[^{}]*\}/g, " ")            // JSX expressions
    .replace(/<[^<>]*>/g, " ")              // nested tags
    .replace(/&[a-z]+;|&#\d+;/gi, " ")      // entities
    .replace(/\\n|\\t/g, " ");
  return text.match(/[A-Za-z0-9][A-Za-z0-9'’./%-]*/g) ?? [];
}

/** The readable spans of a line, with non-copy attribute values removed. */
function copySpans(line: string): string[] {
  const l = line.replace(NON_COPY_ATTR, " ");
  const spans: string[] = [];
  for (const m of l.matchAll(/"([^"]*)"|'([^']*)'|`([^`]*)`/g)) spans.push(m[1] ?? m[2] ?? m[3] ?? "");
  for (const m of l.matchAll(/>([^<>{}]+)</g)) spans.push(m[1]);
  return spans;
}

export interface Breach {
  line: number;
  kind: BudgetKind | "note-count";
  words: number;
  budget: number;
  text: string;
}

function fmtBreach(label: string, b: Breach): string {
  return b.kind === "note-count"
    ? `${label}:${b.line} — note-count: a card may carry ${MAX_NOTES_PER_REGION} explanatory note; this is note #${b.words} · ${JSON.stringify(b.text.slice(0, 70))}`
    : `${label}:${b.line} — ${b.kind}: ${b.words} words, budget ${b.budget} · ${JSON.stringify(b.text.slice(0, 70))}`;
}

/**
 * Every budget breach in one shipped source file.
 *
 * Line-oriented on purpose: a breach must name a line an author can open. The
 * one exception is headings, which are matched across the whole file so a
 * heading split over two lines is still counted (and its line is recovered from
 * the match offset).
 */
export function scanWordBudget(source: string): Breach[] {
  const text = stripComments(source);
  const out: Breach[] = [];

  // ── headings ──────────────────────────────────────────────────────────────
  const lineOf = (offset: number) => text.slice(0, offset).split("\n").length;
  for (const m of text.matchAll(HEADING_RE)) {
    const kind: BudgetKind = m[1] === "h1" || m[1] === "h2" ? "heading" : "cardHeading";
    const words = copyWords(m[2]);
    if (words.length > BUDGET[kind]) {
      out.push({ line: lineOf(m.index ?? 0), kind, words: words.length, budget: BUDGET[kind], text: words.join(" ") });
    }
  }

  // ── captions, notes, empty states ─────────────────────────────────────────
  const lines = text.split("\n");
  // Region = "since the last heading" — the proxy for "this card" (see above).
  let notesInRegion = 0;
  lines.forEach((line, i) => {
    if (/<h[1-6]\b/.test(line)) notesInRegion = 0;

    const kinds: BudgetKind[] = [];
    if (CAPTION_CLASS.test(line) || CAPTION_PROP.test(line)) kinds.push("caption");
    if (NOTE_CLASS.test(line)) kinds.push("note");
    if (EMPTY_CLASS.test(line)) kinds.push("empty");
    if (kinds.length === 0) return;

    // The text may sit on the next line when the element opens alone.
    let spans = copySpans(line);
    if (spans.every((s) => copyWords(s).length === 0) && i + 1 < lines.length && !/[<{]/.test(lines[i + 1])) {
      spans = spans.concat(lines[i + 1]);
    }

    for (const kind of kinds) {
      let carried = false;
      for (const span of spans) {
        const words = copyWords(span);
        if (words.length === 0) continue;
        carried = true;
        if (words.length > BUDGET[kind]) {
          out.push({ line: i + 1, kind, words: words.length, budget: BUDGET[kind], text: words.join(" ") });
        }
      }
      if (kind === "note" && carried) {
        notesInRegion += 1;
        if (notesInRegion > MAX_NOTES_PER_REGION) {
          out.push({ line: i + 1, kind: "note-count", words: notesInRegion, budget: MAX_NOTES_PER_REGION, text: spans.join(" ") });
        }
      }
    }
  });

  return out;
}

// ── the sweep debt ───────────────────────────────────────────────────────────
//
// Seeded 2026-09-06 with every file that was over budget on the day the guard
// landed (92 files, 401 breaches); sweep 1 removed 14 of them (78 files, 353
// breaches), sweep 2 (Security + Data Protection) removed 16 more (62 files,
// 312 breaches), and sweep 3 (Administration · Licence · Registries · Cloud
// ingest · Platform tools) removed 6 more, and sweep 4 (Topology · WAN · Wireless
// · Device detail · Routing protocols · Path trace · New monitor) removed 8 more,
// leaving 48 files and 202 breaches. Sweep 5 removed the other 47 — BGP, the RCA
// workspace, the account and tenant gates, Reports, the reliability scorecard,
// the legacy troubleshooting board, TAC, the tabs (flows, log search,
// correlations, collectors, credentials, the Iris drawer), device inventory,
// telemetry coverage and the app-observability pages — so ONE file is left:
// pages/iris/Knowledge.tsx, which was being rewritten in another change while
// sweep 5 ran and is the next (and last) sweep. The number is that file's breach
// count, so the whole backlog is visible in one diff and each sweep is a
// deletion from this list. Sweep order and the "done" definition are in the
// design doc; a swept file loses its line here.
export const ALLOW: Readonly<Record<string, number>> = Object.freeze(
  JSON.parse(readFileSync(join(SRC, "wordBudget.allow.json"), "utf-8")) as Record<string, number>,
);

function sourceFiles(dir: string, out: string[] = []): string[] {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, e.name);
    if (e.isDirectory()) {
      if (e.name === "node_modules" || e.name === "mock" || e.name === "test") continue;
      sourceFiles(full, out);
      continue;
    }
    if (!/\.tsx?$/.test(e.name)) continue;
    if (e.name.includes(".test.")) continue;
    if (e.name === "rcaPreview.tsx") continue;   // standalone static preview harness
    if (e.name === "vite-env.d.ts") continue;
    out.push(full);
  }
  return out;
}

const rel = (f: string) => relative(SRC, f).split(sep).join("/");

describe("UI word budget — a screen states facts, it does not teach", () => {
  const files = sourceFiles(SRC);
  const counted = new Map<string, Breach[]>(
    files.map((f) => [rel(f), scanWordBudget(readFileSync(f, "utf-8"))]),
  );

  it("finds source files to scan (a broken walk must not pass silently)", () => {
    expect(files.length).toBeGreaterThan(200);
  });

  it("no shipped file exceeds its budgets beyond the recorded debt", () => {
    const over: string[] = [];
    for (const [label, breaches] of counted) {
      const allowed = ALLOW[label] ?? 0;
      if (breaches.length > allowed) {
        over.push(
          `${label}: ${breaches.length} breach(es), ${allowed} allowed\n` +
          breaches.map((b) => "    " + fmtBreach(label, b)).join("\n"),
        );
      }
    }
    expect(
      over,
      "over budget — shorten the copy, or move the explanation into " +
      "src/backend/ai/skills/explain/<topic>.md and put an <AskIris topic=…/> where it was:\n" +
      over.join("\n"),
    ).toEqual([]);
  });

  // The ratchet. Without this the allowlist would record yesterday's debt
  // forever and a swept page would still read as unfinished.
  it("no allowlist entry is stale (the debt list only ever shrinks)", () => {
    const stale: string[] = [];
    for (const [label, allowed] of Object.entries(ALLOW)) {
      if (!existsSync(join(SRC, label))) {
        stale.push(`${label}: file no longer exists — delete this entry`);
        continue;
      }
      const actual = counted.get(label)?.length ?? 0;
      if (actual === 0) stale.push(`${label}: swept clean — DELETE this entry`);
      else if (actual < allowed) stale.push(`${label}: down to ${actual} (recorded ${allowed}) — lower it`);
    }
    expect(stale, `wordBudget.allow.json is out of date:\n${stale.join("\n")}`).toEqual([]);
  });

  // Sweeps 1 (Dashboard/Command Center · Operations · Alerts), 2 (Security ·
  // Data Protection), 3 (Administration · Licence · Registries · Cloud ingest ·
  // Platform tools), 4 (Topology · WAN · Wireless) and 5 (BGP · RCA workspace ·
  // Reports · reliability scorecard · troubleshooting · TAC · the tabs · device
  // inventory · telemetry) are DONE, so these files must never reappear in the
  // debt list — the allowlist may not grow a new entry for one, and its breach
  // count must stay zero.
  it.each([
    "components/noc.tsx",
    "pages/CommandCenter.tsx",
    "pages/Dashboard.tsx",
    "pages/ActionQueue.tsx",
    "pages/Devices.tsx",
    "pages/DigitalExperience.tsx",
    "tabs/Alerts.tsx",
    "tabs/Incidents.tsx",
    "pages/experience/ExperiencePage.tsx",
    "pages/experience/ExperienceOverview.tsx",
    "pages/experience/ExperienceIncidents.tsx",
    "pages/experience/ExperienceIncidentView.tsx",
    "pages/experience/ExperienceJourneys.tsx",
    "pages/experience/ExperiencePaths.tsx",
    "pages/experience/ExperienceSynthetics.tsx",
    "pages/experience/ExperienceChanges.tsx",
    "pages/experience/ExperienceDataHealth.tsx",
    "pages/experience/incidentTable.tsx",
    "pages/experience/heatmap.tsx",
    "pages/experience/scrubber.tsx",
    // sweep 2 — Security (Findings, Exposures, Stories, Vulnerabilities, Threat
    // Detection, Lane health, Compliance) and Data Protection.
    "pages/security/SecurityOverview.tsx",
    "pages/security/Exposures.tsx",
    "pages/security/ExposureStories.tsx",
    "pages/security/ThreatDetectionView.tsx",
    "pages/security/SecurityCompliance.tsx",
    "pages/security/ComplianceFrameworks.tsx",
    "pages/security/SecurityRules.tsx",
    "pages/security/SavedViews.tsx",
    "pages/security/LaneHealth.tsx",
    "pages/security/SeamGroups.tsx",
    "pages/security/parts.tsx",
    "pages/security/model.ts",
    "pages/security/fixtures.ts",
    "pages/ThreatDetection.tsx",
    "pages/VulnerabilityManagement.tsx",
    "pages/ComplianceMonitoring.tsx",
    "pages/DataProtection.tsx",
    // sweep 3 — Administration (users, roles, tenants, orgs, regions, access,
    // sessions, API keys + the scope picker, auth providers, token policy,
    // notifications and contact points, integrations, RCA auto-ticketing),
    // Licence, Registries, Cloud ingest and the Platform tools.
    "tabs/admin.tsx",
    "tabs/AdminSsoIdp.tsx",
    "tabs/VerificationSettingsCard.tsx",
    "pages/Licence.tsx",
    "components/licence/UpgradeCard.tsx",
    "pages/admin/TicketDelivery.tsx",
    "pages/platform/PipelineDebugger.tsx",
    "pages/platform/Quarantine.tsx",
    "pages/appobs/Registries.tsx",
    "pages/appobs/Ingestion.tsx",
    // sweep 4 — the topology canvas and its rails (inventory, legend, path trace,
    // cloud slice, empty states), WAN circuits, Wireless and its remediation
    // queue, the device drill-down, Routing protocols, Flow Trace and New monitor.
    "features/topology/renderers/react-flow/TopologyCanvas.tsx",
    "features/topology/components/TopologyLegend.tsx",
    "features/topology/components/NetworkPathView.tsx",
    "features/topology/components/PathAnalysisPanel.tsx",
    "features/topology/components/ConfidencePanel.tsx",
    "features/topology/components/CapacityPanel.tsx",
    "features/topology/components/TopologySideDrawer.tsx",
    "features/topology/components/TopologyInventoryPanel.tsx",
    "features/topology/utils/topologyOverlays.ts",
    "features/topology/utils/topologyDomains.ts",
    "pages/WanCircuits.tsx",
    "pages/wanCircuits.model.ts",
    "pages/Wireless.tsx",
    "pages/WirelessRemediation.tsx",
    "pages/DeviceDetailPage.tsx",
    "pages/DeviceNeighbors.tsx",
    "pages/BgpOspf.tsx",
    "pages/NetworkPath.tsx",
    "pages/NewMonitor.tsx",
    // sweep 5 — everything that was left: the BGP surfaces, the RCA workspace and
    // the account/tenant gates, Reports, the reliability scorecard, the legacy
    // troubleshooting board and the TAC/investigation panels, the tabs (flows,
    // log search, correlations, collectors, SNMP credentials, source of truth,
    // transport security, tunnels, access explorer, the Iris drawer), device
    // inventory and geomap, device monitoring, NMS integrations, telemetry
    // coverage, the app-observability pages and the shared panel libraries.
    "pages/BgpOps.tsx",
    "pages/bgp/AlertPolicyPanel.tsx",
    "pages/bgp/AsPathGraphPanel.tsx",
    "pages/bgp/AspaCard.tsx",
    "pages/bgp/BogonsPanel.tsx",
    "pages/bgp/GeofeedPanel.tsx",
    "pages/bgp/LiveFeedPanel.tsx",
    "pages/bgp/PeersPanel.tsx",
    "pages/bgp/PrefixesPanel.tsx",
    "pages/bgp/RpkiPanel.tsx",
    "components/TenantGate.tsx",
    "components/TwoFactorCard.tsx",
    "components/rca/RcaAskAi.tsx",
    "components/rca/RcaPathCausality.tsx",
    "components/rca/RcaTicketCard.tsx",
    "components/rca/RcaWorkspace.tsx",
    "components/rca/rcaCase.ts",
    "pages/Reports.tsx",
    "pages/ReliabilityScorecard.tsx",
    "pages/Troubleshooting.tsx",
    "pages/troubleshoot/TacEscalationPanel.tsx",
    "pages/troubleshoot/InvestigationLanes.tsx",
    "tabs/AccessExplorer.tsx",
    "tabs/Collectors.tsx",
    "tabs/Correlations.tsx",
    "tabs/Flows.tsx",
    "tabs/flowsAppViews.ts",
    "tabs/Logs.tsx",
    "tabs/Opsis.tsx",
    "tabs/SnmpCredentials.tsx",
    "tabs/SourceOfTruth.tsx",
    "tabs/TransportSecurity.tsx",
    "tabs/Tunnels.tsx",
    "pages/CloudLogs.tsx",
    "pages/DemoShowcase.tsx",
    "pages/DeviceGeomap.tsx",
    "pages/DeviceMonitoring.tsx",
    "pages/NmsIntegrations.tsx",
    "pages/appobs/AppDetail.tsx",
    "pages/appobs/ConnectorWizard.tsx",
    "pages/appobs/ServiceMap.tsx",
    "pages/config/DeviceConfigPanel.tsx",
    "pages/demoPanels.tsx",
    "pages/device/VrfInterfaces.tsx",
    "pages/igp/IgpAdjacencies.tsx",
    "pages/panels.tsx",
    "pages/telemetry/TelemetryCoverage.tsx",
    "pages/telemetry/coverageModel.ts",
  ])("%s stays swept", (label) => {
    expect(ALLOW[label], `${label} is in a completed sweep and may not carry budget debt`).toBeUndefined();
    expect(counted.get(label)?.map((b) => fmtBreach(label, b)) ?? [], `${label} regressed`).toEqual([]);
  });

  // Teeth: every rule must still fire on the copy it was written to remove, or a
  // typo in a regex turns the whole guard into a no-op that reports green.
  it.each([
    ["heading", "<h1>Command Center for network operations teams</h1>", "heading"],
    ["cardHeading", "<h3>Ticketing gap across correlated incidents</h3>", "cardHeading"],
    ["caption", '<CcKpi n={4} label="Confirmed RCA" interp="two or more evidence streams align" />', "caption"],
    ["note", '<p className="cc-sub">What is burning, who owns it, and what still needs a human being to act</p>', "note"],
    ["empty", '<div className="cc-empty">No correlated incidents require action right now on this fleet</div>', "empty"],
  ])("the %s budget still fires", (_id, sample, kind) => {
    expect(scanWordBudget(sample).map((b) => b.kind)).toContain(kind);
  });

  it("a second note in the same card is a breach", () => {
    const two = [
      "<h3>Evidence</h3>",
      '<p className="cc-sub">One short note.</p>',
      '<p className="cc-sub">A second note.</p>',
    ].join("\n");
    expect(scanWordBudget(two).map((b) => b.kind)).toEqual(["note-count"]);
  });

  it("never counts identifiers, class names, comments or expressions", () => {
    const legit = [
      '<h1 className="cc-h1 cc-h1-wide">Command Center</h1>',
      '<span className="mini-meta">{summaryOfTheWholeQueueAndItsCounts}</span>',
      '// <p className="cc-sub">this long removed sentence lives only in a comment now</p>',
      '<a className="cc-kpi" href="#/operations/queue?filter=needs-action-right-now">Queue</a>',
      '<div className="cc-empty">Nothing correlated yet.</div>',
    ].join("\n");
    expect(scanWordBudget(legit)).toEqual([]);
  });
});
