import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { join, dirname, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { stripComments, readableSpans } from "./lib/copyScan";

// ── NOC-OPERATOR VOICE REGRESSION (copy pass, 2026-09-02) ───────────────────
//
// docs/design/COPY_AUDIT_2026-09-02.md audited every page and component for
// developer-speak and replaced it. This test is the ratchet: each rule below
// names copy that WAS on a screen and is now gone, so it cannot come back
// quietly in the next feature.
//
// This is a companion to components/rca/vocabulary.test.ts (which guards the
// single engine word "Signals"); both scan through lib/copyScan so "what a
// person can read" means the same thing in both.
//
// SCOPE IS COPY, NOT CODE. Comments are blanked first, and only string literals
// and JSX text nodes are matched — identifiers, API field names and code
// comments are deliberately untouched. `payload.limit` in an expression is
// code; `title="…payload…"` is copy.
//
// ADDING A RULE. Only add one for a phrase you actually removed, with a
// `why` an author can act on. A rule with standing exemptions must say why each
// one is legitimate — an unexplained exemption list is how a guard rots.

const SRC = dirname(fileURLToPath(import.meta.url));

export interface CopyRule {
  /** Short id used in the failure message. */
  id: string;
  re: RegExp;
  /** What to write instead — this is what the failing author reads. */
  why: string;
  /**
   * Paths (relative to src/, "/"-joined) where the phrase is legitimate.
   * Every entry needs a reason in the comment above it.
   */
  allow?: readonly string[];
  /**
   * Only fire when the span reads like a SENTENCE. Some denied words are also
   * legitimate code that happens to live in a string — a metric name inside a
   * PromQL query, an API query-parameter key. Those are not copy, and a guard
   * that fails on them would be turned off within a week.
   */
  proseOnly?: boolean;
}

/**
 * Query/expression punctuation. A span carrying it is code, not copy — braces
 * and comparisons, or a function call like `count(` (PromQL, which is what most
 * of these metric names legitimately live inside).
 */
const EXPRESSION = /[{}<>*]|==|!=|[A-Za-z_]\(/;

/**
 * True when the span reads like a sentence about the thing, rather than being
 * the thing: at least three ordinary words once the matched term is removed,
 * and no expression punctuation anywhere.
 */
function readsAsProse(span: string, re: RegExp): boolean {
  if (EXPRESSION.test(span)) return false;
  const rest = span.replace(new RegExp(re.source, "g"), " ");
  const words = rest.match(/[A-Za-z][A-Za-z'’-]{1,}/g) ?? [];
  return words.length >= 3;
}

export const RULES: readonly CopyRule[] = [
  // ── instructional chrome: the UI explains itself; words explaining it spend
  //    the operator's reading budget on nothing.
  {
    id: "click-instruction",
    re: /\b[Cc]lick (to|a row|any|a cell|a hop|a marker)\b/,
    why: 'Do not tell the operator to click. Name the thing instead ("Resize", "Not configured").',
  },
  {
    id: "hover-instruction",
    re: /\bHover (any|over)\b/,
    why: "Do not tell the operator to hover; describe what the element carries.",
  },
  {
    id: "drag-instruction",
    re: /\bDrag to resize\b/,
    why: 'Name the affordance ("Resize"), not the gesture.',
  },
  {
    id: "tip-prefix",
    re: /\bTip:/,
    why: "A UI that needs a tip needs better labels. State the fact directly.",
  },

  // ── placeholder / stub text: never ship a promise or a scaffold note.
  {
    id: "coming-soon",
    re: /\bcoming soon\b/i,
    why: 'Say what is true now ("Not collected here", "not open yet"), never a promise.',
    // Placeholders.tsx keeps the phrase only in its own file comment about the
    // era when those pages WERE stubs; the scanner strips comments, so this
    // exemption exists solely as documentation of that history.
    allow: [],
  },
  {
    id: "stub-note",
    re: /\bPhase \d+ stub\b|\bbundled stand-in\b|\bso the renderer can be evaluated\b/,
    why: "Internal build notes are not copy. Say what the operator sees and why.",
  },
  {
    id: "mock-hostname",
    re: /\bmock-nms\b|\bmock-[a-z]+:\d+/,
    why: "A development stand-in hostname must never appear in shipped copy.",
  },
  {
    id: "fixture-word",
    re: /^Fixture$|\bmining not yet run\b/,
    why: '"Fixture" and "mining" are build words. Say "Sample event" / "analysis has not run yet".',
  },

  // ── internal store and engine names: an operator does not run our database.
  {
    id: "store-names",
    re: /\b(ClickHouse|VictoriaMetrics|Lucene)\b/,
    why: "Name the DATA, not the store: “flows”, “SNMP metrics”, “Search”.",
  },
  {
    id: "opensearch",
    re: /\bOpenSearch\b/,
    why: "Name the data (“Log search”), not the store.",
    allow: [
      // The embedded third-party UI: "OpenSearch Dashboards" is its real product
      // name and the iframe title must match what the operator is looking at.
      "tabs/SearchDashboards.tsx",
      // Backup/restore is an administrator surface where the snapshot engine is
      // the actionable fact — you restore an OpenSearch snapshot, not "a search".
      "pages/DataProtection.tsx",
    ],
  },
  {
    id: "regex-engine",
    re: /\bRE2\b|\bCustom regex\b|\b\(regex[ )]/,
    why: 'Say "pattern". The engine behind it is not the operator\'s concern.',
  },

  // ── raw schema keys and internal identifiers presented as copy.
  {
    id: "raw-field-names",
    re: /\b(fw_logs|cx_sensitive|cost_center)\b/,
    why: "A wire field name is not a label. Use the operator's word for the thing.",
  },
  {
    // These ARE the metric/edge names — legitimate inside a PromQL query or an
    // edge-kind constant, and wrong the moment they appear in a sentence an
    // operator reads ("No BGP peers in telemetry (device_bgp_peer_state)…").
    id: "wire-name-in-prose",
    re: /\b(talks_to|depends_on|backed_by|cloud_flow|window_hours|device_bgp_peer_state|device_ospf_nbr_state|device_isis_adj_state)\b/,
    why: "Do not put a wire field name inside a sentence — name the thing in the operator's words.",
    proseOnly: true,
  },

  // ── collection vocabulary: we collect telemetry, we do not "poll".
  {
    id: "poller",
    re: /\bpoller\b|\bPolling…|\bPoll now\b|\b(Pause|Resume) polling\b|\bring buffer\b|\bbasemap\b/,
    why: 'Use collection language ("Collecting…", "Collect now"); "poller"/"ring buffer"/"basemap" are implementation words.',
  },

  // ── developer error text reaching the screen.
  {
    id: "lowercase-failure",
    re: /\bfailed to [a-z]|\bExpression error:|^· Error: $|^lookup failed$|^export failed$/,
    why: "Render an operator sentence via lib/errors.ts `operatorError(e, fallback)`, not a raw failure string.",
  },
  {
    id: "backend-word",
    re: /\bbackend\b/i,
    why: 'Operators do not have a "backend". Name the capability ("Inventory did not answer").',
    allow: [
      // Administration → integrations: the vendor's own capability-pack wording.
      "pages/appobs/providers.tsx",
    ],
  },

  // ── empty / unknown states phrased as a developer would.
  {
    id: "no-data",
    re: /\bNo data\b(?!\s+arriving)/,
    why: 'Say what did not happen: "Nothing collected in this window."  ("No data arriving" is fine — it is about the feed.)',
  },
  {
    id: "n-a",
    re: /(^|[\s>"'(])n\/a([\s<"')._]|$)/i,
    why: 'Say why it is absent: "Not rated", "Not assessed", "not measured".',
    allow: [
      // Normalizes vendor junk values on the way IN; these are inputs being
      // rejected, not copy being rendered.
      "pages/appobs/timeline.ts",
      // Explains in prose that "n/a" is exactly what we refuse to print.
      "components/rca/rcaExport.ts",
    ],
  },
  {
    id: "shouty-state",
    re: /\bNO certificate\b|\bValidator (fatal|warn)\b|\bPAUSED · |"POLLING"|\bDebug View\b/,
    why: "Sentence-case an operator-readable state, not a shouted internal one.",
  },
];

// ── the scan ────────────────────────────────────────────────────────────────

function sourceFiles(dir: string, out: string[] = []): string[] {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, e.name);
    if (e.isDirectory()) {
      if (e.name === "node_modules") continue;
      if (e.name === "mock") continue;   // fixtures mirror vendor JSON verbatim
      if (e.name === "test") continue;   // test factories, not shipped copy
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

/** Returns "path:line — id: why" for every denied phrase that reaches a screen. */
export function scanCopy(text: string, label: string, rules: readonly CopyRule[] = RULES): string[] {
  const hits: string[] = [];
  stripComments(text).split("\n").forEach((line, i) => {
    const spans = readableSpans(line);
    if (spans.length === 0) return;
    for (const rule of rules) {
      if (rule.allow?.includes(label)) continue;
      const bad = spans.find((s) => rule.re.test(s) && (!rule.proseOnly || readsAsProse(s, rule.re)));
      if (bad !== undefined) hits.push(`${label}:${i + 1} — ${rule.id}: ${JSON.stringify(bad.trim().slice(0, 90))} · ${rule.why}`);
    }
  });
  return hits;
}

describe("UI copy — developer-speak stays removed", () => {
  const files = sourceFiles(SRC);

  it("finds source files to scan (a broken walk must not pass silently)", () => {
    expect(files.length).toBeGreaterThan(200);
  });

  it("no shipped .ts/.tsx shows a denied phrase to an operator", () => {
    const hits = files.flatMap((f) =>
      scanCopy(readFileSync(f, "utf-8"), relative(SRC, f).split(sep).join("/")),
    );
    expect(
      hits,
      `developer-speak reached the UI (${hits.length} hit(s)):\n${hits.join("\n")}`,
    ).toEqual([]);
  });

  // Teeth: every rule must still fire on the copy it was written to kill.
  // Without this a typo in a regex turns the whole guard into a no-op that
  // reports green forever.
  it.each([
    ["click-instruction", '<span title="Click to configure">x</span>'],
    ["click-instruction", 'title="…observed-since; click a row to focus it on the map."'],
    ["hover-instruction", "<p>Hover any AS for its details</p>"],
    ["drag-instruction", 'title="Drag to resize"'],
    ["tip-prefix", "<b>Tip:</b>"],
    ["coming-soon", 'label: "Coming soon",'],
    ["stub-note", 'title={`${a} (Phase 2 stub — resolution backend lands later)`}'],
    ["mock-hostname", 'hint="or http://mock-nms:8091 for the bundled stand-in"'],
    ["fixture-word", '<CodeBlock title="Fixture" content={x} />'],
    ["wire-name-in-prose", '<p>No BGP peers in telemetry (device_bgp_peer_state) for this device.</p>'],
    ["store-names", 'down.push("flows (ClickHouse)");'],
    ["opensearch", 'sub: "OpenSearch",'],
    ["regex-engine", '<span>RE2 syntax · validated on save</span>'],
    ["raw-field-names", '<option value="fw_logs">fw_logs</option>'],
    ["wire-name-in-prose", 'hint="talks_to / depends_on edges from cloud flow logs"'],
    ["poller", '{busy ? "Polling…" : "Poll now"}'],
    ["lowercase-failure", 'setErr("failed to load audit log");'],
    ["backend-word", 'hint="The inventory backend did not answer."'],
    ["no-data", '<Empty msg="No data yet." />'],
    ["n-a", '<span className="sec-unassessed">n/a</span>'],
    ["shouty-state", '<button>Debug View</button>'],
  ])("rule %s still fires on the copy it removed", (id, sample) => {
    const hits = scanCopy(sample, "fixture.tsx");
    expect(hits.join("\n"), `rule ${id} did not fire on: ${sample}`).toContain(`${id}:`);
  });

  it("never fires on identifiers, field access, or comments", () => {
    const legit = [
      'import { pollStatus } from "./api";',
      "const backend = useBackend();",
      "if (status.polling) return <Chip label={\"Receiving\"} />;",
      "<div>Showing the first {payload.limit} events</div>",
      "const noData = rows.length === 0;",
      "// Click to configure was the old copy; do not bring it back",
      '/* "No data yet." lived here until the 2026-09-02 copy pass */',
      '<span title="the connection has produced no data within its expected cadence">No data arriving</span>',
      // A metric name inside a query, and an API parameter key, are CODE.
      'promql: "count(device_bgp_peer_state == 6) or vector(0)",',
      'const q = `device_ospf_nbr_state{device="${id}"}`;',
      'p.set("window_hours", String(h));',
      'const EDGE = "talks_to";',
    ].join("\n");
    expect(scanCopy(legit, "legit.tsx")).toEqual([]);
  });
});
