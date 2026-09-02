// rcaExport.test.ts — the operator-verdict line in the exported RCA document
// (Project 2 P7). The printed report must carry the latest human judgement of
// the case when one exists, and print NOTHING when nobody has judged it — an
// invented "no verdict recorded" line would be a claim the data doesn't make.

import { describe, it, expect } from "vitest";
import { reportHtml } from "./rcaExport";
import { rcaVerdictLine } from "./labels";
import { EXAMPLE_CASE, type RcaCase } from "./rcaCase";
import type { RcaFeedback } from "../../services/api";

const WRONG: RcaFeedback = {
  id: "fb-2", tenant_id: "acme", correlation_id: "c-1",
  verdict: "wrong", wrong_part: "owner", reason: "ISP was not at fault",
  correlation_version: 3, created_by: "alice", created_at: "2026-09-01T12:00:00Z",
};

describe("rcaVerdictLine", () => {
  it("renders verdict — part — reason — who, when", () => {
    const line = rcaVerdictLine(WRONG, { utc: true });
    expect(line).toBe("Operator verdict: Wrong — owner — 'ISP was not at fault' — alice, Sep 01, 12:00:00 UTC");
  });

  it("omits the parts that were not recorded", () => {
    expect(rcaVerdictLine({ ...WRONG, wrong_part: undefined, reason: "", created_at: "" }, { utc: true }))
      .toBe("Operator verdict: Wrong — alice");
  });

  it('reads "Partially correct" in prose, not the bare button word', () => {
    const line = rcaVerdictLine({ ...WRONG, verdict: "partial", reason: "", created_at: "" }, { utc: true });
    expect(line).toContain("Partially correct");
  });
});

describe("exported RCA document", () => {
  it("prints the latest recorded verdict when one exists", () => {
    const html = reportHtml(EXAMPLE_CASE, "obj-123", WRONG);
    expect(html).toContain("Operator verdict: Wrong");
    expect(html).toContain("'ISP was not at fault'");
    expect(html).toContain("alice");
    expect(html).toContain('class="verdict-fb"');
  });

  it("prints no verdict line when the case has never been judged", () => {
    const html = reportHtml(EXAMPLE_CASE, "obj-123");
    expect(html).not.toContain("Operator verdict");
    expect(html).not.toContain("verdict-fb\">");
  });
});

// ── Fidelity + security attribution reach the printed report (A7 / T2b) ──────
// A report that dropped the rule grade or the held-back reason would let a
// reader over-trust evidence the screen honestly qualified.

const GRADED: RcaCase = {
  ...EXAMPLE_CASE,
  evidence: [
    { variant: "main", dot: "orange", title: "Routing / link", pill: { tone: "orange", text: "Main evidence" },
      desc: "BGP, link up/down", finding: "2 observations used.", foot: "Primary evidence", fidelity: "live_validated" },
    { variant: "confirm", dot: "purple", title: "Exposure", pill: { tone: "green", text: "Used" },
      desc: "reachable service / advisory exposure on the asset", finding: "1 observation used.",
      foot: "Independent of the network classes — a rule verdict, not a wire measurement",
      chips: ["Seam: ISP (seam-7)", "Internet-facing", "Observed by vuln"], fidelity: "doc_claimed" },
    { variant: "missing", dot: "gray", title: "Active checks", pill: { tone: "gray", text: "No data" },
      desc: "ping, HTTP", finding: "No telemetry.", foot: "Coverage gap" },
  ],
  ladderNote: "Confirmation held back — evidence from unvalidated parser rules: netrule.exposed_mgmt",
};

describe("exported RCA document — evidence fidelity + fidelity gap", () => {
  const html = reportHtml(GRADED, "obj-123");

  it("prints a Rule fidelity column with the same badge wording the screen uses", () => {
    expect(html).toContain("<th>Rule fidelity</th>");
    expect(html).toContain("live validated");
    expect(html).toContain("doc claimed");
  });

  it("prints an em dash — not a guess — for a row that declared no fidelity", () => {
    expect(html).toContain("&mdash;");
  });

  it("prints the security row's seam, exposure and provider attribution", () => {
    expect(html).toContain("Seam: ISP (seam-7) · Internet-facing · Observed by vuln");
  });

  it("prints the held-back line under the confidence ladder", () => {
    expect(html).toContain("Confirmation held back — evidence from unvalidated parser rules: netrule.exposed_mgmt");
  });

  it("prints no held-back line when the case carries no gap", () => {
    expect(reportHtml(EXAMPLE_CASE, "obj-123")).not.toContain("Confirmation held back");
  });
});
