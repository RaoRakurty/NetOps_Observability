// parts.tsx — the shared presentation pieces of the Security (CTEM) section.
//
// PURE PRESENTATION. Every one of these renders data the adapters in model.ts
// already computed; none of them fetches, and none decides a verdict. Model
// output is rendered as ESCAPED React text throughout — no dangerouslySetInnerHTML
// anywhere in this section (§15 LLM02 applies to any provider-authored string:
// a finding's observed/remediation text is untrusted content, not markup).

import { ReactNode } from "react";
import {
  Coverage, FacetRow, FunnelStage, SeamCard, SecFindingLike, Tone, Verdict,
  VERDICT_LABEL, evidenceClassLabel, severityTone, subjectLine, verdictOf, verdictTone,
} from "./model";
import { fmtDateTime } from "../../lib/time";

const toneClass = (t: Tone): string => (t === "bad" ? "t-bad" : t === "warn" ? "t-warn" : t === "good" ? "t-good" : "");

/** Severity as a badge. An absent severity reads "unrated", never "low". */
export function SeverityBadge({ severity }: { severity?: string }) {
  const s = (severity ?? "").trim();
  if (!s) return <span className="badge sec-unassessed">unrated</span>;
  return <span className={`badge ${severityTone(s)}`}>{s}</span>;
}

/** OCSF verdict as a badge. "Unassessed" is neutral — never the pass colour. */
export function VerdictBadge({ verdict }: { verdict: Verdict }) {
  const tone = verdictTone(verdict);
  return (
    <span className={`badge ${tone}`} title={verdict === "unassessed"
      ? "The check did not produce a verdict (not applicable or errored) — unknown, not clear."
      : undefined}>
      {VERDICT_LABEL[verdict]}
    </span>
  );
}

/** The CTEM pipeline band. */
export function CtemFunnel({ stages }: { stages: FunnelStage[] }) {
  return (
    <ol className="sec-funnel" aria-label="Continuous threat exposure management pipeline">
      {stages.map((s) => (
        <li key={s.key} className={`sec-stage${s.correlix ? " is-validate" : ""}`}>
          {s.correlix && <span className="tag">live</span>}
          <span className="k">{s.label}</span>
          <span className="v">{s.value.toLocaleString()}</span>
          <span className="d">{s.caption}</span>
          <span className="r">{s.ofPrevious === null ? "—" : `${s.ofPrevious}% of previous stage`}</span>
        </li>
      ))}
    </ol>
  );
}

/**
 * Assessment coverage. The headline is COVERAGE, not a score: the platform can
 * only state what share of the estate it actually measured, and it says so.
 */
export function CoverageCard({ coverage }: { coverage: Coverage }) {
  return (
    <section className="sec-card sec-coverage" aria-label="Assessment coverage">
      <div className="sec-eyebrow">Assessment coverage</div>
      <div className="sec-cov-num">
        {coverage.pct === null
          ? <span className="sec-unassessed">n/a</span>
          : <>{coverage.pct}<small>%</small></>}
      </div>
      <div className="sec-cov-lbl">{coverage.label}</div>
      {coverage.pct !== null && (
        <div className="sec-cov-bar"><i style={{ width: `${coverage.pct}%` }} /></div>
      )}
      {coverage.hasGap && (
        <p className="mini-meta" style={{ margin: "8px 0 0" }}>
          {coverage.unassessed.toLocaleString()} asset{coverage.unassessed === 1 ? "" : "s"} were never
          assessed. Absence of a finding on them means <span className="sec-unassessed">unknown</span>, not safe.
        </p>
      )}
    </section>
  );
}

/** One finding as a dense evidence-lane row. Clicking opens the Inspector. */
export function FindingRow({ finding, onOpen }: { finding: SecFindingLike; onOpen?: (f: SecFindingLike) => void }) {
  const v = verdictOf(finding);
  const tone = v === "unassessed" ? "" : severityTone(finding.severity) || verdictTone(v);
  const title = finding.control_title || finding.control || finding.raw_rule_id || "Untitled check";
  return (
    <button type="button" className="sec-row" onClick={() => onOpen?.(finding)}>
      <span className={`sec-stripe ${toneClass(tone)}`} aria-hidden="true" />
      <span className="main">
        <b>{title}</b>
        <span className="sub">
          {subjectLine(finding)}
          {finding.seam?.seam_type ? ` · seam ${finding.seam.seam_type}` : ""}
          {v === "unassessed" ? " · unassessed" : ""}
        </span>
      </span>
      <span className="fix">{finding.remediation || (v === "unassessed" ? "no verdict" : "")}</span>
    </button>
  );
}

/** An evidence-lane card: heading, count pill, then rows (or an honest empty). */
export function EvidenceLane({
  title, count, tone = "", empty, children,
}: { title: string; count?: ReactNode; tone?: Tone; empty?: ReactNode; children?: ReactNode }) {
  return (
    <section className="sec-card" aria-label={title}>
      <div className="sec-lane-h">
        <h3 className="t" style={{ margin: 0 }}>{title}</h3>
        {count !== undefined && <span className={`badge ${tone}`}>{count}</span>}
      </div>
      {children ?? <div className="empty">{empty ?? "Nothing assessed in this lane yet."}</div>}
    </section>
  );
}

/** The "exposure by seam" strip. An unscored seam renders "—", never 0. */
export function SeamStrip({ cards }: { cards: SeamCard[] }) {
  if (cards.length === 0) {
    return <div className="empty">No seams are known yet — the seam inventory has nothing to attribute exposure to.</div>;
  }
  return (
    <div className="sec-seams">
      {cards.map((c) => {
        const tone: Tone = !c.assessed ? "" : (c.count ?? 0) > 0 ? "bad" : "good";
        return (
          <div key={c.seam} className="sec-seam">
            <span className={`edge ${toneClass(tone)}`} aria-hidden="true" />
            <div className="nm">{c.label}</div>
            <div className={`ct${c.assessed ? "" : " sec-unassessed"}`}>
              {c.assessed ? (c.count ?? 0).toLocaleString() : "—"}
            </div>
            <div className="ow">
              {c.assessed ? `open findings${c.owner ? ` · ${c.owner}` : ""}` : "unassessed"}
            </div>
          </div>
        );
      })}
    </div>
  );
}

/**
 * A facet group in the Exposures sidebar. With `onToggle` the rows are real
 * toggle buttons (aria-pressed); WITHOUT it they render as a read-only
 * breakdown. That distinction is deliberate: a facet the read API cannot
 * actually filter on must not look clickable, because a control that changes
 * nothing is a lie about what the screen is showing.
 */
export function FacetGroup({
  title, rows, onToggle, note,
}: { title: string; rows: FacetRow[]; onToggle?: (key: string) => void; note?: string }) {
  if (!onToggle) {
    return (
      <div>
        <h3 className="sec-facet-h">{title}</h3>
        {rows.length === 0
          ? <div className="mini-meta">No values in range.</div>
          : rows.map((r) => (
            <div key={r.key} className="sec-facet-btn" style={{ cursor: "default" }}>
              <span>{r.label}</span>
              <span className="n">{r.count.toLocaleString()}</span>
            </div>
          ))}
        {note && <p className="mini-meta" style={{ margin: "4px 0 0" }}>{note}</p>}
      </div>
    );
  }
  return (
    <div>
      <h3 className="sec-facet-h">{title}</h3>
      {rows.length === 0
        ? <div className="mini-meta">No values in range.</div>
        : rows.map((r) => (
          <button
            key={r.key}
            type="button"
            className="sec-facet-btn"
            aria-pressed={r.selected}
            disabled={r.count === 0 && !r.selected}
            onClick={() => onToggle(r.key)}
          >
            <span>{r.label}</span>
            <span className="n">{r.count.toLocaleString()}</span>
          </button>
        ))}
      {note && <p className="mini-meta" style={{ margin: "4px 0 0" }}>{note}</p>}
    </div>
  );
}

/**
 * The Finding detail body rendered in the Inspector: observed vs intended, the
 * by-reference evidence pointer, remediation, and the standards chips. Every
 * value is escaped React text — provider strings are data, never markup.
 */
export function FindingDetail({ finding }: { finding: SecFindingLike }) {
  const v = verdictOf(finding);
  const std = finding.standards ?? [];
  const ref = finding.evidence_ref;
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
      <div style={{ display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center" }}>
        <VerdictBadge verdict={v} />
        <SeverityBadge severity={finding.severity} />
        <span className="badge">{evidenceClassLabel(finding.evidence_class)}</span>
        {finding.seam?.internet_facing && <span className="badge bad">internet-facing seam</span>}
      </div>

      <h3 style={{ margin: 0, fontSize: 15 }}>
        {finding.control_title || finding.control || finding.raw_rule_id || "Untitled check"}
      </h3>

      <div className="sec-oi">
        <div>
          <h4>Observed</h4>
          <p>{finding.observed || <span className="sec-unassessed">not recorded</span>}</p>
        </div>
        <div>
          <h4>Intended</h4>
          <p>{finding.intended || <span className="sec-unassessed">not recorded</span>}</p>
        </div>
      </div>

      {finding.status_detail && (
        <div>
          <h4 className="sec-facet-h">Detail</h4>
          <p style={{ margin: 0, fontSize: 12.5 }}>{finding.status_detail}</p>
        </div>
      )}

      {finding.remediation && (
        <div>
          <h4 className="sec-facet-h">Remediation</h4>
          <p className="sec-mono" style={{ margin: 0 }}>{finding.remediation}</p>
        </div>
      )}

      <div>
        <h4 className="sec-facet-h">Evidence</h4>
        {ref ? (
          <dl className="sec-kv">
            <dt>Locator</dt><dd className="sec-mono">{ref.locator}</dd>
            {ref.kind && <><dt>Kind</dt><dd>{ref.kind}</dd></>}
            {ref.ruleset_version && <><dt>Ruleset</dt><dd className="sec-mono">{ref.ruleset_version}</dd></>}
            {ref.digest && <><dt>Digest</dt><dd className="sec-mono">{ref.digest}</dd></>}
          </dl>
        ) : (
          <p className="mini-meta" style={{ margin: 0 }}>
            This verdict carries no evidence pointer — it cannot be replayed against the raw artifact.
          </p>
        )}
      </div>

      <div>
        <h4 className="sec-facet-h">Standards</h4>
        {std.length === 0
          ? <span className="sec-unassessed" style={{ fontSize: 12.5 }}>untagged</span>
          : (
            <div className="sec-chips">
              {std.map((s) => <span key={s} className="sec-chip">{s}</span>)}
            </div>
          )}
      </div>

      <dl className="sec-kv">
        <dt>Asset</dt><dd>{subjectLine(finding)}</dd>
        {finding.resource?.ip && <><dt>Address</dt><dd className="sec-mono">{finding.resource.ip}</dd></>}
        {finding.seam?.seam_type && <><dt>Seam</dt><dd>{finding.seam.seam_type}</dd></>}
        <dt>Verdict at</dt><dd>{finding.time ? fmtDateTime(finding.time) : "—"}</dd>
        {finding.source && <><dt>Provider</dt><dd>{finding.source}</dd></>}
        {(finding.scan_id || finding.scan_uid) && (
          <><dt>Scan</dt><dd className="sec-mono">{finding.scan_id || finding.scan_uid}</dd></>
        )}
        <dt>Identity</dt><dd className="sec-mono">{finding.native_id || finding.id}</dd>
      </dl>
    </div>
  );
}
