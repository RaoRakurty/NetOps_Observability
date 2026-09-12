// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { useMemo, useState } from "react";
import "./Security.css";
import { Group, Panel } from "../../components/board/panels";
import type { SecCompliance, SecFrameworkCatalog } from "../../services/api";
import {
  benchmarkChipsByControl, controlVerdict, FrameworkCard, frameworkCards,
  FrameworkRow, frameworkRows, frameworksPutPayload, VERDICT_LABEL, verdictTone,
} from "./model";
import AskIris from "../../components/AskIris";

// ComplianceFrameworks — WHICH frameworks this tenant is assessed against, and
// the score for each.
//
// Owner direction, 2026-09-03: "we shouldn't be checking all compliances by
// default; compliance is analyzed per customer requirement." The previous view
// derived its framework list from the distinct standards TAGS on findings, so
// every invented `CIS-NET-x.y` benchmark section rendered as its own framework —
// and HIPAA, which is a projection rather than a tag, could never appear at all.
//
// WORD SWEEP (2026-09-06, tracker 270): the per-customer scoping rule and the
// "a benchmark is a citation, not a framework" rule are now
// ai/skills/explain/compliance.*.md behind the `(i)`; the rules themselves are
// unchanged and still enforced here.
//
// Three rules this file exists to keep:
//
//  · The list comes from the framework CATALOGUE, not from tags. A tenant runs
//    the NIST 800-53 base plus CIS Controls by default; NIST CSF, HIPAA and PCI
//    DSS are added deliberately, by an admin, from "Add framework".
//  · A framework with nothing assessed shows the SENTENCE, never a percentage.
//    0% reads as total failure and 100% reads as a clean bill; both would be a
//    claim the data does not support.
//  · A CIS device benchmark is a CITATION on a control row — its published
//    title, version and section heading — never an entry in the framework list.

type Props = {
  catalog: SecFrameworkCatalog | null;
  compliance: SecCompliance | null;
  /** Admin-only: absent means the picker is read-only (the PUT is gated). */
  onSave?: (updates: ReturnType<typeof frameworksPutPayload>) => Promise<void>;
  saving?: boolean;
  saveError?: string | null;
  saveNote?: string | null;
};

function ScoreCard({ card, selected, onSelect }: {
  card: FrameworkCard; selected: boolean; onSelect: () => void;
}) {
  const toneCls = card.tone === "bad" ? "t-bad" : card.tone === "warn" ? "t-warn" : card.tone === "good" ? "t-good" : "";
  return (
    <button
      type="button"
      className="sec-seam"
      aria-pressed={selected}
      onClick={onSelect}
      style={{
        textAlign: "left", cursor: "pointer", font: "inherit", color: "inherit",
        outline: selected ? "2px solid var(--accent)" : undefined,
      }}
    >
      <i className={`edge ${toneCls}`} aria-hidden="true" />
      <div className="nm">{card.framework}</div>
      <div className="ct" style={{ fontSize: card.pct === null ? 13 : undefined }}>
        {card.pct === null ? <span className="sec-unassessed">Not assessed</span> : `${card.pct}%`}
      </div>
      <div className="ow">
        {card.pct === null
          ? `${card.inScope} in scope`
          : `${card.passed}/${card.passed + card.warned + card.failed} passing`}
      </div>
      <div className="ow">
        {card.coveragePct === null
          ? "Nothing in scope"
          : `${card.withCheck}/${card.inScope} with a check`}
      </div>
    </button>
  );
}

export default function ComplianceFrameworks({
  catalog, compliance, onSave, saving, saveError, saveNote,
}: Props) {
  const rows = useMemo<FrameworkRow[]>(() => frameworkRows(catalog), [catalog]);
  const cards = useMemo<FrameworkCard[]>(() => frameworkCards(compliance), [compliance]);
  const chips = useMemo(() => benchmarkChipsByControl(catalog?.benchmark_citations), [catalog]);
  const [pending, setPending] = useState<Record<string, boolean>>({});
  const [adding, setAdding] = useState(false);
  const [focus, setFocus] = useState<string | null>(null);

  const enabledOf = (r: FrameworkRow): boolean =>
    Object.prototype.hasOwnProperty.call(pending, r.id) ? pending[r.id] : r.enabled;
  const payload = useMemo(() => frameworksPutPayload(rows, pending), [rows, pending]);

  const optIn = rows.filter((r) => !enabledOf(r));
  const active = cards.find((c) => c.framework === focus) ?? cards[0] ?? null;

  return (
    <>
      <Group title="Frameworks in use" hue="#8b5cf6">
        <Panel title="Selection">
          <p className="sec-line" style={{ marginTop: 0 }}>
            {catalog && !catalog.configured ? "Shipped default set." : "Scored while turned on."}
            <AskIris topic="compliance.framework-scope" label="framework selection" />
          </p>
          <ul
            aria-label="Frameworks in use"
            style={{ listStyle: "none", margin: 0, padding: 0, display: "flex", flexDirection: "column", gap: 8 }}
          >
            {rows.filter((r) => enabledOf(r)).map((r) => (
              <li key={r.id} className="sec-row" style={{ display: "flex", gap: 10, alignItems: "flex-start" }}>
                <label style={{ display: "inline-flex", alignItems: "center", gap: 8 }}>
                  <input
                    type="checkbox"
                    checked={enabledOf(r)}
                    disabled={!onSave}
                    aria-label={`${r.name} enabled`}
                    onChange={(e) => setPending((p) => ({ ...p, [r.id]: e.target.checked }))}
                  />
                </label>
                <div className="sec-main">
                  <b>{r.name}</b>
                  <div className="sub">{r.origin} · version {r.version}</div>
                  <div className="sub">{r.scope}</div>
                </div>
              </li>
            ))}
          </ul>

          {optIn.length > 0 && onSave ? (
            <div style={{ marginTop: 10 }}>
              <button type="button" className="btn" onClick={() => setAdding((v) => !v)} aria-expanded={adding}>
                Add framework…
              </button>
              {adding ? (
                <ul
                  aria-label="Frameworks available to add"
                  style={{ listStyle: "none", margin: "8px 0 0", padding: 0, display: "flex", flexDirection: "column", gap: 8 }}
                >
                  {optIn.map((r) => (
                    <li key={r.id} className="sec-row" style={{ display: "flex", gap: 10, alignItems: "flex-start" }}>
                      <label style={{ display: "inline-flex", alignItems: "center", gap: 8 }}>
                        <input
                          type="checkbox"
                          checked={false}
                          aria-label={`${r.name} enabled`}
                          onChange={(e) => setPending((p) => ({ ...p, [r.id]: e.target.checked }))}
                        />
                      </label>
                      <div className="sec-main">
                        <b>{r.name}</b>
                        <div className="sub">{r.origin} · version {r.version}</div>
                        <div className="sub">{r.scope}</div>
                      </div>
                    </li>
                  ))}
                </ul>
              ) : null}
            </div>
          ) : null}

          {onSave ? (
            <div style={{ display: "flex", gap: 8, alignItems: "center", marginTop: 10 }}>
              <button
                type="button"
                className="btn primary"
                disabled={payload.length === 0 || !!saving}
                onClick={() => { void onSave(payload).then(() => setPending({})); }}
              >
                {saving ? "Saving…" : `Save selection${payload.length ? ` (${payload.length})` : ""}`}
              </button>
              {saveNote ? <span className="mini-meta" role="status">{saveNote}</span> : null}
              {saveError ? <span className="mini-meta" role="alert" style={{ color: "var(--bad)" }}>{saveError}</span> : null}
            </div>
          ) : (
            <p className="sec-line">Changing the selection needs an administrator.</p>
          )}
        </Panel>

        <Panel title="Score by framework">
          {cards.length === 0 ? (
            <div className="empty">
              No framework is turned on.
              <AskIris topic="compliance.framework-scope" label="framework selection" />
            </div>
          ) : (
            <>
              <div className="sec-seams">
                {cards.map((c) => (
                  <ScoreCard
                    key={c.framework}
                    card={c}
                    selected={active?.framework === c.framework}
                    onSelect={() => setFocus(c.framework)}
                  />
                ))}
              </div>
              <p className="sec-line" style={{ marginBottom: 0 }}>
                {cards[0]?.claim}
                <AskIris topic="compliance.not-certified" label="a framework score" />
              </p>
            </>
          )}
        </Panel>
      </Group>

      {active ? (
        <Group title={active.framework} hue="#8b5cf6">
          {active.pct === null ? (
            <div className="empty" role="status">
              {active.emptyNote}
              <AskIris topic="compliance.unassessed-control" label="an unassessed control" />
            </div>
          ) : null}
          <table className="ds-table" aria-label={`${active.framework} controls`}>
            <thead>
              <tr>
                <th scope="col">Control</th>
                <th scope="col">Satisfies</th>
                <th scope="col">Verdict</th>
                <th scope="col">Findings</th>
                <th scope="col">Benchmark reference</th>
              </tr>
            </thead>
            <tbody>
              {active.controls.map((c) => {
                const v = c.findings > 0 ? controlVerdict(c.status_id) : "unassessed";
                const tone = verdictTone(v);
                return (
                  <tr key={c.control_id}>
                    <th scope="row" style={{ textAlign: "left", fontWeight: 500 }}>
                      {c.control_id}
                      {c.title ? <div className="sub">{c.title}</div> : null}
                      {!c.has_check ? (
                        <div className="sec-line sec-unassessed">
                          No check
                          <AskIris topic="compliance.no-check" label="a control with no check" />
                        </div>
                      ) : null}
                    </th>
                    <td>
                      {(c.requirements ?? []).map((r) => (
                        <div key={`${r.requirement_id}-${r.title ?? ""}`}>
                          <b>{r.requirement_id}</b>{r.title ? ` · ${r.title}` : ""}
                        </div>
                      ))}
                    </td>
                    <td>
                      <span className={tone ? `t-${tone}` : "sec-unassessed"}>{VERDICT_LABEL[v]}</span>
                    </td>
                    <td>{c.findings.toLocaleString()}</td>
                    <td>
                      {(chips[c.control_id] ?? []).length === 0 ? (
                        <span className="sec-unassessed">None published</span>
                      ) : (
                        <div className="sec-chips" style={{ marginTop: 0 }}>
                          {(chips[c.control_id] ?? []).map((label) => (
                            <span className="sec-chip" key={label}>{label}</span>
                          ))}
                        </div>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          <p className="sec-line" style={{ margin: 0 }} role="status">
            {active.assessed.toLocaleString()} of {active.inScope.toLocaleString()} in scope assessed
            {active.unassessed > 0 ? `, ${active.unassessed.toLocaleString()} not looked at` : ""}
            <AskIris topic="compliance.benchmark-citation" label="Benchmark reference" />
          </p>
        </Group>
      ) : null}
    </>
  );
}
