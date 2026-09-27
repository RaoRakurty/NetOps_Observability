// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// cards.tsx — the three answer cards (tracker 337 N-E3, design Part 2 §30):
//
//   · IncidentCard       — "why did this incident happen", from the engine's RCA
//                          contract (ai.RCAResult). The root cause is shown only
//                          when the ENGINE says it is identified; otherwise the
//                          card says so and offers the engine's "possibly
//                          because of …" line, labelled as possible.
//   · ChangeCard         — one change, with the honest relation wording.
//   · RecommendationCard — suggested next steps. Iris never acts: the footer
//                          always reads "No action has been executed."
//
// The RCA contract is serialised with Go field names (no JSON tags), so the
// reader accepts both "Title" and "title". Every value is untrusted: read
// through typed accessors, clipped, and rendered as escaped React text.

import { fmtDateTime } from "../lib/time";
import { cellText, clip, humanize, type Row } from "./presentation";
import { changeSourceText, changeTitle, relationText, automationText, str } from "./changes";
import { SafeLink } from "./links";

// ── tolerant readers over unknown JSON ───────────────────────────────────────

type Obj = Record<string, unknown>;

function isObj(v: unknown): v is Obj {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function pick(o: unknown, key: string): unknown {
  if (!isObj(o)) return undefined;
  if (key in o) return o[key];
  const snake = key.replace(/([a-z0-9])([A-Z])/g, "$1_$2").toLowerCase();
  if (snake in o) return o[snake];
  const lower = key.charAt(0).toLowerCase() + key.slice(1);
  return o[lower];
}

function pStr(o: unknown, key: string, n = 500): string {
  const v = pick(o, key);
  return typeof v === "string" ? clip(v.trim(), n) : "";
}

function pList(o: unknown, key: string, max = 8): string[] {
  const v = pick(o, key);
  if (!Array.isArray(v)) return [];
  return v.filter((x): x is string => typeof x === "string" && x.trim() !== "").slice(0, max).map((x) => clip(x, 300));
}

function pNum(o: unknown, key: string): number | null {
  const v = pick(o, key);
  return typeof v === "number" && Number.isFinite(v) ? v : null;
}

// ── IncidentCard ──────────────────────────────────────────────────────────────

export function IncidentCard({ row, detail }: { row?: Row; detail?: unknown }) {
  const id = (row && str(row, "incident_id")) || pStr(detail, "IncidentID", 128);
  const displayId = (row && str(row, "display_id")) || pStr(detail, "DisplayID", 64);
  const title = (row && str(row, "title")) || pStr(detail, "Title", 300) || "Incident";
  const state = row ? cellText(row.state) : null;
  const created = row ? str(row, "created_at") : "";
  const verdict = pStr(detail, "Verdict", 40);
  const confLabel = pStr(detail, "ConfidenceLabel", 40);
  const conf = pNum(detail, "Confidence");
  const rc = pick(detail, "RootCause");
  const identified = pick(rc, "Identified") === true;
  const statement = pStr(rc, "Statement");
  const possible = pStr(rc, "PossibleCause");
  const loc = pick(detail, "Localization");
  const locStatement = pick(loc, "Localized") === true ? pStr(loc, "Statement") : "";
  const affected = pick(detail, "Affected");
  const devices = pList(affected, "Devices", 50);
  const sites = pList(affected, "Sites", 50);
  const services = pList(affected, "Services", 50);
  const owner = pick(detail, "Owner");
  const triage = pStr(owner, "Triage", 120);
  const missing = pList(detail, "Missing");
  // The accent follows the ENGINE's own label — the UI never invents a threshold.
  const highConfidence = identified && confLabel.toLowerCase() === "high";

  if (!row && !isObj(detail)) {
    return <p className="iris-empty" role="status">No incident was found for this question.</p>;
  }

  const name = displayId ? `${displayId} · ${title}` : title;
  const heading = id ? (
    <SafeLink kind="incident" id={id}>
      {name}
    </SafeLink>
  ) : (
    name
  );
  return (
    <article className="iris-card" aria-label="Incident">
      <header className="iris-card-head">
        <h3 className="iris-h">{heading}</h3>
        <div className="iris-card-meta">
          {state && <span className="iris-pill">{humanize(state)}</span>}
          {verdict && <span className="iris-pill">{humanize(verdict)}</span>}
          {(confLabel || conf !== null) && (
            <span className={`iris-pill${highConfidence ? " accent-evidence" : ""}`}>
              Confidence: {confLabel || `${Math.round((conf as number) * 100)}%`}
            </span>
          )}
        </div>
      </header>

      <dl className="iris-kv">
        <dt>Started</dt>
        <dd>{created ? <span className="iris-accent accent-start">{fmtDateTime(created)}</span> : <span className="iris-muted">Not recorded</span>}</dd>

        <dt>Root cause</dt>
        <dd>
          {identified && statement ? (
            <span className="iris-accent accent-cause">{statement}</span>
          ) : (
            <>
              Not identified yet.
              {possible && <> Possibly because of: {possible}</>}
            </>
          )}
        </dd>

        {locStatement && (
          <>
            <dt>Where the evidence points</dt>
            <dd>{locStatement}</dd>
          </>
        )}

        {(devices.length > 0 || sites.length > 0 || services.length > 0) && (
          <>
            <dt>Affected</dt>
            <dd>
              {[
                devices.length > 0 && `${devices.length} device${devices.length === 1 ? "" : "s"}`,
                sites.length > 0 && `${sites.length} site${sites.length === 1 ? "" : "s"}`,
                services.length > 0 && `${services.length} service${services.length === 1 ? "" : "s"}`,
              ]
                .filter(Boolean)
                .join(" · ")}
              {devices.length > 0 && (
                <ul className="iris-inline-list">
                  {devices.slice(0, 8).map((d) => (
                    <li key={d}>
                      <SafeLink kind="device" id={d}>
                        {d}
                      </SafeLink>
                    </li>
                  ))}
                </ul>
              )}
            </dd>
          </>
        )}

        {triage && (
          <>
            <dt>Who should look first</dt>
            <dd>{triage}</dd>
          </>
        )}
      </dl>

      {missing.length > 0 && (
        <>
          <h4 className="iris-h4">Evidence still needed</h4>
          <ul className="iris-plain-list">
            {missing.map((m, i) => (
              <li key={i}>{m}</li>
            ))}
          </ul>
        </>
      )}
      {!isObj(detail) && (
        <p className="iris-note">The root-cause analysis for this incident is not available yet.</p>
      )}
    </article>
  );
}

/** The engine's evidence lines for an incident, for the EVIDENCE_LIST view. */
export function incidentEvidence(detail: unknown): { known: string[]; missing: string[] } {
  const rc = pick(detail, "RootCause");
  return { known: pList(rc, "Known", 20), missing: pList(rc, "Missing", 20) };
}

// ── ChangeCard ────────────────────────────────────────────────────────────────

export function ChangeCard({ row, critical = false }: { row?: Row; critical?: boolean }) {
  if (!row) return <p className="iris-empty" role="status">No change was found for this question.</p>;
  const changeId = str(row, "change_id");
  const incidentId = str(row, "incident_id");
  const time = str(row, "time");
  return (
    <article className="iris-card" aria-label="Change">
      <header className="iris-card-head">
        <h3 className="iris-h">
          {changeId ? (
            <SafeLink kind="change" id={changeId}>
              {changeTitle(row)}
            </SafeLink>
          ) : (
            changeTitle(row)
          )}
        </h3>
        {critical && <span className="iris-pill accent-critical">Critical change</span>}
      </header>
      {cellText(row.summary) && <p className="iris-text">{cellText(row.summary)}</p>}
      <dl className="iris-kv">
        <dt>When</dt>
        <dd>{time ? fmtDateTime(time) : <span className="iris-muted">Not recorded</span>}</dd>
        <dt>Who</dt>
        <dd>{cellText(row.actor) ?? <span className="iris-muted">Not recorded</span>}</dd>
        <dt>Recorded by</dt>
        <dd>
          {changeSourceText(row)} · {automationText(row)}
        </dd>
        {str(row, "site") && (
          <>
            <dt>Site</dt>
            <dd>
              <SafeLink kind="site" id={str(row, "site")}>
                {str(row, "site")}
              </SafeLink>
            </dd>
          </>
        )}
        {cellText(row.ticket) && (
          <>
            <dt>Ticket</dt>
            <dd>{cellText(row.ticket)}</dd>
          </>
        )}
        <dt>Relation</dt>
        <dd>
          {relationText(row)}
          {incidentId && (
            <>
              {" "}
              to incident{" "}
              <SafeLink kind="incident" id={incidentId}>
                {incidentId}
              </SafeLink>
            </>
          )}
        </dd>
      </dl>
    </article>
  );
}

// ── RecommendationCard ────────────────────────────────────────────────────────

export interface Recommendation {
  title: string;
  steps: string[];
  rationale: string;
  refs: { label: string; href: string }[];
}

/** Read a recommendation out of untrusted detail; null when there is none. */
export function readRecommendation(v: unknown): Recommendation | null {
  const src = isObj(v) && isObj(pick(v, "recommendation")) ? pick(v, "recommendation") : v;
  if (!isObj(src)) return null;
  const steps = pList(src, "steps", 10);
  const title = pStr(src, "title", 200);
  if (!title && steps.length === 0) return null;
  const refsRaw = pick(src, "refs");
  const refs = Array.isArray(refsRaw)
    ? refsRaw
        .filter((r): r is Obj => isObj(r) && typeof r.label === "string" && typeof r.href === "string")
        .slice(0, 8)
        .map((r) => ({ label: clip(String(r.label), 120), href: String(r.href) }))
    : [];
  return { title: title || "Suggested next steps", steps, rationale: pStr(src, "rationale", 1000), refs };
}

export function RecommendationCard({ recommendation }: { recommendation: unknown }) {
  const rec = readRecommendation(recommendation);
  return (
    <article className="iris-card" aria-label="Recommendation">
      {rec ? (
        <>
          <header className="iris-card-head">
            <h3 className="iris-h">{rec.title}</h3>
          </header>
          {rec.rationale && <p className="iris-text">{rec.rationale}</p>}
          {rec.steps.length > 0 && (
            <ol className="iris-steps">
              {rec.steps.map((s, i) => (
                <li key={i}>{s}</li>
              ))}
            </ol>
          )}
          {rec.refs.length > 0 && (
            <ul className="iris-inline-list" aria-label="References">
              {rec.refs.map((r, i) => (
                <li key={i}>
                  {/* Checked by safeCiteHref; anything off-origin renders as text. */}
                  <SafeLink href={r.href}>{r.label}</SafeLink>
                </li>
              ))}
            </ul>
          )}
        </>
      ) : (
        <p className="iris-empty">No recommendation was made for this answer.</p>
      )}
      <footer className="iris-card-foot">No action has been executed.</footer>
    </article>
  );
}
