// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// DataProtection.tsx — the Correlix backup & recovery console.
//
// THE PAGE ANSWERS ONE QUESTION, AT THE TOP, IN PLAIN WORDS:
//
//     "Can this appliance be recovered, and how much would be lost?"
//
// Owner direction, 2026-09-08, verbatim: "Can you revise Data Protection page
// and clean up the jargon, and bring that to PROD level page. It's looking too
// messy and not clear about the goal of the page."
//
// WHAT THAT CHANGED. The console used to open with five peer sections — a
// posture hero, a nine-column coverage matrix, a seventy-row footprint table, a
// restore-point grid, two policy forms and an audit feed — every one of them at
// the same visual weight. All of it was true; none of it was an answer. The
// page now leads with the ANSWER CARD (recoverable · last good copy · what an
// outage right now would cost · last drill · the one action that matters), and
// everything else is arranged behind three plain headings:
//
//   PROTECT  — what is copied, when, and for how long. One short table
//              (store · copied · last copy · kept for), the schedule and the
//              retention as two editable lines, and whether a copy exists
//              anywhere but this host.
//   RECOVER  — restore from a copy, prove a copy with a drill, and the drill
//              history. The restore-point grid and the audit trail moved behind
//              disclosures: they are evidence, not the answer.
//   STORAGE  — bytes on disk, measured. Collapsed, because a footprint is a
//              capacity question, not a recovery one.
//
// NOTHING WAS DELETED FROM THE CONTRACT. The nine-column matrix, the
// recovery-point objectives, the destination classes, the immutability and
// encryption badges, the external host jobs, the operations ring capacity and
// the applier's ownership are all still rendered — one disclosure down, where
// an operator goes when the short answer is not enough.
//
// THE HONESTY RULE IS STILL THE PRODUCT. The server encodes an unmeasured value
// as null plus a sibling `*_detail`; `measured()` in dataProtection.model.ts is
// the only door those come through, and nothing here turns an absent value into
// a 0, a dash or a green tick. "Not measured" (nobody looked) stays visually
// distinct from "Never" (we looked, and it has not happened). And the answer is
// never green from nothing: an unreadable coverage table reads Unknown, and
// Recoverable: Yes requires a restore somebody actually proved.
//
// WORDS. Headings are one or two words; a card carries at most one short note;
// no chip or heading speaks engine ("snapshot repository", "ring", "applier",
// "restorability") — those live in ai/skills/explain/backup.*.md behind the
// `(i)`. The destructive-path text (in-place restore, delete) is UNCHANGED and
// stays on screen in full: a consequence you must read before typing a
// confirmation is not an explanation, it is part of the action.
//
// GATING. Every route behind this page is platform-global and
// requirePlatformAdmin on the server. A tenant admin sees the answer read-only
// and is told why the controls are absent, rather than buttons that 403.

import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import {
  api,
  type BackupCoverageView,
  type BackupConfig,
  type BackupOperation,
  type EngineCoverage,
  type SnapshotListView,
  type SnapshotRestoreRequest,
  type SnapshotView,
  type SnapshotPolicy,
  type StorageMeasuredReport,
  type StorageReading,
} from "../services/api";
import { useAuth } from "../hooks/useAuth";
import Icon from "../components/Icon";
import DataTable, { type Column } from "../components/DataTable";
import { Modal } from "../components/ui";
import Wizard, { type WizardStep } from "../components/Wizard";
import { operatorError } from "../lib/errors";
import AskIris from "../components/AskIris";
import {
  BACKUP_DOC,
  DEFAULT_RESTORE_PREFIX,
  confirmMatches,
  compressionRatio,
  copyStoreWord,
  coverageLabel,
  coverageTone,
  drillTone,
  drillWord,
  engineLabel,
  fmtAgo,
  fmtBytes,
  fmtDuration,
  fmtRatio,
  fmtUntil,
  headroom,
  isDrill,
  isExternal,
  isRestorable,
  keptForText,
  lastGoodCopy,
  lastProvenRestore,
  lossWindow,
  lossWindowText,
  measured,
  measuredTotalLabel,
  nextAction,
  notMeasuredText,
  offHostState,
  operationLabel,
  operationTone,
  policyRetentionWords,
  prefixUsable,
  recoverability,
  recoverableLabel,
  repositoryAdvice,
  repositoryStateFrom,
  restorableVerdict,
  restorePreview,
  rpoVerdict,
  scheduleWords,
  scopeLabel,
  shardSummary,
  snapshotStateLabel,
  snapshotTone,
  parseRetention,
  retentionHint,
  sortedEngines,
  storeLabel,
  targetMeaning,
  unmeasuredBytesText,
  verifyEvidence,
  type Measured,
  type NextAction,
  type RepositoryState,
  type Tone,
} from "./dataProtection.model";

/** How often a running operation's progress is re-read. */
const OP_POLL_MS = 2000;

/** Rows shown before the operator asks for the rest (the ShowAll convention). */
const ACTIVITY_CAP = 8;
const DRILL_CAP = 4;
const INDEX_CAP = 12;
const STORE_CAP = 12;

// ── panel plumbing ──────────────────────────────────────────────────────────

type Panel<T> = { data: T | null; error: string | null; loading: boolean };

/**
 * One independent read. Each panel owns its own failure so a dead activity feed
 * never blanks the restore points, and the failure is an operator sentence.
 */
function usePanel<T>(read: () => Promise<T>, fallback: string, key = ""): [Panel<T>, () => void] {
  const [state, setState] = useState<Panel<T>>({ data: null, error: null, loading: true });
  // The reader is held in a ref so a fresh closure each render does not re-fetch;
  // `key` is the ONLY thing that re-reads on its own, and it names the query
  // (a changed query is a different read, a re-rendered parent is not).
  const readRef = useRef(read);
  readRef.current = read;
  const reload = useCallback(() => {
    setState((p) => ({ ...p, loading: true }));
    readRef
      .current()
      .then((data) => setState({ data, error: null, loading: false }))
      .catch((e: unknown) => setState({ data: null, error: operatorError(e, fallback), loading: false }));
  }, [fallback, key]);
  useEffect(() => { reload(); }, [reload]);
  return [state, reload];
}

/** Keeps a long list to its first `n` rows until the operator asks for more. */
function useCap<T>(items: readonly T[], n: number) {
  const [expanded, setExpanded] = useState(false);
  const rows = useMemo(() => (expanded ? [...items] : items.slice(0, n)), [items, n, expanded]);
  return { rows, hidden: Math.max(0, items.length - rows.length), expanded, toggle: () => setExpanded((v) => !v) };
}

function ShowAll<T>({ cap, noun }: { cap: ReturnType<typeof useCap<T>>; noun: string }) {
  if (cap.hidden === 0 && !cap.expanded) return null;
  return (
    <button type="button" className="dp-more" onClick={cap.toggle}>
      {cap.expanded ? `Show fewer ${noun}` : `Show all ${cap.hidden + cap.rows.length} ${noun}`}
    </button>
  );
}

// ── presentation primitives ─────────────────────────────────────────────────

function Pill({ tone, children, title }: { tone: Tone; children: ReactNode; title?: string }) {
  return <span className={`dp-pill dp-${tone}`} title={title}>{children}</span>;
}

/** A section of the console: a landmark, a stable id, and its own header. */
function Section({ id, title, note, topic, actions, children }: {
  id: string; title: string; note?: string;
  /** The authored explanation for this section (ai/skills/explain/<topic>.md). */
  topic?: string;
  actions?: ReactNode; children: ReactNode;
}) {
  return (
    <section className="dp-sec" data-section={id} role="region" aria-label={title}>
      <div className="dp-sec-hd">
        <h2>{title}</h2>
        {note && <span className="dp-sec-note">{note}</span>}
        {topic && <AskIris topic={topic} label={title} />}
        <span className="dp-sp" />
        {actions}
      </div>
      <div className="dp-sec-bd">{children}</div>
    </section>
  );
}

/**
 * Renders a measured value, or the reason it is absent. This is the only way a
 * nullable contract value reaches the screen — there is deliberately no
 * formatter that takes a bare nullable number.
 */
function Value<T>({ m, render }: { m: Measured<T>; render: (v: T) => ReactNode }) {
  if (!m.measured) return <span className="dp-unmeasured">{notMeasuredText(m.reason)}</span>;
  return <>{render(m.value)}</>;
}

/** An honest state: what is wrong, the exact next action, and the procedure. */
function HonestState({ tone, headline, remedy, topic, doc }: {
  tone: Tone; headline: string; remedy: string;
  /** Where the reasoning went when the remedy was cut to one sentence. */
  topic?: string;
  doc?: string;
}) {
  return (
    <div className={`dp-honest dp-${tone}`} role="note">
      <strong>{headline}</strong>
      <span>
        {remedy}
        {topic && <AskIris topic={topic} label={headline} />}
      </span>
      {doc && (
        <a className="dp-doclink" href={doc} target="_blank" rel="noopener noreferrer">
          Back up and restore procedure
          <Icon name="external" size={12} />
        </a>
      )}
    </div>
  );
}

function Loading({ what }: { what: string }) {
  return <div className="dp-loading">Reading {what}…</div>;
}

function PanelError({ text, onRetry }: { text: string; onRetry: () => void }) {
  return (
    <div className="dp-honest dp-bad" role="alert">
      <strong>{text}</strong>
      <button type="button" className="dp-more" onClick={onRetry}>Read it again</button>
    </div>
  );
}

/** One labelled fact in the answer card or on an editable line. */
function Fact({ label, topic, children }: { label: string; topic?: string; children: ReactNode }) {
  return (
    <div className="dp-fact">
      <span className="dp-fact-k">
        {label}
        {topic && <AskIris topic={topic} label={label} />}
      </span>
      <span className="dp-fact-v">{children}</span>
    </div>
  );
}

// ── 1 · the answer ──────────────────────────────────────────────────────────

/**
 * The whole point of the page, in one card.
 *
 * Every value comes from the contract the other sections render — nothing here
 * is a second opinion. An absent value reads "not measured — <reason>", and the
 * verdict is Unknown rather than green whenever the facts behind it are missing.
 */
function AnswerCard({ coverage, repoState, now, action, onAct, canAct, busy }: {
  coverage: BackupCoverageView | null;
  repoState: RepositoryState;
  now: number;
  action: NextAction;
  onAct: () => void;
  /** False = the action mutates and this caller may not. Never a button that 403s. */
  canAct: boolean;
  busy: boolean;
}) {
  const rec = recoverability(coverage, repoState);
  const copy = lastGoodCopy(coverage);
  const lose = lossWindow(coverage);
  const proven = lastProvenRestore(coverage);

  return (
    <section className={`dp-answer dp-${rec.tone}`} data-section="answer" role="region" aria-label="Recovery">
      <p className="dp-answer-q">Can this appliance be recovered, and how much would be lost?</p>
      <div className="dp-answer-hd">
        <span className="dp-answer-k">
          Recoverable
          <AskIris topic="backup.recoverable" label="Recoverable" />
        </span>
        <span className="dp-answer-v" data-state={rec.state}>{recoverableLabel(rec.state)}</span>
        <span className="dp-sp" />
        {canAct && (
          <button type="button" className="btn accent dp-do" onClick={onAct} disabled={busy}>
            {busy ? "Working…" : action.label}
          </button>
        )}
      </div>
      <p className="dp-answer-why">{rec.reason}</p>

      <div className="dp-facts">
        <Fact label="Last good copy">
          <Value
            m={copy}
            render={(v) => (
              <>
                <span className="mono">{fmtAgo(v.at, now) ?? v.at}</span>
                <span className="dp-fine"> · {v.engine}</span>
              </>
            )}
          />
        </Fact>
        <Fact label="Would lose" topic="backup.loss-window">
          <Value
            m={lose}
            render={(v) => (
              <>
                <span className="mono">{lossWindowText(v)}</span>
                <span className="dp-fine"> · {v.engine}</span>
              </>
            )}
          />
        </Fact>
        <Fact label="Last drill" topic="backup.proven-restore">
          {proven.measured ? (
            <>
              <Pill tone="good">Drill passed</Pill>{" "}
              <span className="mono">{fmtAgo(proven.value.at, now) ?? proven.value.at}</span>
            </>
          ) : (
            <Pill tone="warn" title={proven.reason}>Never</Pill>
          )}
        </Fact>
      </div>
    </section>
  );
}

// ── 2 · protect ─────────────────────────────────────────────────────────────

/**
 * Absence in the SHORT table. The reason is a server sentence and is often a
 * paragraph — printing it in a four-column table is what made this page a wall
 * of text. It is carried here on hover and IN FULL, unabridged, one disclosure
 * down in the per-store matrix. Nothing is invented and nothing becomes a zero;
 * only the paragraph moves.
 */
function ShortAbsence({ reason }: { reason: string }) {
  return <span className="dp-unmeasured" title={notMeasuredText(reason)}>Not measured</span>;
}

/** The short table: what is copied, when it last was, and how long it is kept. */
function ProtectTable({ engines, now }: { engines: readonly EngineCoverage[]; now: number }) {
  const rows = useMemo(() => sortedEngines(engines), [engines]);
  if (rows.length === 0) {
    return (
      <HonestState
        tone="warn"
        headline="Nothing was listed to protect."
        remedy="Read it again; if the list stays empty, the data-protection service is not answering."
        doc={BACKUP_DOC}
      />
    );
  }
  return (
    <div className="dp-tblwrap">
      <table className="dp-tbl" aria-label="What is copied">
        <thead>
          <tr>
            <th scope="col">Store</th>
            <th scope="col">Copied</th>
            <th scope="col">Last copy</th>
            <th scope="col">Kept for</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((e) => {
            const kept = keptForText(e.retention);
            return (
              <tr key={e.id} className={e.covered === "not_applicable" ? "dp-row-na" : undefined}>
                <th scope="row">{engineLabel(e)}</th>
                <td>
                  <Pill tone={coverageTone(e.covered)} title={e.covered_reason}>{coverageLabel(e.covered)}</Pill>
                </td>
                <td>
                  {e.covered === "not_applicable" ? (
                    <span className="dp-fine">{e.covered_reason}</span>
                  ) : e.last_success_at ? (
                    <span className="mono">{fmtAgo(e.last_success_at, now) ?? e.last_success_at}</span>
                  ) : (
                    <Pill tone="bad" title={e.covered_reason}>Not copied yet</Pill>
                  )}
                </td>
                <td>
                  {kept.measured
                    ? <span>{kept.value}</span>
                    : <ShortAbsence reason={kept.reason} />}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

/** One editable line: a plain sentence, and the control that changes it. */
function Line({ label, topic, value, onEdit, canEdit }: {
  label: string; topic?: string; value: ReactNode; onEdit: () => void; canEdit: boolean;
}) {
  return (
    <div className="dp-line">
      <span className="dp-fact-k">
        {label}
        {topic && <AskIris topic={topic} label={label} />}
      </span>
      <span className="dp-fact-v">{value}</span>
      {canEdit && <button type="button" className="btn sm" onClick={onEdit}>Edit</button>}
    </div>
  );
}

/**
 * Everything the short table demoted, one disclosure down: the full matrix, the
 * recovery-point objectives, the destination classes and the host jobs this
 * page does not govern. Closed by default — this is evidence, not the answer.
 */
function ProtectDetails({ coverage, repoState, list, now, open, onToggle, anchor }: {
  coverage: BackupCoverageView;
  repoState: RepositoryState;
  list: SnapshotListView | null;
  now: number;
  open: boolean;
  onToggle: (v: boolean) => void;
  /** A mutable box, not a `ref=` prop: the parent scrolls to it after "Fix …". */
  anchor: { current: HTMLDetailsElement | null };
}) {
  const rows = useMemo(() => sortedEngines(coverage.engines), [coverage.engines]);
  const rpoRows = rows.filter((e) => e.covered !== "not_applicable");
  const space = headroom(list?.repository);
  return (
    <details
      className="dp-details" open={open}
      ref={(el) => { anchor.current = el; }}
      onToggle={(ev) => onToggle((ev.currentTarget as HTMLDetailsElement).open)}
    >
      <summary>Per-store details</summary>

      <ul className="dp-kv">
        <li>
          <span>Copy store</span>
          <Pill tone={repoState === "ok" ? "good" : repoState === "unverified" ? "warn" : "bad"}>
            {copyStoreWord(repoState)}
          </Pill>
          {list?.repository && (
            <span className="dp-fine">
              {list.repository.name}
              {list.repository.location ? ` · ${list.repository.location}` : ""}
            </span>
          )}
          <AskIris topic="backup.repository" label="Copy store" />
        </li>
        <li>
          <span>Free space</span>
          <Value
            m={space}
            render={(v) => (
              <span className="mono">
                {fmtBytes(v.free)} free of {fmtBytes(v.total)} ({v.freePct.toFixed(0)}%)
              </span>
            )}
          />
        </li>
      </ul>

      <div className="dp-tblwrap">
        <table className="dp-tbl" aria-label="Protection coverage by store">
          <thead>
            <tr>
              <th scope="col">Store</th>
              <th scope="col">Copied</th>
              <th scope="col">Schedule</th>
              <th scope="col">Last attempt</th>
              <th scope="col">Last success</th>
              <th scope="col">Last proved</th>
              <th scope="col" className="num">Size</th>
              <th scope="col">Kept for</th>
              <th scope="col">Where it lands</th>
            </tr>
          </thead>
          <tbody>{rows.map((e) => <CoverageRow key={e.id} e={e} now={now} />)}</tbody>
        </table>
      </div>

      <h3 className="dp-sub-h">
        Recovery point
        <AskIris topic="backup.recovery-point" label="Recovery point" />
      </h3>
      {rpoRows.length === 0 ? (
        <span className="dp-unmeasured">{notMeasuredText("the coverage table reported no stores")}</span>
      ) : (
        <ul className="dp-rpo-list">
          {rpoRows.map((e) => {
            const v = rpoVerdict(e);
            return (
              <li key={e.id} className="dp-rpo-item">
                <span className="dp-rpo-name">{engineLabel(e)}</span>
                {v.state === "unmeasured" ? (
                  <span className="dp-unmeasured">{notMeasuredText(v.reason)}</span>
                ) : v.state === "achieved_only" ? (
                  <Pill tone="muted" title={v.reason}>{v.text} · objective not set</Pill>
                ) : (
                  <Pill tone={v.state === "met" ? "good" : "warn"}>
                    {v.state === "met" ? "Objective met" : "Objective missed"} · {v.text}
                  </Pill>
                )}
              </li>
            );
          })}
        </ul>
      )}

      <h3 className="dp-sub-h">
        Outside jobs
        <AskIris topic="backup.external-job" label="Outside jobs" />
      </h3>
      {coverage.external.length === 0 ? (
        <span className="dp-fine">None reported.</span>
      ) : (
        <ul className="dp-feed">
          {coverage.external.map((x) => (
            <li key={`${x.source}:${x.name}`}>
              <span className="dp-feed-a">{x.name}</span>
              <span className="dp-fine">{x.source}{x.schedule ? ` · ${x.schedule}` : ""}</span>
              <span className="dp-fine">{x.detail}</span>
            </li>
          ))}
        </ul>
      )}
      {coverage.detail && <p className="dp-fine">{coverage.detail}</p>}
    </details>
  );
}

function BoolBadge({ on, onLabel, offLabel, detail }: {
  on: boolean | null | undefined; onLabel: string; offLabel: string; detail?: string;
}) {
  const m = measured(on, detail);
  if (!m.measured) return <span className="dp-unmeasured">{notMeasuredText(m.reason)}</span>;
  return <Pill tone={m.value ? "good" : "muted"} title={detail}>{m.value ? onLabel : offLabel}</Pill>;
}

function CoverageRow({ e, now }: { e: EngineCoverage; now: number }) {
  const label = engineLabel(e);
  if (e.covered === "not_applicable") {
    return (
      <tr className="dp-row-na">
        <th scope="row">{label}</th>
        <td colSpan={8} className="dp-na">
          <Pill tone="muted">{coverageLabel(e.covered)}</Pill> {e.covered_reason}
        </td>
      </tr>
    );
  }
  const schedule = measured(e.schedule, e.detail || e.covered_reason);
  const attempt = measured(e.last_attempt, e.detail || "no attempt has been recorded for this store");
  const verified = measured(e.last_verified, e.detail || "no restore has been proved for this store");
  const size = measured(e.size_bytes, e.size_detail);
  const kept = keptForText(e.retention);

  return (
    <tr>
      <th scope="row">
        {label}
        {isExternal(e) && (
          <span className="dp-fine dp-block" title={e.schedule?.detail}>
            External{e.schedule?.detail ? ` — ${e.schedule.detail}` : ""}
          </span>
        )}
      </th>
      <td>
        <Pill tone={coverageTone(e.covered)} title={e.covered_reason}>{coverageLabel(e.covered)}</Pill>
        <span className="dp-fine dp-block">{e.covered_reason}</span>
      </td>
      <td>
        <Value
          m={schedule}
          render={(v) => (
            <>
              <span>{scheduleWords(v.cron, v.timezone) ?? <span className="mono">{v.cron || "no schedule expression"}</span>}</span>
              {!v.enabled && <span className="dp-fine dp-block">off — {v.detail}</span>}
            </>
          )}
        />
      </td>
      <td>
        <Value
          m={attempt}
          render={(v) => (
            <>
              <Pill tone={v.result === "success" || v.result === "pass" ? "good" : v.result === "partial" ? "warn" : "bad"}>
                {v.result}
              </Pill>{" "}
              <span className="mono">{fmtAgo(v.at, now) ?? v.at}</span>
              {v.detail && v.result !== "success" ? <span className="dp-fine dp-block">{v.detail}</span> : null}
            </>
          )}
        />
      </td>
      <td>
        {e.last_success_at
          ? <span className="mono">{fmtAgo(e.last_success_at, now) ?? e.last_success_at}</span>
          : <Pill tone="bad" title={e.covered_reason}>Never succeeded</Pill>}
      </td>
      <td>
        <Value
          m={verified}
          render={(v) => (
            <>
              <Pill tone={v.result === "pass" || v.result === "success" ? "good" : "bad"}>
                {v.result === "pass" || v.result === "success" ? "Drill passed" : "Drill failed"}
              </Pill>{" "}
              <span className="mono">{fmtAgo(v.at, now) ?? v.at}</span>
            </>
          )}
        />
      </td>
      <td className="num"><Value m={size} render={(v) => fmtBytes(v)} /></td>
      <td><Value m={kept} render={(v) => <span>{v}</span>} /></td>
      <td>
        <Pill tone={e.target.kind === "none" ? "bad" : e.target.kind === "local" ? "warn" : "good"}
              title={targetMeaning(e.target.kind)}>
          {e.target.kind}
        </Pill>
        {e.target.location ? <span className="dp-fine dp-block">{e.target.location}</span> : null}
        <span className="dp-badges">
          <BoolBadge on={e.target.immutable} onLabel="Immutable" offLabel="Mutable" detail={e.target.immutable_detail} />
          <BoolBadge on={e.target.encrypted} onLabel="Encrypted" offLabel="Not encrypted" detail={e.target.encrypted_detail} />
        </span>
      </td>
    </tr>
  );
}

// ── 4 · storage ─────────────────────────────────────────────────────────────
//
// Every storage number this platform published until 2026-09-06 was DERIVED — a
// row rate times an assumed bytes-per-row. This section is the other kind: each
// figure was read back from the store that owns the bytes, and each row carries
// the query it came from and the moment it was taken. A store nobody could weigh
// keeps the same contract as the rest of the page: the reason, in words, never a
// zero. It is collapsed because a footprint is a capacity question, not a
// recovery one.

/** One store's size, or the sentence explaining why there is not one. */
function ReadingSize({ r }: { r: StorageReading }) {
  const m = measured(r.bytes_on_disk, r.detail);
  if (!m.measured) return <span className="dp-unmeasured">{unmeasuredBytesText(r.detail)}</span>;
  return <span className="mono">{fmtBytes(m.value)}</span>;
}

/** Where the bytes are inside one store, with the MEASURED ratio where it exists. */
function ComponentBreakdown({ r }: { r: StorageReading }) {
  const comps = r.components ?? [];
  if (comps.length === 0) return null;
  return (
    <details className="dp-details">
      <summary>Where the bytes are · {comps.length} largest</summary>
      <ul className="dp-parts">
        {comps.map((c) => {
          const ratio = compressionRatio(c);
          return (
            <li key={c.name} className="dp-part">
              <span className="dp-part-n mono">{c.name}</span>
              <span className="mono">{fmtBytes(c.bytes_on_disk)}</span>
              {c.rows !== null && <span className="dp-fine">{c.rows} rows</span>}
              {ratio !== null && <span className="dp-fine">{fmtRatio(ratio)} (measured)</span>}
            </li>
          );
        })}
      </ul>
    </details>
  );
}

function StorageRow({ r, now }: { r: StorageReading; now: number }) {
  const taken = fmtAgo(r.sampled_at, now) ?? r.sampled_at;
  const isMeasured = r.bytes_on_disk !== null && r.bytes_on_disk !== undefined;
  return (
    <>
      <tr>
        <th scope="row">{storeLabel(r.store)}</th>
        <td>{scopeLabel(r.scope)}</td>
        <td className="num"><ReadingSize r={r} /></td>
        <td>
          <span className="mono">{taken}</span>
          {isMeasured && r.detail ? <span className="dp-fine dp-block">{r.detail}</span> : null}
        </td>
        <td>
          {r.source
            ? <span className="dp-audit">{r.source}</span>
            : <span className="dp-unmeasured">{notMeasuredText("nothing was read, so there is no query to name")}</span>}
        </td>
      </tr>
      {(r.components ?? []).length > 0 && (
        <tr className="dp-parts-row">
          <td colSpan={5}><ComponentBreakdown r={r} /></td>
        </tr>
      )}
    </>
  );
}

function StorageSection({ report, space, now }: {
  report: StorageMeasuredReport;
  space: Measured<{ free: number; total: number; freePct: number }>;
  now: number;
}) {
  const readings = report.readings ?? [];
  const sorted = useMemo(
    () => [...readings].sort((a, b) => (b.bytes_on_disk ?? -1) - (a.bytes_on_disk ?? -1)),
    [readings],
  );
  const cap = useCap(sorted, STORE_CAP);
  return (
    <>
      <div className="dp-facts">
        <Fact label={measuredTotalLabel(report.unmeasured_stores)} topic="backup.measured-bytes">
          <span className="mono">{fmtBytes(report.total_measured_bytes)}</span>
          <span className="dp-fine"> · taken {fmtAgo(report.generated_at, now) ?? report.generated_at}</span>
        </Fact>
        <Fact label="Free space">
          <Value
            m={space}
            render={(v) => (
              <span className="mono">{fmtBytes(v.free)} free ({v.freePct.toFixed(0)}%)</span>
            )}
          />
        </Fact>
        <Fact label="Not weighed">
          {report.unmeasured_stores.length === 0 ? (
            <Pill tone="good">Every store weighed</Pill>
          ) : (
            <span className="dp-badges">
              {report.unmeasured_stores.map((s) => <Pill key={s} tone="warn">{storeLabel(s)}</Pill>)}
            </span>
          )}
        </Fact>
      </div>

      {readings.length === 0 ? (
        <HonestState tone="warn" headline="Nothing was weighed." remedy={report.measurement_note} />
      ) : (
        <details className="dp-details">
          <summary>Bytes by store · {readings.length}</summary>
          <p className="dp-fine">{report.measurement_note}</p>
          <div className="dp-tblwrap">
            <table className="dp-tbl" aria-label="Bytes on disk by store">
              <thead>
                <tr>
                  <th scope="col">Store</th>
                  <th scope="col">Scope</th>
                  <th scope="col" className="num">Bytes on disk</th>
                  <th scope="col">Taken</th>
                  <th scope="col">Read from</th>
                </tr>
              </thead>
              <tbody>
                {cap.rows.map((r) => <StorageRow key={`${r.store}:${r.scope}`} r={r} now={now} />)}
              </tbody>
            </table>
          </div>
          <ShowAll cap={cap} noun="stores" />
        </details>
      )}
    </>
  );
}

// ── 3 · recover ─────────────────────────────────────────────────────────────

/** The live state of one long-running action, polled until it settles. */
function OperationProgress({ op, onDismiss }: { op: BackupOperation; onDismiss: () => void }) {
  const settled = op.state !== "running";
  const evidence = verifyEvidence(op);
  return (
    <div className={`dp-op dp-${operationTone(op.state)}`} role="status" aria-live="polite">
      <strong>
        {operationLabel(op.kind)} · {op.state}
        {op.target?.snapshot ? ` · ${op.target.snapshot}` : ""}
      </strong>
      <span>{op.progress || (settled ? "" : "Accepted. Waiting for the first progress report.")}</span>
      {!settled && <span className="dp-op-bar"><progress aria-label="Operation progress" /></span>}
      {op.error && <span className="dp-bad-text">{op.error}</span>}
      {evidence && <span className="dp-audit">{evidence}</span>}
      {settled && (
        <span className="dp-audit">Recorded · {op.actor} · {op.kind} · {op.id}</span>
      )}
      {settled && <button type="button" className="dp-more" onClick={onDismiss}>Dismiss</button>}
    </div>
  );
}

type RestoreDraft = {
  snap: SnapshotView;
  indices: string[];        // [] = every index in the restore point
  prefix: string;
  inPlace: boolean;
  confirm: string;
};

function RestoreWizard({ draft, setDraft, onCancel, onFinish }: {
  draft: RestoreDraft;
  setDraft: (d: RestoreDraft) => void;
  onCancel: () => void;
  onFinish: () => Promise<void>;
}) {
  const all = draft.snap.indices ?? [];
  const chosen = draft.indices.length ? draft.indices : all;
  const cap = useCap(all, INDEX_CAP);
  const usable = prefixUsable(chosen, draft.prefix);

  const steps: WizardStep[] = [
    {
      id: "scope",
      title: "Scope",
      hint: "Restore the whole copy, or only the indices you name.",
      isValid: () => draft.indices.length === 0 || draft.indices.length > 0,
      render: () => (
        <div className="dp-form">
          <label className="dp-check">
            <input
              type="checkbox"
              checked={draft.indices.length === 0}
              onChange={(ev) => setDraft({ ...draft, indices: ev.target.checked ? [] : [...all] })}
            />
            Whole copy ({all.length} indices)
          </label>
          {draft.indices.length > 0 && (
            <fieldset className="dp-fieldset">
              <legend>Indices to restore</legend>
              {cap.rows.map((n) => (
                <label key={n} className="dp-check">
                  <input
                    type="checkbox"
                    checked={draft.indices.includes(n)}
                    onChange={(ev) =>
                      setDraft({
                        ...draft,
                        indices: ev.target.checked
                          ? [...draft.indices, n]
                          : draft.indices.filter((x) => x !== n),
                      })
                    }
                  />
                  <span className="mono">{n}</span>
                </label>
              ))}
              <ShowAll cap={cap} noun="indices" />
            </fieldset>
          )}
        </div>
      ),
    },
    {
      id: "destination",
      title: "Destination",
      hint: "By default the data lands beside the live indices under a new name. Nothing live is touched.",
      isValid: () => (draft.inPlace ? true : usable),
      render: () => (
        <div className="dp-form">
          <label className="dp-check">
            <input
              type="radio" name="dp-restore-target"
              checked={!draft.inPlace}
              onChange={() => setDraft({ ...draft, inPlace: false, confirm: "" })}
            />
            Restore alongside, under a new name (recommended)
          </label>
          <label className="dp-field">
            <span>Name prefix</span>
            <input
              className="dp-input mono" aria-label="Name prefix for the restored indices"
              value={draft.prefix} disabled={draft.inPlace}
              onChange={(ev) => setDraft({ ...draft, prefix: ev.target.value })}
            />
          </label>
          {!draft.inPlace && (
            <div className="dp-preview">
              <span className="dp-fine">New names</span>
              <ul>
                {chosen.slice(0, 5).map((n) => {
                  const to = restorePreview(n, draft.prefix);
                  return (
                    <li key={n} className="mono">
                      {n} → {to ?? <span className="dp-unmeasured">this prefix is not a usable index name</span>}
                    </li>
                  );
                })}
              </ul>
              {!usable && (
                <p className="dp-bad-text">
                  An empty or illegal prefix would put the restored data back on the live names.
                  That is an overwrite, not a rename — give a usable prefix, or choose the in-place
                  path below and confirm it.
                </p>
              )}
            </div>
          )}
          <label className="dp-check dp-danger">
            <input
              type="radio" name="dp-restore-target"
              checked={draft.inPlace}
              onChange={() => setDraft({ ...draft, inPlace: true })}
            />
            Restore in place, overwriting the live data
          </label>
        </div>
      ),
    },
    ...(draft.inPlace
      ? [{
          id: "in-place",
          title: "Confirm overwrite",
          hint: "This is the destructive path. Read the consequence, then type the confirmation.",
          isValid: () => confirmMatches(draft.confirm, draft.snap.name),
          render: () => (
            <div className="dp-form">
              <div className="dp-honest dp-bad" role="note">
                <strong>An in-place restore closes and overwrites the live indices.</strong>
                <span>
                  Everything written to {chosen.length} index(es) since{" "}
                  {draft.snap.ended_at || draft.snap.started_at || draft.snap.name} is lost and cannot be
                  recovered from this restore point. Search is unavailable for those indices while it runs.
                </span>
              </div>
              <label className="dp-field">
                <span>Type the restore point name <span className="mono">{draft.snap.name}</span> to authorise it</span>
                <input
                  className="dp-input mono"
                  aria-label={`Type ${draft.snap.name} to authorise the in-place restore`}
                  value={draft.confirm}
                  onChange={(ev) => setDraft({ ...draft, confirm: ev.target.value })}
                />
              </label>
            </div>
          ),
        } as WizardStep]
      : []),
    {
      id: "review",
      title: "Review",
      isValid: () => true,
      render: () => (
        <dl className="dp-review">
          <div><dt>Copy</dt><dd className="mono">{draft.snap.name}</dd></div>
          <div><dt>Taken</dt><dd className="mono">{draft.snap.ended_at || draft.snap.started_at || "start time not reported"}</dd></div>
          <div><dt>Indices</dt><dd>{draft.indices.length === 0 ? `whole copy (${all.length})` : `${draft.indices.length} selected`}</dd></div>
          <div>
            <dt>Destination</dt>
            <dd>
              {draft.inPlace
                ? "In place — the live indices are closed and replaced"
                : `Alongside, under the prefix ${draft.prefix}`}
            </dd>
          </div>
        </dl>
      ),
    },
  ];

  return <Wizard steps={steps} onFinish={onFinish} onCancel={onCancel} finishLabel="Start restore" />;
}

function DeleteConfirm({ snap, onCancel, onConfirm }: {
  snap: SnapshotView; onCancel: () => void; onConfirm: (typed: string) => Promise<void>;
}) {
  const [typed, setTyped] = useState("");
  const [busy, setBusy] = useState(false);
  const ok = confirmMatches(typed, snap.name);
  return (
    <div className="dp-form">
      <div className="dp-honest dp-bad" role="note">
        <strong>Deleting a restore point cannot be undone.</strong>
        <span>
          Everything only this copy holds becomes unrecoverable. If it is the newest good copy, the
          achieved recovery point moves back to the one before it from the moment it is gone.
        </span>
      </div>
      <label className="dp-field">
        <span>Type the restore point name <span className="mono">{snap.name}</span> to confirm</span>
        <input
          className="dp-input mono"
          aria-label={`Type ${snap.name} to confirm deletion`}
          value={typed}
          onChange={(e) => setTyped(e.target.value)}
        />
      </label>
      <div className="dp-actions">
        <button type="button" className="btn" onClick={onCancel} disabled={busy}>Cancel</button>
        <button
          type="button" className="btn danger" disabled={!ok || busy}
          onClick={async () => { setBusy(true); try { await onConfirm(typed); } finally { setBusy(false); } }}
        >
          {busy ? "Deleting…" : "Delete restore point"}
        </button>
      </div>
    </div>
  );
}

// ── the page ────────────────────────────────────────────────────────────────

export default function DataProtection() {
  const { user, loading: authLoading } = useAuth();
  const platformAdmin = !!user?.platform_admin;
  // A single render-time clock: every relative age on one paint is measured
  // from the same instant, so two rows can be compared against each other.
  const [now, setNow] = useState(() => Date.now());
  // Sizes cost one repository call per restore point, so they are opt-in.
  const [withSizes, setWithSizes] = useState(false);

  const readList = useCallback(() => api.snapshotList({ sizes: withSizes }), [withSizes]);

  const [coverage, reloadCoverage] = usePanel<BackupCoverageView>(
    () => api.backupCoverage(),
    "The list of what is copied could not be read.",
  );
  const [list, reloadList] = usePanel<SnapshotListView>(
    readList,
    "The restore points could not be read.",
    String(withSizes),
  );
  const [storage, reloadStorage] = usePanel<StorageMeasuredReport>(
    () => api.storageMeasured(),
    "The measured bytes on disk could not be read.",
  );
  const [policy, reloadPolicy] = usePanel<SnapshotPolicy>(
    () => api.snapshotPolicy(),
    "The schedule could not be read.",
  );
  const [bundle, reloadBundle] = usePanel(
    () => api.backupConfig(),
    "The off-host destination could not be read.",
  );
  const [ops, reloadOps] = usePanel(
    () => api.backupOperations(),
    "The activity trail could not be read.",
  );

  const [op, setOp] = useState<BackupOperation | null>(null);
  const [opError, setOpError] = useState<string | null>(null);
  const [restore, setRestore] = useState<RestoreDraft | null>(null);
  const [toDelete, setToDelete] = useState<SnapshotView | null>(null);
  const [editing, setEditing] = useState<null | "schedule" | "offhost">(null);
  const [filter, setFilter] = useState("");
  const [detailsOpen, setDetailsOpen] = useState(false);
  const detailsRef = useRef<HTMLDetailsElement | null>(null);

  const refreshAll = useCallback(() => {
    setNow(Date.now());
    reloadCoverage();
    reloadList();
    reloadOps();
    reloadStorage();
  }, [reloadCoverage, reloadList, reloadOps, reloadStorage]);

  // Poll one operation to completion. The first read happens immediately so the
  // operator sees the action was accepted, not a silent pause.
  const opId = op?.id ?? null;
  const opRunning = op?.state === "running";
  useEffect(() => {
    if (!opId || !opRunning) return;
    let live = true;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const tick = () => {
      api.backupOperation(opId)
        .then((next) => {
          if (!live) return;
          setOp(next);
          if (next.state !== "running") { refreshAll(); return; }
          timer = setTimeout(tick, OP_POLL_MS);
        })
        .catch((e: unknown) => {
          if (!live) return;
          setOpError(operatorError(e, "The action was started, but its progress could not be read."));
        });
    };
    // First read immediately (a create often finishes inside a second), then on
    // the poll cadence — an operator must not stare at "queued" for two seconds.
    timer = setTimeout(tick, 0);
    return () => { live = false; if (timer) clearTimeout(timer); };
  }, [opId, opRunning, refreshAll]);

  const start = useCallback(async (run: () => Promise<BackupOperation>) => {
    setOpError(null);
    try {
      const accepted = await run();
      setOp(accepted);
      if (accepted.state !== "running") refreshAll();
    } catch (e: unknown) {
      setOpError(operatorError(e, "The action was not accepted."));
    }
  }, [refreshAll]);

  const snapshots = list.data?.snapshots ?? [];
  const repoBroken = !!list.error;
  const repoState = repositoryStateFrom(list.data?.repository, policy.data?.repository, repoBroken);
  const advice = repositoryAdvice(repoState, list.error ?? list.data?.repository?.detail ?? "");

  // The ONE action. It is derived from exactly the facts the answer card reads,
  // so the button and the sentence beside it can never disagree.
  const action = useMemo(
    () => nextAction(coverage.data, repoState, lastProvenRestore(coverage.data), lastGoodCopy(coverage.data)),
    [coverage.data, repoState],
  );
  const runAction = useCallback(() => {
    switch (action.kind) {
      case "backup":
        if (platformAdmin) start(() => api.createSnapshot());
        return;
      case "drill":
        if (platformAdmin) start(() => api.verifySnapshot());
        return;
      case "fix":
        // "Fix" is not something a page can do for you: it opens the evidence
        // that names the failing part, rather than pretending to repair it.
        setDetailsOpen(true);
        requestAnimationFrame(() => detailsRef.current?.scrollIntoView({ block: "start" }));
        return;
      default:
        refreshAll();
    }
  }, [action.kind, platformAdmin, start, refreshAll]);

  const columns: Column<SnapshotView>[] = useMemo(() => [
    {
      key: "name", header: "Copy", width: "1.6fr", sortable: true,
      text: (r) => r.name,
      render: (r) => <span className="mono dp-nowrap" title={r.name}>{r.name}</span>,
    },
    {
      key: "state", header: "State", width: 130, sortable: true,
      text: (r) => r.state,
      render: (r) => <Pill tone={snapshotTone(r.state)}>{snapshotStateLabel(r.state)}</Pill>,
    },
    {
      key: "started", header: "Started", width: 180, sortable: true,
      sortValue: (r) => r.started_at ?? "",
      text: (r) => r.started_at ?? "",
      render: (r) => <span className="mono">{r.started_at ?? <span className="dp-unmeasured">start time not reported</span>}</span>,
    },
    {
      key: "duration", header: "Duration", width: 100, align: "right", sortable: true,
      sortValue: (r) => r.duration_seconds,
      render: (r) => (r.ended_at ? fmtDuration(r.duration_seconds) : <span className="dp-fine">still running</span>),
    },
    {
      key: "indices", header: "Indices", width: 90, align: "right", sortable: true,
      sortValue: (r) => r.index_count,
      render: (r) => String(r.index_count),
    },
    {
      key: "size", header: "Size", width: 150, align: "right", sortable: true,
      sortValue: (r) => r.size_bytes ?? -1,
      render: (r) => <Value m={measured(r.size_bytes, r.size_detail)} render={(v) => fmtBytes(v)} />,
    },
    {
      key: "verified", header: "Proved", width: 210,
      text: (r) => String(r.restorable_verified),
      render: (r) => {
        const v = restorableVerdict(r);
        if (v.state === "never") return <Pill tone="warn" title={v.detail}>Never proved</Pill>;
        return (
          <Pill tone={v.state === "verified" ? "good" : "bad"} title={v.detail}>
            {v.state === "verified" ? "Drill passed" : "Drill failed"}
            {v.at ? ` · ${fmtAgo(v.at, now) ?? v.at}` : ""}
          </Pill>
        );
      },
    },
    {
      key: "failures", header: "Failures", width: "1fr",
      text: (r) => r.failures.map((f) => f.reason).join(" "),
      render: (r) => {
        if (r.failures.length === 0) return <span className="dp-fine">none reported</span>;
        const first = r.failures[0];
        return (
          <span className="dp-bad-text" title={r.failures.map((f) => `${f.index}[${f.shard}] ${f.reason}`).join("\n")}>
            {shardSummary(r) ? `${shardSummary(r)} · ` : ""}{first.index}[{first.shard}] {first.reason}
            {r.failures_trimmed > 0 ? ` · ${r.failures_trimmed} more not listed` : ""}
          </span>
        );
      },
    },
  ], [now]);

  const rowActions = useCallback((r: SnapshotView) => {
    if (!platformAdmin) return null;
    return (
      <span className="dp-rowacts">
        <button
          type="button" className="btn sm" disabled={!isRestorable(r)}
          title={isRestorable(r) ? "Restore from this copy" : "Only a completed copy can be restored"}
          onClick={() => setRestore({ snap: r, indices: [], prefix: DEFAULT_RESTORE_PREFIX, inPlace: false, confirm: "" })}
        >
          Restore…
        </button>
        <button
          type="button" className="btn sm" disabled={!isRestorable(r)}
          onClick={() => start(() => api.verifySnapshot(r.name))}
        >
          Run a drill
        </button>
        <button type="button" className="btn sm danger" onClick={() => setToDelete(r)}>
          Delete…
        </button>
      </span>
    );
  }, [platformAdmin, start]);

  const opRows = ops.data?.operations ?? [];
  const drills = useMemo(() => opRows.filter((o) => isDrill(o.kind)), [opRows]);
  const activityCap = useCap(opRows, ACTIVITY_CAP);
  const drillCap = useCap(drills, DRILL_CAP);
  const proven = lastProvenRestore(coverage.data);
  const space = headroom(list.data?.repository ?? policy.data?.repository);
  const offHost = offHostState(bundle.data?.config);
  const schedule = policy.data
    ? (policy.data.enabled
        ? (scheduleWords(policy.data.schedule_cron) ?? policy.data.schedule_cron)
        : "Off")
    : null;
  const nextRun = measured(
    policy.data?.enabled ? policy.data.next_run || null : null,
    policy.data
      ? (policy.data.enabled ? "the schedule did not report its next run" : "the schedule is off")
      : "the schedule could not be read",
  );

  return (
    <div className="dp-page">
      {/* ── the answer ── */}
      {coverage.error ? (
        <div className="dp-answer dp-bad" data-section="answer" role="region" aria-label="Recovery">
          <p className="dp-answer-q">Can this appliance be recovered, and how much would be lost?</p>
          <PanelError text={coverage.error} onRetry={reloadCoverage} />
        </div>
      ) : coverage.loading && !coverage.data ? (
        <div className="dp-answer dp-muted" data-section="answer" role="region" aria-label="Recovery">
          <p className="dp-answer-q">Can this appliance be recovered, and how much would be lost?</p>
          <Loading what="the recovery answer" />
        </div>
      ) : (
        <AnswerCard
          coverage={coverage.data}
          repoState={repoState}
          now={now}
          action={action}
          onAct={runAction}
          canAct={platformAdmin || action.kind === "fix" || action.kind === "reread"}
          busy={op?.state === "running"}
        />
      )}

      {opError && <HonestState tone="bad" headline="The action did not complete." remedy={opError} />}
      {op && <OperationProgress op={op} onDismiss={() => setOp(null)} />}
      {advice && <HonestState tone={advice.tone} headline={advice.headline} remedy={advice.remedy} doc={advice.doc} />}
      {!authLoading && !platformAdmin && (
        <HonestState
          tone="muted"
          headline="This page is read-only for you."
          remedy="Backing up, restoring and drills need a platform administrator."
          topic="backup.read-only"
        />
      )}

      {/* ── protect ── */}
      <Section
        id="protect"
        title="Protect"
        note="What is copied, and how long it is kept."
        actions={
          <>
            <button type="button" className="btn sm" onClick={refreshAll}>
              <Icon name="refresh" size={13} /> Re-read
            </button>
            {platformAdmin && (
              <button type="button" className="btn sm" onClick={() => start(() => api.createSnapshot())}>
                Back up now
              </button>
            )}
          </>
        }
      >
        {coverage.data ? (
          <>
            <ProtectTable engines={coverage.data.engines} now={now} />

            <div className="dp-lines">
              <Line
                label="Schedule" canEdit={platformAdmin} onEdit={() => setEditing("schedule")}
                value={
                  policy.error ? <span className="dp-bad-text">{policy.error}</span>
                  : schedule === null ? <span className="dp-fine">Reading…</span>
                  : (
                    <>
                      <span>{schedule}</span>
                      <Value m={nextRun} render={(v) => <span className="dp-fine"> · next {fmtUntil(v, now) ?? v}</span>} />
                    </>
                  )
                }
              />
              <Line
                label="Retention" canEdit={platformAdmin} onEdit={() => setEditing("schedule")}
                topic="backup.kept-for"
                value={
                  policy.data
                    ? <span>{policyRetentionWords(policy.data.retention_max_count, policy.data.retention_max_age_days)}</span>
                    : <span className="dp-fine">Reading…</span>
                }
              />
              <Line
                label="Off-host copy" canEdit={platformAdmin} onEdit={() => setEditing("offhost")}
                topic="backup.off-host"
                value={
                  bundle.error ? <span className="dp-bad-text">{bundle.error}</span> : (
                    <>
                      <Pill tone={offHost.tone}>{offHost.word}</Pill>{" "}
                      {bundle.data?.config.remote_url
                        ? <span className="mono">{bundle.data.config.remote_url}</span>
                        : <span className="dp-fine">One disk failure would lose both copies.</span>}
                    </>
                  )
                }
              />
            </div>

            <ProtectDetails
              coverage={coverage.data}
              repoState={repoState}
              list={list.data}
              now={now}
              open={detailsOpen}
              onToggle={setDetailsOpen}
              anchor={detailsRef}
            />
          </>
        ) : coverage.error ? null : (
          <Loading what="what is copied" />
        )}
      </Section>

      {/* ── recover ── */}
      <Section
        id="recover"
        title="Recover"
        note="Prove a restore works before you need it."
        actions={
          platformAdmin ? (
            <button type="button" className="btn sm accent" onClick={() => start(() => api.verifySnapshot())}>
              Run a drill
            </button>
          ) : null
        }
      >
        {drills.length === 0 && proven.measured ? (
          // The answer card says a restore WAS proved; this list is the drills
          // this page ran, and it is empty. Saying "never proved" here would
          // contradict the card two inches above it.
          <HonestState
            tone="muted"
            headline="No drill has run from here."
            remedy={`The last proof came from ${proven.value.engine}, ${fmtAgo(proven.value.at, now) ?? proven.value.at}.`}
            topic="backup.proven-restore"
          />
        ) : drills.length === 0 ? (
          <HonestState
            tone="warn"
            headline="No restore has ever been proved."
            remedy="Run a drill; its result is recorded here."
            topic="backup.proven-restore"
            doc={BACKUP_DOC}
          />
        ) : (
          <>
            <ul className="dp-feed">
              {drillCap.rows.map((a) => (
                <li key={a.id}>
                  <Pill tone={drillTone(a)}>{drillWord(a)}</Pill>
                  <span className="mono dp-feed-t">{fmtAgo(a.started_at, now) ?? a.started_at}</span>
                  <span className="dp-fine">{a.target?.snapshot ?? a.verify?.snapshot ?? "target not recorded"}</span>
                  {a.error && <span className="dp-bad-text">{a.error}</span>}
                </li>
              ))}
            </ul>
            <ShowAll cap={drillCap} noun="drills" />
          </>
        )}

        <details className="dp-details">
          <summary>Restore from a copy · {list.data?.total ?? snapshots.length}</summary>
          <div className="dp-rowhead">
            <input
              className="dp-input dp-filter"
              placeholder="Filter copies"
              aria-label="Filter copies"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
            />
            <button
              type="button" className="btn sm" aria-pressed={withSizes}
              title="Measuring sizes costs one repository call per copy"
              onClick={() => setWithSizes((v) => !v)}
            >
              {withSizes ? "Stop measuring sizes" : "Measure sizes"}
            </button>
          </div>
          {list.error ? (
            <PanelError text={list.error} onRetry={reloadList} />
          ) : list.loading && !list.data ? (
            <Loading what="the copies" />
          ) : list.data?.detail && snapshots.length === 0 ? (
            <HonestState
              tone="bad"
              headline="The copies could not be listed."
              remedy={list.data.detail}
              doc={BACKUP_DOC}
            />
          ) : snapshots.length === 0 ? (
            <HonestState
              tone="warn"
              headline="No copy exists yet."
              remedy="Back up now, then run a drill."
              topic="backup.no-restore-point"
              doc={BACKUP_DOC}
            />
          ) : (
            <>
              {list.data?.detail && <p className="dp-fine">{list.data.detail}</p>}
              <DataTable
                rows={snapshots}
                columns={columns}
                rowKey={(r) => r.name}
                filter={filter}
                height={360}
                rowActions={rowActions}
                ariaLabel="Copies"
                empty={<span className="dp-fine">No copy matches that filter.</span>}
              />
            </>
          )}
        </details>

        <details className="dp-details">
          <summary>Activity · {opRows.length}</summary>
          {ops.error ? (
            <PanelError text={ops.error} onRetry={reloadOps} />
          ) : ops.loading && !ops.data ? (
            <Loading what="the activity trail" />
          ) : opRows.length === 0 ? (
            <p className="dp-fine">{ops.data?.detail || "Nothing has run since the platform last started."}</p>
          ) : (
            <>
              <ul className="dp-feed">
                {activityCap.rows.map((a) => (
                  <li key={a.id}>
                    <span className="mono dp-feed-t">{a.started_at}</span>
                    <Pill tone={operationTone(a.state)}>{a.state}</Pill>
                    <span className="dp-feed-a">{a.actor}</span>
                    <span>{operationLabel(a.kind)}{a.target?.snapshot ? ` · ${a.target.snapshot}` : ""}</span>
                    {a.error && <span className="dp-bad-text">{a.error}</span>}
                  </li>
                ))}
              </ul>
              <ShowAll cap={activityCap} noun="entries" />
              {ops.data && <p className="dp-fine">The platform keeps the newest {ops.data.capacity} entries.</p>}
            </>
          )}
        </details>
      </Section>

      {/* ── storage ── */}
      <Section
        id="storage"
        title="Storage"
        note="Measured from each store, never estimated."
        topic="backup.measured-bytes"
      >
        {storage.error ? (
          <PanelError text={storage.error} onRetry={reloadStorage} />
        ) : storage.data ? (
          <StorageSection report={storage.data} space={space} now={now} />
        ) : (
          <Loading what="the bytes on disk" />
        )}
      </Section>

      {/* ── modals ── */}
      {editing === "schedule" && (
        <Modal title="Schedule and retention" onClose={() => setEditing(null)} wide>
          <SnapshotPolicyForm
            panel={policy}
            onReload={reloadPolicy}
            canEdit={platformAdmin}
            onSaved={refreshAll}
          />
        </Modal>
      )}

      {editing === "offhost" && (
        <Modal title="Off-host copy" onClose={() => setEditing(null)} wide>
          <BundlePolicyForm panel={bundle} onReload={reloadBundle} canEdit={platformAdmin} />
        </Modal>
      )}

      {restore && (
        <Modal
          title={`Restore from ${restore.snap.name}`}
          subtitle="Nothing is written until the last step is confirmed."
          onClose={() => setRestore(null)}
          wide
        >
          <RestoreWizard
            draft={restore}
            setDraft={setRestore}
            onCancel={() => setRestore(null)}
            onFinish={async () => {
              const req: SnapshotRestoreRequest = restore.inPlace
                ? { snapshot: restore.snap.name, indices: restore.indices, mode: "in_place", confirm: restore.confirm }
                : { snapshot: restore.snap.name, indices: restore.indices, mode: "renamed", rename_prefix: restore.prefix };
              setRestore(null);
              await start(() => api.restoreSnapshot(req));
            }}
          />
        </Modal>
      )}

      {toDelete && (
        <Modal title={`Delete ${toDelete.name}`} onClose={() => setToDelete(null)}>
          <DeleteConfirm
            snap={toDelete}
            onCancel={() => setToDelete(null)}
            onConfirm={async (typed) => {
              const name = toDelete.name;
              setToDelete(null);
              await start(() => api.deleteSnapshot(name, typed));
            }}
          />
        </Modal>
      )}
    </div>
  );
}

// ── schedule and retention (modal) ──────────────────────────────────────────

function SnapshotPolicyForm({ panel, onReload, canEdit, onSaved }: {
  panel: Panel<SnapshotPolicy>; onReload: () => void; canEdit: boolean; onSaved: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ tone: Tone; text: string } | null>(null);
  // Turning the schedule OFF is an intent the platform records with its reason,
  // so a stopped schedule can never be mistaken for an accident later. The
  // reason is asked for BEFORE the write, not after.
  const [disableReason, setDisableReason] = useState<string | null>(null);
  const snap = panel.data;

  const save = async (upd: Parameters<typeof api.setSnapshotPolicy>[0]) => {
    setBusy(true); setMsg(null);
    try {
      await api.setSnapshotPolicy(upd);
      setMsg({ tone: "good", text: "Saved." });
      onReload();
      onSaved();
    } catch (e: unknown) {
      setMsg({ tone: "bad", text: operatorError(e, "The change could not be saved.") });
    } finally { setBusy(false); }
  };

  if (panel.error) return <PanelError text={panel.error} onRetry={onReload} />;
  if (!snap) return <Loading what="the schedule" />;

  return (
    <div className="dp-policy">
      <div className="dp-policy-hd">
        <label className="dp-check">
          <input
            type="checkbox" checked={snap.enabled} disabled={busy || !canEdit}
            onChange={(e) => {
              if (e.target.checked) { setDisableReason(null); save({ enabled: true }); return; }
              setDisableReason("");
            }}
          />
          Copies run on this schedule
        </label>
      </div>

      {disableReason !== null && (
        <div className="dp-honest dp-warn" role="note">
          <strong>Turning this off stops new copies being made.</strong>
          <span>Say why, so whoever finds it off later knows it was deliberate.</span>
          <label className="dp-field">
            <span>Reason</span>
            <input
              className="dp-input" aria-label="Reason for turning the schedule off"
              value={disableReason} onChange={(e) => setDisableReason(e.target.value)}
            />
          </label>
          <div className="dp-actions">
            <button type="button" className="btn" onClick={() => setDisableReason(null)}>Keep it on</button>
            <button
              type="button" className="btn danger" disabled={busy || !disableReason.trim()}
              onClick={async () => { const reason = disableReason.trim(); setDisableReason(null); await save({ enabled: false, reason }); }}
            >
              Turn it off
            </button>
          </div>
        </div>
      )}

      {snap.detail && (
        <HonestState tone="warn" headline="The schedule could not be read in full." remedy={snap.detail} doc={BACKUP_DOC} />
      )}
      {!snap.enabled && (
        <HonestState
          tone="bad"
          headline="The schedule is off."
          topic="backup.recovery-point"
          remedy={
            "No new copies will be made. " +
            (snap.disabled_reason
              ? `Turned off by ${snap.disabled_by || "an unrecorded operator"}${snap.disabled_at ? ` on ${snap.disabled_at}` : ""}: ${snap.disabled_reason}`
              : "The platform recorded no reason for it being off, so this may not have been deliberate.")
          }
          doc={BACKUP_DOC}
        />
      )}
      {snap.managed_by && snap.managed_by !== "gui" && (
        <HonestState
          tone="warn"
          headline="This switch is not authoritative."
          remedy={`The on/off state is owned by ${snap.managed_by}, so a change made here can be overwritten by it.`}
        />
      )}

      <div className="dp-grid3">
        <label className="dp-field">
          <span>Window (cron, UTC)</span>
          <input
            className="dp-input mono" defaultValue={snap.schedule_cron} disabled={busy || !canEdit}
            aria-label="Copy window, cron in UTC"
            onBlur={(e) => { if (e.target.value !== snap.schedule_cron) save({ schedule_cron: e.target.value }); }}
          />
        </label>
        <label className="dp-field">
          <span>Keep newest</span>
          <input
            className="dp-input" type="number" min={1} max={365} defaultValue={snap.retention_max_count}
            disabled={busy || !canEdit} aria-label="Retention, keep newest count"
            onBlur={(e) => { const n = parseInt(e.target.value, 10); if (n && n !== snap.retention_max_count) save({ retention_max_count: n }); }}
          />
        </label>
        <label className="dp-field">
          <span>Maximum age (days)</span>
          <input
            className="dp-input" type="number" min={0} max={3650} placeholder="no age limit"
            defaultValue={snap.retention_max_age_days || ""} disabled={busy || !canEdit}
            aria-label="Retention, maximum age in days"
            onBlur={(e) => {
              const n = e.target.value === "" ? 0 : parseInt(e.target.value, 10);
              if (!Number.isNaN(n) && n !== snap.retention_max_age_days) save({ retention_max_age_days: n });
            }}
          />
        </label>
      </div>

      <ul className="dp-kv">
        <li>
          <span>Last run</span>
          {snap.last_run ? (
            <>
              <Pill tone={snap.last_run.status === "SUCCESS" ? "good" : "bad"}>{snapshotStateLabel(snap.last_run.status)}</Pill>
              <span className="mono">
                {snap.last_run.time ?? "end time not reported"}
                {snap.last_run.duration_seconds ? ` · ${fmtDuration(snap.last_run.duration_seconds)}` : ""}
              </span>
            </>
          ) : (
            <span className="dp-unmeasured">{notMeasuredText("the schedule has not reported a run")}</span>
          )}
        </li>
        <li>
          <span>Next run</span>
          <Value
            m={measured(
              snap.enabled ? snap.next_run || null : null,
              snap.enabled ? "the schedule did not report its next run" : "the schedule is off",
            )}
            render={(v) => <span className="mono">{v}</span>}
          />
        </li>
        {snap.managed_by && (
          <li>
            <span>Owned by</span>
            <span className="dp-fine">{snap.managed_by}{snap.managed_by_detail ? ` — ${snap.managed_by_detail}` : ""}</span>
          </li>
        )}
      </ul>

      {msg && <p className={`dp-msg dp-${msg.tone}`} role="status">{msg.text}</p>}
      {!canEdit && <p className="dp-fine">Changing this needs a platform administrator.</p>}
    </div>
  );
}

// ── off-host copy (modal) ───────────────────────────────────────────────────

function BundlePolicyForm({ panel, onReload, canEdit }: {
  panel: Panel<{ config: BackupConfig }>; onReload: () => void; canEdit: boolean;
}) {
  const [cfg, setCfg] = useState<BackupConfig | null>(null);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ tone: Tone; text: string } | null>(null);

  useEffect(() => { if (panel.data) setCfg(panel.data.config); }, [panel.data]);

  if (panel.error) return <PanelError text={panel.error} onRetry={onReload} />;
  if (!cfg) return <Loading what="the off-host destination" />;

  const save = async () => {
    setBusy(true); setMsg(null);
    try {
      const r = await api.setBackupConfig(cfg);
      setCfg(r.config);
      // Re-read the panel, the way the snapshot form does. Without this the
      // retention hint went on quoting the value loaded at MOUNT, so after a
      // save it could tell the operator "Saving keeps 7" while the platform
      // was already keeping 14.
      onReload();
      setMsg({ tone: "good", text: "Saved. The host applier picks it up on its next run." });
    } catch (e: unknown) {
      setMsg({ tone: "bad", text: operatorError(e, "The change could not be saved.") });
    } finally { setBusy(false); }
  };

  return (
    <div className="dp-policy">
      {!cfg.remote_url && (
        <HonestState
          tone="warn"
          headline="There is no off-host copy."
          remedy="One disk failure would lose both copies — name a destination below."
          doc={BACKUP_DOC}
        />
      )}
      <div className="dp-grid2">
        <label className="dp-field">
          <span>Destination</span>
          <input
            className="dp-input" aria-label="Off-host destination" disabled={!canEdit}
            placeholder="rsync://host/correlix/ · s3://bucket/ · /mnt/nas/correlix/"
            value={cfg.remote_url} onChange={(e) => setCfg({ ...cfg, remote_url: e.target.value })}
          />
        </label>
        <label className="dp-field">
          <span>Push command</span>
          <input
            className="dp-input mono" aria-label="Push command" disabled={!canEdit}
            placeholder="rsync -a (default) · rclone copy"
            value={cfg.push_command ?? ""} onChange={(e) => setCfg({ ...cfg, push_command: e.target.value })}
          />
        </label>
      </div>
      <label className="dp-check">
        <input
          type="checkbox" checked={cfg.schedule_enabled} disabled={!canEdit}
          onChange={(e) => setCfg({ ...cfg, schedule_enabled: e.target.checked })}
        />
        Copy off-host on a schedule
      </label>
      <div className="dp-grid2">
        <label className="dp-field">
          <span>Schedule (cron)</span>
          <input
            className="dp-input mono" aria-label="Off-host schedule, cron" disabled={!canEdit}
            placeholder="30 2 * * *  (02:30 daily)"
            value={cfg.schedule_cron ?? ""} onChange={(e) => setCfg({ ...cfg, schedule_cron: e.target.value })}
          />
        </label>
        <label className="dp-field">
          <span>Copies kept<AskIris topic="backup.copies-kept" label="Copies kept" /></span>
          <input
            className="dp-input" type="number" min={0} max={365} step={1} inputMode="numeric"
            aria-label="Off-host copies kept" disabled={!canEdit}
            placeholder="unset"
            value={cfg.retain_count ?? ""}
            onChange={(e) => {
              // An empty box is "not set", never 0 — see parseRetention. A
              // value the server would refuse is simply not applied.
              const r = parseRetention(e.target.value);
              if (r.ok) setCfg({ ...cfg, retain_count: r.value });
            }}
          />
        </label>
      </div>
      <p className="dp-fine">{retentionHint(cfg.retain_count, panel.data?.config.retain_count)}</p>
      {msg && <p className={`dp-msg dp-${msg.tone}`} role="status">{msg.text}</p>}
      {canEdit && (
        <div className="dp-actions">
          <button type="button" className="btn accent" disabled={busy} onClick={save}>
            {busy ? "Saving…" : "Save"}
          </button>
        </div>
      )}
    </div>
  );
}
