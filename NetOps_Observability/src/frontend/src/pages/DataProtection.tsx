// DataProtection.tsx — the Correlix backup & recovery console.
//
// WHAT CHANGED AND WHY. This surface used to be two forms and a status card: it
// told an operator whether a remote was configured and how old the newest
// snapshot was. That answers "is a backup running", which is the easy half. It
// did not answer the question that matters at 3am — "can I get the data back,
// from what point in time, for which engine, and has anyone ever proved it" —
// and it deliberately refused to expose restore at all ("runbook-only").
//
// The console answers the hard half. Its information architecture is taken from
// the enterprise backup products; the study, and what was taken from each, is
// docs/design/DATA_PROTECTION_PAGE_2026-09-04.md.
//
//   1 PROTECTION HEALTH  — one verdict with the specific condition that decided
//     it, the achieved recovery point per engine, the time since the last copy
//     anyone actually PROVED restorable, the next scheduled run, and the
//     repository's own state. (Veeam's SLA view; Rubrik's last/next snapshot.)
//   2 COVERAGE MATRIX    — one row per engine: covered, schedule, last attempt,
//     last success, last verified restore, size, retention, destination class,
//     immutability and encryption. A row the platform does not protect says WHY,
//     and a job a host cron owns is named as external rather than claimed.
//     (Cohesity/Rubrik policy-centric coverage.)
//   3 RESTORE POINTS     — the copies a restore can come from, with state,
//     duration, index count, shard failures with their reason text, and the
//     three-way restorability verdict; per row a restore wizard, a drill and a
//     delete, plus "take one now". (Elastic's snapshot list and restore wizard;
//     NetBackup's type-to-confirm on destructive actions.)
//   4 POLICIES           — the recovery-point policy and the full-bundle policy,
//     each with the CONSEQUENCE of turning it off written next to the switch.
//   5 ACTIVITY & DRILLS  — every operation the platform ran, who ran it and what
//     it returned, with the drill history and its document-count evidence split
//     out. (NetBackup/Commvault audit trail.)
//
// THE HONESTY RULE IS THE PRODUCT. The server encodes an unmeasured value as
// null plus a sibling `*_detail`; `measured()` in dataProtection.model.ts is the
// only door those come through, and nothing here turns an absent value into a 0,
// a dash or a green tick. The page also keeps "not measured" (nobody looked)
// visually distinct from "never" (we looked, and it has not happened) — the
// second is a gap, the first is only silence.
//
// GATING. Every route behind this page is platform-global and requirePlatformAdmin
// on the server. A tenant admin sees the posture read-only and is told why the
// controls are absent, rather than being shown buttons that 403.

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
} from "../services/api";
import { useAuth } from "../hooks/useAuth";
import Icon from "../components/Icon";
import DataTable, { type Column } from "../components/DataTable";
import { Modal } from "../components/ui";
import Wizard, { type WizardStep } from "../components/Wizard";
import { operatorError } from "../lib/errors";
import {
  BACKUP_DOC,
  DEFAULT_RESTORE_PREFIX,
  confirmMatches,
  coverageLabel,
  coverageTone,
  engineLabel,
  fmtAgo,
  fmtBytes,
  fmtDuration,
  fmtUntil,
  isDrill,
  isExternal,
  isRestorable,
  lastProvenRestore,
  measured,
  notMeasuredText,
  operationLabel,
  operationTone,
  posture,
  postureLabel,
  postureTone,
  prefixUsable,
  repositoryAdvice,
  repositoryStateFrom,
  restorableVerdict,
  restorePreview,
  rpoVerdict,
  shardSummary,
  snapshotStateLabel,
  snapshotTone,
  sortedEngines,
  targetMeaning,
  verifyEvidence,
  type Measured,
  type RepositoryState,
  type Tone,
} from "./dataProtection.model";

/** How often a running operation's progress is re-read. */
const OP_POLL_MS = 2000;

/** Rows shown before the operator asks for the rest (the ShowAll convention). */
const ACTIVITY_CAP = 8;
const DRILL_CAP = 5;
const INDEX_CAP = 12;

/** Reason shown for the one header number the platform does not publish yet. */
const HEADROOM_UNREPORTED = "the platform does not report the repository volume's capacity";

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
function Section({ id, title, note, actions, children }: {
  id: string; title: string; note?: ReactNode; actions?: ReactNode; children: ReactNode;
}) {
  return (
    <section className="dp-sec" data-section={id} role="region" aria-label={title}>
      <div className="dp-sec-hd">
        <h2>{title}</h2>
        {note && <span className="dp-sec-note">{note}</span>}
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
function HonestState({ tone, headline, remedy, doc }: {
  tone: Tone; headline: string; remedy: string; doc?: string;
}) {
  return (
    <div className={`dp-honest dp-${tone}`} role="note">
      <strong>{headline}</strong>
      <span>{remedy}</span>
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
      <span>Nothing on this panel is a statement about the backup posture until it loads.</span>
      <button type="button" className="dp-more" onClick={onRetry}>Read it again</button>
    </div>
  );
}

// ── 1 · protection health ───────────────────────────────────────────────────

function ProtectionHealth({ coverage, list, repoBroken, policy, now }: {
  coverage: BackupCoverageView | null;
  list: SnapshotListView | null;
  repoBroken: boolean;
  policy: SnapshotPolicy | null;
  now: number;
}) {
  const repoState = repositoryStateFrom(list?.repository, policy?.repository, repoBroken);
  const p = posture(coverage, repoState);
  const tone = postureTone(p.state);
  const proven = lastProvenRestore(coverage);
  const nextRun = measured(
    policy?.enabled ? policy.next_run || null : null,
    policy ? (policy.enabled ? "the policy did not report a next trigger" : "the recovery-point policy is disabled")
           : "the policy could not be read",
  );
  const rpoRows = (coverage?.engines ?? []).filter((e) => e.covered !== "not_applicable");

  return (
    <div className={`dp-hero dp-${tone}`}>
      <div className="dp-hero-head">
        <Icon name="shield" size={22} />
        <div className="dp-hero-verdict">
          <span className="dp-hero-state">{postureLabel(p.state)}</span>
          <span className="dp-hero-reason">{p.reason}</span>
        </div>
      </div>

      <dl className="dp-stats">
        <div className="dp-stat">
          <dt>Last proven restorable copy</dt>
          <dd>
            <Value
              m={proven}
              render={(v) => (
                <>
                  <Pill tone="good">Proved</Pill>{" "}
                  <span className="mono">{fmtAgo(v.at, now) ?? v.at}</span>
                  <span className="dp-sub"> · {v.engine}</span>
                </>
              )}
            />
          </dd>
        </div>

        <div className="dp-stat">
          <dt>Next scheduled run</dt>
          <dd>
            <Value
              m={nextRun}
              render={(v) => (
                <>
                  <span className="mono">{fmtUntil(v, now) ?? v}</span>
                  <span className="dp-sub"> · {v}</span>
                </>
              )}
            />
          </dd>
        </div>

        <div className="dp-stat">
          <dt>Repository headroom</dt>
          {/* The one header number the contract does not carry yet. It is named
              as unreported rather than dropped, so the gap is visible to the
              operator and to whoever closes it. */}
          <dd><span className="dp-unmeasured">{notMeasuredText(HEADROOM_UNREPORTED)}</span></dd>
        </div>

        <div className="dp-stat">
          <dt>Repository</dt>
          <dd>
            <Pill tone={repoState === "ok" ? "good" : repoState === "unverified" ? "warn" : "bad"}>
              {repoState === "ok" ? "Registered and verified" : repositoryStateWord(repoState)}
            </Pill>{" "}
            {list?.repository && (
              <span className="dp-sub">
                {list.repository.name}
                {list.total > 0 ? ` · ${list.total} restore points` : ""}
              </span>
            )}
          </dd>
        </div>
      </dl>

      <div className="dp-rpo">
        <span className="dp-rpo-h">Recovery point per engine</span>
        {rpoRows.length === 0 ? (
          <span className="dp-unmeasured">{notMeasuredText("the coverage table reported no engines")}</span>
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
      </div>
    </div>
  );
}

function repositoryStateWord(s: RepositoryState): string {
  switch (s) {
    case "unregistered":
      return "Not registered";
    case "damaged":
      return "Failed verification";
    case "unverified":
      return "Not verified";
    case "unreachable":
      return "Could not be read";
    default:
      return "Registered and verified";
  }
}

// ── 2 · coverage matrix ─────────────────────────────────────────────────────

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
  const attempt = measured(e.last_attempt, e.detail || "no attempt has been recorded for this engine");
  const verified = measured(e.last_verified, e.detail || "no restorability probe has been recorded for this engine");
  const size = measured(e.size_bytes, e.size_detail);
  const retention = measured(e.retention, e.detail || "the platform did not report a retention rule");

  return (
    <tr>
      <th scope="row">
        {label}
        {isExternal(e) && (
          <span className="dp-sub dp-block" title={e.schedule?.detail}>
            External, not governed here{e.schedule?.detail ? ` — ${e.schedule.detail}` : ""}
          </span>
        )}
      </th>
      <td>
        <Pill tone={coverageTone(e.covered)} title={e.covered_reason}>{coverageLabel(e.covered)}</Pill>
        <span className="dp-sub dp-block">{e.covered_reason}</span>
      </td>
      <td>
        <Value
          m={schedule}
          render={(v) => (
            <>
              <span className="mono">{v.cron || "no schedule expression"}</span>
              {!v.enabled && <span className="dp-sub dp-block">off — {v.detail}</span>}
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
              {v.detail && v.result !== "success" ? <span className="dp-sub dp-block">{v.detail}</span> : null}
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
              <Pill tone={v.result === "pass" || v.result === "success" ? "good" : "bad"}>{v.result}</Pill>{" "}
              <span className="mono">{fmtAgo(v.at, now) ?? v.at}</span>
            </>
          )}
        />
      </td>
      <td className="num"><Value m={size} render={(v) => fmtBytes(v)} /></td>
      <td>
        <Value
          m={retention}
          render={(v) => (
            <>
              <span>
                {v.max_count === null ? "" : `${v.max_count} copies`}
                {v.max_count !== null && v.max_age_days ? " · " : ""}
                {v.max_age_days ? `${v.max_age_days} days` : ""}
                {v.max_count === null && !v.max_age_days ? v.detail : ""}
              </span>
            </>
          )}
        />
      </td>
      <td>
        <Pill tone={e.target.kind === "none" ? "bad" : e.target.kind === "local" ? "warn" : "good"}
              title={targetMeaning(e.target.kind)}>
          {e.target.kind}
        </Pill>
        {e.target.location ? <span className="dp-sub dp-block">{e.target.location}</span> : null}
        <span className="dp-badges">
          <BoolBadge on={e.target.immutable} onLabel="Immutable" offLabel="Mutable" detail={e.target.immutable_detail} />
          <BoolBadge on={e.target.encrypted} onLabel="Encrypted" offLabel="Not encrypted" detail={e.target.encrypted_detail} />
        </span>
      </td>
    </tr>
  );
}

function CoverageMatrix({ engines, now }: { engines: readonly EngineCoverage[]; now: number }) {
  const rows = useMemo(() => sortedEngines(engines), [engines]);
  if (rows.length === 0) {
    return (
      <HonestState
        tone="warn"
        headline="The platform listed no engines to protect."
        remedy="Until it does, treat nothing on this page as coverage. Read it again, and if the list stays empty check that the data-protection service is running."
        doc={BACKUP_DOC}
      />
    );
  }
  return (
    <div className="dp-tblwrap">
      <table className="dp-tbl" aria-label="Protection coverage by engine">
        <thead>
          <tr>
            <th scope="col">Engine</th>
            <th scope="col">Covered</th>
            <th scope="col">Schedule</th>
            <th scope="col">Last attempt</th>
            <th scope="col">Last success</th>
            <th scope="col">Last verified restore</th>
            <th scope="col" className="num">Size</th>
            <th scope="col">Retention</th>
            <th scope="col">Destination</th>
          </tr>
        </thead>
        <tbody>{rows.map((e) => <CoverageRow key={e.id} e={e} now={now} />)}</tbody>
      </table>
    </div>
  );
}

// ── 3 · restore points ──────────────────────────────────────────────────────

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
      hint: "Restore the whole restore point, or only the indices you name.",
      isValid: () => draft.indices.length === 0 || draft.indices.length > 0,
      render: () => (
        <div className="dp-form">
          <label className="dp-check">
            <input
              type="checkbox"
              checked={draft.indices.length === 0}
              onChange={(ev) => setDraft({ ...draft, indices: ev.target.checked ? [] : [...all] })}
            />
            Whole restore point ({all.length} indices)
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
              <span className="dp-sec-note">New names</span>
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
          <div><dt>Restore point</dt><dd className="mono">{draft.snap.name}</dd></div>
          <div><dt>Taken</dt><dd className="mono">{draft.snap.ended_at || draft.snap.started_at || "start time not reported"}</dd></div>
          <div><dt>Indices</dt><dd>{draft.indices.length === 0 ? `whole restore point (${all.length})` : `${draft.indices.length} selected`}</dd></div>
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
    "The coverage table could not be read.",
  );
  const [list, reloadList] = usePanel<SnapshotListView>(
    readList,
    "The restore points could not be read.",
    String(withSizes),
  );
  const [policy, reloadPolicy] = usePanel<SnapshotPolicy>(
    () => api.snapshotPolicy(),
    "The recovery-point policy could not be read.",
  );
  const [bundle, reloadBundle] = usePanel(
    () => api.backupConfig(),
    "The backup destination could not be read.",
  );
  const [ops, reloadOps] = usePanel(
    () => api.backupOperations(),
    "The activity trail could not be read.",
  );

  const [op, setOp] = useState<BackupOperation | null>(null);
  const [opError, setOpError] = useState<string | null>(null);
  const [restore, setRestore] = useState<RestoreDraft | null>(null);
  const [toDelete, setToDelete] = useState<SnapshotView | null>(null);
  const [filter, setFilter] = useState("");

  const refreshAll = useCallback(() => {
    setNow(Date.now());
    reloadCoverage();
    reloadList();
    reloadOps();
  }, [reloadCoverage, reloadList, reloadOps]);

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

  const columns: Column<SnapshotView>[] = useMemo(() => [
    {
      key: "name", header: "Restore point", width: "1.6fr", sortable: true,
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
      render: (r) => (r.ended_at ? fmtDuration(r.duration_seconds) : <span className="dp-sub">still running</span>),
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
      key: "verified", header: "Restorable", width: 230,
      text: (r) => String(r.restorable_verified),
      render: (r) => {
        const v = restorableVerdict(r);
        if (v.state === "never") return <Pill tone="warn" title={v.detail}>Never verified</Pill>;
        return (
          <Pill tone={v.state === "verified" ? "good" : "bad"} title={v.detail}>
            {v.state === "verified" ? "Verified" : "Verification failed"}
            {v.at ? ` · ${fmtAgo(v.at, now) ?? v.at}` : ""}
          </Pill>
        );
      },
    },
    {
      key: "failures", header: "Failures", width: "1fr",
      text: (r) => r.failures.map((f) => f.reason).join(" "),
      render: (r) => {
        if (r.failures.length === 0) return <span className="dp-sub">none reported</span>;
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
          Verify now
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
  const external = coverage.data?.external ?? [];

  return (
    <div className="dp-page">
      {/* ── 1 · protection health ── */}
      <Section
        id="health"
        title="Protection health"
        note="Platform-global — one posture for the whole stack"
        actions={<button type="button" className="btn sm" onClick={refreshAll}><Icon name="refresh" size={13} /> Re-read</button>}
      >
        {coverage.error ? (
          <PanelError text={coverage.error} onRetry={reloadCoverage} />
        ) : coverage.loading && !coverage.data ? (
          <Loading what="the protection posture" />
        ) : (
          <ProtectionHealth
            coverage={coverage.data}
            list={list.data}
            repoBroken={repoBroken}
            policy={policy.data}
            now={now}
          />
        )}

        {advice && <HonestState tone={advice.tone} headline={advice.headline} remedy={advice.remedy} doc={advice.doc} />}
        {!authLoading && !platformAdmin && (
          <HonestState
            tone="muted"
            headline="You are seeing this posture read-only."
            remedy="Backup and recovery is platform-global configuration. Taking, restoring, verifying and deleting restore points requires a platform administrator."
          />
        )}
      </Section>

      {/* ── 2 · coverage ── */}
      <Section
        id="coverage"
        title="Coverage"
        note="One row per engine the platform is responsible for"
      >
        {coverage.error ? (
          <PanelError text={coverage.error} onRetry={reloadCoverage} />
        ) : coverage.data ? (
          <>
            {coverage.data.detail && (
              <HonestState
                tone="warn"
                headline="The coverage table is incomplete."
                remedy={coverage.data.detail}
                doc={BACKUP_DOC}
              />
            )}
            <CoverageMatrix engines={coverage.data.engines} now={now} />
          </>
        ) : (
          <Loading what="the coverage matrix" />
        )}
      </Section>

      {/* ── 3 · restore points ── */}
      <Section
        id="restore-points"
        title="Restore points"
        note="OpenSearch snapshots — the copies a restore can come from"
        actions={
          <>
            <input
              className="dp-input dp-filter"
              placeholder="Filter restore points"
              aria-label="Filter restore points"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
            />
            <button
              type="button" className="btn sm" aria-pressed={withSizes}
              title="Measuring sizes costs one repository call per restore point"
              onClick={() => setWithSizes((v) => !v)}
            >
              {withSizes ? "Stop measuring sizes" : "Measure sizes"}
            </button>
            {platformAdmin && (
              <button type="button" className="btn sm accent" onClick={() => start(() => api.createSnapshot())}>
                Take restore point now
              </button>
            )}
          </>
        }
      >
        {opError && <HonestState tone="bad" headline="The action did not complete." remedy={opError} />}
        {op && <OperationProgress op={op} onDismiss={() => setOp(null)} />}

        {list.error ? (
          <PanelError text={list.error} onRetry={reloadList} />
        ) : list.loading && !list.data ? (
          <Loading what="the restore points" />
        ) : list.data?.detail && snapshots.length === 0 ? (
          <HonestState
            tone="bad"
            headline="The restore points could not be listed."
            remedy={list.data.detail}
            doc={BACKUP_DOC}
          />
        ) : snapshots.length === 0 ? (
          <HonestState
            tone="warn"
            headline="No restore point exists yet."
            remedy="There is nothing to restore from. Take one now, then run a restore drill so the first copy is proved rather than assumed."
            doc={BACKUP_DOC}
          />
        ) : (
          <>
            {list.data?.detail && <p className="dp-sub">{list.data.detail}</p>}
            <DataTable
              rows={snapshots}
              columns={columns}
              rowKey={(r) => r.name}
              filter={filter}
              height={420}
              rowActions={rowActions}
              ariaLabel="Restore points"
              empty={<span className="dp-sub">No restore point matches that filter.</span>}
            />
          </>
        )}
      </Section>

      {/* ── 4 · policies ── */}
      <Section id="policies" title="Policies" note="What creates restore points, and how long they live">
        <SnapshotPolicyForm panel={policy} onReload={reloadPolicy} canEdit={platformAdmin} onSaved={refreshAll} />
        <BundlePolicyForm panel={bundle} onReload={reloadBundle} canEdit={platformAdmin} />
        {external.map((x) => (
          <HonestState
            key={`${x.source}:${x.name}`}
            tone="muted"
            headline={`${x.name} is external, not governed here.`}
            remedy={`${x.detail} Source: ${x.source}${x.schedule ? ` · ${x.schedule}` : ""}.`}
          />
        ))}
      </Section>

      {/* ── 5 · activity and drills ── */}
      <Section
        id="activity"
        title="Activity and drills"
        note={ops.data ? `The platform keeps the newest ${ops.data.capacity} operations` : "Who ran what, and what it returned"}
        actions={
          platformAdmin ? (
            <button type="button" className="btn sm" onClick={() => start(() => api.verifySnapshot())}>
              Run restore drill
            </button>
          ) : null
        }
      >
        <div className="dp-two">
          <div>
            <h3 className="dp-sub-h">Audit trail</h3>
            {ops.error ? (
              <PanelError text={ops.error} onRetry={reloadOps} />
            ) : ops.loading && !ops.data ? (
              <Loading what="the activity trail" />
            ) : opRows.length === 0 ? (
              <HonestState
                tone="muted"
                headline="No backup or restore action has been recorded."
                remedy={ops.data?.detail || "Nothing has been taken, restored, verified or deleted since the platform last started."}
              />
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
              </>
            )}
          </div>
          <div>
            <h3 className="dp-sub-h">Restore drills</h3>
            {drills.length === 0 ? (
              <HonestState
                tone="warn"
                headline="No restore has ever been proved."
                remedy="A copy nobody has restored is a copy nobody knows is good. Run a restore drill: it restores the smallest index of the newest good copy under a temporary name, compares document counts against the live source, and records the result here."
                doc={BACKUP_DOC}
              />
            ) : (
              <>
                <ul className="dp-feed">
                  {drillCap.rows.map((a) => (
                    <li key={a.id}>
                      <span className="mono dp-feed-t">{a.started_at}</span>
                      <Pill tone={a.verify ? (a.verify.match ? "good" : "bad") : operationTone(a.state)}>
                        {a.verify ? (a.verify.match ? "documents matched" : "documents did not match") : a.state}
                      </Pill>
                      <span>{a.target?.snapshot ?? a.verify?.snapshot ?? "target not recorded"}</span>
                      {verifyEvidence(a) && <span className="dp-sub">{verifyEvidence(a)}</span>}
                      {a.error && <span className="dp-bad-text">{a.error}</span>}
                    </li>
                  ))}
                </ul>
                <ShowAll cap={drillCap} noun="drills" />
              </>
            )}
          </div>
        </div>
      </Section>

      {/* ── modals ── */}
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

// ── 4a · recovery-point policy ──────────────────────────────────────────────

function SnapshotPolicyForm({ panel, onReload, canEdit, onSaved }: {
  panel: Panel<SnapshotPolicy>; onReload: () => void; canEdit: boolean; onSaved: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ tone: Tone; text: string } | null>(null);
  // Turning the policy OFF is an intent the platform records with its reason, so
  // a stopped schedule can never be mistaken for an accident later. The reason is
  // asked for BEFORE the write, not after.
  const [disableReason, setDisableReason] = useState<string | null>(null);
  const snap = panel.data;

  const save = async (upd: Parameters<typeof api.setSnapshotPolicy>[0]) => {
    setBusy(true); setMsg(null);
    try {
      await api.setSnapshotPolicy(upd);
      setMsg({ tone: "good", text: "Recovery-point policy updated." });
      onReload();
      onSaved();
    } catch (e: unknown) {
      setMsg({ tone: "bad", text: operatorError(e, "The change could not be saved.") });
    } finally { setBusy(false); }
  };

  if (panel.error) return <PanelError text={panel.error} onRetry={onReload} />;
  if (!snap) return <Loading what="the recovery-point policy" />;

  return (
    <div className="dp-policy">
      <div className="dp-policy-hd">
        <h3 className="dp-sub-h">Recovery-point policy</h3>
        <span className="dp-sp" />
        <label className="dp-check">
          <input
            type="checkbox" checked={snap.enabled} disabled={busy || !canEdit}
            onChange={(e) => {
              if (e.target.checked) { setDisableReason(null); save({ enabled: true }); return; }
              setDisableReason("");
            }}
          />
          Enabled
        </label>
      </div>

      {disableReason !== null && (
        <div className="dp-honest dp-warn" role="note">
          <strong>Turning this off stops new restore points being created.</strong>
          <span>Say why, so whoever finds it off later knows it was deliberate.</span>
          <label className="dp-field">
            <span>Reason</span>
            <input
              className="dp-input" aria-label="Reason for turning the recovery-point policy off"
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
        <HonestState tone="warn" headline="The policy could not be read in full." remedy={snap.detail} doc={BACKUP_DOC} />
      )}
      {!snap.enabled && (
        <HonestState
          tone="bad"
          headline="The recovery-point policy is disabled."
          remedy={
            "No new restore points will be created. Everything already taken stays restorable until " +
            "retention removes it, and from then on the achieved recovery point only gets older. " +
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
          remedy={`The enabled flag is owned by ${snap.managed_by}, so a change made here can be overwritten by it.`}
        />
      )}

      <div className="dp-grid3">
        <label className="dp-field">
          <span>Window (cron, UTC)</span>
          <input
            className="dp-input mono" defaultValue={snap.schedule_cron} disabled={busy || !canEdit}
            aria-label="Recovery-point window, cron in UTC"
            onBlur={(e) => { if (e.target.value !== snap.schedule_cron) save({ schedule_cron: e.target.value }); }}
          />
        </label>
        <label className="dp-field">
          <span>Retention — keep newest</span>
          <input
            className="dp-input" type="number" min={1} max={365} defaultValue={snap.retention_max_count}
            disabled={busy || !canEdit} aria-label="Retention, keep newest count"
            onBlur={(e) => { const n = parseInt(e.target.value, 10); if (n && n !== snap.retention_max_count) save({ retention_max_count: n }); }}
          />
        </label>
        <label className="dp-field">
          <span>Retention — maximum age (days)</span>
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
            <span className="dp-unmeasured">{notMeasuredText("the policy has not reported a run")}</span>
          )}
        </li>
        <li>
          <span>Next run</span>
          <Value
            m={measured(
              snap.enabled ? snap.next_run || null : null,
              snap.enabled ? "the policy did not report a next trigger" : "the policy is disabled",
            )}
            render={(v) => <span className="mono">{v}</span>}
          />
        </li>
      </ul>

      {msg && <p className={`dp-msg dp-${msg.tone}`} role="status">{msg.text}</p>}
      {!canEdit && <p className="dp-sub">Changing the policy requires a platform administrator.</p>}
    </div>
  );
}

// ── 4b · full-bundle policy ─────────────────────────────────────────────────

function BundlePolicyForm({ panel, onReload, canEdit }: {
  panel: Panel<{ config: BackupConfig }>; onReload: () => void; canEdit: boolean;
}) {
  const [cfg, setCfg] = useState<BackupConfig | null>(null);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ tone: Tone; text: string } | null>(null);

  useEffect(() => { if (panel.data) setCfg(panel.data.config); }, [panel.data]);

  if (panel.error) return <PanelError text={panel.error} onRetry={onReload} />;
  if (!cfg) return <Loading what="the backup destination" />;

  const save = async () => {
    setBusy(true); setMsg(null);
    try {
      const r = await api.setBackupConfig(cfg);
      setCfg(r.config);
      setMsg({ tone: "good", text: "Saved. The host-side applier writes the schedule and destination on its next run." });
    } catch (e: unknown) {
      setMsg({ tone: "bad", text: operatorError(e, "The change could not be saved.") });
    } finally { setBusy(false); }
  };

  return (
    <div className="dp-policy">
      <h3 className="dp-sub-h">Full-bundle policy</h3>
      {!cfg.remote_url && (
        <HonestState
          tone="warn"
          headline="The bundle has no off-host destination."
          remedy="Copies stay on the same disk as the live data, so one disk failure loses both. Name a destination below; the schedule cannot be enabled without one."
          doc={BACKUP_DOC}
        />
      )}
      <div className="dp-grid2">
        <label className="dp-field">
          <span>Off-host destination</span>
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
        Run the full bundle on a schedule
      </label>
      <label className="dp-field">
        <span>Schedule (cron)</span>
        <input
          className="dp-input mono" aria-label="Bundle schedule, cron" disabled={!canEdit}
          placeholder="30 2 * * *  (02:30 daily)"
          value={cfg.schedule_cron ?? ""} onChange={(e) => setCfg({ ...cfg, schedule_cron: e.target.value })}
        />
      </label>
      {msg && <p className={`dp-msg dp-${msg.tone}`} role="status">{msg.text}</p>}
      {canEdit && (
        <div className="dp-actions">
          <button type="button" className="btn accent" disabled={busy} onClick={save}>
            {busy ? "Saving…" : "Save bundle policy"}
          </button>
        </div>
      )}
    </div>
  );
}
