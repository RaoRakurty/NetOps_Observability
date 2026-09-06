// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Iris → Knowledge — what Correlix actually knows, per vendor dialect.
//
// This is the other half of the TAC escalation pack
// (docs/design/TAC_ESCALATION_2026-09-05.md §5): the issue × command matrix that
// used to be a manual bench on Investigate → Troubleshooting is not a workbench
// at all, it is Iris's KNOWLEDGE, and this page is where an operator reads it.
//
// It is deliberately unflattering, because a coverage page that only shows what
// works is a marketing page:
//   · every planned dialect shows bound vs total intents, and how many of its
//     commands are VERIFIED against a real capture versus taken from a vendor's
//     documentation and never run here;
//   · every class shows which of its deep-dive intents this dialect cannot
//     answer, by name;
//   · platforms Correlix recognises and has authored NO plan for are listed in
//     their own section rather than omitted;
//   · what the owner's output-only command policy EXCLUDED is stated as a count
//     per family — and only as a count. A config / restart / daemon command is
//     not knowledge Correlix holds (owner, 2026-09-05), and this page is
//     knowledge, so the command text is never rendered here or anywhere else;
//   · the unknown-output backlog IS counted now (tracker 243): every collection
//     is read back through the parsers and what they could not recognise
//     becomes a work item here, with the reason and a redacted excerpt.
//
// THE BACKLOG IS THE ONE TENANT-SCOPED THING ON THIS PAGE. The coverage
// catalogue above it is version-pinned REFERENCE data, identical for every
// tenant and revealing nothing about anyone's devices. A learning record is the
// opposite: it holds redacted excerpts of THIS tenant's own device output, and
// a candidate holds what a vendor told THIS tenant. Both are scoped by the
// caller's token on the server (`/api/tac/learning`, requirePerm + the tenant
// filter); the page renders what that returns and asks for nothing wider.
//
// A CANDIDATE IS A PROPOSAL, AND THE PAGE SAYS SO EVERY TIME. Promoting an
// answer here writes a candidate and nothing else: the shipped catalogue, the
// version pin and the doc_claimed gate are untouched. The only exit is the
// exported research file, reviewed by a human and merged by
// scripts/tac-merge-research.py.
//
// Every string on the page is rendered as escaped React text.

import { useCallback, useEffect, useMemo, useState } from "react";
import "../troubleshoot/investigation.css";
import {
  api,
  type TacCandidate,
  type TacDialectCoverage,
  type TacGap,
  type TacKnowledge,
  type TacLearningResponse,
  type TacTemplate,
  type TacTemplateItemResponse,
} from "../../services/api";
import AskIris from "../../components/AskIris";
import WindowedList from "../../components/WindowedList";
import {
  BACKLOG_CLEAN,
  BACKLOG_EMPTY,
  BACKLOG_FAILED,
  BACKLOG_UNTRACKED,
  CANDIDATE_EXPORT_FAILED,
  CANDIDATE_NONE,
  CANDIDATE_NOTE,
  COMMAND_POLICY_NO_EXCLUSIONS,
  COMMAND_POLICY_NOTE,
  KNOWLEDGE_FAILED,
  KNOWLEDGE_GROWTH_NOTE,
  GAP_KIND_LABEL,
  NO_UNPLANNED_DIALECTS,
  REVIEW_POLICY_NOTE,
  TEMPLATES_FAILED,
  tacError,
  templateLabel,
  verifiedLabel,
} from "../troubleshoot/tacModel";

/** Row pitch of the intent table. Fixed, because that is what lets the list
 *  stay flat in the DOM however long the intent vocabulary grows. */
const INTENT_ROW_PX = 30;

/** The owner's three families, in the order the policy states them. */
const FAMILY_ORDER = ["config", "restart", "daemon"] as const;

export default function IrisKnowledge() {
  const [data, setData] = useState<TacKnowledge | null>(null);
  const [err, setErr] = useState("");
  const [open, setOpen] = useState("");
  // The command templates (tracker 250). Defaults are reference data; the
  // tenant's own sets are its data, and they are listed here beside the
  // coverage they were built from.
  const [templates, setTemplates] = useState<TacTemplate[]>([]);
  const [defaults, setDefaults] = useState<TacTemplate[]>([]);
  const [tplErr, setTplErr] = useState("");
  // The learning backlog (tracker 243). `learn === null` with no error is
  // "the api does not carry it", which is a third state, not an empty one.
  const [learn, setLearn] = useState<TacLearningResponse | null>(null);
  const [learnErr, setLearnErr] = useState("");

  const reloadLearning = useCallback(() => {
    api.tacLearning()
      .then((r) => { setLearn(r); setLearnErr(""); })
      .catch((e: unknown) => setLearnErr(tacError(e, BACKLOG_FAILED)));
  }, []);

  useEffect(() => {
    let alive = true;
    api.tacLearning()
      .then((r) => { if (alive) { setLearn(r); setLearnErr(""); } })
      .catch((e: unknown) => { if (alive) setLearnErr(tacError(e, BACKLOG_FAILED)); });
    return () => { alive = false; };
  }, []);

  useEffect(() => {
    let alive = true;
    api.tacKnowledge()
      .then((k) => { if (alive) { setData(k); setErr(""); } })
      .catch((e: unknown) => { if (alive) setErr(tacError(e, KNOWLEDGE_FAILED)); });
    return () => { alive = false; };
  }, []);

  useEffect(() => {
    let alive = true;
    api.tacTemplates()
      .then((r) => {
        if (!alive) return;
        setTemplates(r.templates ?? []);
        setDefaults(r.defaults ?? []);
        setTplErr("");
      })
      .catch((e: unknown) => { if (alive) setTplErr(tacError(e, TEMPLATES_FAILED)); });
    return () => { alive = false; };
  }, []);

  const dialects = useMemo(() => data?.dialects ?? [], [data]);
  const unplanned = useMemo(() => data?.unplanned_dialects ?? [], [data]);

  if (err) {
    return (
      <div className="dm-board tac-know">
        <h1 className="tac-h">Knowledge</h1>
        <p className="tac-bad" role="alert">{err}</p>
      </div>
    );
  }
  if (!data) {
    return (
      <div className="dm-board tac-know">
        <h1 className="tac-h">Knowledge</h1>
        <p className="mini-meta" role="status">Reading the coverage catalogue…</p>
      </div>
    );
  }

  return (
    <div className="dm-board tac-know">
      <header className="tac-know-head">
        <h1 className="tac-h">Knowledge</h1>
        <p className="fact-line">
          Issue catalogue {data.catalog_version} · engine {data.engine_version} ·{" "}
          {data.classes.length} issue classes · {data.intents.length} command intents.{" "}
          <AskIris topic="tac.coverage-catalogue" label="Knowledge" />
        </p>
      </header>

      <section className="tac-step" aria-labelledby="tac-know-dialects-h">
        <h2 id="tac-know-dialects-h" className="tac-step-h">Coverage by vendor dialect</h2>
        {dialects.length === 0 ? (
          <p className="mini-meta tac-note">No dialect carries an authored plan on this build.</p>
        ) : (
          <ul className="tac-dialects">
            {dialects.map((d) => (
              <li key={d.dialect} className="tac-dialect" data-testid={`tac-dialect-${d.dialect}`}>
                <button
                  type="button"
                  className="tac-dialect-head"
                  aria-expanded={open === d.dialect}
                  onClick={() => setOpen((o) => (o === d.dialect ? "" : d.dialect))}
                >
                  <span className="tac-dialect-t">{d.display}</span>
                  <code className="tac-id">{d.dialect}</code>
                  <span className="mini-meta">
                    {d.bound_intents} of {d.total_intents} intents bound ·{" "}
                    {d.verified_commands} verified · {d.doc_claimed_commands} documented ·{" "}
                    {d.baseline_intents} baseline · {d.optional_intents} optional
                  </span>
                  <span className="mini-meta">
                    {d.plan_version ? `plan ${d.plan_version}` : "no plan version recorded"}
                    {(d.excluded_by_policy?.total ?? 0) > 0
                      ? ` · ${d.excluded_by_policy.total} excluded by policy`
                      : ""}
                  </span>
                </button>
                {open === d.dialect && <DialectDetail d={d} />}
              </li>
            ))}
          </ul>
        )}
      </section>

      <section className="tac-step" aria-labelledby="tac-know-unplanned-h">
        <h2 id="tac-know-unplanned-h" className="tac-step-h">Platforms with no plan</h2>
        <p className="mini-meta tac-note">
          Recognised; no command set is authored for them.
          <AskIris topic="tac.unplanned-platforms" label="Platforms with no plan" />
        </p>
        {unplanned.length === 0 ? (
          <p className="mini-meta tac-note">{NO_UNPLANNED_DIALECTS}</p>
        ) : (
          <ul className="tac-unplanned" data-testid="tac-unplanned">
            {unplanned.map((d) => (
              <li key={d.dialect}>
                <span className="tac-dialect-t">{d.display}</span>{" "}
                <code className="tac-id">{d.dialect}</code>{" "}
                <span className="mini-meta">
                  {d.profile} · 0 of {d.total_intents} intents bound · {d.classes.length} classes unplannable
                </span>
              </li>
            ))}
          </ul>
        )}
      </section>

      <section className="tac-step" aria-labelledby="tac-know-policy-h">
        <h2 id="tac-know-policy-h" className="tac-step-h">What Correlix never learns</h2>
        <p className="mini-meta tac-note">{COMMAND_POLICY_NOTE}</p>
        <p className="mini-meta tac-note">
          Policy <code className="tac-id">{data.command_policy?.version || "not loaded"}</code>
          {data.command_policy?.generated ? ` · census ${data.command_policy.generated}` : ""}
        </p>
        {(data.command_policy?.total ?? 0) === 0 ? (
          <p className="mini-meta tac-note" data-testid="tac-policy-excluded">
            {COMMAND_POLICY_NO_EXCLUSIONS}
          </p>
        ) : (
          <p className="mini-meta tac-note" data-testid="tac-policy-excluded">
            <strong>Excluded by policy: {data.command_policy.total}</strong>{" "}
            ({FAMILY_ORDER.map((f) => `${f} ${data.command_policy.by_family?.[f] ?? 0}`).join(" · ")})
          </p>
        )}
        <ul className="tac-policy-families">
          {(data.command_policy?.families ?? []).map((f) => (
            <li key={f.id}>
              <span className="tac-alt-t">{f.title}</span>{" "}
              <code className="tac-id">{f.id}</code>{" "}
              <span className="mini-meta">{f.rule}</span>
            </li>
          ))}
        </ul>
      </section>

      <section className="tac-step" aria-labelledby="tac-know-tpl-h">
        <h2 id="tac-know-tpl-h" className="tac-step-h">Command templates</h2>
        <p className="mini-meta tac-note">
          Correlix defaults are read-only. Your saved sets stay in your tenant.
          <AskIris topic="tac.command-templates" label="Command templates" />
        </p>
        <p className="mini-meta tac-note" data-testid="tac-tpl-policy">{REVIEW_POLICY_NOTE}</p>
        {tplErr && <p className="tac-bad" role="alert">{tplErr}</p>}

        <h3 className="tac-section-h">Correlix defaults</h3>
        {defaults.length === 0 ? (
          <p className="mini-meta tac-note">This build ships no default command set.</p>
        ) : (
          <ul className="tac-tpl-list" data-testid="tac-tpl-defaults">
            {defaults.map((t) => (
              <li key={t.id}>
                <span className="tac-alt-t">{t.name}</span>{" "}
                <code className="tac-id">{t.dialect}</code>{" "}
                <span className="badge">{templateLabel(t)}</span>{" "}
                <span className="mini-meta">{t.steps.length} commands</span>
              </li>
            ))}
          </ul>
        )}

        <h3 className="tac-section-h">Your saved sets</h3>
        {templates.length === 0 ? (
          <p className="mini-meta tac-note" data-testid="tac-tpl-none">
            No set saved yet. Build one in an escalation review.
          </p>
        ) : (
          <ul className="tac-tpl-list" data-testid="tac-tpl-mine">
            {templates.map((t) => <TenantTemplate key={t.id} t={t} />)}
          </ul>
        )}
      </section>

      <section className="tac-step" aria-labelledby="tac-know-grow-h">
        <h2 id="tac-know-grow-h" className="tac-step-h">How this grows</h2>
        <p className="mini-meta tac-note">{KNOWLEDGE_GROWTH_NOTE}</p>
        <LearningBacklog learn={learn} err={learnErr} onChange={reloadLearning} />
      </section>
    </div>
  );
}

/** One tenant template, with what it changed about the Correlix default it was
 *  forked from. The diff is fetched on demand: a listing that eagerly diffed
 *  every set would read the whole catalogue for a panel nobody opened. */
function TenantTemplate({ t }: { t: TacTemplate }) {
  const [detail, setDetail] = useState<TacTemplateItemResponse | null>(null);
  const [open, setOpen] = useState(false);
  const [err, setErr] = useState("");

  const toggle = () => {
    const next = !open;
    setOpen(next);
    if (!next || detail) return;
    api.tacTemplate(t.id)
      .then((r) => { setDetail(r); setErr(""); })
      .catch((e: unknown) => setErr(tacError(e, TEMPLATES_FAILED)));
  };

  const diff = detail?.diff_vs_default ?? [];
  return (
    <li data-testid={`tac-tpl-${t.id}`}>
      <button type="button" className="tac-dialect-head" aria-expanded={open} onClick={toggle}>
        <span className="tac-alt-t">{t.name}</span>{" "}
        <code className="tac-id">{t.dialect}</code>{" "}
        <span className="mini-meta">{templateLabel(t)} · {t.steps.length} commands</span>
      </button>
      {open && (
        <div className="tac-dialect-body">
          {err && <p className="tac-bad" role="alert">{err}</p>}
          {t.description && <p className="mini-meta tac-note">{t.description}</p>}
          {!t.based_on ? (
            <p className="mini-meta tac-note">
              Written from scratch — there is no Correlix default to compare it with.
            </p>
          ) : detail && diff.length === 0 ? (
            <p className="mini-meta tac-note">
              Identical to <code className="tac-id">{t.based_on}</code>.
            </p>
          ) : (
            <ul className="tac-steps" data-testid={`tac-tpl-diff-${t.id}`}>
              {diff.map((d, i) => (
                <li className="tac-step-row" key={`${d.kind}-${i}`}>
                  <span className="badge">{d.kind}</span>{" "}
                  <code className="tac-cmd">{d.command}</code>
                </li>
              ))}
            </ul>
          )}
          <ul className="tac-steps">
            {t.steps.map((st, i) => (
              <li className="tac-step-row" key={`s-${i}`}>
                <code className="tac-cmd">{st.command}</code>
                {st.note ? <span className="mini-meta">{st.note}</span> : null}
              </li>
            ))}
          </ul>
        </div>
      )}
    </li>
  );
}

/** One dialect opened: its per-class coverage, then its per-intent table. */
function DialectDetail({ d }: { d: TacDialectCoverage }) {
  const classes = d.classes ?? [];
  const intents = d.intents ?? [];
  return (
    <div className="tac-dialect-body" data-testid={`tac-dialect-body-${d.dialect}`}>
      <h3 className="tac-section-h">Issue classes on {d.display}</h3>
      {classes.length === 0 ? (
        <p className="mini-meta tac-note">This dialect carries no class coverage.</p>
      ) : (
        <ul className="tac-classes">
          {classes.map((c) => (
            <li key={c.class_id} className={c.bound === c.total ? "full" : "partial"}>
              <span className="tac-alt-t">{c.title}</span>{" "}
              <code className="tac-id">{c.class_id}</code>{" "}
              <span className="mini-meta">{c.protocol} · {c.bound} of {c.total} intents bound</span>
              {(c.missing ?? []).length > 0 && (
                <span className="mini-meta"> — missing: {(c.missing ?? []).join(" · ")}</span>
              )}
            </li>
          ))}
        </ul>
      )}

      <h3 className="tac-section-h">Commands on {d.display}</h3>
      {intents.length === 0 ? (
        <p className="mini-meta tac-note">No intent is bound on this dialect.</p>
      ) : (
        <>
          <div className="tac-intent-head" aria-hidden="true">
            <span>Intent</span><span>What it answers</span><span>Command</span><span>Confidence</span>
          </div>
          <WindowedList
            items={intents}
            rowHeight={INTENT_ROW_PX}
            className="tac-intents"
            ariaLabel={`Commands on ${d.display}`}
            itemKey={(it) => it.intent}
            // No list/listitem roles: WindowedList puts a positioning wrapper
            // between the scroller and each row, so a "list" here would own no
            // "listitem" and the semantics would be a lie the reader acts on.
            renderItem={(it) => (
              <div className="tac-intent">
                <code className="tac-id">{it.intent}</code>
                <span className="tac-intent-t">{it.title}</span>
                {it.bound && it.command
                  ? <code className="tac-cmd">{it.command}</code>
                  : <span className="fact-line">this dialect binds no command for it</span>}
                <span className="fact-line">{verifiedLabel(it.verified) || "not bound"}</span>
              </div>
            )}
          />
          <p className="fact-line">{intents.length} intents</p>
        </>
      )}
    </div>
  );
}

// ── the learning backlog (tracker 243) ───────────────────────────────────────
//
// THREE STATES, NOT TWO, and the difference matters to an operator deciding
// whether coverage is real:
//   · the api does not carry the backlog (an older build) — say so;
//   · it carries it and nothing has been collected — say that instead of 0;
//   · it carries it, collections ran, and everything was recognised — that IS
//     a zero, and it is the only case where showing one is honest.
//
// A gap names the WORK ITEM, not just a failure: "no parser for this concept"
// sends someone to write one, "no parser on this platform" sends them to extend
// one, and "the parser could not read it" hands them the excerpt that proves it.
function LearningBacklog(
  { learn, err, onChange }: { learn: TacLearningResponse | null; err: string; onChange: () => void },
) {
  const [writing, setWriting] = useState<TacGap | null>(null);

  if (err) {
    return (
      <>
        <h3 className="tac-section-h">Unrecognised outputs</h3>
        <p className="tac-bad" role="alert" data-testid="tac-backlog">{err}</p>
      </>
    );
  }
  if (!learn || !learn.tracked) {
    return (
      <>
        <h3 className="tac-section-h">Unrecognised outputs</h3>
        <p className="mini-meta tac-note" data-testid="tac-backlog">{BACKLOG_UNTRACKED}</p>
      </>
    );
  }

  const collected = learn.records.length;
  const state = collected === 0 ? BACKLOG_EMPTY : learn.gap_total === 0 ? BACKLOG_CLEAN : "";

  return (
    <>
      <h3 className="tac-section-h">Unrecognised outputs</h3>
      {state ? (
        <p className="mini-meta tac-note" data-testid="tac-backlog">{state}</p>
      ) : (
        <>
          <ul className="tac-gap-counts" data-testid="tac-backlog">
            {learn.gap_kinds.map((k) => (
              <li key={k}>
                <span className="tac-gap-n">{learn.gap_counts[k] ?? 0}</span>{" "}
                <span className="tac-learn-meta">{GAP_KIND_LABEL[k] ?? k}</span>
              </li>
            ))}
          </ul>
          <ul className="tac-gaps" data-testid="tac-gap-list">
            {learn.records.flatMap((rec) =>
              rec.gaps.map((g, i) => (
                <li key={`${rec.id}-${i}`} className="tac-gap" data-testid={`tac-gap-${rec.id}-${i}`}>
                  <code className="tac-id">{g.command}</code>{" "}
                  <span className="tac-learn-meta">
                    {(GAP_KIND_LABEL[g.kind] ?? g.kind) + " · " + g.dialect + " · " + rec.hostname}
                  </span>
                  <p className="tac-gap-why">{g.reason}</p>
                  {g.excerpt && <pre className="tac-gap-out">{g.excerpt}</pre>}
                  <button type="button" className="btn sm" onClick={() => setWriting(g)}>
                    Write the answer
                  </button>
                </li>
              )),
            )}
          </ul>
        </>
      )}

      <h3 className="tac-section-h">Signature candidates</h3>
      <p className="mini-meta tac-note">{CANDIDATE_NOTE}</p>
      {writing && (
        <CandidateForm
          gap={writing}
          onClose={() => setWriting(null)}
          onSaved={() => { setWriting(null); onChange(); }}
        />
      )}
      {learn.candidates.length === 0 ? (
        <p className="tac-cand-empty" data-testid="tac-cand-none">{CANDIDATE_NONE}</p>
      ) : (
        <ul className="tac-cands" data-testid="tac-cand-list">
          {learn.candidates.map((c) => (
            <CandidateRow key={c.id} c={c} onChange={onChange} />
          ))}
        </ul>
      )}
    </>
  );
}

/** One saved candidate, with the export that carries it out to a research file
 *  and the delete that drops it. Both are the operator's, never the engine's. */
function CandidateRow({ c, onChange }: { c: TacCandidate; onChange: () => void }) {
  const [busy, setBusy] = useState("");
  const [err, setErr] = useState("");

  const exportOne = () => {
    setBusy("export");
    api.tacCandidateExport(c.dialect)
      .then((text) => {
        setErr("");
        // A Blob, not a link to the route: the route needs the session header,
        // and a bare href would arrive unauthenticated and read as broken.
        const url = URL.createObjectURL(new Blob([text], { type: "text/yaml" }));
        const a = document.createElement("a");
        a.href = url;
        a.download = `${c.dialect}-candidates.yaml`;
        a.click();
        URL.revokeObjectURL(url);
      })
      .catch((e: unknown) => setErr(tacError(e, CANDIDATE_EXPORT_FAILED)))
      .finally(() => setBusy(""));
  };

  return (
    <li data-testid={`tac-cand-${c.id}`}>
      <span className="tac-alt-t">{c.title}</span>{" "}
      <code className="tac-id">{c.class_id}</code>{" "}
      <span className="tac-learn-meta">
        {c.dialect + (c.proposed_class ? " · proposed class" : "") + " · " + c.status}
      </span>
      {err && <p className="tac-bad" role="alert">{err}</p>}
      <span className="tac-cand-actions">
        <button type="button" className="btn sm" disabled={busy !== ""} onClick={exportOne}>
          Export research file
        </button>
        <button
          type="button"
          className="btn sm"
          disabled={busy !== ""}
          onClick={() => {
            setBusy("delete");
            api.tacCandidateDelete(c.id)
              .then(() => { setErr(""); onChange(); })
              .catch((e: unknown) => setErr(tacError(e, CANDIDATE_EXPORT_FAILED)))
              .finally(() => setBusy(""));
          }}
        >
          Drop
        </button>
      </span>
    </li>
  );
}

/** Writing a TAC answer down against one gap.
 *
 *  The form is seeded from the gap — the command Correlix ran and the dialect it
 *  ran on are facts, not something an operator should retype — and everything
 *  else is theirs. The server re-validates every field; a refusal is rendered
 *  verbatim rather than reduced to "invalid", because the operator needs to
 *  know WHICH line Correlix will not carry. */
function CandidateForm(
  { gap, onClose, onSaved }: { gap: TacGap; onClose: () => void; onSaved: () => void },
) {
  const [title, setTitle] = useState("");
  const [classID, setClassID] = useState("");
  const [logLine, setLogLine] = useState("");
  const [answer, setAnswer] = useState("");
  const [source, setSource] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  const save = () => {
    setBusy(true);
    api.tacCandidateSave({
      dialect: gap.dialect,
      class_id: classID.trim(),
      title: title.trim(),
      log_signatures: logLine.trim() ? [logLine.trim()] : [],
      commands: [{ intent: gap.intent, command: gap.command }],
      sources: source.trim() ? [{ url: source.trim() }] : [],
      answer: answer.trim(),
    })
      .then(() => { setErr(""); onSaved(); })
      .catch((e: unknown) => setErr(tacError(e, CANDIDATE_EXPORT_FAILED)))
      .finally(() => setBusy(false));
  };

  return (
    <form
      className="tac-cand-form"
      data-testid="tac-cand-form"
      onSubmit={(e) => { e.preventDefault(); save(); }}
    >
      <label>
        Title
        <input value={title} onChange={(e) => setTitle(e.target.value)} required />
      </label>
      <label>
        Issue class
        <input value={classID} onChange={(e) => setClassID(e.target.value)} required />
      </label>
      <label>
        Log line
        <input value={logLine} onChange={(e) => setLogLine(e.target.value)} />
      </label>
      <label>
        What TAC said
        <textarea value={answer} onChange={(e) => setAnswer(e.target.value)} rows={3} />
      </label>
      <label>
        Source link
        <input value={source} onChange={(e) => setSource(e.target.value)} type="url" />
      </label>
      {err && <p className="tac-bad" role="alert">{err}</p>}
      <span className="tac-cand-actions">
        <button type="submit" className="btn sm" disabled={busy}>Save candidate</button>
        <button type="button" className="btn sm" onClick={onClose}>Cancel</button>
      </span>
    </form>
  );
}
