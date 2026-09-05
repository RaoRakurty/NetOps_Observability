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
//   · the unknown-output backlog is NOT counted anywhere yet, so it renders as
//     an explicit "not yet tracked" — a zero there would read as "there is
//     none", which is a claim nobody has earned.
//
// Everything on this page is version-pinned REFERENCE data, identical for every
// tenant; it reveals nothing about anyone's devices or incidents. Every string
// is still rendered as escaped React text.

import { useEffect, useMemo, useState } from "react";
import "../troubleshoot/investigation.css";
import { api, type TacDialectCoverage, type TacKnowledge } from "../../services/api";
import WindowedList from "../../components/WindowedList";
import {
  BACKLOG_NOT_TRACKED,
  COMMAND_POLICY_NO_EXCLUSIONS,
  COMMAND_POLICY_NOTE,
  KNOWLEDGE_FAILED,
  KNOWLEDGE_GROWTH_NOTE,
  NO_UNPLANNED_DIALECTS,
  tacError,
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

  useEffect(() => {
    let alive = true;
    api.tacKnowledge()
      .then((k) => { if (alive) { setData(k); setErr(""); } })
      .catch((e: unknown) => { if (alive) setErr(tacError(e, KNOWLEDGE_FAILED)); });
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
        <p className="mini-meta">
          What Correlix can plan and collect for each vendor dialect when an incident is escalated.
          Issue catalogue {data.catalog_version} · engine {data.engine_version} ·{" "}
          {data.classes.length} issue classes · {data.intents.length} command intents.
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
        <h2 id="tac-know-unplanned-h" className="tac-step-h">Platforms with no authored plan</h2>
        <p className="mini-meta tac-note">
          Correlix recognises these platforms and has authored no command set for them. An escalation on
          one of them says so and offers the paste path instead of guessing a command.
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
        <h2 id="tac-know-policy-h" className="tac-step-h">What Correlix will not learn</h2>
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

      <section className="tac-step" aria-labelledby="tac-know-grow-h">
        <h2 id="tac-know-grow-h" className="tac-step-h">How this grows</h2>
        <p className="mini-meta tac-note">{KNOWLEDGE_GROWTH_NOTE}</p>
        <p className="mini-meta tac-note">
          <strong>Unrecognised outputs:</strong>{" "}
          <span data-testid="tac-backlog">{BACKLOG_NOT_TRACKED}</span>
        </p>
      </section>
    </div>
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
                  : <span className="mini-meta">this dialect binds no command for it</span>}
                <span className="mini-meta">{verifiedLabel(it.verified) || "not bound"}</span>
              </div>
            )}
          />
          <p className="mini-meta tac-note">
            {intents.length} intents · scroll the table; only the rows in view are drawn.
          </p>
        </>
      )}
    </div>
  );
}
