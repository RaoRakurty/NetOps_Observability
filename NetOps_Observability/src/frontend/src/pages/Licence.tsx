// Licence.tsx — the platform Licence page.
//
// WHAT THIS PAGE IS FOR. An operator opens it to answer four questions, and it
// is laid out in that order:
//
//   1 LICENCE      — who this platform is licensed to, at what tier, until
//                    when, and whether it is actually in force right now. A
//                    licence past its grace period, or one we REFUSED, is the
//                    loudest thing on the page: the operator believes they have
//                    a licence, and they do not.
//   2 CURRENT USAGE— where the platform stands against every ceiling the
//                    licence carries. Two of the seven are gated in the product
//                    today; the other five are carried so an issued file is
//                    complete, and they say so rather than being drawn as bars
//                    that bite.
//   3 FEATURES     — which commercial capabilities this licence grants, and for
//                    the ones it does not, the tier that would.
//   4 INSTALL      — put a licence on the platform, or take it off. A refusal
//                    is shown WORD FOR WORD: someone holding a file we will not
//                    accept needs the exact reason, not "that was not accepted".
//   5 VERIFICATION — the public key and the offline recipe, so a customer can
//                    check what we sent them without trusting this page, plus
//                    the standing note that expiry policy is still open.
//
// THE HONESTY RULES ARE THE PRODUCT (docs/design/DATA_PROTECTION_PAGE §3, the
// pattern of record for this page):
//
//   - A ceiling the platform does not count arrives as null with a reason, goes
//     through `measured()` in licence.model.ts, and renders as
//     "not measured — <reason>". Never a 0, never an empty bar, never a tick.
//   - An unlimited ceiling has no percentage, so no bar is drawn for it.
//   - Community is not a degraded mode. It is the free tier and it is styled as
//     a plain fact, not as a warning.
//   - Nothing on this page can delete anything. What is over a ceiling is
//     LISTED, and the page says so beside the list.
//
// GATING. The route behind this page is platform-global and requirePlatformAdmin
// on the server. A tenant admin sees the licence read-only and is told why the
// controls are absent, rather than being shown buttons that 403.

import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { api, type LicenceCeiling, type LicenceKey, type LicenceView } from "../services/api";
import { useAuth } from "../hooks/useAuth";
import Icon from "../components/Icon";
import { operatorError } from "../lib/errors";
import {
  NOT_ENFORCED_NOTE,
  NOT_ENFORCED_REASON,
  checkDocument,
  confirmMatches,
  expiryVerdict,
  featureStatus,
  fmtLimit,
  headline,
  keyFileBody,
  keyFileName,
  keyRoleLabel,
  liftedByText,
  measured,
  notMeasuredText,
  overageSummary,
  refusalReason,
  sortedCeilings,
  tierLabel,
  usageBar,
  type Measured,
  type Tone,
} from "./licence.model";

// ── panel plumbing ──────────────────────────────────────────────────────────

type Panel<T> = { data: T | null; error: string | null; loading: boolean };

/**
 * The page's one read. Every section renders from it, and every section states
 * its own absence — a failed read leaves five sections each saying they cannot
 * describe the licence, rather than one blank page that implies nothing is
 * wrong.
 */
function usePanel<T>(read: () => Promise<T>, fallback: string): [Panel<T>, () => void, (v: T) => void] {
  const [state, setState] = useState<Panel<T>>({ data: null, error: null, loading: true });
  const readRef = useRef(read);
  readRef.current = read;
  const reload = useCallback(() => {
    setState((p) => ({ ...p, loading: true }));
    readRef
      .current()
      .then((data) => setState({ data, error: null, loading: false }))
      .catch((e: unknown) => setState({ data: null, error: operatorError(e, fallback), loading: false }));
  }, [fallback]);
  useEffect(() => { reload(); }, [reload]);
  const put = useCallback((v: T) => setState({ data: v, error: null, loading: false }), []);
  return [state, reload, put];
}

// ── presentation primitives ─────────────────────────────────────────────────

function Pill({ tone, children, title }: { tone: Tone; children: ReactNode; title?: string }) {
  return <span className={`lic-pill lic-${tone}`} title={title}>{children}</span>;
}

/** A section of the page: a landmark, a stable id, and its own header. */
function Section({ id, title, note, actions, children }: {
  id: string; title: string; note?: ReactNode; actions?: ReactNode; children: ReactNode;
}) {
  return (
    <section className="lic-sec" data-section={id} role="region" aria-label={title}>
      <div className="lic-sec-hd">
        <h2>{title}</h2>
        {note && <span className="lic-sec-note">{note}</span>}
        <span className="lic-sp" />
        {actions}
      </div>
      <div className="lic-sec-bd">{children}</div>
    </section>
  );
}

/**
 * Renders a measured value, or the reason it is absent. This is the only way a
 * nullable contract value reaches the screen.
 */
function Value<T>({ m, render }: { m: Measured<T>; render: (v: T) => ReactNode }) {
  if (!m.measured) return <span className="lic-absent">{notMeasuredText(m.reason)}</span>;
  return <>{render(m.value)}</>;
}

/** An honest state: what is true, and what to do about it. */
function HonestState({ tone, headline: head, remedy }: { tone: Tone; headline: string; remedy: string }) {
  return (
    <div className={`lic-honest lic-${tone}`} role="note">
      <strong>{head}</strong>
      <span>{remedy}</span>
    </div>
  );
}

function Loading({ what }: { what: string }) {
  return <div className="lic-loading">Reading {what}…</div>;
}

function PanelError({ text, onRetry }: { text: string; onRetry: () => void }) {
  return (
    <div className="lic-honest lic-bad" role="alert">
      <strong>{text}</strong>
      <span>Nothing in this part of the page is a statement about the licence until it loads.</span>
      <button type="button" className="lic-more" onClick={onRetry}>Read it again</button>
    </div>
  );
}

/** One fact in the headline grid. The box is reserved, so nothing shifts. */
function Fact({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="lic-fact">
      <dt>{label}</dt>
      <dd>{children}</dd>
    </div>
  );
}

// ── 1 · the licence itself ──────────────────────────────────────────────────

function LicenceHeadline({ view }: { view: LicenceView }) {
  const st = view.state;
  const h = headline(st);
  const expiry = expiryVerdict(view);
  const summary = overageSummary(view.overages);
  const support = st.support;

  return (
    <>
      <div className={`lic-hero lic-${h.tone}`}>
        <div className="lic-hero-head">
          <Icon name="shield" size={22} />
          <div className="lic-hero-verdict">
            <span className="lic-hero-state">{h.label}</span>
            <span className="lic-hero-reason">{h.reason}</span>
          </div>
        </div>

        <dl className="lic-facts">
          <Fact label="Customer">
            <Value
              m={measured(st.customer || null, "no licence names a customer on this platform")}
              render={(v) => <span>{v}</span>}
            />
          </Fact>
          <Fact label="Tier in force">
            <Pill tone={h.tone === "bad" ? "bad" : h.tone === "warn" ? "warn" : "good"}>{tierLabel(st.tier)}</Pill>
            {st.licensed_tier && st.licensed_tier !== st.tier && (
              <span className="lic-sub lic-block">the licence names {tierLabel(st.licensed_tier)}</span>
            )}
          </Fact>
          <Fact label="Licence">
            <Value
              m={measured(st.licence_id || null, "no licence is installed")}
              render={(v) => <span className="mono">{v}</span>}
            />
            {st.issued_at && <span className="lic-sub lic-block">issued {st.issued_at}</span>}
          </Fact>
          <Fact label="Expiry">
            {expiry.state === "none" ? (
              <span className="lic-sub">{expiry.text}</span>
            ) : (
              <>
                <Pill tone={expiry.tone}>{expiry.text}</Pill>
                <span className="lic-sub lic-block mono">{st.expires_at}</span>
              </>
            )}
          </Fact>
          <Fact label="Grace period">
            <Value
              m={measured(st.grace_days ?? null, "no licence is installed, so no grace period applies")}
              render={(v) => <span>{v} days, set by the issuer</span>}
            />
          </Fact>
          <Fact label="Support">
            <Value
              m={measured(support?.level || null, "the licence records no support level")}
              render={(v) => (
                <>
                  <span>{v}</span>
                  {support?.contact && <span className="lic-sub lic-block">{support.contact}</span>}
                </>
              )}
            />
          </Fact>
        </dl>
      </div>

      {st.load_error && (
        <HonestState
          tone="bad"
          headline="A licence is installed, and the platform will not use it."
          remedy={`${st.load_error} Until that is fixed the Community ceilings are the ones in force — install a licence the platform accepts, or remove this one so the page stops reporting a licence nobody is getting the benefit of.`}
        />
      )}

      {summary && (
        <div className="lic-over" role="note">
          <strong>{summary}</strong>
          <ul className="lic-over-list">
            {view.overages.map((o) => (
              <li key={o.ceiling}>
                <Pill tone="bad">{o.over} over</Pill>
                <span>{o.message}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </>
  );
}

// ── 2 · current usage ───────────────────────────────────────────────────────

function UsageRow({ row }: { row: LicenceCeiling }) {
  const bar = usageBar(row);
  const lifted = liftedByText(row.lifted_by);
  const tone: Tone = !row.enforced ? "muted" : row.over ? "bad" : bar.kind === "measured" && bar.percent >= 90 ? "warn" : "good";

  return (
    <li className={`lic-usage-row lic-${tone}`}>
      <div className="lic-usage-hd">
        <span className="lic-usage-name">{row.label}</span>
        {!row.enforced && <Pill tone="muted" title={NOT_ENFORCED_REASON}>{NOT_ENFORCED_NOTE}</Pill>}
        {row.over && <Pill tone="bad">over the ceiling</Pill>}
        <span className="lic-sp" />
        <span className="lic-usage-num">
          {bar.kind === "unmeasured"
            ? <span className="lic-absent">{notMeasuredText(bar.reason)}</span>
            : <span className="mono">{bar.text}</span>}
        </span>
      </div>

      {/* A bar is drawn ONLY where a percentage is a real number AND something
          gates on it: a counted value against a finite limit that the product
          actually enforces. Unlimited, uncounted and carried-but-un-enforced
          rows keep the track and get no fill — a bar nothing enforces would
          read as a live gate, and a bar against "no limit" would be a number we
          invented. Every row keeps the same height, so the list does not jump
          between reads. */}
      <div className="lic-bar" aria-hidden="true">
        {bar.kind === "measured" && row.enforced && (
          <span className="lic-bar-fill" style={{ width: `${bar.percent}%` }} />
        )}
      </div>

      <div className="lic-usage-ft">
        <span className="lic-sub">
          {bar.kind === "unlimited"
            ? "This licence sets no limit here."
            : `Licensed limit ${fmtLimit(row.limit)}.`}
          {row.enforced ? "" : ` ${NOT_ENFORCED_REASON}`}
        </span>
        {lifted && <Pill tone="muted">{lifted}</Pill>}
      </div>
    </li>
  );
}

function Usage({ rows }: { rows: readonly LicenceCeiling[] }) {
  const ordered = useMemo(() => sortedCeilings(rows), [rows]);
  if (ordered.length === 0) {
    return (
      <HonestState
        tone="warn"
        headline="The platform listed no ceilings."
        remedy="Until it does, nothing here is a statement about what this licence covers. Read the page again."
      />
    );
  }
  return <ul className="lic-usage">{ordered.map((r) => <UsageRow key={r.name} row={r} />)}</ul>;
}

// ── 3 · features ────────────────────────────────────────────────────────────

function Features({ view }: { view: LicenceView }) {
  if (view.features.length === 0) {
    return (
      <HonestState
        tone="warn"
        headline="The platform listed no commercial capabilities."
        remedy="Read the page again. An empty list is not the same as a licence that grants nothing."
      />
    );
  }
  return (
    <div className="lic-tblwrap">
      <table className="lic-tbl" aria-label="Commercial capabilities">
        <thead>
          <tr>
            <th scope="col">Capability</th>
            <th scope="col">This licence</th>
            <th scope="col">Lowest tier that includes it</th>
          </tr>
        </thead>
        <tbody>
          {view.features.map((f) => {
            const s = featureStatus(f);
            return (
              <tr key={f.name}>
                <th scope="row">{f.label}</th>
                <td><Pill tone={s.tone}>{s.text}</Pill></td>
                <td>{tierLabel(f.included_in) || <span className="lic-absent">not stated</span>}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

// ── 4 · install ─────────────────────────────────────────────────────────────

function InstallPanel({ view, canEdit, onInstalled }: {
  view: LicenceView; canEdit: boolean; onInstalled: (v: LicenceView) => void;
}) {
  const [text, setText] = useState("");
  const [busy, setBusy] = useState(false);
  const [refused, setRefused] = useState<string | null>(null);
  const [done, setDone] = useState<string | null>(null);
  const [confirm, setConfirm] = useState<string | null>(null);
  const [typed, setTyped] = useState("");
  const installed = view.state.source === "file" || !!view.state.load_error;
  const removeToken = view.state.licence_id || "remove";

  const install = async (document: string) => {
    setBusy(true); setRefused(null); setDone(null);
    try {
      const next = await api.putLicence(document);
      onInstalled(next);
      setText("");
      setDone(
        next.state.licence_id
          ? `Installed ${next.state.licence_id} — ${tierLabel(next.state.licensed_tier || next.state.tier)}.`
          : "Installed.",
      );
    } catch (e: unknown) {
      // VERBATIM. The server's refusal is the only thing that helps whoever is
      // holding the file, and softening it here would send them to us instead.
      setRefused(refusalReason(e, "The platform did not say why it refused that document."));
    } finally {
      setBusy(false);
    }
  };

  const submitText = async () => {
    const check = checkDocument(text);
    if (!check.ok) { setRefused(check.reason); return; }
    await install(check.document);
  };

  const onFile = async (file: File | undefined) => {
    if (!file) return;
    setRefused(null); setDone(null);
    let body = "";
    try {
      body = await file.text();
    } catch {
      setRefused("That file could not be read in this browser. Open it and paste its contents below.");
      return;
    }
    const check = checkDocument(body);
    if (!check.ok) { setRefused(check.reason); return; }
    setText(check.document);
    await install(check.document);
  };

  const remove = async () => {
    setBusy(true); setRefused(null); setDone(null);
    try {
      const next = await api.deleteLicence();
      onInstalled(next);
      setConfirm(null); setTyped("");
      setDone("The licence was removed. The Community ceilings are now the ones in force.");
    } catch (e: unknown) {
      setRefused(refusalReason(e, "The licence could not be removed."));
    } finally {
      setBusy(false);
    }
  };

  if (!canEdit) {
    return (
      <HonestState
        tone="muted"
        headline="You are seeing this licence read-only."
        remedy="A licence covers the whole platform, not one tenant, so installing or removing one requires a platform administrator. Everything above is what is in force for every tenant on this platform."
      />
    );
  }

  return (
    <div className="lic-install">
      <p className="lic-sub">
        The document is verified before anything is written, so a licence the platform will not accept never
        displaces the one already in force.
      </p>

      <label className="lic-field">
        <span>Licence file</span>
        <input
          type="file"
          className="lic-file"
          aria-label="Licence file to install"
          disabled={busy}
          onChange={(e) => { void onFile(e.target.files?.[0]); }}
        />
      </label>

      <label className="lic-field">
        <span>Or paste the licence document</span>
        <textarea
          className="lic-textarea mono"
          aria-label="Licence document"
          rows={6}
          spellCheck={false}
          value={text}
          disabled={busy}
          placeholder={'{"licence_id": "…", "customer": "…", …}'}
          onChange={(e) => setText(e.target.value)}
        />
      </label>

      {refused && (
        <div className="lic-honest lic-bad" role="alert">
          <strong>The platform refused that licence.</strong>
          <span className="lic-verbatim mono">{refused}</span>
          <span className="lic-sub">
            That is the platform's own words, unchanged. The licence already in force, if any, was not touched.
          </span>
        </div>
      )}
      {done && <p className="lic-msg lic-good" role="status">{done}</p>}

      <div className="lic-actions">
        <button type="button" className="btn accent" disabled={busy || !text.trim()} onClick={() => { void submitText(); }}>
          {busy ? "Installing…" : "Install licence"}
        </button>
        {installed && (
          <button type="button" className="btn danger" disabled={busy} onClick={() => { setConfirm(removeToken); setTyped(""); }}>
            Remove licence…
          </button>
        )}
      </div>

      {confirm !== null && (
        <div className="lic-honest lic-warn" role="note">
          <strong>Removing the licence drops the platform to the Community ceilings.</strong>
          <span>
            No data is deleted and nothing stops collecting. What is over a Community ceiling stays exactly where
            it is and is listed at the top of this page as over-ceiling.
          </span>
          <label className="lic-field">
            <span>Type <span className="mono">{confirm}</span> to confirm</span>
            <input
              className="lic-input mono"
              aria-label={`Type ${confirm} to confirm removing the licence`}
              value={typed}
              onChange={(e) => setTyped(e.target.value)}
            />
          </label>
          <div className="lic-actions">
            <button type="button" className="btn" disabled={busy} onClick={() => { setConfirm(null); setTyped(""); }}>
              Keep it
            </button>
            <button
              type="button" className="btn danger"
              disabled={busy || !confirmMatches(typed, confirm)}
              onClick={() => { void remove(); }}
            >
              {busy ? "Removing…" : "Remove licence"}
            </button>
          </div>
        </div>
      )}

      <p className="lic-sub">
        A licence may also be placed on the host by hand at <span className="mono">{view.path}</span>.
      </p>
    </div>
  );
}

// ── 5 · verification ────────────────────────────────────────────────────────

/** Hands the operator a file. Guarded: a browser without object URLs says so. */
function downloadText(filename: string, body: string): boolean {
  if (typeof URL?.createObjectURL !== "function") return false;
  const url = URL.createObjectURL(new Blob([body], { type: "text/plain" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
  return true;
}

function Verification({ view }: { view: LicenceView }) {
  const [note, setNote] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const save = (k: LicenceKey) => {
    const ok = downloadText(keyFileName(k.id), keyFileBody(k));
    setNote(ok ? `Saved ${keyFileName(k.id)}.` : "This browser would not save the file. The key is shown above and can be copied.");
  };

  const copyHint = async () => {
    try {
      await navigator.clipboard.writeText(view.verify_hint);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      setCopied(false);
      setNote("This browser would not put it on the clipboard. The command is shown in full above.");
    }
  };

  return (
    <>
      <p className="lic-sub">
        A licence is a signed document. Anyone can check ours without this page, and without us: the public keys
        this build trusts are below, and the recipe beside them uses nothing but the file and the key.
      </p>

      {/* Verbatim, because it is a command someone is going to run. */}
      <div className="lic-cmdwrap">
        <pre className="lic-cmd">{view.verify_hint}</pre>
        <button type="button" className="btn sm" onClick={() => { void copyHint(); }}>
          {copied ? "Copied" : "Copy command"}
        </button>
      </div>

      {view.keys.length === 0 ? (
        <HonestState
          tone="bad"
          headline="This build trusts no signing key."
          remedy="No licence can be verified, so none can be installed. That is a build fault, not a configuration one — report it with the platform version."
        />
      ) : (
        <ul className="lic-keys">
          {view.keys.map((k) => (
            <li key={k.id}>
              <div className="lic-key-hd">
                <span className="mono lic-key-id">{k.id}</span>
                <Pill tone={k.role === "current" ? "good" : "muted"}>{keyRoleLabel(k.role)}</Pill>
                <span className="lic-sp" />
                <button type="button" className="btn sm" onClick={() => save(k)}>
                  <Icon name="key" size={13} /> Download public key
                </button>
              </div>
              <code className="lic-key-b64">{k.base64}</code>
              {k.note && <span className="lic-sub lic-block">{k.note}</span>}
            </li>
          ))}
        </ul>
      )}

      {note && <p className="lic-msg lic-muted" role="status">{note}</p>}

      {/* The standing note. It is on the page and not only in a design document
          because a policy that is still open is a fact about the product. */}
      <div className="lic-honest lic-muted" role="note">
        <strong>What expiry does, and what it never does</strong>
        <span>{view.expiry_semantics}</span>
      </div>
    </>
  );
}

// ── the page ────────────────────────────────────────────────────────────────

export default function Licence() {
  const { user, loading: authLoading } = useAuth();
  const platformAdmin = !!user?.platform_admin;
  const [panel, reload, put] = usePanel<LicenceView>(
    () => api.getLicence(),
    "The licence could not be read.",
  );
  const view = panel.data;

  const body = (what: string, render: (v: LicenceView) => ReactNode): ReactNode => {
    if (panel.error) return <PanelError text={panel.error} onRetry={reload} />;
    if (!view) return <Loading what={what} />;
    return render(view);
  };

  return (
    <div className="lic-page">
      <Section
        id="licence"
        title="Licence"
        note="Platform-global — one licence for every tenant on this platform"
        actions={
          <button type="button" className="btn sm" onClick={reload}>
            <Icon name="refresh" size={13} /> Re-read
          </button>
        }
      >
        {body("the licence", (v) => <LicenceHeadline view={v} />)}
        {!authLoading && !platformAdmin && (
          <HonestState
            tone="muted"
            headline="You are seeing this licence read-only."
            remedy="A licence covers the whole platform rather than one tenant, so changing it requires a platform administrator. What is shown here is what is in force for everyone."
          />
        )}
      </Section>

      <Section
        id="usage"
        title="Current usage"
        note="Where this platform stands against every ceiling the licence carries"
      >
        {body("the ceilings", (v) => <Usage rows={v.ceilings} />)}
      </Section>

      <Section
        id="features"
        title="Features"
        note="The commercial capabilities, and the tier each one belongs to"
      >
        {body("the capabilities", (v) => <Features view={v} />)}
      </Section>

      <Section id="install" title="Install a licence" note="Verified before it is written">
        {body("the licence", (v) => (
          <InstallPanel view={v} canEdit={platformAdmin} onInstalled={put} />
        ))}
      </Section>

      <Section id="verification" title="Verification" note="Check what we sent you without trusting this page">
        {body("the trusted keys", (v) => <Verification view={v} />)}
      </Section>
    </div>
  );
}
