// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

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
// GATING — TWO SCOPES, and the SERVER decides which one you get. There is ONE
// licence file per installation, so installing or replacing it stays the
// provider's action: PUT/DELETE run licenceGate → requirePlatformAdmin
// (internal/licence/api.go), and licence_routes_test.go asserts a tenant admin
// is refused on both. The READ was split on 2026-09-05 (the owner's IA,
// docs/design/ADMIN_IA_2026-09-05.md): GET runs licenceReadGate →
// requireAdmin, so a tenant/org admin sees what the installation's licence puts
// in force FOR THEM.
//
// The payload says which it is — `view.scope`:
//
//   platform — the provider view. Everything below renders, including the
//              install/remove controls, the trusted keys and the offline recipe.
//   tenant   — the tenant projection. Same licence, seen from one tenant: their
//              OWN usage beside the shared ceilings, the tier and features in
//              force, expiry state, and who to ask to change it. The customer,
//              the licence id, the support terms, the file path and the key
//              material are NOT in the payload, so this page does not render a
//              "not measured" placeholder where they would be — a fact withheld
//              from a tenant and a fact the platform does not have are
//              different things, and only one of them belongs on a page.
//
// The page therefore branches on `view.scope` (what the server actually
// answered) rather than on the caller's platform_admin flag (what the SPA
// believes about the caller): a platform owner narrowed into a tenant with the
// tenant switcher gets the tenant projection, and the page must render what it
// was given.

import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import {
  api,
  type LicenceCeiling,
  type LicenceKey,
  type LicenceUsageView,
  type LicenceView,
} from "../services/api";
import { useAuth } from "../hooks/useAuth";
import Icon from "../components/Icon";
import AskIris from "../components/AskIris";
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
  overageSince,
  overageSummary,
  refusalReason,
  sortedCeilings,
  stateChip,
  tierLabel,
  usageBand,
  usageBar,
  bandLabel,
  bandTone,
  ceilingConsequence,
  DEFAULT_USAGE_PERIOD,
  INSTALLATION_TENANT,
  NOT_MEASURED_FALLBACK,
  NO_SNAPSHOT_TEXT,
  USAGE_PERIODS,
  meterSeries,
  meterUnitText,
  monitoringLine,
  periodFor,
  periodLabel,
  snapshotAge,
  usageRows,
  type UsageMeterRow,
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
function Section({ id, title, note, topic, actions, children }: {
  id: string; title: string; note?: ReactNode; topic?: string; actions?: ReactNode; children: ReactNode;
}) {
  return (
    <section className="lic-sec" data-section={id} role="region" aria-label={title}>
      <div className="lic-sec-hd">
        <h2>{title}{topic ? <AskIris topic={topic} label={title} /> : null}</h2>
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
  const chip = stateChip(view);
  const expiry = expiryVerdict(view);
  const summary = overageSummary(view.overages);
  const support = st.support;
  // The provider's commercial identity is not in the tenant projection at all.
  // Those facts are OMITTED rather than rendered as "not measured": the
  // platform knows the customer perfectly well, it simply is not this reader's
  // business, and claiming otherwise would be the page lying on our behalf.
  const provider = view.scope === "platform";

  return (
    <>
      <div className={`lic-hero lic-${h.tone}`}>
        <div className="lic-hero-head">
          <Icon name="shield" size={22} />
          <div className="lic-hero-verdict">
            <span className="lic-hero-state">
              {h.label}
              {/* The one-glance chip: valid · trial · in grace, N days left ·
                  past grace. The days come from the server's own clock, so this
                  and the metric can never disagree by a timezone. */}
              <Pill tone={chip.tone} title={chip.detail}>{chip.label}</Pill>
            </span>
            <span className="lic-hero-reason">{h.reason}</span>
          </div>
        </div>

        <dl className="lic-facts">
          {provider && (
            <Fact label="Customer">
              <Value
                m={measured(st.customer || null, "no licence names a customer on this platform")}
                render={(v) => <span>{v}</span>}
              />
            </Fact>
          )}
          <Fact label="Tier in force">
            <Pill tone={h.tone === "bad" ? "bad" : h.tone === "warn" ? "warn" : "good"}>{tierLabel(st.tier)}</Pill>
            {st.licensed_tier && st.licensed_tier !== st.tier && (
              <span className="lic-line lic-block">the licence names {tierLabel(st.licensed_tier)}</span>
            )}
          </Fact>
          {provider && (
            <Fact label="Licence">
              <Value
                m={measured(st.licence_id || null, "no licence is installed")}
                render={(v) => <span className="mono">{v}</span>}
              />
              {st.issued_at && <span className="lic-line lic-block">issued {st.issued_at}</span>}
            </Fact>
          )}
          <Fact label="Expiry">
            {expiry.state === "none" ? (
              <span className="lic-line">{expiry.text}</span>
            ) : (
              <>
                <Pill tone={expiry.tone}>{expiry.text}</Pill>
                <span className="lic-line lic-block mono">{st.expires_at}</span>
              </>
            )}
          </Fact>
          <Fact label="Grace period">
            <Value
              m={measured(st.grace_days ?? null, "no licence is installed, so no grace period applies")}
              render={(v) => (
                <>
                  <span>{v} days, set by the issuer</span>
                  {st.grace_ends_at && (
                    <span className="lic-line lic-block">
                      {view.grace_days_left === null || view.grace_days_left === undefined
                        ? `covered until ${st.grace_ends_at}`
                        : `${view.grace_days_left} ${view.grace_days_left === 1 ? "day" : "days"} left — until ${st.grace_ends_at}`}
                    </span>
                  )}
                </>
              )}
            />
          </Fact>
          {provider ? (
            <Fact label="Support">
              <Value
                m={measured(support?.level || null, "the licence records no support level")}
                render={(v) => (
                  <>
                    <span>{v}</span>
                    {support?.contact && <span className="lic-line lic-block">{support.contact}</span>}
                  </>
                )}
              />
            </Fact>
          ) : (
            <Fact label="Managed by">
              {/* The pill only. The sentence explaining it belongs where the
                  reader asks the question — beside the licence and where the
                  install controls would be — not a third time in a fact grid. */}
              <Pill tone="muted">{view.managed_by}</Pill>
            </Fact>
          )}
        </dl>
      </div>

      {st.load_error && (
        <HonestState
          tone="bad"
          headline="A licence is installed, and the platform will not use it."
          remedy={`${st.load_error} Until it is fixed the Community ceilings are in force.`}
        />
      )}

      {summary && (
        <div className="lic-over" role="note">
          <strong>{summary}</strong>
          <ul className="lic-over-list">
            {view.overages.map((o) => {
              const since = overageSince(o);
              return (
                <li key={o.ceiling}>
                  {/* A SOFT overage is a billing fact, not a fault: nothing was
                      blocked. Rendering it in the same red as a hard one would
                      send a paid operator hunting for a device that stopped. */}
                  <Pill tone={o.soft ? "warn" : "bad"}>{o.over} {o.soft ? "above" : "over"}</Pill>
                  <span>{o.message}</span>
                  {/* The START of the episode, and nothing else. How long an
                      overage may run is an order-form term; a countdown here
                      would be the product inventing commercial policy. */}
                  {since && <span className="lic-line lic-block">{since}</span>}
                </li>
              );
            })}
          </ul>
        </div>
      )}

      {/* WHICH devices are beyond the allowance. Provider view only — the
          ordering that decides "beyond" is platform-wide, so the server does
          not send this to a tenant. Nothing here is disabled: the note says so
          in the server's own words. */}
      {view.over_ceiling_devices && view.over_ceiling_devices.length > 0 && (
        <div className="lic-over" role="note">
          <strong>{view.over_ceiling_devices.length} monitored device(s) beyond the allowance</strong>
          {view.over_ceiling_note && <span className="lic-line lic-block">{view.over_ceiling_note}</span>}
          <ul className="lic-over-list">
            {view.over_ceiling_devices.map((d) => (
              <li key={d.device_id}>
                <Pill tone="warn">still monitored</Pill>
                <span className="mono">{d.name || d.device_id}</span>
                <span className="lic-line lic-block">{d.reason}</span>
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
  // The 80 / 90 / 100 % ramp, from the three severity tokens the rest of the
  // page uses — one place decides the colour, so a pill, a banner and a bar
  // never disagree about what "warn" means here.
  const band = usageBand(row);
  const tone: Tone = !row.enforced ? "muted" : bandTone(band);
  const bandText = bandLabel(band);

  return (
    <li className={`lic-usage-row lic-${tone}`}>
      <div className="lic-usage-hd">
        <span className="lic-usage-name">{row.label}</span>
        {!row.enforced && <Pill tone="muted" title={NOT_ENFORCED_REASON}>{NOT_ENFORCED_NOTE}</Pill>}
        {/* SOFT is stated on the row, not only in the overage banner: an
            operator reading a bar at 96 % needs to know, right there, whether
            the next device is admitted or refused. */}
        {row.enforced && row.soft && <Pill tone="muted" title={ceilingConsequence(row)}>soft — recorded, not blocked</Pill>}
        {bandText && <Pill tone={tone}>{bandText}</Pill>}
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
        <span className="lic-line">
          {bar.kind === "unlimited"
            ? "This licence sets no limit here."
            : `Licensed limit ${fmtLimit(row.limit)}.`}
          {/* What actually happens past the limit, said only once the bar is in
              a warning band — below 80 % it is noise, and above it, it is the
              question the operator has. */}
          {row.enforced && bandText ? ` ${ceilingConsequence(row)}` : ""}
          {row.enforced ? "" : ` ${NOT_ENFORCED_REASON}`}
        </span>
        {lifted && <Pill tone="muted">{lifted}</Pill>}
      </div>

      {/* A qualifier on a number we DID count — today: devices the ceiling is
          holding back. Distinct from the not-measured text above, which appears
          only when there is no number at all. A bar reading "25 of 25" beside a
          network of forty is true and useless without this line. */}
      {row.note && <p className="lic-line lic-usage-note">{row.note}</p>}
    </li>
  );
}

function Usage({ rows, note }: { rows: readonly LicenceCeiling[]; note?: string }) {
  const ordered = useMemo(() => sortedCeilings(rows), [rows]);
  if (ordered.length === 0) {
    return (
      <HonestState
        tone="warn"
        headline="The platform listed no ceilings."
        remedy="Nothing here states what this licence covers. Read the page again."
      />
    );
  }
  return (
    <>
      {/* In the tenant projection the ceiling and the number beside it are not
          the same population: the ceiling covers the installation, the number
          counts only this tenant. Saying so is the difference between "18 to
          spare" and "18 to spare, shared with everyone else". */}
      {note && (
        <div className="lic-honest lic-muted" role="note">
          <strong>These numbers count your tenant only.</strong>
          <span>{note}</span>
        </div>
      )}
      <ul className="lic-usage">{ordered.map((r) => <UsageRow key={r.name} row={r} />)}</ul>
    </>
  );
}

// ── 2b · recorded usage (metering, tracker 258) ─────────────────────────────
//
// A SEPARATE section from "Current usage" above, deliberately. That one answers
// "where do I stand against my ceilings RIGHT NOW"; this one answers "what did
// this installation actually use over a period, and can I prove it to someone
// else". They are different questions with different data behind them, and one
// table trying to be both would answer neither.

/** A meter's number, or the reason there is none. */
function MeterAmount({ row }: { row: UsageMeterRow }) {
  if (!row.amount.measured) {
    return <span className="lic-absent">{notMeasuredText(row.amount.reason)}</span>;
  }
  const unit = meterUnitText(row.unit);
  return (
    <span className="mono">
      {row.text}
      {unit ? <span className="lic-line"> {unit}</span> : null}
    </span>
  );
}

/**
 * A day-by-day sparkline. Drawn only from days that HAVE a number: a day the
 * recorder did not run leaves a gap in the line rather than a dip to zero,
 * because those are different facts and a chart that merged them would invent a
 * quiet day out of a missed one.
 */
function MeterSparkline({ points, label }: { points: Array<{ day: string; value: number | null }>; label: string }) {
  const measuredPts = points.filter((p) => p.value !== null);
  if (measuredPts.length < 2) return null;
  const values = measuredPts.map((p) => p.value as number);
  const max = Math.max(...values, 1);
  const w = 160;
  const h = 28;
  const step = points.length > 1 ? w / (points.length - 1) : w;
  let d = "";
  points.forEach((p, i) => {
    if (p.value === null) { d += ""; return; }
    const x = i * step;
    const y = h - (p.value / max) * (h - 2) - 1;
    d += `${d.endsWith(" ") || d === "" ? "M" : "L"}${x.toFixed(1)},${y.toFixed(1)} `;
  });
  return (
    <svg className="lic-spark" viewBox={`0 0 ${w} ${h}`} role="img" aria-label={`${label} over the period, peak ${max}`}>
      <path d={d.trim()} fill="none" stroke="currentColor" strokeWidth="1.5" />
    </svg>
  );
}

function MeterTable({ rows, view, tenant }: { rows: UsageMeterRow[]; view: LicenceUsageView; tenant?: string }) {
  if (rows.length === 0) {
    return <p className="lic-line">Nothing was recorded for this period.</p>;
  }
  return (
    <div className="lic-tblwrap">
      <table className="lic-tbl">
        <thead>
          <tr><th>Meter</th><th>Period</th><th>Trend</th><th>Samples</th></tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.name}>
              <th scope="row">
                <span className="lic-meter-name">{r.label}</span>
                <span className="lic-line lic-meter-doc">{r.doc}</span>
                {r.note && <span className="lic-line lic-meter-doc">{r.note}</span>}
              </th>
              <td><MeterAmount row={r} /></td>
              <td><MeterSparkline points={meterSeries(view, r.name, tenant)} label={r.label} /></td>
              <td className="mono">{r.samples}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/** The platform-only per-tenant breakdown. */
function TenantBreakdown({ view }: { view: LicenceUsageView }) {
  const rows = view.tenants ?? [];
  if (rows.length === 0) return null;
  const defs = new Map((view.meter_definitions ?? []).map((d) => [d.name, d]));
  const primary = "monitored_devices_unique";
  const label = defs.get(primary)?.label ?? "Monitored devices";
  return (
    <div className="lic-tblwrap">
      <table className="lic-tbl">
        <thead>
          <tr><th>Tenant</th><th>{label}</th><th>Days recorded</th></tr>
        </thead>
        <tbody>
          {rows.map((t) => {
            const m = (t.meters ?? []).find((x) => x.meter === primary);
            return (
              <tr key={t.tenant_id || "installation"}>
                <th scope="row">
                  {t.label}
                  {t.tenant_id === INSTALLATION_TENANT && (
                    <span className="lic-line lic-meter-doc">
                      Includes devices that belong to no tenant.
                      <AskIris topic="licence.installation-total" label="the installation total" />
                    </span>
                  )}
                </th>
                <td>
                  {!m || m.value === null || m.value === undefined
                    ? <span className="lic-absent">{notMeasuredText(m?.reason ?? NOT_MEASURED_FALLBACK)}</span>
                    : <span className="mono">{Math.round(m.value).toLocaleString()}</span>}
                </td>
                <td className="mono">{t.days}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function RecordedUsage({
  view, period, onPeriod, onDownload, downloading, downloadError,
}: {
  view: LicenceUsageView;
  period: string;
  onPeriod: (id: string) => void;
  onDownload: () => void;
  downloading: boolean;
  downloadError: string | null;
}) {
  const entitlement = useMemo(() => usageRows(view, "entitlement"), [view]);
  const diagnostic = useMemo(() => usageRows(view, "diagnostic"), [view]);
  const tenant = view.scope === "tenant" ? view.tenant : INSTALLATION_TENANT;
  const line = monitoringLine(view);
  const age = snapshotAge(view);

  return (
    <>
      {view.store_error && (
        <HonestState
          tone="warn"
          headline="The recorded usage could not be read."
          remedy={`${view.store_error} What is shown below is not the whole period.`}
        />
      )}

      {/* The headline the tiering plan fixes the wording for: what is monitored,
          against what is licensed, and the sentence that stops a customer
          believing discovery costs them devices. */}
      {line && (
        <div className="lic-honest lic-muted" role="note">
          <strong>{line}</strong>
          <span>{age ?? NO_SNAPSHOT_TEXT}</span>
        </div>
      )}
      {!line && !view.last_snapshot && (
        <HonestState tone="muted" headline="Nothing recorded yet." remedy={NO_SNAPSHOT_TEXT} />
      )}

      <p className="lic-line">{view.snapshot_note}</p>

      <h3 className="lic-subhead">Entitlement meters</h3>
      <MeterTable rows={entitlement} view={view} tenant={tenant} />

      {/* DIAGNOSTIC meters are labelled as such on the page, not only in the
          document: an operator seeing byte counts beside a device count must
          know at a glance which of them anything is charged for. */}
      <h3 className="lic-subhead">Diagnostic meters</h3>
      <p className="lic-sub">
        Nothing here is charged for.
        <AskIris topic="licence.diagnostic-meters" label="diagnostic meters" />
      </p>
      <MeterTable rows={diagnostic} view={view} tenant={tenant} />

      {view.scope === "platform" && (view.tenants?.length ?? 0) > 0 && (
        <>
          <h3 className="lic-subhead">By tenant</h3>
          <TenantBreakdown view={view} />
        </>
      )}

      <h3 className="lic-subhead">Signed usage report</h3>
      <p className="lic-line">{view.report_hint}</p>
      {view.key ? (
        <p className="lic-line">
          Signed by this installation&rsquo;s own key <span className="mono">{view.key.id}</span>. {view.key.note}
        </p>
      ) : (
        <p className="lic-line">{view.key_note}</p>
      )}
      <div className="lic-actions lic-usage-actions">
        <label className="lic-line" htmlFor="lic-usage-period">Period</label>
        <select
          id="lic-usage-period"
          className="lic-input"
          value={period}
          onChange={(e) => onPeriod(e.target.value)}
        >
          {USAGE_PERIODS.map((p) => <option key={p.id} value={p.id}>{p.label}</option>)}
        </select>
        <button type="button" className="btn sm" onClick={onDownload} disabled={downloading || !view.key}>
          <Icon name="download" size={13} /> {downloading ? "Preparing…" : "Download signed usage report"}
        </button>
      </div>
      {downloadError && (
        <HonestState
          tone="bad"
          headline="The usage report was not produced."
          remedy={downloadError}
        />
      )}
    </>
  );
}

// ── 3 · features ────────────────────────────────────────────────────────────

function Features({ view }: { view: LicenceView }) {
  if (view.features.length === 0) {
    return (
      <HonestState
        tone="warn"
        headline="The platform listed no commercial capabilities."
        remedy="Read the page again. An empty list is not a licence that grants nothing."
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
    // REACHABLE since the 2026-09-05 read split: this is what a tenant/org
    // admin — and a platform owner narrowed into a tenant — sees where the
    // install controls would be. The remedy sentence is the server's own
    // managed_by_detail, so the product says WHO may change the licence in
    // exactly one place.
    return (
      <HonestState
        tone="muted"
        headline="You are seeing this licence read-only."
        remedy={view.managed_by_detail}
      />
    );
  }

  return (
    <div className="lic-install">
      <p className="lic-line">
        A refused licence never displaces the one in force.
        <AskIris topic="licence.install-verified" label="verified before it is written" />
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
          <span className="lic-line">
            The platform&rsquo;s own words. Nothing in force was touched.
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

      <p className="lic-line">
        A licence may also be placed on the host at <span className="mono">{view.path}</span>.
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

/**
 * The standing statement that expiry policy is still an owner decision. Every
 * reader gets it, in both scopes: it is a fact about the product, and the
 * tenant projection carries it for exactly the same reason the provider view
 * does.
 */
function ExpiryNote({ text }: { text: string }) {
  return (
    <div className="lic-honest lic-muted" role="note">
      <strong>What expiry does, and what it never does</strong>
      <span>{text}</span>
    </div>
  );
}

function Verification({ view }: { view: LicenceView }) {
  const [note, setNote] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  // Provider-only payload. The page renders this section only in the platform
  // scope, so these are always present here; the fallbacks keep the component
  // total rather than trusting that.
  const keys = view.keys ?? [];
  const hint = view.verify_hint ?? "";

  const save = (k: LicenceKey) => {
    const ok = downloadText(keyFileName(k.id), keyFileBody(k));
    setNote(ok ? `Saved ${keyFileName(k.id)}.` : "This browser would not save the file. The key is shown above and can be copied.");
  };

  const copyHint = async () => {
    try {
      await navigator.clipboard.writeText(hint);
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
        Anyone can check ours without this page, and without us.
        <AskIris topic="licence.independent-verification" label="independent verification" />
      </p>

      {/* Verbatim, because it is a command someone is going to run. */}
      <div className="lic-cmdwrap">
        <pre className="lic-cmd">{hint}</pre>
        <button type="button" className="btn sm" onClick={() => { void copyHint(); }}>
          {copied ? "Copied" : "Copy command"}
        </button>
      </div>

      {keys.length === 0 ? (
        <HonestState
          tone="bad"
          headline="This build trusts no signing key."
          remedy="No licence can be verified, so none can be installed. Report it with the platform version."
        />
      ) : (
        <ul className="lic-keys">
          {keys.map((k) => (
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
              {k.note && <span className="lic-line lic-block">{k.note}</span>}
            </li>
          ))}
        </ul>
      )}

      {note && <p className="lic-msg lic-muted" role="status">{note}</p>}

      {/* The standing note. It is on the page and not only in a design document
          because a policy that is still open is a fact about the product. */}
      <ExpiryNote text={view.expiry_semantics} />
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

  // RECORDED USAGE is its own read, on its own period. It is a second contract
  // (src/backend/internal/metering), and keeping it a second panel means a
  // metering store that cannot be read leaves the licence sections intact and
  // says so in one place, instead of blanking the page.
  const [period, setPeriod] = useState<string>(DEFAULT_USAGE_PERIOD);
  const span = useMemo(() => periodFor(period), [period]);
  const readUsage = useCallback(() => api.licenceUsage({ from: span.from, to: span.to }), [span.from, span.to]);
  const [usage, reloadUsage] = usePanel<LicenceUsageView>(readUsage, "The recorded usage could not be read.");
  // usePanel deliberately reads ONCE and only re-reads when asked, so that a
  // re-render cannot turn into a request storm. A period change is exactly such
  // an ask, and it has to be made explicitly. The first run is skipped because
  // the panel's own mount read has already happened with these same bounds —
  // reading the same period twice on open would be a wasted round trip, not a
  // safer one.
  const firstUsageRead = useRef(true);
  useEffect(() => {
    if (firstUsageRead.current) {
      firstUsageRead.current = false;
      return;
    }
    reloadUsage();
  }, [span.from, span.to, reloadUsage]);
  const [downloading, setDownloading] = useState(false);
  const [downloadError, setDownloadError] = useState<string | null>(null);
  const downloadReport = useCallback(() => {
    setDownloading(true);
    setDownloadError(null);
    api
      .downloadLicenceUsageReport({ from: span.from, to: span.to })
      .catch((e: unknown) => setDownloadError(operatorError(e, "The usage report could not be produced.")))
      .finally(() => setDownloading(false));
  }, [span.from, span.to]);
  // What the SERVER answered, not what the SPA believes about the caller. Until
  // the read lands we know nothing, and the page claims nothing.
  const provider = view?.scope === "platform";
  const tenantScope = view?.scope === "tenant";

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
        note={
          tenantScope
            ? "In force for your tenant"
            : "One licence, every tenant"
        }
        actions={
          <button type="button" className="btn sm" onClick={reload}>
            <Icon name="refresh" size={13} /> Re-read
          </button>
        }
      >
        {body("the licence", (v) => <LicenceHeadline view={v} />)}
        {!authLoading && view && !provider && (
          <HonestState
            tone="muted"
            headline="You are seeing this licence read-only."
            remedy={
              platformAdmin
                ? `${view.managed_by_detail} You are scoped into a tenant; return to the Global view to install or replace it.`
                : view.managed_by_detail
            }
          />
        )}
      </Section>

      <Section
        id="usage"
        title="Current usage"
        topic="licence.ceilings"
        note={tenantScope ? "Your tenant against every ceiling" : "This platform against every ceiling"}
      >
        {body("the ceilings", (v) => <Usage rows={v.ceilings} note={v.scope_note} />)}
      </Section>

      {/* RECORDED USAGE — what was actually consumed, and the signed document
          that proves it. Placed after "Current usage" because it answers the
          next question an operator has, and before "Features" because it is
          still about consumption rather than capability. */}
      <Section
        id="metering"
        title="Usage"
        note={`Recorded usage, ${periodLabel(span)} (UTC)`}
        actions={
          <button type="button" className="btn sm" onClick={reloadUsage}>
            <Icon name="refresh" size={13} /> Re-read
          </button>
        }
      >
        {usage.error
          ? <PanelError text={usage.error} onRetry={reloadUsage} />
          : !usage.data
            ? <Loading what="the recorded usage" />
            : (
              <RecordedUsage
                view={usage.data}
                period={period}
                onPeriod={setPeriod}
                onDownload={downloadReport}
                downloading={downloading}
                downloadError={downloadError}
              />
            )}
      </Section>

      <Section
        id="features"
        title="Features"
        topic="licence.features"
        note="Capabilities, and the tier each needs"
      >
        {body("the capabilities", (v) => <Features view={v} />)}
      </Section>

      <Section
        id="install"
        title={provider ? "Install a licence" : "Changing this licence"}
        note="One licence file per installation"
      >
        {body("the licence", (v) => (
          <InstallPanel view={v} canEdit={v.scope === "platform"} onInstalled={put} />
        ))}
      </Section>

      {/* VERIFICATION is provider-only, because the payload is: the trusted
          public keys and the offline recipe are not in the tenant projection.
          The standing expiry note is NOT provider-only, so the tenant scope
          still gets it — on its own, rather than as a heading over an empty
          section. */}
      {tenantScope ? (
        <Section id="expiry" title="Expiry" note="What expiry can and cannot do">
          {body("the expiry policy", (v) => <ExpiryNote text={v.expiry_semantics} />)}
        </Section>
      ) : (
        <Section id="verification" title="Verification" note="Check it without trusting this page">
          {body("the trusted keys", (v) => <Verification view={v} />)}
        </Section>
      )}
    </div>
  );
}
