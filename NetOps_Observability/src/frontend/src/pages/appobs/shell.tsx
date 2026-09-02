// App Observability — global shell primitives (#81 P3F+1).
//
// The trust chrome that wraps every Cloud App Observability page: scope + freshness
// + data mode (CloudScopeBar), source status (SourceStatusBadge / FreshnessBadge),
// the readiness summary strip (ReadinessStrip), and the honest "this isn't measured"
// value renderers (MeasuredValue / MeasuredState). All built on the existing NOC kit
// (Chip, MetricCard, var(--*) tokens) — no new fonts, hex, or spacing.

import { ReactNode, Fragment } from "react";
import { Chip } from "../../components/noc";
import { MetricCard } from "./badges";
import {
  CloudScope, DataMode, DATA_MODE_LABEL, DATA_MODE_TONE, ReadinessSummary,
  SourceStatus, STATUS_META, MeasureState, MEASURE_LABEL, getMeasurementState,
  freshnessLabel,
} from "./readiness";
import type { CloudScopeState, ScopeDim } from "./scopeUrl";
import type { ScopeOptions } from "./scope";
import { CLOUD_RANGES } from "./range";

// ── Data mode chip — replaces the old "Live · mock"; always an honest label ────
export function DataModeChip({ mode, lastSyncIso }: { mode: DataMode; lastSyncIso?: string }) {
  const detail = mode === "live" && lastSyncIso ? ` · updated ${freshnessLabel(lastSyncIso)}` : "";
  return <Chip label={`${DATA_MODE_LABEL[mode]}${detail}`} tone={DATA_MODE_TONE[mode]} title="how to read this data" />;
}

// ── Source status badge ───────────────────────────────────────────────────────
export function SourceStatusBadge({ status }: { status: SourceStatus }) {
  const m = STATUS_META[status];
  return <Chip label={m.label} tone={m.tone} title={`source status: ${m.label}`} />;
}

// ── Freshness badge — "updated 42s ago" / status when not flowing ─────────────
export function FreshnessBadge({ iso, status }: { iso?: string; status?: SourceStatus }) {
  if (status && status !== "flowing" && status !== "stale") {
    return <span className="ao-fresh ao-fresh--off">{STATUS_META[status].label}</span>;
  }
  const stale = status === "stale";
  return (
    <span className={`ao-fresh${stale ? " ao-fresh--stale" : ""}`} title="last successful update">
      <span className="ao-fresh-dot" /> {iso ? freshnessLabel(iso) : "—"}
    </span>
  );
}

// ── Scope pills — compact flowing/stale/off/permission counts ─────────────────
function ScopePills({ s }: { s: ReadinessSummary }) {
  const pills: { label: string; n: number; tone: string; always?: boolean }[] = [
    { label: "Flowing", n: s.flowing, tone: "var(--ok)", always: true },
    { label: "Stale", n: s.stale, tone: "var(--warn)" },
    { label: "Off", n: s.off, tone: "var(--fg-subtle)" },
    { label: "Permission errors", n: s.permissionErrors, tone: "var(--crit)" },
    { label: "Partial data", n: s.partial, tone: "var(--warn)" },
  ];
  return (
    <span className="ao-scope-pills">
      {pills.filter((p) => p.always || p.n > 0).map((p) => (
        <Chip key={p.label} label={`${p.n} ${p.label.toLowerCase()}`} tone={p.tone} />
      ))}
    </span>
  );
}

// ── Interactive scope control (Wave 2 #5) ─────────────────────────────────────
// What the scope bar needs to be a real global filter instead of a summary:
// the URL-backed scope state, the option sets measured from the tenant's own
// inventory, and the mutators from useCloudScope. All optional on CloudScopeBar
// so the bar still renders as an honest read-only summary where no control is
// wired (and in the existing tests).
export interface ScopeBarControl {
  scope: CloudScopeState;
  options: ScopeOptions;
  active: boolean;
  add: (dim: ScopeDim, value: string) => void;
  remove: (dim: ScopeDim, value: string) => void;
  clearFilters: () => void;
  setRangeMinutes: (minutes: number) => void;
}

// One editable dimension: the active values render as removable chips (each ×
// clears exactly that value) and the trailing select adds another. Options are
// only what the inventory actually contains — never a dead filter choice.
function ScopeDimField({ label, dim, values, options, fmt, add, remove }: {
  label: string; dim: ScopeDim; values: string[]; options: string[];
  fmt?: (v: string) => string; add: ScopeBarControl["add"]; remove: ScopeBarControl["remove"];
}) {
  const show = (v: string) => (fmt ? fmt(v) : v);
  const remaining = options.filter((o) => !values.includes(o));
  return (
    <span className="ao-scope-f ao-scope-f--edit">
      <span className="ao-scope-k">{label}</span>
      {values.map((v) => (
        <button key={v} type="button" className="ao-scope-chip"
          onClick={() => remove(dim, v)} aria-label={`Remove ${label} filter ${show(v)}`}
          title={`Remove this ${label.toLowerCase()} filter`}>
          {show(v)}<span className="ao-scope-chip-x" aria-hidden="true">×</span>
        </button>
      ))}
      <select className="app-select ao-scope-add" value=""
        aria-label={`Add ${label} filter`}
        onChange={(e) => { if (e.target.value) add(dim, e.target.value); }}
        disabled={remaining.length === 0}>
        <option value="">{values.length ? "+ add" : "All"}</option>
        {remaining.map((o) => <option key={o} value={o}>{show(o)}</option>)}
      </select>
    </span>
  );
}

// ── CloudScopeBar — the global scope/freshness strip under the page header ─────
// With `control`: provider/account/region/env are REAL multi-select filters and
// Range is the REAL read window every signal surface parameterizes on (Wave 2
// #5 — the display-only bar with its static "Last 1h" was the one dishonest
// label on the page). Without `control` it stays the read-only summary.
export function CloudScopeBar({ scope, mode, summary, control }: {
  scope: CloudScope; mode: DataMode; summary: ReadinessSummary; control?: ScopeBarControl;
}) {
  const Field = ({ k, v }: { k: string; v: string }) => (
    <span className="ao-scope-f"><span className="ao-scope-k">{k}</span><span className="ao-scope-v">{v}</span></span>
  );
  return (
    <div className="ao-scope" role="region" aria-label="Cloud scope and freshness">
      <div className="ao-scope-fields">
        {/* Tenant is NEVER a filter here: scope narrows within the caller's
            tenant view, it cannot widen it (§3a). */}
        <Field k="Tenant" v={scope.tenant} />
        {control ? (
          <>
            <ScopeDimField label="Provider" dim="providers" values={control.scope.providers}
              options={control.options.providers} fmt={(p) => p.toUpperCase()}
              add={control.add} remove={control.remove} />
            <ScopeDimField label="Account" dim="accounts" values={control.scope.accounts}
              options={control.options.accounts} add={control.add} remove={control.remove} />
            <ScopeDimField label="Region" dim="regions" values={control.scope.regions}
              options={control.options.regions} add={control.add} remove={control.remove} />
            <ScopeDimField label="Env" dim="envs" values={control.scope.envs}
              options={control.options.envs} add={control.add} remove={control.remove} />
            <span className="ao-scope-f ao-scope-f--edit">
              <span className="ao-scope-k">Range</span>
              <select className="app-select ao-scope-add" aria-label="Time range"
                value={String(control.scope.rangeMinutes)}
                onChange={(e) => control.setRangeMinutes(Number(e.target.value))}>
                {CLOUD_RANGES.map((r) => (
                  <option key={r.label} value={String(r.minutes)}>{r.label}</option>
                ))}
              </select>
            </span>
            {control.active && (
              <button type="button" className="ao-btn ao-btn--sm ao-scope-clear"
                onClick={control.clearFilters}>Clear filters</button>
            )}
          </>
        ) : (
          <>
            <Field k="Provider" v={scope.provider} />
            <Field k="Account" v={scope.account} />
            <Field k="Region" v={scope.region} />
            <Field k="Env" v={scope.env} />
            <Field k="Range" v={scope.timeRange} />
          </>
        )}
        <Field k="Updated" v={freshnessLabel(summary.lastSyncIso)} />
      </div>
      <div className="ao-scope-right">
        <DataModeChip mode={mode} lastSyncIso={summary.lastSyncIso} />
        <ScopePills s={summary} />
      </div>
    </div>
  );
}

// ── ReadinessStrip — the 6 summary cards (Overview + Ingestion share these) ────
export function ReadinessStrip({ summary }: { summary: ReadinessSummary }) {
  const s = summary;
  return (
    <div className="ao-cards ao-readiness">
      <MetricCard label="Connected accounts" value={s.connectedAccounts} tone={s.connectedAccounts ? "accent" : undefined} />
      <MetricCard label="Flowing sources" value={s.flowing} tone={s.flowing ? "good" : undefined} />
      <MetricCard label="Stale sources" value={s.stale} tone={s.stale ? "warn" : undefined} />
      <MetricCard label="Off sources" value={s.off} tone={s.off ? "warn" : undefined} />
      <MetricCard label="Permission errors" value={s.permissionErrors} tone={s.permissionErrors ? "bad" : undefined} />
      <MetricCard label="Last successful sync" value={freshnessLabel(s.lastSyncIso)} />
    </div>
  );
}

// ── Honest value renderers ────────────────────────────────────────────────────
// MeasuredState: the muted "not measured" / "partial data" / "permission denied"
// token shown anywhere a value can't be claimed.
export function MeasuredState({ state, title }: { state: MeasureState; title?: string }) {
  if (state === "ok") return null;
  return <span className="ao-meas ao-muted" title={title ?? MEASURE_LABEL[state]}>{MEASURE_LABEL[state]}</span>;
}

// MeasuredValue: render the value only when the backing source is measured; show a
// stale-tagged value when stale; otherwise the honest state — NEVER a fabricated 0.
export function MeasuredValue({ value, status, fmt }: {
  value: number; status: SourceStatus | undefined; fmt: (n: number) => ReactNode;
}) {
  const st = getMeasurementState(status);
  if (st === "ok") return <>{fmt(value)}</>;
  if (st === "stale") return <span className="ao-meas ao-meas--stale">{fmt(value)}<span className="ao-meas-tag">stale</span></span>;
  return <MeasuredState state={st} />;
}

// ── AppPathStrip — the app→underlay path ribbon (User→…→seam→…→App) ───────────
// A horizontal hop ribbon with the degraded segment lit. Honest: a segment with
// no measurement reads muted ("unknown"), never green.
export type PathSegState = "ok" | "degraded" | "unknown";
export interface PathSeg { label: string; state?: PathSegState; sub?: string }

export function AppPathStrip({ segments }: { segments: PathSeg[] }) {
  return (
    <div className="ao-path" role="list" aria-label="App to underlay path">
      {segments.map((s, i) => (
        <Fragment key={i}>
          <span className={`ao-path-node ao-path-node--${s.state ?? "ok"}`} role="listitem" title={s.sub}>
            <span className="ao-path-l">{s.label}</span>
            {s.sub && <span className="ao-path-sub">{s.sub}</span>}
          </span>
          {i < segments.length - 1 && (
            <span className={`ao-path-arrow${s.state === "degraded" || segments[i + 1].state === "degraded" ? " is-bad" : ""}`} aria-hidden>→</span>
          )}
        </Fragment>
      ))}
    </div>
  );
}
