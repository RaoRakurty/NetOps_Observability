// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// EventSections — every section of the Event Intelligence panel and page, each one a
// pure function of an EventView (lib/eventModel.ts). Nothing here reads a raw record,
// and every value is rendered as escaped React text. Severity colour comes from one
// place: the root carries `evd-tone-<severity>`, which sets --tone/--tone-bg/
// --tone-solid/--tone-on from the --sev-* tokens, and every tinted part reads those.

import { KeyboardEvent, ReactNode, useId, useMemo, useRef, useState } from "react";
import {
  AuditData, BgpData, DASH, EventView, FlowData, GenericData, InterfaceData, PrimaryVisual, Provenance, SyslogFaultData,
  TimelineEntry, Tone, TunnelData, UtilizationData, ViewRow, fmtPercent, fmtPercentShort, fmtUtc,
} from "../../lib/eventModel";
import { fieldsOf } from "../../lib/logEvent";
import { LogJson } from "../../lib/logfmt";
import { SEVERITY_TONES } from "../../theme/severity";
import EvIcon from "./EvIcon";
import { RelatedState, TrendState, copyText, mergedTimeline } from "./useEventData";

export const EVENT_TABS = ["Overview", "Metrics", "Timeline", "Technical Details", "Raw Event"] as const;
export type EventTab = (typeof EVENT_TABS)[number];

const TAB_ICON = { Overview: "list", Metrics: "chart", Timeline: "clock", "Technical Details": "code", "Raw Event": "braces" } as const;

export function toneClass(t: Tone | null | undefined): string {
  return `evd-tone-${t ?? "none"}`;
}

// ── small parts ──────────────────────────────────────────────────────────────

const PROV_WORD: Record<Provenance, string> = {
  observed: "observed", derived: "derived", reported: "reported by device", guidance: "guidance", unknown: "unknown",
};

export function ProvTag({ prov }: { prov?: Provenance }) {
  if (!prov) return null;
  return <span className={`evd-prov evd-prov-${prov}`}>{PROV_WORD[prov]}</span>;
}

function Tip({ label, text }: { label: string; text: string }) {
  const id = useId();
  return (
    <span className="evd-tip-wrap">
      <button type="button" className="evd-tip" aria-label={`About ${label}`} aria-describedby={id}>
        <EvIcon name="info" size={14} />
      </button>
      <span role="tooltip" id={id} className="evd-tip-pop">{text}</span>
    </span>
  );
}

export function CopyButton({ text, label }: { text: string; label: string }) {
  const [state, setState] = useState("");
  const ref = useRef<HTMLSpanElement>(null);
  return (
    <>
      <span ref={ref} className="evd-sr">{text}</span>
      <button
        type="button"
        className="evd-icon-btn evd-copy"
        aria-label={`Copy ${label}`}
        title={`Copy ${label}`}
        onClick={async () => setState(await copyText(text, ref.current))}
      >
        <EvIcon name="copy" size={15} />
      </button>
      <span className="evd-copy-state" role="status">{state}</span>
    </>
  );
}

function Pill({ tone, icon, children }: { tone: Tone; icon?: ViewRow["icon"]; children: ReactNode }) {
  return (
    <span className={`evd-pill evd-pill-${tone === "accent" || tone === "neutral" ? tone : "sev"} ${tone !== "accent" && tone !== "neutral" ? toneClass(tone) : ""}`}>
      {icon && <EvIcon name={icon} size={14} />}
      {children}
    </span>
  );
}

/** One label/value row, in the screenshots' shape. */
export function KvRow({ row }: { row: ViewRow }) {
  const value = row.pill
    ? <Pill tone={row.pill} icon={row.icon}>{row.value}</Pill>
    : (
      <span className={`evd-kv-val${row.mono ? " evd-mono" : ""}${row.value === DASH ? " evd-dash" : ""}`}>
        {row.icon && <EvIcon name={row.icon} size={15} className={`evd-kv-ico evd-kv-ico-${row.icon}`} />}
        {row.value}
      </span>
    );
  return (
    <div className="evd-kv-row" data-row={row.key}>
      <dt className="evd-kv-label">
        {row.label}
        {row.tip && <Tip label={row.label} text={row.tip} />}
      </dt>
      <dd className="evd-kv-dd">
        <span className="evd-kv-line">
          {value}
          {row.copy && <CopyButton text={row.value} label={row.label} />}
        </span>
        {row.secondary && <span className="evd-kv-sec">{row.secondary}</span>}
      </dd>
    </div>
  );
}

export function KvList({ rows, className }: { rows: ViewRow[]; className?: string }) {
  if (rows.length === 0) return null;
  return <dl className={`evd-kv${className ? ` ${className}` : ""}`}>{rows.map((r) => <KvRow key={r.key} row={r} />)}</dl>;
}

export function Card({ icon, title, children, className, aside, testId, iconTone }: {
  icon: ViewRow["icon"] & string; title: string; children: ReactNode; className?: string; aside?: ReactNode; testId?: string; iconTone?: "warn";
}) {
  const id = useId();
  return (
    <section className={`evd-card${className ? ` ${className}` : ""}`} aria-labelledby={id} data-testid={testId}>
      <header className="evd-card-head">
        <EvIcon name={icon} size={18} className={iconTone === "warn" ? "evd-card-ico evd-card-ico-warn" : "evd-card-ico"} />
        <h3 className="evd-card-title" id={id}>{title}</h3>
        {aside && <span className="evd-card-aside">{aside}</span>}
      </header>
      {children}
    </section>
  );
}

// ── header ───────────────────────────────────────────────────────────────────

export function EventHeader({ view, actions, close, titleId }: { view: EventView; actions?: ReactNode; close?: ReactNode; titleId: string }) {
  const tone = view.severity.tone;
  const icon = tone ? SEVERITY_TONES[tone].icon : "info";
  return (
    <header className="evd-head">
      <div className="evd-head-tile" aria-hidden="true"><EvIcon name={icon} size={30} /></div>
      <div className="evd-head-main">
        <div className="evd-head-line">
          {view.severity.label && (
            <span className="evd-sev-pill" data-testid="event-severity">
              <EvIcon name={icon} size={15} className="evd-sev-pill-ico" />
              {view.severity.label}
            </span>
          )}
          <h2 className="evd-title" id={titleId} data-testid="event-title">{view.title}</h2>
        </div>
        {view.subtitle && <p className="evd-subtitle">{view.subtitle}</p>}
        <div className="evd-head-row">
          <ul className="evd-chips" aria-label="Event classification">
            {view.chips.map((c) => (
              <li key={`${c.key}:${c.label}`} className={`evd-chip evd-chip-${c.key}${c.tone && c.tone !== "neutral" ? ` evd-chip-toned ${toneClass(c.tone === "accent" ? null : c.tone)}` : ""}`}>
                <EvIcon name={c.icon} size={14} />
                {c.label}
              </li>
            ))}
          </ul>
          {actions && <div className="evd-actions">{actions}</div>}
        </div>
      </div>
      {close && <div className="evd-head-close">{close}</div>}
    </header>
  );
}

// ── tabs ─────────────────────────────────────────────────────────────────────

export function EventTabs({ tab, onTab, uid }: { tab: EventTab; onTab: (t: EventTab) => void; uid: string }) {
  const onKey = (e: KeyboardEvent<HTMLButtonElement>) => {
    const i = EVENT_TABS.indexOf(tab);
    const next =
      e.key === "ArrowRight" ? EVENT_TABS[(i + 1) % EVENT_TABS.length]
      : e.key === "ArrowLeft" ? EVENT_TABS[(i + EVENT_TABS.length - 1) % EVENT_TABS.length]
      : e.key === "Home" ? EVENT_TABS[0]
      : e.key === "End" ? EVENT_TABS[EVENT_TABS.length - 1]
      : null;
    if (!next) return;
    e.preventDefault();
    onTab(next);
    e.currentTarget.parentElement?.querySelector<HTMLButtonElement>(`[data-tab="${next}"]`)?.focus();
  };
  return (
    <div className="evd-tabs" role="tablist" aria-label="Event details">
      {EVENT_TABS.map((t) => (
        <button
          key={t}
          type="button"
          role="tab"
          data-tab={t}
          id={`${uid}-tab-${t.replace(/\s/g, "")}`}
          className="evd-tab"
          aria-selected={tab === t}
          aria-controls={`${uid}-panel`}
          tabIndex={tab === t ? 0 : -1}
          onClick={() => onTab(t)}
          onKeyDown={onKey}
        >
          <EvIcon name={TAB_ICON[t]} size={16} />
          {t}
        </button>
      ))}
    </div>
  );
}

// ── primary visuals ──────────────────────────────────────────────────────────

function Ring({ value, label }: { value: number; label: string }) {
  const size = 150, stroke = 14, r = (size - stroke) / 2, c = 2 * Math.PI * r;
  const filled = (Math.max(0, Math.min(100, value)) / 100) * c;
  return (
    <div className="evd-ring" role="img" aria-label={`${label} ${fmtPercentShort(value)}`} data-testid="event-ring">
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} aria-hidden="true">
        <circle cx={size / 2} cy={size / 2} r={r} className="evd-ring-track" strokeWidth={stroke} fill="none" />
        <circle
          cx={size / 2} cy={size / 2} r={r} className="evd-ring-fill" strokeWidth={stroke} fill="none"
          strokeDasharray={`${filled} ${c}`} transform={`rotate(-90 ${size / 2} ${size / 2})`} strokeLinecap={value >= 100 ? "butt" : "round"}
        />
      </svg>
      <span className="evd-ring-text" aria-hidden="true">
        <span className="evd-ring-value" data-testid="event-ring-value">{fmtPercentShort(value)}</span>
        <span className="evd-ring-label">{label}</span>
      </span>
    </div>
  );
}

const SEG_CLASS: Record<string, string> = { system: "evd-seg-primary", used: "evd-seg-primary", user: "evd-seg-secondary", idle: "evd-seg-idle", free: "evd-seg-idle" };

function UtilBar({ u }: { u: UtilizationData }) {
  return (
    <div className="evd-util">
      <div className={`evd-bar-wrap${u.threshold ? " evd-bar-wrap-thr" : ""}`}>
        {u.threshold && (
          // Centred on the line, except near an end, where it leans inward so it never
          // spills past the bar (and the page) on a narrow screen.
          <div
            className="evd-thr"
            style={{ left: `${u.threshold.value}%`, transform: `translateX(-${u.threshold.value < 15 || u.threshold.value > 85 ? Math.round(u.threshold.value) : 50}%)` }}
            data-testid="event-threshold"
          >
            <span className="evd-thr-pill">{u.threshold.label}</span>
            <span className="evd-thr-val evd-mono">{fmtPercentShort(u.threshold.value)}</span>
          </div>
        )}
        <div className="evd-bar" role="img" aria-label={u.segments.map((s) => `${s.label} ${fmtPercent(s.value)}`).join(", ")}>
          {u.segments.map((s) => (
            <span key={s.key} className={`evd-seg ${SEG_CLASS[s.key]}`} style={{ width: `${Math.max(0, Math.min(100, s.value))}%` }}>
              {s.value >= 6 && <span className="evd-seg-label evd-mono">{fmtPercent(s.value)}</span>}
            </span>
          ))}
          {u.threshold && <span className="evd-thr-line" style={{ left: `${u.threshold.value}%` }} aria-hidden="true" />}
        </div>
      </div>
      <ul className="evd-legend">
        {u.segments.map((s) => (
          <li key={s.key}>
            <span className={`evd-swatch ${SEG_CLASS[s.key]}`} aria-hidden="true" />
            <span className="evd-legend-k">{s.label}</span>
            <span className="evd-legend-v evd-mono">{fmtPercent(s.value)}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

function StateChip({ state, muted }: { state: string; muted?: boolean }) {
  return <span className={`evd-state${muted ? " evd-state-muted" : ""}`}>{state}</span>;
}

function BgpVisual({ b }: { b: BgpData }) {
  return (
    <div className="evd-bgp" data-testid="event-bgp">
      <div className="evd-bgp-peer">
        <span className="evd-bgp-k">Peer</span>
        <span className="evd-bgp-addr evd-mono">{b.peerAddress || DASH}</span>
        <span className="evd-bgp-tags">
          {b.afi && <span className="evd-chip">{b.afi}</span>}
          {b.peerAs && <span className="evd-chip evd-mono">AS {b.peerAs}</span>}
          {b.vrf && <span className="evd-chip evd-mono">VRF {b.vrf}</span>}
        </span>
      </div>
      <div className="evd-bgp-move" aria-label={`${b.prev ?? "previous state not reported"} to ${b.state}`}>
        {b.prev ? <StateChip state={b.prev} muted /> : <StateChip state="Previous state not reported" muted />}
        <EvIcon name="arrow-right" size={22} className="evd-bgp-arrow" />
        <span className="evd-state evd-state-now">{b.state || DASH}</span>
      </div>
      {b.sentence && <p className="evd-bgp-sentence">{b.sentence}</p>}
      {b.occurrences !== null && b.occurrences > 1 && (
        <p className="evd-bgp-occ"><EvIcon name="layers" size={15} /> {b.occurrences} notifications grouped</p>
      )}
    </div>
  );
}

function FlowNode({ k, address, port, iface }: { k: string; address: string; port: string; iface: string }) {
  return (
    <div className="evd-flow-node">
      <span className="evd-flow-k">{k}</span>
      <span className="evd-flow-addr evd-mono">{address || DASH}{port && `:${port}`}</span>
      {iface && <span className="evd-flow-if"><EvIcon name="network" size={14} /> <span className="evd-mono">{iface}</span></span>}
    </div>
  );
}

function FlowVisual({ f }: { f: FlowData }) {
  return (
    <div className="evd-flow" data-testid="flow-strip">
      {f.exporter && (
        <p className="evd-flow-exp">Exporter {f.exporterName && <>{f.exporterName} </>}<span className="evd-mono">{f.exporter}</span></p>
      )}
      <div className="evd-flow-row">
        <FlowNode k="Source" address={f.source.address} port={f.source.port} iface={f.inInterfaceLabel && `in ${f.inInterfaceLabel}`} />
        <div className="evd-flow-mid" aria-label={f.protocol ? `${f.protocol} to` : "to"}>
          {(f.protocol || f.service) && <span className="evd-chip">{[f.protocol, f.service].filter(Boolean).join(" · ")}</span>}
          <EvIcon name="arrow-right" size={22} />
        </div>
        <FlowNode k="Destination" address={f.destination.address} port={f.destination.port} iface={f.outInterfaceLabel && `out ${f.outInterfaceLabel}`} />
      </div>
      {f.trafficClass && <p className="evd-flow-class"><EvIcon name="tag" size={14} /> {f.trafficClass}</p>}
    </div>
  );
}

function SyslogVisual({ s, toneLabel }: { s: SyslogFaultData; toneLabel: string }) {
  return (
    <div className="evd-sys" data-testid="event-syslog">
      {s.unparsed ? (
        <div className="evd-callout evd-callout-warn" role="note">
          <EvIcon name="triangle" size={18} />
          <div>
            <strong>Not parsed yet</strong>
            <p>No parser understands this line yet, so Correlix offers no explanation for it. The original frame is below, exactly as the device sent it.</p>
          </div>
        </div>
      ) : s.explanation ? (
        <div className="evd-callout evd-callout-tone" role="note">
          <EvIcon name="info" size={18} />
          <div><strong>What the parser says</strong><p>{s.explanation}</p></div>
        </div>
      ) : null}
      <ul className="evd-sys-chips">
        {s.process && <li className="evd-chip"><EvIcon name="terminal" size={14} /> Process {s.process}{s.procid && <span className="evd-mono">[{s.procid}]</span>}</li>}
        {s.facility && <li className="evd-chip"><EvIcon name="tag" size={14} /> Facility {s.facility}</li>}
        {s.deviceSeverity && <li className="evd-chip evd-chip-toned"><EvIcon name="triangle" size={14} /> Device severity {s.deviceSeverity}{toneLabel && s.deviceSeverity.toLowerCase() !== toneLabel.toLowerCase() ? ` (${toneLabel})` : ""}</li>}
        {s.frameFormat && <li className="evd-chip evd-mono">{s.frameFormat}</li>}
      </ul>
      {s.frame && (
        <figure className="evd-frame">
          <figcaption>Original frame</figcaption>
          <pre className="evd-mono">{s.frame}</pre>
        </figure>
      )}
    </div>
  );
}

function AuditVisual({ a }: { a: AuditData }) {
  return (
    <div className="evd-audit" data-testid="event-audit">
      {a.unparsed
        ? <p className="evd-muted">Who and what have not been split out of this line yet. The device's words are below.</p>
        : <KvList rows={a.rows} className="evd-kv-audit" />}
      {a.message && <pre className="evd-frame-inline evd-mono">{a.message}</pre>}
    </div>
  );
}

function InterfaceVisual({ i }: { i: InterfaceData }) {
  return (
    <div className="evd-iface">
      <span className="evd-bgp-addr evd-mono">{i.name}</span>
      {i.how && <span className="evd-muted">{i.how}</span>}
      <span className="evd-bgp-tags">
        {i.oper && <span className="evd-state evd-state-now">Oper {i.oper}</span>}
        {i.admin && <span className="evd-state evd-state-muted">Admin {i.admin}</span>}
      </span>
    </div>
  );
}

function TunnelVisual({ t }: { t: TunnelData }) {
  return (
    <div className="evd-iface">
      <span className="evd-bgp-addr evd-mono">{t.name}</span>
      <span className="evd-bgp-tags">
        {t.state && <span className="evd-state evd-state-now">{t.state}</span>}
        {t.peer && <span className="evd-chip evd-mono">Peer {t.peer}</span>}
      </span>
    </div>
  );
}

function GenericVisual({ g }: { g: GenericData }) {
  return (
    <div className="evd-generic">
      {g.headline && <p className="evd-generic-head">{g.headline}</p>}
      <KvList rows={g.rows} />
      {g.message && g.message !== g.headline && <pre className="evd-frame-inline evd-mono">{g.message}</pre>}
    </div>
  );
}

export function StatTable({ rows }: { rows: ViewRow[] }) {
  if (rows.length === 0) return null;
  return (
    <dl className="evd-stats" data-testid="event-stats">
      {rows.map((r, i) => (
        <div key={r.key} className={`evd-stat${i === 0 && r.key === "total" ? " evd-stat-total" : ""}`}>
          <dt>{r.label}</dt>
          <dd className={r.mono ? "evd-mono" : undefined} title={r.formula ? `= ${r.formula}` : undefined}>{r.value}</dd>
        </div>
      ))}
    </dl>
  );
}

function VisualBody({ v, view }: { v: PrimaryVisual; view: EventView }) {
  switch (v.kind) {
    case "cpu":
    case "memory":
      return (
        <>
          {v.data.total !== null && <Ring value={v.data.total} label={v.kind === "cpu" ? "CPU Utilization" : "Memory Utilization"} />}
          <div className="evd-vis-main">
            <h3 className="evd-vis-title">{v.title}</h3>
            <UtilBar u={v.data} />
          </div>
        </>
      );
    case "bgp": return <div className="evd-vis-main"><h3 className="evd-vis-title">{v.title}</h3><BgpVisual b={v.data} /></div>;
    case "flow": return <div className="evd-vis-main"><h3 className="evd-vis-title">{v.title}</h3><FlowVisual f={v.data} /></div>;
    case "syslog_fault": return <div className="evd-vis-main"><h3 className="evd-vis-title">{v.title}</h3><SyslogVisual s={v.data} toneLabel={view.severity.label} /></div>;
    case "audit": return <div className="evd-vis-main"><h3 className="evd-vis-title">{v.title}</h3><AuditVisual a={v.data} /></div>;
    case "interface": return <div className="evd-vis-main"><h3 className="evd-vis-title">{v.title}</h3><InterfaceVisual i={v.data} /></div>;
    case "tunnel": return <div className="evd-vis-main"><h3 className="evd-vis-title">{v.title}</h3><TunnelVisual t={v.data} /></div>;
    default: return <div className="evd-vis-main"><h3 className="evd-vis-title">{v.title}</h3><GenericVisual g={v.data} /></div>;
  }
}

export function PrimaryVisualCard({ view }: { view: EventView }) {
  const v = view.primaryVisual;
  return (
    <section className={`evd-card evd-vis evd-vis-${v.kind}${view.sideStats.length === 0 ? " evd-vis-solo" : ""}`} aria-label={v.title} data-testid="event-visual" data-kind={v.kind}>
      <div className="evd-vis-body"><VisualBody v={v} view={view} /></div>
      {view.sideStats.length > 0 && <StatTable rows={view.sideStats} />}
    </section>
  );
}

// ── context cards ────────────────────────────────────────────────────────────

export function DeviceCard({ view, variant }: { view: EventView; variant: "rows" | "header" }) {
  const d = view.device;
  if (d.rows.length === 0) return null;
  if (variant === "header" && view.lane !== "app" && view.lane !== "cloud") {
    const rest = d.rows.filter((r) => !["device", "ip", "inventory"].includes(r.key));
    return (
      <section className="evd-card evd-device-head" aria-label="Device" data-testid="event-device">
        <header className="evd-dev-top">
          <span className="evd-dev-ico" aria-hidden="true"><EvIcon name="server" size={22} /></span>
          <span className="evd-dev-id">
            <span className="evd-dev-name" title={d.name || undefined}>{d.name || DASH}</span>
            {d.address && d.address !== d.name && <span className="evd-dev-ip evd-mono">{d.address}</span>}
          </span>
          {d.inventory && <Pill tone={d.inventory.tone} icon={d.inventory.tone === "ok" ? "check" : "triangle"}>{d.inventory.label}</Pill>}
        </header>
        <KvList rows={rest} />
      </section>
    );
  }
  return (
    <Card icon="server" title={view.lane === "app" || view.lane === "cloud" ? "Source" : "Device"} testId="event-device">
      <KvList rows={d.rows} />
    </Card>
  );
}

export function TimingCard({ view }: { view: EventView }) {
  if (view.timing.length === 0) return null;
  return <Card icon="calendar" title="Event Timing" testId="event-timing"><KvList rows={view.timing} className="evd-kv-timing" /></Card>;
}

export function ClassificationCard({ view }: { view: EventView }) {
  if (view.classification.length === 0) return null;
  return <Card icon="grid" title="Event Classification" testId="event-classification"><KvList rows={view.classification} /></Card>;
}

function GuidanceTag({ basis }: { basis: string }) {
  return (
    <span className="evd-guidance" title={basis ? `Guidance from the ${basis}, not measured on this device` : "Guidance, not measured on this device"}>
      Guidance{basis ? ` · ${basis}` : ""}
    </span>
  );
}

export function ImpactCard({ view }: { view: EventView }) {
  if (view.overview.impact.length === 0) return null;
  return (
    <Card icon="triangle" iconTone="warn" title="Impact" testId="event-impact" aside={<GuidanceTag basis={view.overview.basis} />}>
      <ul className="evd-bullets">{view.overview.impact.map((s, i) => <li key={i}>{s}</li>)}</ul>
    </Card>
  );
}

export function NextChecksCard({ view }: { view: EventView }) {
  if (view.overview.nextChecks.length === 0) return null;
  return (
    <Card icon="wrench" title="Recommended Next Checks" testId="event-checks" aside={<GuidanceTag basis={view.overview.basis} />}>
      <ul className="evd-bullets">{view.overview.nextChecks.map((s, i) => <li key={i}>{s}</li>)}</ul>
    </Card>
  );
}

/** Page layout (B): What Happened over a split Impact | Next checks block. */
export function WhatHappenedCard({ view }: { view: EventView }) {
  const o = view.overview;
  if (!o.what && o.impact.length === 0 && o.nextChecks.length === 0) return null;
  return (
    <section className="evd-card evd-what" aria-label="What happened" data-testid="event-what">
      {o.what && (
        <>
          <header className="evd-card-head"><EvIcon name="doc" size={18} className="evd-card-ico" /><h3 className="evd-card-title">What Happened</h3></header>
          <p className="evd-what-text">{o.what}</p>
        </>
      )}
      {(o.impact.length > 0 || o.nextChecks.length > 0) && (
        <div className="evd-what-split">
          {o.impact.length > 0 && (
            <div>
              <h4 className="evd-sub-title"><EvIcon name="triangle" size={17} className="evd-card-ico evd-card-ico-warn" /> Impact</h4>
              <ul className="evd-bullets">{o.impact.map((s, i) => <li key={i}>{s}</li>)}</ul>
            </div>
          )}
          {o.nextChecks.length > 0 && (
            <div>
              <h4 className="evd-sub-title"><EvIcon name="wrench" size={17} className="evd-card-ico" /> Recommended Next Checks</h4>
              <ul className="evd-bullets">{o.nextChecks.map((s, i) => <li key={i}>{s}</li>)}</ul>
            </div>
          )}
          <GuidanceTag basis={o.basis} />
        </div>
      )}
    </section>
  );
}

export function IdentityCard({ view, related, title }: { view: EventView; related: RelatedState; title: string }) {
  const rows = [...view.identity.rows];
  if (related.status === "done") {
    const n = related.records.length;
    rows.push({ key: "related", label: "Related Events", value: n === 0 ? "0 (no related records yet)" : `${n}`, mono: false, tip: related.basis });
  } else if (related.status === "error") {
    rows.push({ key: "related", label: "Related Events", value: "Could not be searched", tip: related.error });
  }
  if (rows.length === 0) return null;
  return (
    <Card icon="fingerprint" title={title} testId="event-identity">
      <KvList rows={rows} className={`evd-kv-identity ${toneClass(view.identity.lifecycle === "clear" ? "ok" : view.severity.tone)}`} />
    </Card>
  );
}

// ── timeline ─────────────────────────────────────────────────────────────────

function TimelineItem({ e }: { e: TimelineEntry }) {
  const tone = e.tone === "accent" ? "accent" : e.tone === "neutral" ? "none" : e.tone;
  return (
    <li className={`evd-tl-item evd-tone-${tone}`}>
      <span className="evd-tl-dot" aria-hidden="true" />
      <div className="evd-tl-body">
        <div className="evd-tl-line">
          <span className="evd-tl-pill">{e.pill}</span>
          <span className="evd-tl-text">{e.text}</span>
        </div>
        <div className="evd-tl-time evd-mono">
          {fmtUtc(e.time)}
          <span className="evd-tl-basis">
            {" "}({e.afterSeconds !== undefined ? `${Number(e.afterSeconds.toFixed(3))} s after device time` : e.timeBasis})
          </span>
        </div>
      </div>
    </li>
  );
}

export function TimelineCard({ view, related, title = "Event Timeline" }: { view: EventView; related: RelatedState; title?: string }) {
  const entries = useMemo(() => mergedTimeline(view, related), [view, related]);
  const cleared = related.records.some((r) => r.identity.lifecycle === "clear");
  const showNoRecovery = view.identity.recovery?.verified === false && view.identity.lifecycle !== "clear" && related.status === "done" && !cleared;
  return (
    <Card icon="list" title={title} testId="event-timeline">
      <div className="evd-tl-wrap">
        <ol className="evd-tl">{entries.map((e) => <TimelineItem key={e.key} e={e} />)}</ol>
        {showNoRecovery && (
          <div className="evd-callout evd-callout-info" role="note" data-testid="event-no-recovery">
            <EvIcon name="info" size={18} />
            <div>
              <strong>No recovery event yet</strong>
              <p>The device has not reported a recovery for this event in the records searched.</p>
            </div>
          </div>
        )}
      </div>
      <p className="evd-note">
        {related.status === "loading" && "Searching for related records…"}
        {related.status === "done" && `${related.records.length === 0 ? "No related records" : `${related.records.length} related record${related.records.length === 1 ? "" : "s"}`} within a day of this event. Linked by: ${related.basis}.`}
        {related.status === "error" && `Related records could not be searched: ${related.error}`}
        {related.status === "none" && "This record carries nothing the search can link related records by."}
      </p>
    </Card>
  );
}

// ── technical details ────────────────────────────────────────────────────────

export function DetailsCard({ view }: { view: EventView }) {
  const d = view.details;
  if (d.kind === "varbinds") {
    return (
      <Card icon="list" title={d.title} testId="event-varbinds">
        <div className="evd-table-scroll">
          <table className="evd-table">
            <thead><tr><th scope="col">Name</th><th scope="col">OID</th><th scope="col">Type</th><th scope="col">Value (Decoded)</th></tr></thead>
            <tbody>
              {d.varbinds.map((v, i) => (
                <tr key={`${v.oid}#${i}`}>
                  <td className={v.name ? undefined : "evd-mono"}>{v.name || DASH}</td>
                  <td className="evd-mono">{v.oid}</td>
                  <td className="evd-mono">{v.type || DASH}</td>
                  <td className="evd-mono">
                    {v.tone
                      ? <span className={`evd-pill evd-pill-sev ${toneClass(v.tone)}`}>{v.decoded || v.value}</span>
                      : <>{v.isTime && <EvIcon name="calendar" size={14} className="evd-kv-ico" />}{v.decoded || v.value}</>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    );
  }
  if (d.rows.length === 0) return null;
  return (
    <Card icon="list" title={d.title} testId="event-fields">
      <div className="evd-table-scroll">
        <table className="evd-table evd-table-fields">
          <thead><tr><th scope="col">Name</th><th scope="col">Source</th><th scope="col">Value</th></tr></thead>
          <tbody>
            {d.rows.map((r) => (
              <tr key={r.key}>
                <td>{r.label}</td>
                <td>{r.prov ? <ProvTag prov={r.prov} /> : <span className="evd-dash">stated</span>}</td>
                <td className="evd-mono">{r.value}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  );
}

function FieldTable({ rows, label }: { rows: { name: string; value: string }[]; label: string }) {
  return (
    <table className="evd-table evd-table-kv" aria-label={label}>
      <thead><tr><th scope="col">Name</th><th scope="col">Value</th></tr></thead>
      <tbody>
        {rows.map((f) => <tr key={f.name}><td>{f.name}</td><td className="evd-mono">{f.value || DASH}</td></tr>)}
      </tbody>
    </table>
  );
}

export function TechnicalTab({ view }: { view: EventView }) {
  const pipeline = useMemo(() => fieldsOf(view.pipeline), [view.pipeline]);
  return (
    <div className="evd-stack">
      <DetailsCard view={view} />
      <Card icon="grid" title="All Fields" testId="event-all-fields">
        <div className="evd-table-scroll"><FieldTable rows={view.fields} label="All fields" /></div>
        {pipeline.length > 0 && (
          <details className="evd-pipeline" data-testid="pipeline-details">
            <summary>Pipeline details</summary>
            <FieldTable rows={pipeline} label="Pipeline details" />
          </details>
        )}
      </Card>
    </div>
  );
}

// ── metrics ──────────────────────────────────────────────────────────────────

function Trend({ trend, label }: { trend: TrendState; label: string }) {
  const w = 640, h = 160, pad = 28;
  const pts = trend.points;
  const t0 = pts[0]?.t ?? 0, t1 = pts[pts.length - 1]?.t ?? 1;
  const x = (t: number) => pad + ((t - t0) / Math.max(1, t1 - t0)) * (w - pad * 2);
  const y = (v: number) => h - pad - (Math.max(0, Math.min(100, v)) / 100) * (h - pad * 2);
  const path = pts.map((p, i) => `${i ? "L" : "M"}${x(p.t).toFixed(1)},${y(p.v).toFixed(1)}`).join(" ");
  const max = pts.reduce((m, p) => Math.max(m, p.v), 0);
  return (
    <figure className="evd-trend" data-testid="event-trend">
      <svg viewBox={`0 0 ${w} ${h}`} role="img" aria-label={`${label}: ${pts.length} measurements, peak ${fmtPercentShort(Number(max.toFixed(2)))}`}>
        <line x1={pad} x2={w - pad} y1={y(0)} y2={y(0)} className="evd-trend-axis" />
        <line x1={pad} x2={w - pad} y1={y(100)} y2={y(100)} className="evd-trend-grid" />
        <text x={4} y={y(100) + 4} className="evd-trend-tick">100%</text>
        <text x={4} y={y(0) + 4} className="evd-trend-tick">0%</text>
        <path d={path} className="evd-trend-line" fill="none" />
      </svg>
      <figcaption className="evd-note">
        {pts.length} measurements from {fmtUtc(new Date(t0).toISOString())} to {fmtUtc(new Date(t1).toISOString())}. Source: the stored series <span className="evd-mono">{trend.source}</span>.
      </figcaption>
    </figure>
  );
}

export function MetricsTab({ view, trend }: { view: EventView; trend: TrendState }) {
  return (
    <div className="evd-stack">
      {view.metrics.length > 0 ? (
        <Card icon="chart" title="Measurements in This Event" testId="event-metrics">
          <div className="evd-table-scroll">
            <table className="evd-table evd-table-metrics">
              <thead><tr><th scope="col">Metric</th><th scope="col">Value</th><th scope="col">Basis</th></tr></thead>
              <tbody>
                {view.metrics.map((m) => (
                  <tr key={m.key}>
                    <td>{m.label}{m.tip && <Tip label={m.label} text={m.tip} />}</td>
                    <td className="evd-mono evd-num">{m.value}</td>
                    <td><ProvTag prov={m.prov} />{m.formula && <span className="evd-formula evd-mono"> = {m.formula}</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      ) : (
        <Card icon="chart" title="Measurements in This Event"><p className="evd-muted">This record carries no measurements.</p></Card>
      )}
      {view.metricSeries && (
        <Card icon="chart" title={`${view.metricSeries.label} for This Device`} testId="event-trend-card">
          {trend.status === "loading" && <p className="evd-muted">Reading the stored measurements…</p>}
          {trend.status === "error" && <p className="evd-muted">The stored measurements could not be read: {trend.error}</p>}
          {trend.status === "done" && trend.points.length < 2 && (
            <p className="evd-muted">No polled measurements are stored for this device around this event, so no trend is shown.</p>
          )}
          {trend.status === "done" && trend.points.length >= 2 && <Trend trend={trend} label={view.metricSeries.label} />}
        </Card>
      )}
    </div>
  );
}

// ── raw ──────────────────────────────────────────────────────────────────────

export function RawTab({ view }: { view: EventView }) {
  const [state, setState] = useState("");
  const ref = useRef<HTMLDivElement>(null);
  return (
    <Card icon="braces" title="Raw Event" testId="event-raw"
      aside={(
        <span className="evd-copy-row">
          <button type="button" className="evd-btn" onClick={async () => setState(await copyText(JSON.stringify(view.raw, null, 2), ref.current))}>
            <EvIcon name="copy" size={15} /> Copy JSON
          </button>
          <span className="evd-copy-state" role="status">{state}</span>
        </span>
      )}
    >
      <p className="evd-note">The stored record, read-only. Secrets show as “hidden”.</p>
      <div className="evd-raw" ref={ref}><LogJson value={view.raw} /></div>
    </Card>
  );
}

