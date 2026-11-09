// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// LogLineDetailBody — one log record in the Inspector (shell-v2) or inline (v1).
// Summary reads the record in plain terms, Fields lists what it carries, Raw is the
// document itself. Everything shown comes through toLogEvent, so secrets are already
// replaced, and every value is escaped React text.

import { KeyboardEvent, useId, useMemo, useState } from "react";
import { FlowView, LogEvent, LogField, LogVarbind, fieldsOf, isIpLike, toLogEvent } from "../lib/logEvent";
import { LogJson, LogLevel, LogMessage, LogTime } from "../lib/logfmt";

const TABS = ["Summary", "Fields", "Raw"] as const;
type Tab = (typeof TABS)[number];

export function LogLineDetailBody({ line }: { line: { index: string; raw: Record<string, any> } }) {
  const ev = useMemo(() => toLogEvent({ _index: line.index, _source: line.raw }), [line.index, line.raw]);
  const [tab, setTab] = useState<Tab>("Summary");
  const uid = useId();

  const onTabKey = (e: KeyboardEvent<HTMLButtonElement>) => {
    const i = TABS.indexOf(tab);
    const next =
      e.key === "ArrowRight" ? TABS[(i + 1) % TABS.length]
      : e.key === "ArrowLeft" ? TABS[(i + TABS.length - 1) % TABS.length]
      : e.key === "Home" ? TABS[0]
      : e.key === "End" ? TABS[TABS.length - 1]
      : null;
    if (!next) return;
    e.preventDefault();
    setTab(next);
    const list = e.currentTarget.parentElement;
    list?.querySelector<HTMLButtonElement>(`[data-tab="${next}"]`)?.focus();
  };

  return (
    <div className="lv-det" data-testid="log-detail">
      <div className="lv-tabs" role="tablist" aria-label="Log record">
        {TABS.map((t) => (
          <button
            key={t}
            type="button"
            role="tab"
            data-tab={t}
            id={`${uid}-${t}`}
            className="lv-tab"
            aria-selected={tab === t}
            aria-controls={`${uid}-panel`}
            tabIndex={tab === t ? 0 : -1}
            onClick={() => setTab(t)}
            onKeyDown={onTabKey}
          >
            {t}
          </button>
        ))}
      </div>
      <div className="lv-panel" role="tabpanel" id={`${uid}-panel`} aria-labelledby={`${uid}-${tab}`} tabIndex={0}>
        {tab === "Summary" && <SummaryTab ev={ev} />}
        {tab === "Fields" && <FieldsTab ev={ev} />}
        {tab === "Raw" && <RawTab ev={ev} />}
      </div>
    </div>
  );
}

function SummaryTab({ ev }: { ev: LogEvent }) {
  return (
    <>
      <h3 className={`lv-det-title${ev.flow ? " lv-mono" : ""}`}>{ev.title}</h3>
      <div className="lv-chips">
        {ev.severity && <LogLevel level={ev.severity} />}
        {ev.lifecycle && <span className="lv-quiet-chip">{ev.lifecycle}</span>}
        <span className="lv-quiet-chip">{ev.signalLabel}</span>
        {ev.vendor && <span className="lv-quiet-chip">{ev.vendor}</span>}
        {ev.chips.map((c) => <span key={c.label} className="lv-quiet-chip">{c.label}</span>)}
      </div>
      <dl className="lv-kv">
        <dt>Time</dt>
        <dd><LogTime ts={ev.time} /></dd>
        {ev.deviceLabel && (
          <>
            <dt>Device</dt>
            <dd>
              <span className={isIpLike(ev.deviceLabel) ? "lv-mono" : undefined}>{ev.deviceLabel}</span>
              {ev.deviceAddress && <> <span className="lv-addr">{ev.deviceAddress}</span></>}
            </dd>
          </>
        )}
        {ev.trap?.oid && (
          <>
            <dt>Trap OID</dt>
            <dd className="lv-mono">{ev.trap.oid}</dd>
          </>
        )}
        {ev.trap?.uptime && (
          <>
            <dt>Device up for</dt>
            <dd className="lv-mono">{ev.trap.uptime}</dd>
          </>
        )}
      </dl>
      {ev.varbinds && <VarbindCard varbinds={ev.varbinds} />}
      {ev.flow && <FlowCard flow={ev.flow} />}
      {ev.syslog && <SyslogCard ev={ev} />}
      {!ev.syslog && !ev.flow && !ev.varbinds && ev.message && ev.message !== ev.title && (
        <MessageBlock text={ev.message} />
      )}
    </>
  );
}

function MessageBlock({ text }: { text: string }) {
  return <p className="lv-message"><LogMessage text={text} clamp={false} highlight="stream" /></p>;
}

function VarbindCard({ varbinds }: { varbinds: LogVarbind[] }) {
  return (
    <section className="lv-card" aria-label="Trap values">
      <h4 className="lv-card-title">Trap values</h4>
      <table className="lv-table lv-table-oid">
        <thead>
          <tr><th scope="col">Name</th><th scope="col">Value</th></tr>
        </thead>
        <tbody>
          {varbinds.map((v, i) => (
            <tr key={`${v.oid}#${i}`}>
              <td className={v.numeric ? "lv-mono" : undefined} title={v.oid || undefined}>{v.label}</td>
              <td className="lv-mono">{v.value}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}

function FlowCard({ flow }: { flow: FlowView }) {
  const end = (label: string, e: FlowView["source"]) => (
    <div className="lv-end">
      <span className="lv-end-k">{label}</span>
      <span className="lv-end-v">{e.address || "—"}{e.port && `:${e.port}`}</span>
    </div>
  );
  return (
    <section className="lv-card" aria-label="Flow">
      {flow.exporter && (
        <p className="lv-exporter">
          Exporter {flow.exporterName && <>{flow.exporterName} </>}<span className="lv-mono">{flow.exporter}</span>
        </p>
      )}
      <div className="lv-strip" data-testid="flow-strip">
        {end("Source", flow.source)}
        <div className="lv-arrow" aria-label={flow.protocol ? `${flow.protocol} to` : "to"}>
          {flow.protocol && <span>{flow.protocol}</span>}
          <span className="lv-arrow-glyph" aria-hidden="true">→</span>
        </div>
        {end("Destination", flow.destination)}
      </div>
      <dl className="lv-kv">
        {flow.inInterface && <><dt>In interface</dt><dd className="lv-mono">{flow.inInterface}</dd></>}
        {flow.outInterface && <><dt>Out interface</dt><dd className="lv-mono">{flow.outInterface}</dd></>}
        {flow.packets && <><dt>Packets</dt><dd className="lv-mono">{flow.packets}</dd></>}
        {flow.bytes && <><dt>Bytes</dt><dd className="lv-mono">{flow.bytes}</dd></>}
        {flow.sampling.length > 0 && (
          <>
            <dt>Sampling reported</dt>
            <dd className="lv-mono">{flow.sampling.map((s) => `${s.name} ${s.value}`).join(" · ")}</dd>
          </>
        )}
      </dl>
    </section>
  );
}

function SyslogCard({ ev }: { ev: LogEvent }) {
  const s = ev.syslog!;
  return (
    <section className="lv-card" aria-label="Syslog message">
      {s.pills.length > 0 && (
        <div className="lv-pills">
          {s.pills.map((p) => (
            <span key={p.name} className="lv-pill"><span className="lv-pill-k">{p.name}</span>{p.value}</span>
          ))}
        </div>
      )}
      {s.message && s.message !== ev.title && <MessageBlock text={s.message} />}
    </section>
  );
}

function FieldTable({ rows }: { rows: LogField[] }) {
  return (
    <table className="lv-table">
      <thead>
        <tr><th scope="col">Name</th><th scope="col">Value</th></tr>
      </thead>
      <tbody>
        {rows.map((f) => (
          <tr key={f.name}>
            <td>{f.name}</td>
            <td className="lv-mono">{f.value || "—"}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function FieldsTab({ ev }: { ev: LogEvent }) {
  const pipeline = useMemo(() => fieldsOf(ev.pipeline), [ev.pipeline]);
  return (
    <>
      <FieldTable rows={ev.fields} />
      {pipeline.length > 0 && (
        <details className="lv-pipeline" data-testid="pipeline-details">
          <summary>Pipeline details</summary>
          <FieldTable rows={pipeline} />
        </details>
      )}
    </>
  );
}

function RawTab({ ev }: { ev: LogEvent }) {
  const [copy, setCopy] = useState<"" | "Copied" | "Copy failed">("");
  const onCopy = async () => {
    try {
      await navigator.clipboard.writeText(JSON.stringify(ev.raw, null, 2));
      setCopy("Copied");
    } catch {
      setCopy("Copy failed");
    }
  };
  return (
    <>
      <div className="lv-copy-row">
        <button type="button" className="chip" onClick={onCopy}>Copy</button>
        <span className="lv-copy-state" role="status">{copy}</span>
      </div>
      <div className="lv-raw"><LogJson value={ev.raw} /></div>
    </>
  );
}
