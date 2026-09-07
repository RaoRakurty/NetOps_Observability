// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// TicketDelivery — Administration → Incident Response → Ticket Delivery.
//
// WHY THIS EXISTS. RCA auto-ticketing has a reliable outbox: a policy decides a
// case should reach ServiceNow / Jira / PagerDuty, a row is queued, and a worker
// drains it with bounded retries. Until now none of that was visible. An
// operator whose ticket never arrived had no way to tell "the policy did not
// fire" from "the row is queued behind a provider that is refusing us", and the
// provider's own error text — the one fact that says which — was reachable only
// by curl.
//
// The three reads and the two controls on this page:
//   GET  /api/tickets/outbox        what is still on its way, with last_error
//   GET  /api/tickets/audit         every recorded transition, filterable by case
//   POST /api/integrations/reconcile a drift sweep for this tenant ("Sync now")
//   POST /api/correlations/{id}/ticket/sync   re-drive ONE case's ticket
//
// HONESTY RULES:
//   · `total` is the caller's real row count, so a full page never reads as
//     "that is everything". The page says which it is.
//   · An empty outbox is stated as empty AND as not being proof a ticket was
//     filed — the outbox holds what is in flight, not what was delivered.
//   · "Sync now" sweeps only the BIDIRECTIONAL providers, so it can honestly
//     answer zero while integrations exist; the result says so in those words.
//   · The per-row control enqueues a fresh sync for that case. It does not
//     replay the stuck row, and it does not claim to.
//
// §3a: both reads are tenant-filtered server-side from the bearer token, and the
// reconcile acts on the caller's own tenant only. The page never sends a tenant.

import { useCallback, useEffect, useMemo, useState } from "react";
import { api, TacConnectorInfo, TicketAuditRow, TicketOutboxItem } from "../../services/api";
import { fmtDateTime } from "../../lib/time";
import { httpFailure, operatorError } from "../../lib/errors";
import { Stat, StatStrip } from "../../components/ui";
import AskIris from "../../components/AskIris";
import {
  CONNECTOR_CHIP,
  connectorCapabilityLine,
  connectorState,
  connectorStatusNote,
  connectorTopic,
  humanBytes,
} from "../troubleshoot/tacModel";

const PAGE = 50;

/** Delivery states, grouped the way an operator asks about them. */
const LANES = [
  { key: "all", label: "All" },
  { key: "queued", label: "Queued" },
  { key: "failed", label: "Failed" },
  { key: "delivered", label: "Delivered" },
] as const;
type Lane = (typeof LANES)[number]["key"];

function laneOf(status: string): Exclude<Lane, "all"> | "other" {
  switch ((status || "").toLowerCase()) {
    case "pending":
    case "retrying":
      return "queued";
    case "failed":
    case "dead_letter":
      return "failed";
    case "sent":
      return "delivered";
    default:
      return "other";
  }
}

const STATUS_TONE: Record<string, string> = {
  pending: "",
  retrying: "chip-warn",
  failed: "chip-crit",
  dead_letter: "chip-crit",
  sent: "chip-ok",
};

/** A 36-char RFC 4122 id, the only shape the audit filter accepts server-side. */
const UUID_RE = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

function shortId(id: string): string {
  return id && id.length > 12 ? `${id.slice(0, 8)}…` : id || "—";
}

function caseHref(id: string): string {
  return `#/investigate/rca?id=${encodeURIComponent(id)}`;
}

export default function TicketDelivery() {
  const [outbox, setOutbox] = useState<TicketOutboxItem[] | null>(null);
  const [outboxTotal, setOutboxTotal] = useState(0);
  const [outboxErr, setOutboxErr] = useState<string | null>(null);

  const [audit, setAudit] = useState<TicketAuditRow[] | null>(null);
  const [auditTotal, setAuditTotal] = useState(0);
  const [auditErr, setAuditErr] = useState<string | null>(null);

  const [lane, setLane] = useState<Lane>("all");
  const [caseFilter, setCaseFilter] = useState("");
  const [appliedFilter, setAppliedFilter] = useState("");
  const [filterErr, setFilterErr] = useState<string | null>(null);

  // The case connectors this tenant can reach. This page is where credentials
  // are brought, so it is where each vendor path's standing research belongs
  // (owner, 2026-09-06) — the escalation step no longer prints twelve
  // paragraphs, and the paragraph is behind its own disclosure here.
  const [connectors, setConnectors] = useState<TacConnectorInfo[] | null>(null);
  const [connErr, setConnErr] = useState<string | null>(null);

  const [syncing, setSyncing] = useState(false);
  const [syncNote, setSyncNote] = useState<string | null>(null);
  const [rowBusy, setRowBusy] = useState<string | null>(null);
  const [rowNote, setRowNote] = useState<string | null>(null);

  const loadOutbox = useCallback(async () => {
    try {
      const r = await api.ticketsOutbox(PAGE, 0);
      setOutbox(r.outbox ?? []);
      setOutboxTotal(r.total ?? (r.outbox ?? []).length);
      setOutboxErr(null);
    } catch (e) {
      setOutbox(null);
      setOutboxErr(operatorError(e, "The delivery outbox could not be read."));
    }
  }, []);

  const loadAudit = useCallback(async (corrObjectId: string) => {
    try {
      const r = await api.ticketsAudit({ limit: PAGE, offset: 0, corrObjectId: corrObjectId || undefined });
      setAudit(r.audit ?? []);
      setAuditTotal(r.total ?? (r.audit ?? []).length);
      setAuditErr(null);
    } catch (e) {
      setAudit(null);
      setAuditErr(operatorError(e, "The ticket audit trail could not be read."));
    }
  }, []);

  const loadConnectors = useCallback(async () => {
    try {
      const r = await api.tacConnectors();
      setConnectors(r.connectors ?? []);
      setConnErr(null);
    } catch (e) {
      setConnectors(null);
      setConnErr(operatorError(e, "The case connectors could not be read."));
    }
  }, []);

  useEffect(() => { void loadConnectors(); }, [loadConnectors]);
  useEffect(() => { void loadOutbox(); }, [loadOutbox]);
  useEffect(() => { void loadAudit(appliedFilter); }, [loadAudit, appliedFilter]);

  const applyFilter = useCallback(() => {
    const v = caseFilter.trim();
    if (v && !UUID_RE.test(v)) {
      setFilterErr("An RCA case id is a 36-character identifier. Paste the whole id from the case URL.");
      return;
    }
    setFilterErr(null);
    setAppliedFilter(v);
  }, [caseFilter]);

  const syncNow = useCallback(async () => {
    setSyncing(true);
    setSyncNote(null);
    try {
      const r = await api.integrationsReconcile();
      const n = r.reconciled_providers ?? 0;
      setSyncNote(
        n === 0
          ? "No two-way integration is configured for this tenant, so nothing was swept. A one-way integration still delivers; it just has no state to read back."
          : `Swept ${n} two-way integration${n === 1 ? "" : "s"} for drift. Any state change the provider made is now recorded.`,
      );
      await loadAudit(appliedFilter);
    } catch (e) {
      const f = httpFailure(e);
      setSyncNote(
        f?.status === 409
          ? "Integrations are not available on this deployment, so there is nothing to sweep."
          : operatorError(e, "The drift sweep could not be started."),
      );
    } finally {
      setSyncing(false);
    }
  }, [appliedFilter, loadAudit]);

  const syncCase = useCallback(async (corrObjectId: string) => {
    setRowBusy(corrObjectId);
    setRowNote(null);
    try {
      await api.correlationTicketSync(corrObjectId);
      setRowNote(`A fresh sync was queued for case ${shortId(corrObjectId)} — a new row, not a replay.`);
      await loadOutbox();
    } catch (e) {
      setRowNote(operatorError(e, "That case could not be queued for a sync."));
    } finally {
      setRowBusy(null);
    }
  }, [loadOutbox]);

  const rows = useMemo(
    () => (outbox ?? []).filter((r) => lane === "all" || laneOf(r.status) === lane),
    [outbox, lane],
  );
  const counts = useMemo(() => {
    const c = { queued: 0, failed: 0, delivered: 0, other: 0 };
    for (const r of outbox ?? []) c[laneOf(r.status)] += 1;
    return c;
  }, [outbox]);

  const partial = outbox !== null && outbox.length < outboxTotal;

  return (
    <div className="adm">
      <div className="admin-head">
        <h2 style={{ margin: 0, fontSize: "var(--fs-lg)" }}>
          Ticket delivery
          <AskIris topic="ticketing.outbox" label="Ticket delivery" />
        </h2>
        <p className="admin-sub">What auto-ticketing queued, failed or delivered.</p>
      </div>

      <div className="admin-head-row" style={{ marginTop: "var(--sp-2)" }}>
        <StatStrip>
          <Stat label="Queued" value={outbox === null ? "—" : counts.queued} />
          <Stat label="Failed" value={outbox === null ? "—" : counts.failed} tone={counts.failed > 0 ? "bad" : ""} />
          <Stat label="Delivered" value={outbox === null ? "—" : counts.delivered} tone="good" />
        </StatStrip>
        <button type="button" className="btn" onClick={() => void syncNow()} disabled={syncing}>
          {syncing ? "Sweeping…" : "Sync now"}
        </button>
      </div>
      <p className="adm-line">
        <b>Sync now</b> opens and closes nothing.
        <AskIris topic="ticketing.sync-now" label="the sync sweep" />
      </p>
      {syncNote && <p className="adm-line" role="status">{syncNote}</p>}

      <h3 style={{ marginBottom: "var(--sp-1)" }}>Outbox</h3>
      <div className="admin-head-row">
        <div role="group" aria-label="Filter the outbox by delivery state">
          {LANES.map((l) => (
            <button
              key={l.key}
              type="button"
              className="btn"
              aria-pressed={lane === l.key}
              onClick={() => setLane(l.key)}
              style={{ marginRight: 6 }}
            >
              {l.label}
            </button>
          ))}
        </div>
      </div>

      {outboxErr && <p role="alert" style={{ color: "var(--bad)", fontSize: "var(--fs-meta)" }}>{outboxErr} The outbox contents are unknown, not empty.</p>}
      {rowNote && <p className="adm-line" role="status">{rowNote}</p>}

      {outbox === null && !outboxErr ? (
        <div className="empty" role="status">Reading the delivery outbox…</div>
      ) : outbox !== null && outbox.length === 0 ? (
        <div className="empty">
          Nothing is in flight.
          <AskIris topic="ticketing.empty-outbox" label="nothing in flight" />
        </div>
      ) : outbox !== null && rows.length === 0 ? (
        <div className="empty">No row on this page is {LANES.find((l) => l.key === lane)?.label.toLowerCase()}.</div>
      ) : outbox !== null ? (
        <table className="ds-table" aria-label="Ticket delivery outbox">
          <thead>
            <tr>
              <th scope="col">RCA case</th>
              <th scope="col">Destination</th>
              <th scope="col">Action</th>
              <th scope="col">State</th>
              <th scope="col">Attempts</th>
              <th scope="col">Next attempt</th>
              <th scope="col">Last refusal</th>
              <th scope="col">Updated</th>
              <th scope="col"><span className="sr-only">Re-drive</span></th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.id}>
                <th scope="row" style={{ fontWeight: 500, textAlign: "left" }}>
                  <a href={caseHref(r.corr_object_id)} title={r.corr_object_id}>{shortId(r.corr_object_id)}</a>
                </th>
                <td>{r.external_system || "not stated"}</td>
                <td>{r.action || "not stated"}</td>
                <td><span className={`chip ${STATUS_TONE[(r.status || "").toLowerCase()] ?? ""}`}>{r.status || "not stated"}</span></td>
                <td>{r.retry_count}{r.max_retries > 0 ? ` of ${r.max_retries}` : ""}</td>
                <td>{laneOf(r.status) === "queued" && r.next_retry_at ? fmtDateTime(r.next_retry_at) : "—"}</td>
                <td style={r.last_error ? { color: "var(--bad)" } : undefined}>{r.last_error || "none recorded"}</td>
                <td>{r.updated_at ? fmtDateTime(r.updated_at) : "—"}</td>
                <td>
                  <button
                    type="button"
                    className="btn"
                    disabled={rowBusy === r.corr_object_id}
                    onClick={() => void syncCase(r.corr_object_id)}
                  >
                    {rowBusy === r.corr_object_id ? "Queueing…" : "Sync this case"}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : null}

      {outbox !== null && (
        <p className="adm-line">
          {partial
            ? `Showing the first ${outbox.length} of ${outboxTotal.toLocaleString()} rows — this page is not the whole outbox.`
            : `${outboxTotal.toLocaleString()} row${outboxTotal === 1 ? "" : "s"} — this is the whole outbox.`}
        </p>
      )}

      <h3 style={{ marginBottom: "var(--sp-1)" }}>Audit trail</h3>
      <div className="admin-head-row">
        <label>
          <span className="adm-line">RCA case id</span>{" "}
          <input
            type="text"
            value={caseFilter}
            onChange={(e) => setCaseFilter(e.target.value)}
            onKeyDown={(e) => { if (e.key === "Enter") applyFilter(); }}
            placeholder="filter by case id"
            style={{ minWidth: 320 }}
          />
        </label>
        <button type="button" className="btn" onClick={applyFilter}>Filter</button>
        {appliedFilter && (
          <button type="button" className="btn" onClick={() => { setCaseFilter(""); setAppliedFilter(""); setFilterErr(null); }}>
            Clear
          </button>
        )}
      </div>
      {filterErr && <p role="alert" style={{ color: "var(--bad)", fontSize: "var(--fs-meta)" }}>{filterErr}</p>}
      {auditErr && <p role="alert" style={{ color: "var(--bad)", fontSize: "var(--fs-meta)" }}>{auditErr} The trail is unknown, not empty.</p>}

      {audit === null && !auditErr ? (
        <div className="empty" role="status">Reading the audit trail…</div>
      ) : audit !== null && audit.length === 0 ? (
        <div className="empty">
          {appliedFilter
            ? "No ticket action recorded for that case."
            : "No ticket action has been recorded for this tenant yet."}
        </div>
      ) : audit !== null ? (
        <table className="ds-table" aria-label="Ticket audit trail">
          <thead>
            <tr>
              <th scope="col">When</th>
              <th scope="col">RCA case</th>
              <th scope="col">Destination</th>
              <th scope="col">Action</th>
              <th scope="col">By</th>
              <th scope="col">State change</th>
              <th scope="col">Result</th>
            </tr>
          </thead>
          <tbody>
            {audit.map((a) => (
              <tr key={a.id}>
                <th scope="row" style={{ fontWeight: 500, textAlign: "left" }}>{a.at ? fmtDateTime(a.at) : "—"}</th>
                <td><a href={caseHref(a.corr_object_id)} title={a.corr_object_id}>{shortId(a.corr_object_id)}</a></td>
                <td>{a.external_system || "not stated"}</td>
                <td>{a.action || "not stated"}</td>
                <td>{a.actor || "not stated"}</td>
                <td>{a.old_status || "—"} → {a.new_status || "—"}</td>
                <td style={a.error ? { color: "var(--bad)" } : undefined}>{a.error || a.result || "not stated"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : null}

      {audit !== null && audit.length > 0 && (
        <p className="adm-line">
          {audit.length < auditTotal
            ? `Showing the ${audit.length} most recent of ${auditTotal.toLocaleString()} recorded actions.`
            : `${auditTotal.toLocaleString()} recorded action${auditTotal === 1 ? "" : "s"} — this is the whole trail.`}
        </p>
      )}

      <h3 style={{ marginBottom: "var(--sp-1)" }}>Case connectors</h3>
      <p className="adm-line">
        Vendor and ITSM paths a TAC escalation can use.
        <AskIris topic="tac.case-connector" label="case connectors" />
      </p>
      {connErr && <p role="alert" style={{ color: "var(--bad)", fontSize: "var(--fs-meta)" }}>{connErr}</p>}
      {connectors === null && !connErr ? (
        <div className="empty" role="status">Reading the case connectors…</div>
      ) : connectors !== null && connectors.length === 0 ? (
        <div className="empty">No case connector on this deployment.</div>
      ) : connectors !== null ? (
        <ul className="tdc-list" data-testid="ticket-connectors">
          {connectors.map((c) => {
            const state = connectorState(c);
            const note = connectorStatusNote(c);
            return (
              <li key={c.id} className="tdc-row" data-testid={`ticket-conn-${c.id}`}>
                <div className="tdc-head">
                  <b>{c.display}</b>
                  <span className={`chip ${state === "unavailable" ? "chip-crit" : state === "ready" ? "chip-ok" : ""}`}>
                    {CONNECTOR_CHIP[state]}
                  </span>
                  <span className="adm-line">{connectorCapabilityLine(c)}</span>
                  {c.max_attachment_bytes > 0 && (
                    <span className="adm-line">attaches up to {humanBytes(c.max_attachment_bytes)}</span>
                  )}
                  <AskIris topic={connectorTopic(c.id)} label={c.display} />
                </div>
                {note && (
                  <p className="adm-line" style={state === "unavailable" ? { color: "var(--bad)" } : undefined} role={state === "unavailable" ? "alert" : undefined}>
                    {note}
                  </p>
                )}
                {/* The vendor research, behind its own disclosure — never inline.
                    It is remote-authored text and renders as escaped React text. */}
                {c.note && (
                  <details className="tdc-fold">
                    <summary>What this vendor path needs</summary>
                    <p className="tdc-fold-text">{c.note}</p>
                  </details>
                )}
              </li>
            );
          })}
        </ul>
      ) : null}
    </div>
  );
}
