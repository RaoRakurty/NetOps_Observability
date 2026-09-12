// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// ResolutionActions (Wave 4 #12 — detection→resolution, slice 2) — the action
// row on an open cloud investigation. Three per-service resolution actions,
// every one backed by data that EXISTS (never a fabricated link):
//   1. Open provider console — the server-built cloud_ref console deep-links
//      already on this investigation's evidence rows, surfaced as actions.
//   2. File ITSM ticket — the EXISTING #78 ticketing lane: a status chip read
//      from the correlation's real ticket-link state + a File-ticket affordance
//      that enqueues to the same outbox the RCA ticket card uses.
//   3. Open runbook — the affected services' catalog runbook_url (operator-
//      authored, https-only). Honest empty state when none is configured.
//
// House rules: every URL is re-validated before it reaches an <a href>
// (safeConsoleUrl for console links upstream, safeRunbookUrl here); empty
// states say exactly why there is nothing to click.

import { useCallback, useEffect, useMemo, useState } from "react";
import { api, type BusinessServiceRow, type TicketStatus } from "../../services/api";
import type { CloudRcaObject } from "./api";
import { loadEvidence } from "./api";
import type { EvidenceRow } from "./types";
import { ConsoleLink, consoleName } from "./badges";
import { nameKey, safeRunbookUrl } from "./catalog";
import { ticketStateLabel, ticketStateTone } from "../../components/rca/labels";

// ── pure derivations (unit-tested) ───────────────────────────────────────────

export type ConsoleAction = { resource: string; provider: string; url: string };

// deriveConsoleActions: the DISTINCT console pivots on THIS investigation's
// evidence rows (rcaGroup = correlation id), capped so the action row stays a
// row. Only rows whose cloud_ref survived the safeConsoleUrl gate qualify.
export function deriveConsoleActions(rows: EvidenceRow[], correlationId: string, cap = 5): ConsoleAction[] {
  const out: ConsoleAction[] = [];
  const seen = new Set<string>();
  for (const r of rows) {
    if (r.rcaGroup !== correlationId) continue;
    const url = r.cloudRef?.consoleUrl ?? "";
    if (!url || seen.has(url)) continue;
    seen.add(url);
    out.push({ resource: r.resource || r.cloudRef?.resourceId || "resource", provider: r.cloudRef?.provider ?? "", url });
    if (out.length >= cap) break;
  }
  return out;
}

export type RunbookAction = { service: string; url: string };

// deriveRunbookActions: exact case-insensitive name join from the object's
// affected apps into the catalog (the same join the Services tab uses) — only
// services with a safe runbook_url produce an action. Never a guess.
export function deriveRunbookActions(apps: string[], services: BusinessServiceRow[]): RunbookAction[] {
  const byName = new Map<string, BusinessServiceRow>();
  for (const s of services) byName.set(nameKey(s.name), s);
  const out: RunbookAction[] = [];
  const seen = new Set<string>();
  for (const app of apps) {
    const svc = byName.get(nameKey(app));
    if (!svc || seen.has(svc.business_service_id)) continue;
    seen.add(svc.business_service_id);
    const url = safeRunbookUrl(svc.runbook_url);
    if (url) out.push({ service: svc.name, url });
  }
  return out;
}

// ── the action row ───────────────────────────────────────────────────────────

export default function ResolutionActions({ id }: { id: string }) {
  const [rows, setRows] = useState<EvidenceRow[]>([]);
  const [obj, setObj] = useState<CloudRcaObject | null>(null);
  const [evidenceLoaded, setEvidenceLoaded] = useState(false);
  const [services, setServices] = useState<BusinessServiceRow[] | null>(null);
  const [catalogErr, setCatalogErr] = useState(false);
  const [ticket, setTicket] = useState<TicketStatus | null>(null);
  const [ticketLoaded, setTicketLoaded] = useState(false);
  const [canWrite, setCanWrite] = useState(false);
  const [busy, setBusy] = useState(false);
  const [queued, setQueued] = useState("");

  const loadTicket = useCallback(() => {
    api.correlationTickets(id)
      .then((r) => { setTicket(r.status ?? { state: "not_created" }); setTicketLoaded(true); })
      .catch(() => { setTicket(null); setTicketLoaded(true); });
  }, [id]);

  useEffect(() => {
    let alive = true;
    setEvidenceLoaded(false); setTicketLoaded(false); setQueued("");
    // widest honored server window (7d) so an older investigation still finds
    // its own evidence; the read stays server-bounded either way.
    loadEvidence(undefined, 168)
      .then((b) => {
        if (!alive) return;
        setRows(b.rows.filter((r) => r.rcaGroup === id));
        setObj(b.objects.find((o) => o.correlationId === id) ?? null);
        setEvidenceLoaded(true);
      })
      .catch(() => { if (alive) setEvidenceLoaded(true); });
    api.cloudBusinessServices()
      .then((r) => { if (alive) setServices(r.business_services ?? []); })
      .catch(() => { if (alive) { setServices([]); setCatalogErr(true); } });
    api.permissions()
      .then((p) => { if (alive) setCanWrite((p.permissions?.infrastructure ?? 0) >= 2); })
      .catch(() => { if (alive) setCanWrite(false); });
    loadTicket();
    return () => { alive = false; };
  }, [id, loadTicket]);

  const consoles = useMemo(() => deriveConsoleActions(rows, id), [rows, id]);
  const runbooks = useMemo(
    () => deriveRunbookActions(obj?.apps ?? [], services ?? []),
    [obj, services],
  );

  const fileTicket = async () => {
    setBusy(true); setQueued("");
    try {
      await api.correlationTicketCreate(id);
      setQueued("Ticket creation queued — the worker will open it shortly.");
      setTimeout(loadTicket, 2500);
    } catch (e) {
      setQueued(`Could not queue the ticket: ${String((e as Error)?.message ?? e)}`);
    } finally {
      setBusy(false);
    }
  };

  const ticketCreated = !!ticket && !!ticket.state && ticket.state !== "not_created";

  return (
    <div className="inv-actions" data-testid="resolution-actions">
      <div className="inv-actions-h">Resolution actions</div>

      {/* 1 — provider console */}
      <div className="inv-actions-group">
        <span className="inv-actions-label">Provider console</span>
        {!evidenceLoaded ? (
          <span className="ao-muted">checking evidence…</span>
        ) : consoles.length > 0 ? (
          consoles.map((c) => (
            <ConsoleLink key={c.url} href={c.url}
              label={`${c.resource} · ${consoleName(c.provider)}`} />
          ))
        ) : (
          <span className="ao-muted">no provider console links on this investigation&apos;s evidence</span>
        )}
      </div>

      {/* 2 — ITSM ticket (the #78 lane; full card lives in the analysis below) */}
      <div className="inv-actions-group">
        <span className="inv-actions-label">ITSM ticket</span>
        {!ticketLoaded ? (
          <span className="ao-muted">checking ticket status…</span>
        ) : ticket === null ? (
          <span className="ao-muted">ticket status unavailable</span>
        ) : (
          <>
            <span className={`rw-pill ${ticketStateTone(ticket.state)}`}>{ticketStateLabel(ticket.state)}</span>
            {ticket.ticket_number && (
              ticket.url
                ? <a className="ao-console-link" href={ticket.url} target="_blank" rel="noopener noreferrer">
                    {ticket.ticket_number} ↗
                  </a>
                : <span className="mono">{ticket.ticket_number}</span>
            )}
            {!ticketCreated && canWrite && (
              <button className="ao-btn" disabled={busy} onClick={fileTicket}>
                {busy ? "Queuing…" : "File ticket"}
              </button>
            )}
            {queued && <span className="ao-muted">{queued}</span>}
          </>
        )}
      </div>

      {/* 3 — runbook */}
      <div className="inv-actions-group">
        <span className="inv-actions-label">Runbook</span>
        {services === null ? (
          <span className="ao-muted">checking the service catalog…</span>
        ) : runbooks.length > 0 ? (
          runbooks.map((r) => (
            <a key={r.url} className="ao-console-link" href={r.url}
              target="_blank" rel="noopener noreferrer">
              Open runbook · {r.service} ↗
            </a>
          ))
        ) : catalogErr ? (
          <span className="ao-muted">service catalog unavailable — runbook links cannot be resolved</span>
        ) : (obj?.apps?.length ?? 0) === 0 ? (
          <span className="ao-muted">no affected services recorded on this investigation</span>
        ) : (
          <span className="ao-muted">no runbook configured for the affected services (set one in Services → Catalog)</span>
        )}
      </div>
    </div>
  );
}
