// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// RcaTickets — Administration → Incident response → RCA Tickets (owner,
// 2026-10-18: Ticketing & Automation + Ticket Delivery as ONE
// prerequisite-gated flow).
//
//   1. Connect destinations — where a root-cause ticket can go (ServiceNow,
//      Jira, PagerDuty, Slack — set up in Integrations — or a case connector)
//   2. Ticket rules         — when a root cause opens a ticket (policies)
//   3. Vendor case routing  — optional and never locked: TAC case connectors
//      and routing serve escalation even when auto-ticketing is off
//   4. Deliveries           — what was queued, failed or delivered
//
// A step opens when the one before it is done, or when it already holds data
// of its own (StepFlow): a failing outbox is never hidden behind "finish step
// 2 first". Every step is the page section it was, unchanged; nothing here
// writes. Gates are the sections' own (tenant-scoped: requireAdmin /
// requirePerm + the caller's tenant), so this page is tenant-level.
//
// Deep links: #/admin/ticketing/deliveries and #/admin/ticketing/cases scroll
// to their step (the old #/admin/ticket-delivery lands on deliveries).

import { useEffect, useMemo, useState } from "react";
import { api, type ItsmConfig, type IncidentPolicy, type TacConnectorInfo } from "../../services/api";
import { operatorError } from "../../lib/errors";
import AdminPageHeader from "../../components/admin/AdminPageHeader";
import StepFlow, { type FlowStep } from "../../components/admin/StepFlow";
import { IncidentPoliciesAdmin } from "../../tabs/admin";
import TicketDelivery from "./TicketDelivery";
import { CONNECTOR_CHIP, connectorState } from "../troubleshoot/tacModel";

export type Destination = { id: string; name: string; on: boolean };

/** Which ticket destinations are connected (configured AND enabled). */
export function destinationsOf(cfg: ItsmConfig | undefined): Destination[] {
  return [
    { id: "servicenow", name: "ServiceNow", on: !!(cfg?.servicenow?.configured && cfg.servicenow.enabled) },
    { id: "jira", name: "Jira", on: !!(cfg?.jira?.configured && cfg.jira.enabled) },
    { id: "pagerduty", name: "PagerDuty", on: !!(cfg?.pagerduty?.enabled && cfg.pagerduty.has_routing_key) },
    { id: "slack", name: "Slack", on: !!(cfg?.slack?.enabled && cfg.slack.has_webhook) },
  ];
}

/** A case connector that can take a case (ready, attach-only, or a configured manual path). */
export function usableConnector(c: TacConnectorInfo): boolean {
  const st = connectorState(c);
  return st === "ready" || st === "attach-only" || st === "manual-configured";
}

type Rules = { policies: IncidentPolicy[]; running: boolean | undefined; conflict: boolean };

/** More than one enabled policy for one system holds ALL auto-ticketing (server rule). */
export function policyConflict(policies: readonly IncidentPolicy[]): boolean {
  const per: Record<string, number> = {};
  for (const p of policies) if (p.enabled) per[p.external_system || "servicenow"] = (per[p.external_system || "servicenow"] ?? 0) + 1;
  return Object.values(per).some((n) => n > 1);
}

function subOf(hash: string): string {
  return hash.replace(/^#\/?/, "").split("?")[0].split("/")[2] ?? "";
}

export default function RcaTickets() {
  const [cfg, setCfg] = useState<ItsmConfig | undefined>(undefined);
  const [cfgErr, setCfgErr] = useState<string | null>(null);
  const [connectors, setConnectors] = useState<TacConnectorInfo[] | null>(null);
  const [rules, setRules] = useState<Rules | null>(null);
  const [outboxRows, setOutboxRows] = useState<number | null>(null);

  useEffect(() => {
    api.itsmConfig().then(setCfg).catch((e: unknown) => setCfgErr(operatorError(e, "The ticket destinations could not be read.")));
    api.tacConnectors().then((r) => setConnectors(r.connectors ?? [])).catch(() => setConnectors([]));
    // Read for the GATING even while step 2 is locked: existing rules must open
    // their step (hasData). Step 2 itself re-reports after every edit.
    api.incidentPolicies()
      .then((r) => setRules({ policies: r.policies ?? [], running: r.ticketing_running, conflict: policyConflict(r.policies ?? []) }))
      .catch(() => setRules(null));
    // One row is enough to know whether the outbox holds anything.
    api.ticketsOutbox(1, 0).then((r) => setOutboxRows(r.total ?? (r.outbox ?? []).length)).catch(() => setOutboxRows(null));
  }, []);

  // Deep link to a step.
  useEffect(() => {
    const go = () => {
      const sub = subOf(window.location.hash);
      const id = sub === "deliveries" ? "deliveries" : sub === "cases" ? "cases" : "";
      if (id) document.querySelector(`[data-step="${id}"]`)?.scrollIntoView({ block: "start" });
    };
    const t = setTimeout(go, 0);
    window.addEventListener("hashchange", go);
    return () => { clearTimeout(t); window.removeEventListener("hashchange", go); };
  }, []);

  const dests = destinationsOf(cfg);
  const usable = (connectors ?? []).filter(usableConnector);
  const connected = dests.filter((d) => d.on);

  const steps: FlowStep[] = useMemo(() => [
    {
      id: "destinations",
      title: "Connect destinations",
      done: connected.length > 0 || usable.length > 0,
      status: cfg === undefined && !cfgErr ? "…" : `${connected.length + usable.length} connected`,
      render: () => (
        <div>
          {cfgErr && <p role="alert" style={{ color: "var(--bad)" }}>{cfgErr}</p>}
          <ul className="rca-dests">
            {dests.map((d) => (
              <li key={d.id} data-testid={`dest-${d.id}`}>
                <span className="rca-dest-name">{d.name}</span>
                <span className={`badge ${d.on ? "good" : ""}`}>{d.on ? "Connected" : "Not connected"}</span>
              </li>
            ))}
            {(connectors ?? []).filter(usableConnector).map((c) => (
              <li key={c.id} data-testid={`dest-case-${c.id}`}>
                <span className="rca-dest-name">{c.display}</span>
                <span className="badge good">{CONNECTOR_CHIP[connectorState(c)]}</span>
              </li>
            ))}
          </ul>
          <a className="btn" href="#/admin/integrations">Set up in Integrations</a>
        </div>
      ),
    },
    {
      id: "rules",
      title: "Ticket rules",
      done: rules !== null && rules.running === true && !rules.conflict,
      hasData: (rules?.policies.length ?? 0) > 0,
      status: rules === null ? undefined : rules.running === false ? "Ticketing is off" : rules.conflict ? "Held — two policies enabled" : `${rules.policies.filter((p) => p.enabled).length} active`,
      render: () => <IncidentPoliciesAdmin embedded onLoaded={setRules} />,
    },
    {
      id: "cases",
      title: "Vendor case routing",
      optional: true,
      done: usable.length > 0,
      // Never gated: TAC escalation (Troubleshooting) opens vendor cases
      // through these connectors whether or not auto-ticketing runs, so a
      // platform with ticketing off must still be able to set them up.
      hasData: true,
      render: () => <TicketDelivery part="cases" />,
    },
    {
      id: "deliveries",
      title: "Deliveries",
      done: (outboxRows ?? 0) > 0,
      hasData: (outboxRows ?? 0) > 0,
      status: outboxRows === null ? undefined : `${outboxRows.toLocaleString()} in the outbox`,
      render: () => <TicketDelivery part="deliveries" />,
    },
  // eslint-disable-next-line react-hooks/exhaustive-deps
  ], [cfg, cfgErr, connectors, rules, outboxRows]);

  return (
    <div className="adm rca-tickets">
      <AdminPageHeader title="RCA Tickets" sub="One ticket per root cause." topic="admin.rca-ticketing" />
      <StepFlow steps={steps} label="Set up RCA tickets" />
    </div>
  );
}
