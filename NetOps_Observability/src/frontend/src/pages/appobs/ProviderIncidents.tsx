// Provider incidents + seam health strip (Wave 5 #16) — two small Overview
// lanes over the new tenant-scoped reads:
//
//   ProviderIncidentsPanel  the provider's OWN incident/maintenance events
//                           (kind=provider_event, AWS Health lane). Honest
//                           empty state: no events ≠ "all clear" when the
//                           lane needs an AWS support plan to exist at all.
//   SeamHealthStrip         the hybrid-seam gateway plane, latest measured
//                           state per seam endpoint (#105 lanes — built,
//                           possibly awaiting infra). Absence renders
//                           "awaiting telemetry", never a green guess.

import { useEffect, useState } from "react";
import DataTable from "../../components/DataTable";
import { Chip } from "../../components/noc";
import { Skeleton } from "../../components/ui";
import { api } from "../../services/api";
import type { CloudProviderEventRow, CloudSeamTelemetryRow } from "../../services/api";
import { EmptyState, ProviderBadge, ago } from "./badges";
import { severityRank } from "../../theme/severity";
import { timeRank } from "./sortRanks";

const CATEGORY_LABEL: Record<string, string> = {
  issue: "Incident",
  scheduledChange: "Maintenance",
  accountNotification: "Notification",
};

const CATEGORY_TONE: Record<string, string> = {
  issue: "var(--crit)",
  scheduledChange: "var(--warn)",
  accountNotification: "var(--fg-subtle)",
};

type LoadState = "loading" | "ready" | "error";

export function ProviderIncidentsPanel({ windowHours = 24 }: { windowHours?: number }) {
  const [events, setEvents] = useState<CloudProviderEventRow[]>([]);
  const [status, setStatus] = useState<LoadState>("loading");
  useEffect(() => {
    let live = true;
    setStatus("loading");
    api.cloudProviderEvents(windowHours).then(
      (r) => { if (live) { setEvents(r.events ?? []); setStatus("ready"); } },
      () => { if (live) setStatus("error"); },
    );
    return () => { live = false; };
  }, [windowHours]);

  return (
    <div className="ao-panel">
      <div className="ao-panel-h">Provider incidents
        <span className="ao-panel-meta">the provider&apos;s own incident &amp; maintenance declarations (AWS Health)</span></div>
      {status === "loading" ? <Skeleton h={80} /> : status === "error" ? (
        <EmptyState title="Unable to load provider incidents" hint="retry, or check the cloud connector status in Settings" />
      ) : events.length === 0 ? (
        <EmptyState title="No provider incidents reported in the window"
          hint="the AWS Health lane requires a Business or Enterprise support plan — if the account has one and this stays empty, the provider reported nothing; the lane's status is on Data sources (Cloud Health)" />
      ) : (
        <DataTable<CloudProviderEventRow & { _k: string }>
          rows={events.map((e, i) => ({ ...e, _k: `${e.time}·${e.service}·${e.region}·${i}` }))}
          rowKey={(e) => e._k}
          height={Math.min(300, 56 + events.length * 32)} ariaLabel="Provider incidents"
          columns={[
            { key: "time", header: "Updated", width: 110, sortValue: (e) => timeRank(e.time), render: (e) => ago(e.time) },
            { key: "provider", header: "Provider", width: 90, sortValue: (e) => e.provider,
              render: (e) => <ProviderBadge provider={e.provider} compact /> },
            { key: "service", header: "Service", width: 110, sortValue: (e) => e.service,
              render: (e) => <strong>{e.service}</strong> },
            { key: "region", header: "Region", width: 110, sortValue: (e) => e.region, render: (e) => e.region },
            { key: "category", header: "Type", width: 120, sortValue: (e) => e.category,
              render: (e) => <Chip label={CATEGORY_LABEL[e.category] ?? e.category}
                tone={CATEGORY_TONE[e.category] ?? "var(--fg-subtle)"} /> },
            { key: "status", header: "Status", width: 90, sortValue: (e) => e.status,
              render: (e) => e.status === "—" ? <span className="ao-muted">—</span> : e.status },
            { key: "summary", header: "What the provider says", width: 300, sortValue: (e) => e.summary,
              render: (e) => e.summary
                ? <span className="ao-why" title={e.summary}>{e.summary}</span>
                : <span className="ao-muted">—</span> },
            { key: "sev", header: "Severity", width: 90, sortValue: (e) => severityRank(e.severity),
              render: (e) => e.severity },
          ]} />
      )}
    </div>
  );
}

// ── seam health strip ────────────────────────────────────────────────────────

const SEAM_STATE_TONE: Record<CloudSeamTelemetryRow["state"], string> = {
  up: "var(--ok)", down: "var(--crit)", degraded: "var(--warn)", unknown: "var(--fg-subtle)",
};

// seamShortLabel reduces a seam key ("vpn:vpn-0abc:52.1.2.3", "dxbgp:vif-1:p1")
// to a readable chip label — kind prefix + the provider-native id.
export function seamShortLabel(seamId: string): string {
  const parts = seamId.split(":");
  if (parts.length >= 2) return `${parts[0]} ${parts[1]}`;
  return seamId;
}

export function SeamHealthStrip({ windowHours = 24 }: { windowHours?: number }) {
  const [seams, setSeams] = useState<CloudSeamTelemetryRow[]>([]);
  const [status, setStatus] = useState<LoadState>("loading");
  useEffect(() => {
    let live = true;
    setStatus("loading");
    api.cloudSeamTelemetry(windowHours).then(
      (r) => { if (live) { setSeams(r.seams ?? []); setStatus("ready"); } },
      () => { if (live) setStatus("error"); },
    );
    return () => { live = false; };
  }, [windowHours]);

  return (
    <div className="ao-panel">
      <div className="ao-panel-h">Hybrid seam health
        <span className="ao-panel-meta">VPN tunnels · DX/ER BGP · gateway drops — latest measured state per seam</span></div>
      {status === "loading" ? <Skeleton h={40} /> : status === "error" ? (
        <EmptyState title="Unable to load seam telemetry" hint="retry, or check the cloud connector status in Settings" />
      ) : seams.length === 0 ? (
        <EmptyState title="Awaiting seam telemetry"
          hint="the seam lanes are built and polling; no VPN tunnel, BGP session or gateway-drop signal has been observed in this window — states appear the moment the gateways report" />
      ) : (
        <div className="ao-chips" role="list" aria-label="Seam health">
          {seams.map((s) => (
            <span role="listitem" key={s.seam_id}
              title={`${s.seam_id} · ${s.kind} · last seen ${s.last_seen} · ${s.events} event${s.events === 1 ? "" : "s"} in the window`}>
              <Chip label={`${seamShortLabel(s.seam_id)} · ${s.state}`}
                tone={SEAM_STATE_TONE[s.state] ?? "var(--fg-subtle)"} />
            </span>
          ))}
        </div>
      )}
    </div>
  );
}
