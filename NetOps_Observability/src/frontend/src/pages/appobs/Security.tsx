// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Security (Wave 5 #16) — the security-findings view over the ALREADY-ingested
// log-fidelity rollup lanes: WAF blocks, LB-plane 5xx and DNS resolution
// failures. Nothing here is inferred: every row is a rollup the correlation
// lanes actually landed, and the coverage note says per lane whether telemetry
// is flowing, denied or simply not configured — honest absence, never a quiet
// empty table.

import { useEffect, useState } from "react";
import DataTable from "../../components/DataTable";
import { Chip } from "../../components/noc";
import { Skeleton } from "../../components/ui";
import { api } from "../../services/api";
import type { CloudSecurityFindingRow, CloudIngestionSource } from "../../services/api";
import { EmptyState, ProviderBadge, ago } from "./badges";
import { STATUS_META, SOURCE_LABEL } from "./readiness";
import type { SourceStatus, SourceType } from "./readiness";
import { severityRank } from "../../theme/severity";
import { timeRank } from "./sortRanks";

// lane vocabulary ↔ the ingestion matrix's source chips (1:1 with the backend
// securityLaneKinds map — the coverage note joins on the SAME source types).
export const SECURITY_LANES = [
  { lane: "waf", label: "WAF blocks", source: "firewall_logs" as SourceType },
  { lane: "lb", label: "LB errors", source: "lb_logs" as SourceType },
  { lane: "dns", label: "DNS failures", source: "dns_logs" as SourceType },
] as const;

export type SecurityLane = (typeof SECURITY_LANES)[number]["lane"];

const LANE_LABEL: Record<string, string> = {
  waf: "WAF block", lb: "LB error", dns: "DNS failure", other: "Other",
};

const LANE_TONE: Record<string, string> = {
  waf: "var(--crit)", lb: "var(--warn)", dns: "var(--warn)", other: "var(--fg-subtle)",
};

// laneCoverage joins the global ingestion sources onto the three lanes — which
// lanes are actually flowing vs stale vs not configured vs denied.
export function laneCoverage(sources: CloudIngestionSource[]): {
  lane: SecurityLane; label: string; status: SourceStatus; detail?: string;
}[] {
  const byType = new Map(sources.map((s) => [s.source_type, s]));
  return SECURITY_LANES.map((l) => {
    const src = byType.get(l.source);
    const status = (src?.status ?? "off") as SourceStatus;
    return { lane: l.lane, label: l.label, status, detail: src?.detail };
  });
}

const SEV_TONE: Record<string, string> = {
  critical: "var(--crit)", high: "var(--crit)", warn: "var(--warn)",
  medium: "var(--warn)", info: "var(--fg-subtle)", low: "var(--fg-subtle)",
};

export default function Security({ windowHours = 24 }: { windowHours?: number }) {
  const [findings, setFindings] = useState<CloudSecurityFindingRow[] | null>(null);
  const [sources, setSources] = useState<CloudIngestionSource[]>([]);
  const [status, setStatus] = useState<"loading" | "ready" | "error">("loading");
  const [lane, setLane] = useState<string>("");

  useEffect(() => {
    let live = true;
    setStatus("loading");
    Promise.all([
      api.cloudSecurity(undefined, undefined, windowHours),
      // Coverage note only — an ingestion hiccup must not blank the findings.
      api.cloudIngestion().then((r) => r.sources ?? [], () => [] as CloudIngestionSource[]),
    ]).then(
      ([sec, ing]) => {
        if (!live) return;
        setFindings(sec.findings ?? []);
        setSources(ing);
        setStatus("ready");
      },
      () => { if (live) setStatus("error"); },
    );
    return () => { live = false; };
  }, [windowHours]);

  if (status === "loading") {
    return (
      <div className="ao-panel" role="status" aria-label="Loading security findings">
        <Skeleton w={200} h={14} /><div style={{ marginTop: 12 }}><Skeleton h={220} /></div>
      </div>
    );
  }
  if (status === "error" || findings === null) {
    return <div className="ao-panel" role="alert"><EmptyState title="Unable to load security findings" hint="retry, or check the cloud connector status in Settings" /></div>;
  }

  const coverage = laneCoverage(sources);
  const flowingCount = coverage.filter((c) => c.status === "flowing" || c.status === "stale").length;
  const rows = lane ? findings.filter((f) => f.lane === lane) : findings;

  return (
    <div className="ao-stack">
      {/* Coverage honesty: which of the three lanes actually deliver. */}
      <div className="ao-panel">
        <div className="ao-panel-h">Security lane coverage
          <span className="ao-panel-meta">measured per lane — a lane that is not configured cannot report findings</span></div>
        <div className="ao-chips" role="list" aria-label="Security lane coverage">
          {coverage.map((c) => (
            <span role="listitem" key={c.lane} title={c.detail || `${c.label}: ${STATUS_META[c.status]?.label ?? c.status}`}>
              <Chip
                label={`${c.label} · ${STATUS_META[c.status]?.label ?? c.status}`}
                tone={STATUS_META[c.status]?.tone ?? "var(--fg-subtle)"} />
            </span>
          ))}
        </div>
      </div>

      <div className="ao-panel">
        <div className="ao-panel-h">Security findings
          <span className="ao-panel-meta">
            WAF blocks · LB-plane errors · DNS failures — rollups from the ingested provider logs
          </span></div>
        {/* Toggle filters, not tabs: aria-pressed carries the active state so
            selection isn't conveyed by the highlight color alone (1.4.1/4.1.2). */}
        <div className="ao-chips" style={{ marginBottom: 8 }} role="group" aria-label="Lane filter">
          <button className={`ao-btn${lane === "" ? " ao-btn--primary" : ""}`} aria-pressed={lane === ""} onClick={() => setLane("")}>All lanes</button>
          {SECURITY_LANES.map((l) => (
            <button key={l.lane} className={`ao-btn${lane === l.lane ? " ao-btn--primary" : ""}`} aria-pressed={lane === l.lane}
              onClick={() => setLane(lane === l.lane ? "" : l.lane)}>{l.label}</button>
          ))}
        </div>
        {rows.length === 0 ? (
          flowingCount === 0 ? (
            <EmptyState title="No security lanes are delivering"
              hint={`none of the WAF / LB / DNS log lanes is flowing — see the ${SOURCE_LABEL.firewall_logs}, ${SOURCE_LABEL.lb_logs} and ${SOURCE_LABEL.dns_logs} chips in Data sources for what each lane needs`} />
          ) : (
            <EmptyState title={lane ? `No ${LANE_LABEL[lane].toLowerCase()} findings in the window` : "No security findings in the window"}
              hint="the configured lanes are delivering; nothing security-relevant landed in this time range" />
          )
        ) : (
          <DataTable<CloudSecurityFindingRow & { _k: string }> rows={rows.map((f, i) => ({ ...f, _k: `${f.time}·${f.signal}·${f.resource}·${i}` }))}
            rowKey={(f) => f._k}
            height={Math.min(520, 56 + rows.length * 32)} ariaLabel="Security findings"
            columns={[
              { key: "time", header: "Time", width: 110, sortValue: (f) => timeRank(f.time), render: (f) => ago(f.time) },
              { key: "lane", header: "Lane", width: 110, sortValue: (f) => f.lane,
                render: (f) => <Chip label={LANE_LABEL[f.lane] ?? f.lane} tone={LANE_TONE[f.lane] ?? "var(--fg-subtle)"} /> },
              { key: "src", header: "Provider", width: 90, sortValue: (f) => f.source,
                render: (f) => <ProviderBadge provider={f.source} compact /> },
              { key: "resource", header: "Resource", width: 200, sortValue: (f) => f.resource,
                render: (f) => <strong>{f.resource}</strong> },
              { key: "app", header: "Service", width: 140, sortValue: (f) => f.app,
                render: (f) => f.app === "—" ? <span className="ao-muted">—</span> : f.app },
              { key: "detail", header: "What happened", width: 280, sortValue: (f) => f.detail,
                render: (f) => f.detail
                  ? <span className="ao-why" title={f.detail}>{f.detail}</span>
                  : <span className="ao-muted" title="the rollup carried no further detail">—</span> },
              { key: "count", header: "Events", width: 80, align: "right", sortValue: (f) => f.count,
                render: (f) => f.count.toLocaleString() },
              { key: "sev", header: "Severity", width: 90, sortValue: (f) => severityRank(f.severity),
                render: (f) => <Chip label={f.severity} tone={SEV_TONE[f.severity] ?? "var(--fg-subtle)"} /> },
            ]} />
        )}
      </div>
    </div>
  );
}
