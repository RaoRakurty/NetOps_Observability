// InvestigationLanes — the parallel evidence lanes of the symptom-first
// Troubleshooting surface. One card per lane, each fed by an ALREADY-DEPLOYED
// API, each carrying its own honest empty and not-connected states.
//
// The lanes run in PARALLEL on purpose (design §c): the operator should not have
// to open seven windows serially to find which layer the fault is on. Each card
// names the API it read, so nothing on this page is unverifiable.
//
// HONESTY. A lane never renders a reassuring blank. investigationModel decides
// its state (loading / error / not_connected / empty / ready) and the card
// prints the state's own sentence. "Not connected" (the source was never wired)
// and "empty" (the source is wired and was quiet) are different facts and are
// never collapsed into one.
//
// SECURITY (§3 / §15). Every value below — device ids, event kinds, path
// destinations, flow addresses — is remote-authored text rendered as an escaped
// React text node. There is no innerHTML and no dangerouslySetInnerHTML here.

import { useEffect, useState, type ReactNode } from "react";
import { api, type FeedItem, type PathHealthItem, type ProbePath, type PromInstantSeries } from "../../services/api";
import { operatorError } from "../../lib/errors";
import {
  LANE_SOURCE,
  LANE_TITLE,
  changeLabel,
  classifyChangeLane,
  classifyDemLane,
  classifyEventsLane,
  classifyFlowLane,
  classifyMetricLane,
  classifyPathLane,
  isConfigChangeKind,
  laneError,
  laneLoading,
  type LaneId,
  type LaneResult,
  type LaneState,
} from "./investigationModel";

/** The entity an investigation is scoped to. All fields are optional: an
 *  unscoped investigation reads the fleet-wide view of every lane. */
export interface LaneScope {
  /** Device id / name taken from the case (never from a URL the user typed). */
  device?: string;
  /** Minutes of history — the shell's global range. */
  minutes: number;
  /** Correlation id, when a case drives the investigation. */
  caseId?: string;
}

export type LaneStateReport = (id: LaneId, state: LaneState) => void;

// ── the card shell ───────────────────────────────────────────────────────────

function LaneCard({ id, result, children, action }: {
  id: LaneId;
  result: LaneResult<unknown>;
  children?: ReactNode;
  action?: ReactNode;
}) {
  const headingId = `lane-h-${id}`;
  return (
    <section className="tsl-card card" role="region" aria-labelledby={headingId} data-lane={id} data-state={result.state}>
      <div className="tsl-head">
        <h3 id={headingId} className="tsl-title">{LANE_TITLE[id]}</h3>
        {action}
      </div>
      <div className="tsl-src mini-meta">{LANE_SOURCE[id]}</div>
      {result.state === "loading" && <div className="empty" role="status">Loading…</div>}
      {result.state === "error" && <div className="empty" role="alert" style={{ color: "var(--bad)" }}>{result.note}</div>}
      {result.state === "not_connected" && (
        <div className="tsl-notwired empty" role="status">
          <span className="badge">Not connected</span> {result.note}
        </div>
      )}
      {result.state === "empty" && <div className="empty" role="status">{result.note}</div>}
      {result.state === "ready" && children}
    </section>
  );
}

/** useLane — one lane's fetch, with its state reported up to the ladder. */
function useLane<T>(
  id: LaneId,
  load: () => Promise<LaneResult<T>>,
  deps: unknown[],
  report?: LaneStateReport,
): LaneResult<T> {
  const [res, setRes] = useState<LaneResult<T>>(laneLoading<T>);
  useEffect(() => {
    let alive = true;
    setRes(laneLoading<T>());
    report?.(id, "loading");
    load()
      .then((r) => { if (alive) { setRes(r); report?.(id, r.state); } })
      .catch((e: unknown) => {
        if (!alive) return;
        const r = laneError<T>(`${LANE_TITLE[id]} — ${operatorError(e, "this lane could not be loaded.")}`);
        setRes(r);
        report?.(id, r.state);
      });
    return () => { alive = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
  return res;
}

// ── DEM / probes ─────────────────────────────────────────────────────────────

export function DemLane({ scope, report }: { scope: LaneScope; report?: LaneStateReport }) {
  const res = useLane<PathHealthItem>(
    "dem",
    async () => classifyDemLane((await api.pathsHealth())?.paths ?? []),
    [scope.device, scope.minutes, scope.caseId],
    report,
  );
  return (
    <LaneCard id="dem" result={res}>
      <ul className="tsl-list">
        {res.rows.slice(0, 6).map((p) => (
          <li key={p.path_id} className="tsl-row">
            <span className={`tsl-dot ${p.health_state}`} aria-hidden="true" />
            <span className="tsl-k">{p.agent} → {p.dst}</span>
            <span className="tsl-v">{p.health_state} · confidence {p.confidence}</span>
            <span className="tsl-note">{p.reason}</span>
          </li>
        ))}
      </ul>
    </LaneCard>
  );
}

// ── What changed ─────────────────────────────────────────────────────────────

export function ChangedLane({ scope, report }: { scope: LaneScope; report?: LaneStateReport }) {
  const res = useLane<FeedItem>(
    "changed",
    async () => {
      const params: Record<string, string> = {
        from: `${Math.max(1, Math.round(scope.minutes / 60))}h`,
        class: "changes",
        limit: "25",
      };
      if (scope.device) params.entity = scope.device;
      return classifyChangeLane((await api.eventsFeed(params))?.items ?? []);
    },
    [scope.device, scope.minutes, scope.caseId],
    report,
  );
  return (
    <LaneCard id="changed" result={res}>
      <ul className="tsl-list">
        {res.rows.slice(0, 8).map((it) => (
          <li key={it.signal_id} className="tsl-row">
            <span className={`tsl-dot ${isConfigChangeKind(it.kind) ? "change" : "state"}`} aria-hidden="true" />
            <span className="tsl-k">{changeLabel(it.kind)}</span>
            <span className="tsl-v">{it.entity_id}</span>
            <span className="tsl-note">{it.ts}</span>
          </li>
        ))}
      </ul>
      <p className="mini-meta tsl-foot">Proximity in time, never a causal claim.</p>
    </LaneCard>
  );
}

// ── Device / protocol health ─────────────────────────────────────────────────

const HEALTH_METRICS = ["device_if_oper_status", "device_sysuptime", "device_resource_cpu_pct"];
const HEALTH_QUERY = 'device_if_oper_status == 0';

export function HealthLane({ scope, report, protocolSlot }: {
  scope: LaneScope; report?: LaneStateReport; protocolSlot?: ReactNode;
}) {
  const [openDiag, setOpenDiag] = useState(false);
  const res = useLane<PromInstantSeries>(
    "health",
    async () => {
      const [names, q] = await Promise.all([api.metricNames(), api.metricsQuery(HEALTH_QUERY)]);
      return classifyMetricLane(
        names?.data ?? [],
        HEALTH_METRICS,
        q?.data?.result ?? [],
        "No device metric has ever been scraped — the SNMP/gNMI collectors are not collecting from this fleet.",
      );
    },
    [scope.device, scope.minutes, scope.caseId],
    report,
  );
  return (
    <>
      <LaneCard
        id="health"
        result={res}
        // The toggle exists only when a host actually supplies the slot. It used
        // to render unconditionally, and after the protocol-diagnostics bench
        // was retired (TAC_ESCALATION_2026-09-05 §5) that left a control which
        // expanded to nothing — a button that promises a surface it cannot open.
        action={
          protocolSlot ? (
            <button type="button" className="chip-btn" aria-expanded={openDiag}
              onClick={() => setOpenDiag((o) => !o)}>
              {openDiag ? "Hide protocol diagnostics" : "Protocol diagnostics"}
            </button>
          ) : undefined
        }
      >
        <ul className="tsl-list">
          {res.rows.slice(0, 8).map((s, i) => (
            <li key={`${s.metric.device}-${s.metric.ifName ?? s.metric.index ?? ""}-${i}`} className="tsl-row">
              <span className="tsl-dot bad" aria-hidden="true" />
              <span className="tsl-k">{s.metric.device ?? "unknown device"}</span>
              <span className="tsl-v">{s.metric.ifName ?? s.metric.interface ?? s.metric.index ?? "interface"}</span>
              <span className="tsl-note">operationally down</span>
            </li>
          ))}
        </ul>
      </LaneCard>
      {openDiag && protocolSlot}
    </>
  );
}

// ── Path ─────────────────────────────────────────────────────────────────────

export function PathLane({ scope, report }: { scope: LaneScope; report?: LaneStateReport }) {
  const res = useLane<ProbePath>(
    "path",
    async () => classifyPathLane((await api.probePaths()) ?? []),
    [scope.device, scope.minutes, scope.caseId],
    report,
  );
  return (
    <LaneCard id="path" result={res}>
      <ul className="tsl-list">
        {res.rows.slice(0, 5).map((p, i) => (
          <li key={`${p.dst}-${p.method ?? ""}-${i}`} className="tsl-row">
            <span className={`tsl-dot ${p.reached ? "good" : "bad"}`} aria-hidden="true" />
            <span className="tsl-k">{p.dst}</span>
            <span className="tsl-v">{p.hops?.length ?? 0} hops · {p.reached ? "reached" : "did not reach"}</span>
            <span className="tsl-note">{p.changed ? "path changed" : "path stable"}</span>
          </li>
        ))}
      </ul>
    </LaneCard>
  );
}

// ── Routing / BGP ────────────────────────────────────────────────────────────

const ROUTING_METRICS = ["device_bgp_peer_state", "device_ospf_nbr_state", "device_isis_adj_state"];
const ROUTING_QUERY = "device_bgp_peer_state != 6 or device_ospf_nbr_state != 8 or device_isis_adj_state != 3";

export function RoutingLane({ scope, report }: { scope: LaneScope; report?: LaneStateReport }) {
  const res = useLane<PromInstantSeries>(
    "routing",
    async () => {
      const [names, q] = await Promise.all([api.metricNames(), api.metricsQuery(ROUTING_QUERY)]);
      return classifyMetricLane(
        names?.data ?? [],
        ROUTING_METRICS,
        q?.data?.result ?? [],
        "No routing-protocol metric has ever been scraped — BGP/OSPF/IS-IS collection is not enabled for this fleet.",
      );
    },
    [scope.device, scope.minutes, scope.caseId],
    report,
  );
  return (
    <LaneCard id="routing" result={res}>
      <ul className="tsl-list">
        {res.rows.slice(0, 8).map((s, i) => (
          <li key={`${s.metric.device}-${s.metric.peer ?? s.metric.neighbor ?? ""}-${i}`} className="tsl-row">
            <span className="tsl-dot bad" aria-hidden="true" />
            <span className="tsl-k">{s.metric.device ?? "unknown device"}</span>
            <span className="tsl-v">{s.metric.peer ?? s.metric.neighbor ?? s.metric.isis_neighbor ?? "neighbor"}</span>
            <span className="tsl-note">not in the established state</span>
          </li>
        ))}
      </ul>
    </LaneCard>
  );
}

// ── Flows ────────────────────────────────────────────────────────────────────

type FlowRow = Record<string, unknown>;

export function FlowsLane({ scope, report }: { scope: LaneScope; report?: LaneStateReport }) {
  const res = useLane<FlowRow>(
    "flows",
    async () => {
      const since = Math.max(60, scope.minutes * 60);
      const [types, top] = await Promise.all([
        api.flowsByType(since),
        api.topTalkers(since, 8, "", scope.device ? { device: scope.device } : undefined),
      ]);
      return classifyFlowLane<FlowRow>((types?.data as never) ?? [], (top?.data as FlowRow[]) ?? []);
    },
    [scope.device, scope.minutes, scope.caseId],
    report,
  );
  return (
    <LaneCard id="flows" result={res}>
      <ul className="tsl-list">
        {res.rows.slice(0, 8).map((r, i) => (
          <li key={i} className="tsl-row">
            <span className="tsl-dot state" aria-hidden="true" />
            <span className="tsl-k">{String(r.src_addr ?? r.src ?? "—")}</span>
            <span className="tsl-v">→ {String(r.dst_addr ?? r.dst ?? "—")}</span>
            <span className="tsl-note">{String(r.bytes ?? r.total_bytes ?? "")}</span>
          </li>
        ))}
      </ul>
    </LaneCard>
  );
}

// ── Correlated events ────────────────────────────────────────────────────────

export function EventsLane({ scope, report }: { scope: LaneScope; report?: LaneStateReport }) {
  const res = useLane<FeedItem>(
    "events",
    async () => {
      const params: Record<string, string> = {
        from: `${Math.max(1, Math.round(scope.minutes / 60))}h`,
        limit: "25",
      };
      if (scope.device) params.entity = scope.device;
      return classifyEventsLane((await api.eventsFeed(params))?.items ?? []);
    },
    [scope.device, scope.minutes, scope.caseId],
    report,
  );
  return (
    <LaneCard id="events" result={res}>
      <ul className="tsl-list">
        {res.rows.slice(0, 10).map((it) => (
          <li key={it.signal_id} className="tsl-row">
            <span className={`tsl-dot ${it.severity === "critical" ? "bad" : "state"}`} aria-hidden="true" />
            <span className="tsl-k">{it.title || it.kind}</span>
            <span className="tsl-v">{it.entity_id}</span>
            <span className="tsl-note">{it.ts}</span>
          </li>
        ))}
      </ul>
    </LaneCard>
  );
}

// ── the registry the page renders from ───────────────────────────────────────

export const LANE_COMPONENT: Record<
  LaneId,
  (p: { scope: LaneScope; report?: LaneStateReport; protocolSlot?: ReactNode }) => JSX.Element
> = {
  dem: DemLane,
  changed: ChangedLane,
  health: HealthLane,
  path: PathLane,
  routing: RoutingLane,
  flows: FlowsLane,
  events: EventsLane,
};
