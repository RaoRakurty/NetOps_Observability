// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { useEffect, useState } from "react";
import { api, StackHealth as StackHealthData, StackComponent } from "../services/api";
import Icon from "../components/Icon";
import AskIris from "../components/AskIris";
import { StatStrip, Stat, Skeleton } from "../components/ui";
import { operatorError } from "../lib/errors";
import {
  COLLECTION_QUERIES,
  collectorRows,
  flowSourceRows,
  flowsTotal,
  scalarValue,
  type CollectorRow,
  type FlowSourceRow,
} from "./stackCollection";
// Stack Health — the platform's OWN infrastructure monitoring: the data
// backends, event bus, state stores and visualization that make up the stack
// behind the app. Platform-owner only (the API returns 403 otherwise); the nav
// already hides this from tenant-scoped users, this guard is the backstop.
//
// Presentation mirrors the modern self-service cards (ChangePasswordCard): an
// icon-chip header + subtitle, a data-dense StatStrip, skeleton loading, and a
// scannable per-category status board instead of a flat table.
//
// IT ALSO CARRIES COLLECTION (2026-09-07). Troubleshooting used to keep a second
// section — the June collection-pipeline board — which a `?section=pipeline`
// bookmark reopened on every refresh, reading as a stale page. The board is
// gone; the facts no other screen carried are the Collection section below:
// the fleet counts, one row per collector, and the flow sources. Its model is
// tabs/stackCollection.ts; the words it used to spend teaching now sit behind
// the (i) as ai/skills/explain/pipeline.reachable-zero.md.

const CATEGORY_LABELS: Record<string, string> = {
  search: "Search",
  metrics: "Metrics",
  olap: "OLAP / Flows",
  analytics: "Analytics",
  bus: "Event bus",
  state: "State",
  visualization: "Visualization",
};

const STATUS_META: Record<string, { color: string; label: string }> = {
  up: { color: "var(--good)", label: "Operational" },
  degraded: { color: "var(--sev-warning)", label: "Degraded" },
  down: { color: "var(--bad)", label: "Down" },
};

function overallTone(overall: string): "good" | "warn" | "bad" {
  if (overall === "healthy" || overall === "up") return "good";
  if (overall === "degraded") return "warn";
  return "bad";
}

function Dot({ status }: { status: string }) {
  const color = STATUS_META[status]?.color ?? "var(--muted)";
  return (
    <span
      className="sh-dot"
      style={{ background: color, color }}
      title={STATUS_META[status]?.label ?? status}
      aria-label={STATUS_META[status]?.label ?? status}
    />
  );
}

function Header() {
  return (
    <div className="pw-head">
      <span className="pw-head-icon"><Icon name="stack" size={18} /></span>
      <div>
        <h2>Stack Health</h2>
        <p className="pw-sub">
          Live status of the platform's own infrastructure — the search, metrics,
          OLAP, analytics, event-bus, state and visualization backends behind the
          app. Refreshes every 15&nbsp;seconds.
        </p>
      </div>
    </div>
  );
}

// ── Collection ───────────────────────────────────────────────────────────────
//
// The four fleet counts, one row per collector and the flow sources — what the
// retired collection-pipeline board was the only screen to carry. Facts only:
// the reading that makes them worth putting side by side (reachable 0 while
// monitored is above 0 points at the devices) is behind the (i).

const fmtCount = (n: number | null): string => (n == null ? "—" : Math.round(n).toLocaleString());
const fmtMs = (n: number | null): string => (n == null ? "—" : `${Math.round(n)} ms`);

function CollectionSection() {
  const [monitored, setMonitored] = useState<number | null>(null);
  const [snmpReachable, setSnmpReachable] = useState<number | null>(null);
  const [collectors, setCollectors] = useState<CollectorRow[]>([]);
  const [sources, setSources] = useState<FlowSourceRow[]>([]);
  const [traps, setTraps] = useState<number | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    let alive = true;
    const tick = async () => {
      try {
        const [mon, reach, conf, cReach, poll, byType, trapHits] = await Promise.all([
          api.metricsQuery(COLLECTION_QUERIES.monitored),
          api.metricsQuery(COLLECTION_QUERIES.snmpReachable),
          api.metricsQuery(COLLECTION_QUERIES.configured),
          api.metricsQuery(COLLECTION_QUERIES.reachable),
          api.metricsQuery(COLLECTION_QUERIES.poll),
          api.flowsByType(3600),
          api.searchLogs({ query: "*", signal: "snmptrap", size: 0 }),
        ]);
        if (!alive) return;
        setMonitored(scalarValue(mon?.data?.result));
        setSnmpReachable(scalarValue(reach?.data?.result));
        setCollectors(collectorRows(conf?.data?.result, cReach?.data?.result, poll?.data?.result));
        setSources(flowSourceRows(byType?.data));
        setTraps(Number(trapHits?.hits?.total?.value ?? NaN) || 0);
        setErr(null);
        setLoaded(true);
      } catch (e) {
        if (!alive) return;
        setErr(operatorError(e, "Collection could not be read."));
        setLoaded(true);
      }
    };
    tick();
    const id = setInterval(tick, 30000);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, []);

  const flows = flowsTotal(sources);

  return (
    <div className="card sh-card" data-section="collection">
      <div className="pw-head">
        <span className="pw-head-icon"><Icon name="plug" size={18} /></span>
        <div>
          <h2>Collection<AskIris topic="pipeline.reachable-zero" label="Reachable versus monitored" /></h2>
        </div>
      </div>

      {err ? (
        <p className="sh-note err"><Icon name="alerts" size={14} /> {err}</p>
      ) : !loaded ? (
        <StatStrip>
          {[0, 1, 2, 3].map((i) => (
            <div className="ds-stat" key={i}>
              <Skeleton w={56} h={22} />
              <Skeleton w={68} h={9} style={{ marginTop: 6 }} />
            </div>
          ))}
        </StatStrip>
      ) : (
        <>
          <StatStrip>
            <Stat label="Monitored devices" value={fmtCount(monitored)} />
            <Stat
              label="Reachable (SNMP)"
              value={fmtCount(snmpReachable)}
              tone={snmpReachable == null ? "" : snmpReachable > 0 ? "good" : "bad"}
            />
            <Stat label="Flows (1h)" value={fmtCount(flows)} tone={flows > 0 ? "good" : "warn"} />
            <Stat label="Traps (1h)" value={fmtCount(traps)} />
          </StatStrip>

          <div className="sh-grid">
            <section className="sh-cat">
              <header className="sh-cat-head">
                <span>Collectors</span>
                <span className="sh-cat-count">{collectors.length}</span>
              </header>
              <ul className="sh-list">
                {collectors.length === 0 ? (
                  <li className="sh-row sh-empty">No collector reported.</li>
                ) : (
                  collectors.map((c) => (
                    <li className="sh-row" key={c.collector}>
                      <Dot status={c.status} />
                      <span className="sh-main">
                        <span className="sh-name">{c.collector}</span>
                        <span className="sh-detail">
                          {fmtCount(c.reachable)} / {fmtCount(c.configured)} reachable
                        </span>
                      </span>
                      <span className="sh-lat mono">{fmtMs(c.pollMs)}</span>
                    </li>
                  ))
                )}
              </ul>
            </section>

            <section className="sh-cat">
              <header className="sh-cat-head">
                <span>Flow sources<AskIris topic="pipeline.flow-aggregation" label="Exported versus indexed flows" /></span>
                <span className="sh-cat-count">{sources.length}</span>
              </header>
              <ul className="sh-list">
                {sources.length === 0 ? (
                  <li className="sh-row sh-empty">No flows in the last hour.</li>
                ) : (
                  sources.map((f) => (
                    <li className="sh-row" key={f.flowType}>
                      <Dot status={f.flows > 0 ? "up" : "down"} />
                      <span className="sh-main">
                        <span className="sh-name">{f.flowType}</span>
                        <span className="sh-detail">{f.exporters} exporters</span>
                      </span>
                      <span className="sh-lat mono">{fmtCount(f.flows)}</span>
                    </li>
                  ))
                )}
              </ul>
            </section>
          </div>
        </>
      )}
    </div>
  );
}

export default function StackHealth() {
  const [data, setData] = useState<StackHealthData | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    const tick = async () => {
      try {
        const d = await api.stackHealth();
        if (alive) {
          setData(d);
          setErr(null);
        }
      } catch (e) {
        if (alive) setErr(operatorError(e, "Platform health could not be read."));
      }
    };
    tick();
    const id = setInterval(tick, 15000);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, []);

  if (err) {
    const forbidden = err.includes("403") || err.toLowerCase().includes("forbidden");
    return (
      <div className="page-stack">
        <div className="card sh-card">
          <Header />
          <p className={`sh-note${forbidden ? "" : " err"}`}>
            <Icon name={forbidden ? "lock" : "alerts"} size={14} />{" "}
            {forbidden
              ? "Infrastructure-stack monitoring is available to platform administrators only."
              : `Could not load stack health: ${err}`}
          </p>
        </div>
      </div>
    );
  }

  // Group components by category for a tidy, sectioned board.
  const byCategory = new Map<string, StackComponent[]>();
  for (const c of data?.components ?? []) {
    const arr = byCategory.get(c.category) ?? [];
    arr.push(c);
    byCategory.set(c.category, arr);
  }

  return (
    <div className="page-stack">
      <div className="card sh-card">
        <Header />

        {!data ? (
          <>
            <StatStrip>
              {[0, 1, 2, 3].map((i) => (
                <div className="ds-stat" key={i}>
                  <Skeleton w={56} h={22} />
                  <Skeleton w={68} h={9} style={{ marginTop: 6 }} />
                </div>
              ))}
            </StatStrip>
            <div className="sh-grid">
              {[0, 1, 2].map((i) => (
                <div className="sh-cat" key={i}>
                  <div className="sh-cat-head"><Skeleton w={90} h={11} /></div>
                  <div style={{ padding: "10px 12px", display: "flex", flexDirection: "column", gap: 10 }}>
                    <Skeleton w="80%" /><Skeleton w="65%" /><Skeleton w="72%" />
                  </div>
                </div>
              ))}
            </div>
          </>
        ) : (
          <>
            <StatStrip>
              <Stat label="Stack status" value={data.overall.toUpperCase()} tone={overallTone(data.overall)} />
              <Stat label="Up" value={data.up} tone="good" />
              <Stat label="Degraded" value={data.degraded} tone={data.degraded > 0 ? "warn" : ""} />
              <Stat label="Down" value={data.down} tone={data.down > 0 ? "bad" : ""} />
            </StatStrip>

            <div className="sh-grid">
              {[...byCategory.entries()].map(([cat, comps]) => {
                const up = comps.filter((c) => c.status === "up").length;
                const healthy = up === comps.length;
                return (
                  <section className="sh-cat" key={cat}>
                    <header className="sh-cat-head">
                      <span>{CATEGORY_LABELS[cat] ?? cat}</span>
                      <span className={`sh-cat-count${healthy ? " ok" : " warn"}`}>{up}/{comps.length} up</span>
                    </header>
                    <ul className="sh-list">
                      {comps.map((c) => (
                        <li className="sh-row" key={c.name}>
                          <Dot status={c.status} />
                          <span className="sh-main">
                            <span className="sh-name">{c.name}</span>
                            {c.detail && <span className="sh-detail">{c.detail}</span>}
                          </span>
                          <span className="sh-lat mono">{c.latency_ms} ms</span>
                        </li>
                      ))}
                    </ul>
                  </section>
                );
              })}
            </div>
          </>
        )}
      </div>

      <CollectionSection />
    </div>
  );
}
