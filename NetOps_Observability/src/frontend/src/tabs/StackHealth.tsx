import { useEffect, useState } from "react";
import { api, StackHealth as StackHealthData, StackComponent } from "../services/api";
import Icon from "../components/Icon";
import { StatStrip, Stat, Skeleton } from "../components/ui";

// Stack Health — the platform's OWN infrastructure monitoring: the data
// backends, event bus, state stores and visualization that make up the stack
// behind the app. Platform-owner only (the API returns 403 otherwise); the nav
// already hides this from tenant-scoped users, this guard is the backstop.
//
// Presentation mirrors the modern self-service cards (ChangePasswordCard): an
// icon-chip header + subtitle, a data-dense StatStrip, skeleton loading, and a
// scannable per-category status board instead of a flat table.

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
        if (alive) setErr(e instanceof Error ? e.message : "failed to load stack health");
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
    </div>
  );
}
