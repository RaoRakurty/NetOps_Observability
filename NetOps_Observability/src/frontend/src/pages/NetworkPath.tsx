import { useEffect, useState } from "react";
import { api, ProbePath } from "../services/api";
import DataTable, { Column } from "../components/DataTable";
import { Group, Panel, MetricTop } from "../components/board/panels";
import PathHealthList from "../components/PathHealthList";
import AskIris from "../components/AskIris";

// NetworkPath (Flow Trace) — visualizes the active-measurement pipeline: the
// hop-by-hop path from traceroute (/api/probe/paths) and the path SLA from STAMP
// (probe_* metrics in VictoriaMetrics). Hop-by-hop path measurement. Both
// sources are opt-in (FEATURE_TRACEROUTE / FEATURE_ACTIVE_PROBE) — when nothing
// is configured the board explains how to turn them on rather than going blank.

type Hop = ProbePath["hops"][number];

function HopTable({ hops }: { hops: Hop[] }) {
  const cols: Column<Hop>[] = [
    { key: "ttl", header: "Hop", width: "56px", sortable: true, sortValue: (h) => h.ttl, render: (h) => `${h.ttl}` },
    { key: "ip", header: "Router", sortable: true, text: (h) => h.ip || "*", render: (h) => <span style={{ fontFamily: "var(--font-mono, monospace)", fontSize: 12.5 }}>{h.ip || "* (no reply)"}</span> },
    // rtt_ms / loss_pct can be absent on a hop (no reply, or a prober that doesn't
    // measure per-hop loss) — guard against undefined.toFixed(), which throws and
    // white-screens the whole Flow Trace page.
    { key: "rtt", header: "RTT", align: "right", sortable: true, sortValue: (h) => h.rtt_ms ?? -1, render: (h) => (h.ip && h.rtt_ms != null ? `${h.rtt_ms.toFixed(1)} ms` : "—") },
    { key: "loss", header: "Loss", align: "right", sortable: true, sortValue: (h) => h.loss_pct ?? -1, render: (h) => (h.ip && h.loss_pct != null ? `${h.loss_pct.toFixed(0)}%` : "—") },
  ];
  return <DataTable<Hop> rows={hops} columns={cols} rowKey={(h) => `${h.ttl}-${h.ip}`} height={Math.min(420, 44 + hops.length * 28)} ariaLabel="Path hops" initialSort={{ key: "ttl", dir: "asc" }} />;
}

export default function NetworkPath({ rangeMinutes = 60 }: { rangeMinutes?: number } = {}) {
  const m = rangeMinutes;
  const [paths, setPaths] = useState<ProbePath[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    let alive = true;
    const load = async () => {
      try { const p = await api.probePaths(); if (alive) { setPaths(p ?? []); setErr(null); } }
      catch (e) { if (alive) setErr((e as Error).message); }
      finally { if (alive) setLoaded(true); }
    };
    load();
    const id = setInterval(load, 30_000);
    return () => { alive = false; clearInterval(id); };
  }, []);

  return (
    <div className="dm-board">
      <Group title="Path behaviour" hue="#14B8A6">
        <p className="proto-key">
          Each path against its own baseline. Worst first.
          <AskIris topic="path.behaviour" label="Path behaviour" />
        </p>
        <PathHealthList />
      </Group>

      <Group title="Network paths" hue="#F97316">
        {err ? (
          <div className="empty" style={{ color: "var(--bad)" }}>{err}</div>
        ) : paths.length === 0 ? (
          <Panel title="No paths yet">
            <div className="board-empty">
              <div className="board-empty-msg">No active path measurements.</div>
              <div className="board-empty-hint">
                Enable path discovery in the API settings, then name the targets.
              </div>
            </div>
            {loaded && <p className="proto-key">Probes stay on one path.<AskIris topic="path.traceroute" label="Traceroute" /></p>}
          </Panel>
        ) : (
          paths.map((p) => (
            <Panel key={p.dst} title={`${p.dst} — ${p.hops.length} hops`} action={
              <span style={{ display: "flex", gap: 6 }}>
                <span className={`badge ${p.reached ? "good" : "warn"}`}>{p.reached ? "reached" : "incomplete"}</span>
                {p.changed && <span className="badge bad">path changed</span>}
              </span>
            }>
              <HopTable hops={p.hops} />
            </Panel>
          ))
        )}
      </Group>

      <Group title="Path SLA" hue="#14B8A6">
        <div className="dm-grid">
          <MetricTop title="Round-trip delay by target (ms)" query="(probe_rtt_ms or synthetic_icmp_rtt_ms)" minutes={m} fmtX={(n) => `${n.toFixed(1)} ms`} labelKeys={["dst"]} dataKind="generic" />
          <MetricTop title="One-way delay by target (ms)" query="probe_owd_ms" minutes={m} fmtX={(n) => `${n.toFixed(1)} ms`} labelKeys={["dst"]} dataKind="generic" />
          <MetricTop title="Jitter / PDV by target (ms)" query="probe_pdv_ms" minutes={m} fmtX={(n) => `${n.toFixed(1)} ms`} labelKeys={["dst"]} dataKind="generic" />
          <MetricTop title="Packet loss by target (%)" query="(probe_loss_pct or synthetic_icmp_loss_pct)" minutes={m} fmtX={(n) => `${n.toFixed(1)}%`} labelKeys={["dst"]} dataKind="generic" />
        </div>
        <p className="proto-key">
          Measured by STAMP probes, each direction on its own.
          <AskIris topic="path.stamp" label="Path SLA" />
        </p>
      </Group>

      <Group title="Service checks" hue="#8B5CF6">
        <div className="dm-grid">
          <MetricTop title="HTTP total time by target (ms)" query="synthetic_http_total_ms" minutes={m} fmtX={(n) => `${n.toFixed(0)} ms`} labelKeys={["dst"]} dataKind="synthetics" />
          <MetricTop title="HTTP time to first byte (ms)" query="synthetic_http_ttfb_ms" minutes={m} fmtX={(n) => `${n.toFixed(0)} ms`} labelKeys={["dst"]} dataKind="synthetics" />
          <MetricTop title="ICMP round-trip by target (ms)" query="synthetic_icmp_rtt_ms" minutes={m} fmtX={(n) => `${n.toFixed(1)} ms`} labelKeys={["dst"]} dataKind="synthetics" />
          <MetricTop title="TCP connect by target (ms)" query="synthetic_tcp_connect_ms" minutes={m} fmtX={(n) => `${n.toFixed(1)} ms`} labelKeys={["dst"]} dataKind="synthetics" />
          <MetricTop title="TLS certificate days to expiry" query="synthetic_http_cert_expiry_days" minutes={m} fmtX={(n) => `${n.toFixed(0)} d`} labelKeys={["dst"]} dataKind="synthetics" />
          <MetricTop title="Checks down now" query="1 - synthetic_up" minutes={m} fmtX={(n) => (n >= 1 ? "down" : "up")} labelKeys={["dst", "check"]} dataKind="synthetics" />
        </div>
        <p className="proto-key">
          These measure a service, not a path.
          <AskIris topic="path.synthetics" label="Service checks" />
        </p>
      </Group>
    </div>
  );
}
