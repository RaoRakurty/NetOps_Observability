import { useEffect, useState } from "react";
import { fmtTime } from "../lib/time";
import { useBoardHealth } from "./panels";
import {
  ArcGauge, Ridgeline, ActivityHeatmap, DistributionHistogram,
  RacingBars, StreamGraph, EventTicker, BigStat,
} from "./demoPanels";
import { api } from "../services/api";

// DemoShowcase — the marketing board.
//
// Design brief (owner, 2026-07-31): dense, dark, kinetic, "something is
// happening", no dead white space, 2026 chart vocabulary — patterned radial
// gauges instead of flat wheels, real histogram FAMILIES (distribution,
// ridgeline, heatmap, racing bars, stream) instead of one bar style.
//
// The one rule that survives the styling: every panel is LIVE. Liveness derives
// from real fetch outcomes (useBoardHealth), never a wall clock — a demo that
// fakes "Live" during an outage is the worst possible sales moment.

// PromQL — the same expressions the operational boards use, so the demo is a
// re-styling of real telemetry, not a parallel truth.
const Q = {
  cpu: "avg(device_cpu_percent)",
  mem: "avg(device_mem_percent or (100 * device_mem_used_bytes / (device_mem_used_bytes + device_mem_free_bytes)))",
  band: "100 * sum(rate(device_if_in_octets[5m]) * 8) / (sum(device_if_speed * 1000000) > 0)",
  reach: "100 * sum(collector_targets_reachable) / (sum(collector_targets) > 0)",
  ifUp: "100 * count(device_if_oper_status == 1) / (count(device_if_admin_status == 1) > 0)",
  cpuByDevice: "max by (device) (device_cpu_percent)",
  ifUtil: "100 * (rate(device_if_in_octets[5m]) * 8) / (device_if_speed * 1000000 > 0)",
  ifUtilTop: "topk(9, 100 * (rate(device_if_in_octets[5m]) * 8) / (device_if_speed * 1000000 > 0))",
  errTop: "topk(8, sum by (device, ifName) (rate(device_if_in_errors[5m]) + rate(device_if_out_errors[5m])))",
  thruIn: "sum(rate(device_if_in_octets[5m]))*8",
  thruOut: "sum(rate(device_if_out_octets[5m]))*8",
  rtt: "avg(probe_rtt_ms)",
  loss: "avg(probe_loss_pct)",
};

const bps = (v: number) =>
  v > 1e9 ? `${(v / 1e9).toFixed(1)}G` : v > 1e6 ? `${(v / 1e6).toFixed(0)}M` : `${Math.round(v / 1e3)}K`;

/** Live counts for the hero strip — devices, sites, open alerts. */
function useFleet() {
  const [f, setF] = useState<{ devices: number; alerts: number; crit: number } | null>(null);
  useEffect(() => {
    let alive = true;
    const load = async () => {
      try {
        const [devs, alerts] = await Promise.all([api.devices(), api.alerts()]);
        if (!alive) return;
        const list = alerts ?? [];
        setF({
          devices: (devs ?? []).length,
          alerts: list.length,
          crit: list.filter((a) => /crit|major/i.test(a.severity ?? "")).length,
        });
      } catch { /* hero counters degrade to — rather than blocking the board */ }
    };
    void load();
    const iv = setInterval(load, 20000);
    return () => { alive = false; clearInterval(iv); };
  }, []);
  return f;
}

export default function DemoShowcase() {
  const { lastOk, failing, feeds } = useBoardHealth();
  const fleet = useFleet();
  const degraded = failing > 0;
  const connecting = lastOk === null && !degraded;

  return (
    <div className="demo2">
      {/* ── hero: title + live fleet counters ─────────────────────────────── */}
      <header className="demo2-hero">
        <div className="demo2-hero-grid" aria-hidden />
        <div className="demo2-hero-main">
          <div className="demo2-eyebrow">
            <span className="demo2-pulse" /> Correlix · live network intelligence
          </div>
          <h1 className="demo2-title">
            Every packet, path and platform<span className="demo2-title-accent">.</span>
          </h1>
          <p className="demo2-sub">
            SNMP telemetry · NetFlow · synthetic probes · correlated root cause — one screen, streaming from the running stack.
          </p>
        </div>
        <div className="demo2-hero-stats">
          <div className="demo2-hero-stat">
            <span className="demo2-hero-num">{fleet ? fleet.devices : "—"}</span>
            <span className="demo2-hero-cap">devices</span>
          </div>
          <div className="demo2-hero-stat">
            <span className="demo2-hero-num" style={{ color: fleet && fleet.crit > 0 ? "#f43f5e" : undefined }}>
              {fleet ? fleet.crit : "—"}
            </span>
            <span className="demo2-hero-cap">critical</span>
          </div>
          <div className="demo2-hero-stat">
            <span className="demo2-hero-num">{fleet ? fleet.alerts : "—"}</span>
            <span className="demo2-hero-cap">active alerts</span>
          </div>
          <div className="demo2-live" role="status" aria-live="polite">
            {degraded ? (
              <><span className="demo2-live-dot bad" /> {failing}/{feeds} feeds down</>
            ) : connecting ? (
              <><span className="demo2-live-dot idle" /> connecting</>
            ) : (
              <><span className="demo2-live-dot" /> live · {fmtTime(new Date(lastOk!))}</>
            )}
          </div>
        </div>
      </header>

      {/* ── row 1: five patterned gauges + two big stats ──────────────────── */}
      <section className="demo2-row demo2-row-gauges">
        <ArcGauge query={Q.cpu} label="CPU" hue={0} />
        <ArcGauge query={Q.mem} label="Memory" hue={2} />
        <ArcGauge query={Q.band} label="Bandwidth" hue={3} />
        <ArcGauge query={Q.reach} label="Reachability" hue={1} />
        <ArcGauge query={Q.ifUp} label="Interfaces up" hue={4} />
        <div className="demo2-stat-stack">
          <BigStat query={Q.thruIn} label="Ingress" unit="bps" fmt={bps} hue={0} />
          <BigStat query={Q.rtt} label="Path RTT" unit="ms" fmt={(v) => v.toFixed(1)} hue={1} invert />
        </div>
      </section>

      {/* ── row 2: heatmap + ridgeline ────────────────────────────────────── */}
      <section className="demo2-row demo2-row-2">
        <div className="demo2-card demo2-span-7">
          <div className="demo2-card-h">
            <h3>Fleet activity</h3>
            <span>CPU per device × time · last hour</span>
          </div>
          <ActivityHeatmap query={Q.cpuByDevice} />
        </div>
        <div className="demo2-card demo2-span-5">
          <div className="demo2-card-h">
            <h3>Utilization terrain</h3>
            <span>per-device distribution, stacked</span>
          </div>
          <Ridgeline query={Q.cpuByDevice} />
        </div>
      </section>

      {/* ── row 3: racing bars + histogram + errors ───────────────────────── */}
      <section className="demo2-row demo2-row-3">
        <div className="demo2-card demo2-span-4">
          <div className="demo2-card-h">
            <h3>Interface utilization</h3>
            <span>top 9, live rank</span>
          </div>
          <RacingBars query={Q.ifUtilTop} n={9} />
        </div>
        <div className="demo2-card demo2-span-4">
          <div className="demo2-card-h">
            <h3>Saturation histogram</h3>
            <span>interfaces by % band</span>
          </div>
          <DistributionHistogram query={Q.ifUtil} />
        </div>
        <div className="demo2-card demo2-span-4">
          <div className="demo2-card-h">
            <h3>Error hot spots</h3>
            <span>errors + discards / sec</span>
          </div>
          <RacingBars query={Q.errTop} n={8} unit="/s" fmt={(v) => `${v.toFixed(2)}/s`} />
        </div>
      </section>

      {/* ── row 4: flow stream + live ticker ──────────────────────────────── */}
      <section className="demo2-row demo2-row-4">
        <div className="demo2-card demo2-span-8">
          <div className="demo2-card-h">
            <h3>NetFlow · traffic by protocol</h3>
            <span>stacked stream, last hour</span>
          </div>
          <StreamGraph />
        </div>
        <div className="demo2-card demo2-span-4 demo2-card-tick">
          <div className="demo2-card-h">
            <h3>Event stream</h3>
            <span className="demo2-livetag">live</span>
          </div>
          <EventTicker />
        </div>
      </section>
    </div>
  );
}
