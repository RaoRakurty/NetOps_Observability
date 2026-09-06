import { useEffect, useMemo, useState } from "react";
import { api } from "../services/api";
import { useAppNames } from "../services/appNames";
import { Group, BarPanel, Panel, fmtNum, fmtBytes } from "../components/board/panels";
import AskIris from "../components/AskIris";

// WORD SWEEP (2026-09-06, tracker 270): the scan-signature and high-risk-port
// explanations are ai/skills/explain/threats.*.md behind the `(i)`.
//
// Threat Detection — flow-derived (IPFIX/NetFlow) network threat signals. No new
// collection: every panel is computed from netops.flows. v1 surfaces scan
// behavior (a source touching many distinct hosts or ports) and traffic to
// high-risk service ports. Heuristic, not a verdict — a triage starting point.

// High-risk destination ports (lateral movement / remote access / legacy mgmt).
const RISKY_PORTS: Record<string, string> = {
  "21": "FTP", "23": "Telnet", "135": "MS-RPC", "139": "NetBIOS", "445": "SMB",
  "1433": "MSSQL", "3389": "RDP", "5900": "VNC", "3306": "MySQL", "6379": "Redis",
  "11211": "memcached", "2049": "NFS", "512": "rexec", "513": "rlogin", "514": "rsh",
};

type FanRow = { k: string; dst_count: number; port_count: number; flows: number };
type TopRow = { k: string; bytes_total: number; flows: number };

function useFanout(sort: "hosts" | "ports", since: number) {
  const [rows, setRows] = useState<FanRow[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    let alive = true;
    const run = async () => {
      try { const r = await api.flowsFanout(sort, since, 12); if (alive) { setRows((r?.data as FanRow[]) ?? []); setErr(null); } }
      catch (e) { if (alive) setErr((e as Error).message); }
      finally { if (alive) setLoading(false); }
    };
    run();
    const id = setInterval(run, 30_000);
    return () => { alive = false; clearInterval(id); };
  }, [sort, since]);
  return { rows, err, loading };
}

export default function ThreatDetection({ sinceSeconds }: { sinceSeconds?: number } = {}) {
  const since = sinceSeconds ?? 3600;
  const horiz = useFanout("hosts", since);
  const vert = useFanout("ports", since);
  const [ports, setPorts] = useState<TopRow[]>([]);
  const [portErr, setPortErr] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    const run = async () => {
      try { const r = await api.flowsTopN("dst_port", since, 15); if (alive) { setPorts((r?.data as TopRow[]) ?? []); setPortErr(null); } }
      catch (e) { if (alive) setPortErr((e as Error).message); }
    };
    run();
    const id = setInterval(run, 30_000);
    return () => { alive = false; clearInterval(id); };
  }, [since]);

  const riskyHits = ports.filter((p) => RISKY_PORTS[p.k]);

  // App-name enrichment (#81 P3G): name the scan-suspect source IPs when the
  // unified resolver knows them ("10.0.1.10 · payroll" reads faster than a bare
  // IP); unresolved sources render exactly as before.
  const fanKeys = useMemo(
    () => [...horiz.rows.map((r) => r.k), ...vert.rows.map((r) => r.k)],
    [horiz.rows, vert.rows],
  );
  const apps = useAppNames(fanKeys);
  const withApp = (k: string) => (apps[k] ? `${k} · ${apps[k].app}` : k);

  return (
    <div className="dm-board">
      <Group title="Scan detection" hue="#EF4444">
        <div className="dm-grid">
          <BarPanel
            title="Horizontal scan suspects"
            rows={horiz.rows.map((r) => ({ label: withApp(r.k), value: Number(r.dst_count), danger: Number(r.dst_count) >= 25 }))}
            fmtX={(n) => `${n.toFixed(0)} hosts`}
            loading={horiz.loading}
            err={horiz.err}
          />
          <BarPanel
            title="Vertical scan suspects"
            rows={vert.rows.map((r) => ({ label: withApp(r.k), value: Number(r.port_count), danger: Number(r.port_count) >= 25 }))}
            fmtX={(n) => `${n.toFixed(0)} ports`}
            loading={vert.loading}
            err={vert.err}
          />
        </div>
        <p className="mini-meta" style={{ margin: 0 }}>
          Red past 25 targets, from flow records.
          <AskIris topic="threats.scan-signature" label="a scan signature" />
        </p>
      </Group>

      <Group title="High-risk service exposure" hue="#F59E0B">
        <BarPanel
          title="High-risk ports, bytes"
          rows={riskyHits.map((p) => ({ label: `${p.k} (${RISKY_PORTS[p.k]})`, value: Number(p.bytes_total), danger: true }))}
          fmtX={fmtBytes}
          err={portErr}
        />
        {riskyHits.length === 0 && !portErr && (
          <p className="sec-line" style={{ margin: 0 }}>
            No high-risk port traffic in this window.
            <AskIris topic="threats.risky-ports" label="high-risk ports" />
          </p>
        )}
        <Panel title="Top destination ports">
          {portErr ? (
            <div className="empty" style={{ color: "var(--bad)" }}>{portErr}</div>
          ) : ports.length === 0 ? (
            <div className="empty">No flow data in this window.</div>
          ) : (
            <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
              {ports.map((p) => (
                <span key={p.k} className={`badge ${RISKY_PORTS[p.k] ? "bad" : "accent-badge"}`} title={`${fmtNum(p.flows)} flows`}>
                  {p.k}{RISKY_PORTS[p.k] ? ` (${RISKY_PORTS[p.k]})` : ""}
                </span>
              ))}
            </div>
          )}
        </Panel>
      </Group>
    </div>
  );
}
