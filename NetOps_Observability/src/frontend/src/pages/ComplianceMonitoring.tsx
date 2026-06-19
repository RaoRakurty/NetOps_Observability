import { useEffect, useMemo, useState } from "react";
import { api, ComplianceResponse, ComplianceFinding, ComplianceCheck, ComplianceGap } from "../services/api";
import { StatStrip, Stat, InfoTip } from "../components/ui";
import DataTable, { Column } from "../components/DataTable";
import { Group, Panel } from "../components/board/panels";

// Compliance Monitoring (build-order #14) — drift between the active Source of
// Truth (the internal inventory by default, or an external CMDB when connected)
// and the observed inventory, plus management-plane policy baselines (SNMP
// version/strength, fleet golden OS version, known-exploited CVE exposure). All
// agentless: computed from data the platform already holds. Checks whose data
// source isn't connected render as INACTIVE with the reason — an unrun check is
// "cannot assess", never "compliant".

const sevTone = (s: string): "" | "good" | "warn" | "bad" => {
  if (s === "high") return "bad";
  if (s === "medium") return "warn";
  return "";
};

export default function ComplianceMonitoring() {
  const [resp, setResp] = useState<ComplianceResponse | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [q, setQ] = useState("");

  useEffect(() => {
    let alive = true;
    const load = async () => {
      try {
        const r = await api.compliance();
        if (alive) { setResp(r); setErr(null); }
      } catch (e) {
        if (alive) setErr((e as Error).message);
      }
    };
    load();
    const id = setInterval(load, 60_000);
    return () => { alive = false; clearInterval(id); };
  }, []);

  const findings = resp?.findings ?? [];
  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    if (!needle) return findings;
    return findings.filter((f) =>
      f.device_name.toLowerCase().includes(needle) ||
      f.title.toLowerCase().includes(needle) ||
      f.framework.toLowerCase().includes(needle) ||
      (f.observed ?? "").toLowerCase().includes(needle) ||
      (f.intended ?? "").toLowerCase().includes(needle),
    );
  }, [findings, q]);

  const cols = useMemo<Column<ComplianceFinding>[]>(() => [
    {
      key: "severity", header: "Severity", width: "88px", sortable: true,
      text: (f) => f.severity, sortValue: (f) => ({ high: 3, medium: 2, low: 1 }[f.severity] ?? 0),
      render: (f) => <span className={`badge ${sevTone(f.severity)}`}>{f.severity}</span>,
    },
    {
      key: "class", header: "Class", width: "72px", sortable: true, text: (f) => f.class,
      render: (f) => <span className="badge">{f.class}</span>,
    },
    {
      key: "title", header: "Check", width: "230px", sortable: true, text: (f) => f.title,
      render: (f) => (f.detail ? <span title={f.detail}>{f.title}</span> : f.title),
    },
    { key: "device", header: "Device", width: "150px", sortable: true, text: (f) => f.device_name, render: (f) => f.device_name },
    {
      key: "observed", header: "Observed", width: "200px", sortable: false,
      render: (f) => <span style={{ fontFamily: "var(--font-mono, monospace)", fontSize: 12 }} title={f.observed}>{f.observed || "—"}</span>,
    },
    {
      key: "intended", header: "Intended", width: "200px", sortable: false,
      render: (f) => <span style={{ fontFamily: "var(--font-mono, monospace)", fontSize: 12 }} title={f.intended}>{f.intended || "—"}</span>,
    },
    { key: "framework", header: "Framework", sortable: true, text: (f) => f.framework, render: (f) => <span className="mini-meta">{f.framework}</span> },
  ], []);

  const checkCols = useMemo<Column<ComplianceCheck>[]>(() => [
    {
      key: "status", header: "Status", width: "92px", sortable: true, sortValue: (c) => (c.active ? (c.findings > 0 ? 1 : 2) : 0),
      render: (c) =>
        !c.active ? <span className="badge" title={c.reason}>inactive</span>
        : c.findings > 0 ? <span className="badge warn">{c.findings} finding{c.findings === 1 ? "" : "s"}</span>
        : <span className="badge good">pass</span>,
    },
    { key: "title", header: "Check", width: "270px", sortable: true, text: (c) => c.title, render: (c) => c.title },
    { key: "class", header: "Class", width: "72px", sortable: true, text: (c) => c.class, render: (c) => <span className="badge">{c.class}</span> },
    { key: "framework", header: "Framework", width: "190px", sortable: true, text: (c) => c.framework, render: (c) => <span className="mini-meta">{c.framework}</span> },
    {
      key: "reason", header: "Why inactive", sortable: false,
      render: (c) => (c.active ? "" : <span className="mini-meta">{c.reason}</span>),
    },
  ], []);

  const gapCols = useMemo<Column<ComplianceGap>[]>(() => [
    { key: "device", header: "Device", width: "180px", sortable: true, text: (g) => g.device_name, render: (g) => g.device_name },
    { key: "reason", header: "Checks that had to be skipped", sortable: false, render: (g) => g.reason },
  ], []);

  if (err) {
    return <div className="dm-board"><Panel title="Compliance Monitoring"><div className="empty" style={{ color: "var(--bad)" }}>{err}</div></Panel></div>;
  }
  if (!resp) {
    return <div className="dm-board"><Panel title="Compliance Monitoring"><div className="empty">Loading…</div></Panel></div>;
  }

  // Onboarding: nothing in the inventory yet — there is no posture to assess.
  if (!resp.compliance_enabled) {
    return (
      <div className="dm-board">
        <Group title="Compliance Monitoring" hue="#8B5CF6">
          <Panel title="Add devices to assess">
            <div className="empty board-empty" style={{ alignItems: "flex-start", textAlign: "left" }}>
              <div className="board-empty-msg">No devices in the inventory yet.</div>
              <div className="board-empty-hint">
                Compliance compares what's running against what's intended. Onboard devices first —
                add them under Infrastructure → Devices, point a static inventory file at the stack,
                or connect the Source of Truth under Automation → Source of Truth. Drift checks light
                up once the Source of Truth is connected; policy baselines (SNMP security, golden OS
                version) run on the inventory alone.
              </div>
            </div>
          </Panel>
        </Group>
      </div>
    );
  }

  const s = resp.summary!;
  return (
    <div className="dm-board">
      <Group title="Posture" hue="#8B5CF6">
        <StatStrip>
          <Stat label="Devices" value={s.devices} />
          <Stat label="Compliant" value={s.compliant} tone={s.compliant === s.devices ? "good" : ""} />
          <Stat label="With findings" value={s.affected} tone={s.affected > 0 ? "bad" : "good"} />
          <Stat label="Findings" value={s.findings} tone={s.findings > 0 ? "warn" : "good"} />
          <Stat label="Drift" value={s.drift} tone={s.drift > 0 ? "warn" : "good"} />
          <Stat label="Policy" value={s.policy} tone={s.policy > 0 ? "warn" : "good"} />
          <Stat label="High severity" value={s.high} tone={s.high > 0 ? "bad" : "good"} />
          <Stat label="Checks active" value={`${s.checks_active}/${s.checks_total}`} tone={s.checks_active < s.checks_total ? "warn" : "good"} />
        </StatStrip>
        {!resp.sot?.configured && (
          <p className="mini-meta" style={{ margin: 0 }}>
            No external declared inventory to compare against — intent-drift checks are inactive
            {resp.sot?.provider === "internal" ? " (the internal inventory is itself the Source of Truth)" : ""}.{" "}
            <InfoTip label="?">Connect an external Source of Truth under Automation → Source of Truth, in
            read or two-way mode, to compare the observed inventory against declared intent (registration,
            name, management IP, serial, platform). Policy checks below run regardless.</InfoTip>
          </p>
        )}
        <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
          <input
            placeholder="Filter by device, check, framework…" value={q} onChange={(e) => setQ(e.target.value)}
            style={{ padding: "6px 9px", fontSize: 12.5, border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", background: "var(--surface)", color: "var(--fg)", width: 240 }}
          />
        </div>
        {findings.length === 0 ? (
          <Panel title="Findings">
            <div className="empty">
              No drift or policy violations across {s.devices} device{s.devices === 1 ? "" : "s"} on the
              active checks ({s.checks_active} of {s.checks_total} running).
            </div>
          </Panel>
        ) : (
          <DataTable
            rows={filtered}
            columns={cols}
            rowKey={(f) => `${f.device_id}/${f.check}/${f.observed ?? ""}`}
            rowAccent={(f) => (f.severity === "high" ? "var(--bad)" : f.severity === "medium" ? "var(--warn)" : undefined)}
            height={420}
            ariaLabel="Compliance findings"
          />
        )}
      </Group>

      <Group title="Checks" hue="#3B82F6">
        <Panel title={`What is being checked (${s.checks_active} of ${s.checks_total} active)`}>
          <DataTable rows={resp.checks ?? []} columns={checkCols} rowKey={(c) => c.id} height={300} ariaLabel="Compliance checks" />
        </Panel>
        <p className="mini-meta" style={{ margin: 0 }}>
          An inactive check means its data source isn't connected — that's "cannot assess", not "compliant".
          Drift checks need the Source of Truth; SNMP checks need credential profiles assigned to devices;
          the known-exploited check needs the vulnerability feed.
        </p>
      </Group>

      {(resp.gaps?.length ?? 0) > 0 && (
        <Group title="Coverage gaps" hue="#F59E0B">
          <Panel title={`Devices with skipped checks (${resp.gaps!.length})`}>
            <DataTable rows={resp.gaps!} columns={gapCols} rowKey={(g) => g.device_id} height={220} ariaLabel="Compliance coverage gaps" />
          </Panel>
        </Group>
      )}
    </div>
  );
}
