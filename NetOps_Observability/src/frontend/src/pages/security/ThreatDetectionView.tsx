import { useEffect, useMemo, useState } from "react";
import "./Security.css";
import { api, SecFinding } from "../../services/api";
import ThreatDetection from "../ThreatDetection";
import { useWorkspace } from "../../context/workspace";
import DataTable, { Column } from "../../components/DataTable";
import { Group, Panel } from "../../components/board/panels";
import { Segmented } from "../../components/ui";
import { fmtDateTime } from "../../lib/time";
import { FindingDetail, SeverityBadge } from "./parts";
import { THREAT_EVIDENCE_CLASS, severityRank, subjectLine } from "./model";
import { operatorError } from "../../lib/errors";
// Threat Detection — two sub-views over the same question ("is something acting
// on this estate?"), kept side by side because they answer it from different
// evidence:
//
//  · Detections    — device-log / rule-engine verdicts from the findings store
//                    (evidence_class = threat), each one a normalized finding
//                    with the same detail as any other exposure.
//  · Network Behavior — the existing flow-derived panels (scan fan-out, high-risk
//                    service exposure), reused verbatim as a sub-view rather
//                    than duplicated.
//
// Neither is a verdict on its own: both are triage starting points that ground
// into the correlation engine as Exposure Stories. Tenant isolation (§3a) is
// server-side on both surfaces.

type SubView = "detections" | "behavior";

export default function ThreatDetectionView({ sinceSeconds }: { sinceSeconds?: number } = {}) {
  const ws = useWorkspace();
  const [tab, setTab] = useState<SubView>("detections");
  const [rows, setRows] = useState<SecFinding[]>([]);
  const [total, setTotal] = useState(0);
  const [err, setErr] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [selected, setSelected] = useState<SecFinding | null>(null);

  useEffect(() => {
    let alive = true;
    api.securityFindings({ current: true, limit: 200, framework: undefined })
      .then((p) => {
        if (!alive) return;
        // The lane filter is applied on the SERVER-supplied evidence_class; the
        // dedicated query param is not part of the T8 contract, so the page
        // narrows the current set it is already entitled to rather than
        // inventing an endpoint.
        const lane = (p.items ?? []).filter(
          (f) => (f.evidence_class ?? "").toLowerCase() === THREAT_EVIDENCE_CLASS
            || (f.evidence_class ?? "").toLowerCase() === "signal",
        );
        setRows(lane);
        setTotal(lane.length);
        setErr(null);
      })
      .catch((e: unknown) => { if (alive) setErr(operatorError(e, "Threat detections could not be loaded.")); })
      .finally(() => { if (alive) setLoaded(true); });
    return () => { alive = false; };
  }, []);

  const open = (f: SecFinding) => {
    setSelected(f);
    if (ws.enabled) {
      ws.openInspector(<FindingDetail finding={f} />, {
        title: f.control_title || f.raw_rule_id || "Detection",
        subtitle: `${subjectLine(f)}${f.time ? ` · ${fmtDateTime(f.time)}` : ""}`,
      });
    }
  };

  const columns = useMemo<Column<SecFinding>[]>(() => [
    {
      key: "severity", header: "Severity", width: 100, sortable: true,
      text: (f) => f.severity ?? "", sortValue: (f) => severityRank(f.severity),
      render: (f) => <SeverityBadge severity={f.severity} />,
    },
    {
      key: "detection", header: "Detection", sortable: true,
      text: (f) => `${f.control_title ?? ""} ${f.raw_rule_id ?? ""}`,
      render: (f) => f.control_title || f.raw_rule_id || "—",
    },
    {
      key: "asset", header: "Asset", width: 210, sortable: true,
      text: (f) => subjectLine(f), render: (f) => subjectLine(f),
    },
    {
      key: "technique", header: "Technique", width: 160, sortable: true,
      text: (f) => (f.standards ?? []).join(" "),
      render: (f) => ((f.standards ?? []).length > 0
        ? <span className="sec-chips">{f.standards!.map((s) => <span key={s} className="sec-chip">{s}</span>)}</span>
        : <span className="sec-unassessed">untagged</span>),
    },
    {
      key: "time", header: "Detected", width: 170, sortable: true,
      text: (f) => f.time ?? "", render: (f) => (f.time ? fmtDateTime(f.time) : "—"),
    },
  ], []);

  return (
    <div className="sec dm-board">
      <div className="sec-toolbar">
        <Segmented
          value={tab}
          onChange={setTab}
          options={[
            { value: "detections" as SubView, label: "Detections" },
            { value: "behavior" as SubView, label: "Network Behavior" },
          ]}
          ariaLabel="Threat detection view"
        />
        <span className="mini-meta" role="status" aria-live="polite">
          {tab === "detections"
            ? (loaded ? `${total.toLocaleString()} current device-log detection${total === 1 ? "" : "s"}` : "Loading…")
            : "Flow-derived behavior, computed from records already collected — no new collection."}
        </span>
      </div>

      {tab === "behavior" ? (
        <ThreatDetection sinceSeconds={sinceSeconds} />
      ) : (
        <Group title="Device-log detections" hue="#e11d48">
          {err ? (
            <div className="empty" role="alert" style={{ color: "var(--bad)" }}>{err}</div>
          ) : !loaded ? (
            <div className="empty" role="status">Loading…</div>
          ) : rows.length === 0 ? (
            <div className="empty">
              No device-log detection has fired for this tenant. That means no rule matched what was
              ingested — it does not mean the estate is clean. Check Network Behavior for flow-derived
              activity, and the Rules page for which detections are enabled.
            </div>
          ) : (
            <DataTable
              rows={rows}
              columns={columns}
              rowKey={(f) => f.id}
              height={480}
              onRowClick={open}
              rowSelected={(f) => f.id === selected?.id}
              rowAccent={(f) => {
                const s = (f.severity ?? "").toLowerCase();
                return s === "critical" || s === "high" ? "var(--bad)" : s === "medium" ? "var(--warn)" : undefined;
              }}
              ariaLabel="Device-log detections"
            />
          )}
          <p className="mini-meta" style={{ margin: 0 }}>
            A detection is evidence, not a verdict. Detections ground into the correlation engine and
            surface as Exposure Stories when they land on the same entity and seam as other telemetry.
          </p>
        </Group>
      )}

      {!ws.enabled && selected && tab === "detections" && (
        <Panel title="Detection detail"><FindingDetail finding={selected} /></Panel>
      )}
    </div>
  );
}
