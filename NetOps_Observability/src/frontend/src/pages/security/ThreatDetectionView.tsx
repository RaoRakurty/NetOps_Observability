// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

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
import { THREAT_EVIDENCE_ALIASES, severityRank, subjectLine } from "./model";
import { operatorError } from "../../lib/errors";
import AskIris from "../../components/AskIris";
// WORD SWEEP (2026-09-06, tracker 270): what the two sub-views look at, and why
// a detection is not a verdict, are ai/skills/explain/threats.*.md.
//
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

// DETECTION_PAGE is how many detections the table holds. When the lane has more
// than this the header SAYS so, rather than letting a full page read as the
// whole list.
const DETECTION_PAGE = 200;

export default function ThreatDetectionView({ sinceSeconds }: { sinceSeconds?: number } = {}) {
  const ws = useWorkspace();
  const [tab, setTab] = useState<SubView>("detections");
  const [rows, setRows] = useState<SecFinding[]>([]);
  const [total, setTotal] = useState(0);
  const [limit] = useState(DETECTION_PAGE);
  const [err, setErr] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [selected, setSelected] = useState<SecFinding | null>(null);

  useEffect(() => {
    let alive = true;
    // THE LANE IS SELECTED AT THE STORE (review 2026-09-08, 3.3-03). This used
    // to fetch the newest 200 current findings of EVERY lane and keep the threat
    // ones in the browser. A posture scan is a burst — one pass over a few
    // hundred devices writes thousands of verdicts, all newer than a detection
    // that fired an hour ago — so page one held no detection at all, the filter
    // kept nothing, and the screen printed "No detection fired in this window"
    // over a live detection. next_cursor was ignored, so nothing went looking.
    //
    // `evidence_class` asks OpenSearch for the lane in one terms clause. Both
    // spellings are sent because the store emits "signal" and the contract says
    // "threat"; the server folds them onto one lane. The rows that come back are
    // the lane, so nothing is filtered again here — a second filter over a
    // server-narrowed page can only ever hide rows, never find one.
    api.securityFindings({
      current: true,
      limit,
      evidence_class: THREAT_EVIDENCE_ALIASES.join(","),
    })
      .then((p) => {
        if (!alive) return;
        setRows(p.items ?? []);
        // The COUNT is the server's total for the lane, not the length of what
        // fits on one page.
        setTotal(typeof p.total === "number" ? p.total : (p.items ?? []).length);
        setErr(null);
      })
      .catch((e: unknown) => { if (alive) setErr(operatorError(e, "Threat detections could not be loaded.")); })
      .finally(() => { if (alive) setLoaded(true); });
    return () => { alive = false; };
  }, [limit]);

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
        <span className="sec-line" role="status" aria-live="polite">
          {tab === "detections"
            ? (loaded
              ? `${total.toLocaleString()} current detection${total === 1 ? "" : "s"}`
              + (total > rows.length ? ` · showing the newest ${rows.length.toLocaleString()}` : "")
              : "Loading…")
            : "Flow-derived behavior"}
          <AskIris topic="threats.what-we-detect" label="Threat detection" />
        </span>
      </div>

      {tab === "behavior" ? (
        <ThreatDetection sinceSeconds={sinceSeconds} />
      ) : (
        <Group title="Detections" hue="#e11d48">
          {err ? (
            <div className="empty" role="alert" style={{ color: "var(--bad)" }}>{err}</div>
          ) : !loaded ? (
            <div className="empty" role="status">Loading…</div>
          ) : rows.length === 0 ? (
            <div className="empty">
              No detection fired in this window.
              <AskIris topic="threats.none-matched" label="an empty detections list" />
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
          <p className="sec-line" style={{ margin: 0 }}>
            Evidence, not a verdict.
            <AskIris topic="threats.detection-not-verdict" label="a detection" />
          </p>
        </Group>
      )}

      {!ws.enabled && selected && tab === "detections" && (
        <Panel title="Detection detail"><FindingDetail finding={selected} /></Panel>
      )}
    </div>
  );
}
