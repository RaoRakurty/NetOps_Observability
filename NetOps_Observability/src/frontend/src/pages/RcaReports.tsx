import { useEffect, useMemo, useState } from "react";
import { api, RcaLibraryReport } from "../services/api";
import DataTable, { Column } from "../components/DataTable";
import { NocHeader, Chip } from "../components/noc";
import { fmtDateTime } from "../lib/time";

// RCA Reports (#113) — the MANAGEMENT library. The owner's two-surface model:
// the Correlations page shows every candidate (engineer surface, don't-hide);
// this page lists ONLY promoted real outages — auto-promoted (confirmed verdict
// + confirmed user/app impact + duration) or explicitly, audited-ly promoted —
// and links to their documents. Rows come from the server's built reports; this
// page never re-derives a state or a claim.

const TIER_TONE: Record<string, string> = {
  confirmed: "#E11D48", suspected: "#D97706", undetermined: "#8A93A6",
};
const IMPACT_TONE: Record<string, string> = {
  confirmed: "#E11D48", detected: "#D97706",
};

// fmtDurMs — compact human duration for the library row (exported for tests).
export function fmtDurMs(ms: number): string {
  if (!ms || ms <= 0) return "—";
  const s = Math.round(ms / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m${s % 60 ? ` ${s % 60}s` : ""}`;
  const h = Math.floor(m / 60);
  return `${h}h${m % 60 ? ` ${m % 60}m` : ""}`;
}

// promotionBadge — AUTO/MANUAL basis with attribution (exported for tests).
export function promotionBadge(r: RcaLibraryReport): { label: string; tip: string } {
  if (r.promotion.basis === "manual") {
    const m = r.promotion.manual;
    return {
      label: "MANUAL",
      tip: m ? `Promoted by ${m.promoted_by} at ${m.promoted_at}${m.note ? ` — ${m.note}` : ""}` : "Manually promoted",
    };
  }
  return { label: "AUTO", tip: r.promotion.reason };
}

export default function RcaReports() {
  const [rows, setRows] = useState<RcaLibraryReport[]>([]);
  const [days, setDays] = useState(30);
  const [truncated, setTruncated] = useState(false);
  const [evaluated, setEvaluated] = useState(0);
  const [loaded, setLoaded] = useState(false);
  const [err, setErr] = useState("");

  useEffect(() => {
    let alive = true;
    setLoaded(false);
    setErr("");
    api.rcaLibrary(days)
      .then((r) => {
        if (!alive) return;
        setRows(r?.reports ?? []);
        setTruncated(!!r?.truncated);
        setEvaluated(r?.evaluated ?? 0);
        setLoaded(true);
      })
      .catch((e) => { if (alive) { setErr(String((e as Error)?.message ?? e)); setLoaded(true); } });
    return () => { alive = false; };
  }, [days]);

  const columns = useMemo<Column<RcaLibraryReport>[]>(() => [
    { key: "display_id", header: "ID", width: 88, sortable: true, text: (r) => r.display_id,
      render: (r) => <span style={{ fontFamily: "var(--font-mono)", fontSize: 12 }} title={r.correlation_id}>{r.display_id}</span> },
    { key: "title", header: "Report", width: "2fr", sortable: true, text: (r) => `${r.report_type} ${r.title}`,
      render: (r) => (
        <span style={{ display: "flex", flexDirection: "column", lineHeight: 1.3, minWidth: 0 }}>
          <span style={{ fontWeight: 700, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{r.title}</span>
          <span style={{ fontSize: 11, color: "var(--muted)" }}>{r.report_type}</span>
        </span>
      ) },
    { key: "glance", header: "Where · what · owner", width: "3fr",
      text: (r) => `${r.at_a_glance.where} ${r.at_a_glance.what} ${r.at_a_glance.owners.join(" ")}`,
      render: (r) => (
        <span style={{ display: "flex", flexDirection: "column", lineHeight: 1.3, fontSize: 12, minWidth: 0 }}>
          <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={r.at_a_glance.where}>
            <b>Where:</b> {r.at_a_glance.where}
          </span>
          <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={r.at_a_glance.what}>
            <b>What:</b> {r.at_a_glance.what}
          </span>
          <span style={{ color: "var(--muted)" }}>{r.at_a_glance.owners_label}: {r.at_a_glance.owners.join(" · ")}</span>
        </span>
      ) },
    { key: "verdict", header: "Verdict", width: 100, sortable: true, text: (r) => r.states.analysis,
      render: (r) => <Chip label={r.states.analysis} tone={TIER_TONE[r.states.analysis] ?? "var(--fg-subtle)"} /> },
    { key: "impact", header: "Impact", width: 100, sortable: true, text: (r) => r.states.impact,
      render: (r) => <Chip label={r.states.impact.replace(/_/g, " ")} tone={IMPACT_TONE[r.states.impact] ?? "var(--fg-subtle)"} /> },
    { key: "duration", header: "Duration", width: 88, align: "right", sortable: true,
      sortValue: (r) => r.times.duration_ms,
      render: (r) => <span style={{ fontFamily: "var(--font-mono)", fontSize: 12 }}>{fmtDurMs(r.times.duration_ms)}</span> },
    { key: "end", header: "Ended", width: 150, sortable: true, sortValue: (r) => r.times.end,
      render: (r) => <span style={{ fontFamily: "var(--font-mono)", fontSize: 12 }}>{r.times.end ? fmtDateTime(r.times.end) : "—"}</span> },
    { key: "basis", header: "Promoted", width: 92, sortable: true, text: (r) => r.promotion.basis,
      render: (r) => {
        const b = promotionBadge(r);
        return <Chip label={b.label} tone={b.label === "MANUAL" ? "#7C3AED" : "#16A34A"} title={b.tip} />;
      } },
    { key: "actions", header: "", width: 190,
      render: (r) => (
        <span style={{ display: "inline-flex", gap: 8 }} onClick={(e) => e.stopPropagation()}>
          <a href={`#/investigate/rca?id=${encodeURIComponent(r.correlation_id)}`}
            style={{ fontSize: 12 }} title="Open the full RCA workspace for this outage">
            Open workspace
          </a>
          <button className="rw-btn" style={{ fontSize: 12, padding: "1px 8px" }}
            title="Download the promoted RCA document (PDF; falls back to the print view when the PDF renderer is off)"
            onClick={() => {
              api.downloadRcaReport(r.correlation_id, r.display_id)
                .catch(() => alert("Could not render the document — try again or check the PDF sidecar."));
            }}>
            ⤓ PDF
          </button>
        </span>
      ) },
  ], []);

  return (
    <div>
      <NocHeader
        title="RCA Reports"
        subtitle="Promoted real outages and their documents — the management library. Every candidate (promoted or not) lives in Correlations."
        chips={
          <>
            <Chip label={`${rows.length} promoted`} tone="#16A34A" />
            <select value={days} onChange={(e) => setDays(Number(e.target.value))}
              aria-label="Library window">
              <option value={7}>7 days</option>
              <option value={30}>30 days</option>
              <option value={90}>90 days</option>
              <option value={365}>365 days</option>
            </select>
          </>
        }
      />
      {/* no silent caps: a full evaluation page is disclosed, never hidden */}
      {truncated && (
        <div style={{ fontSize: 12, color: "var(--muted)", margin: "6px 2px" }}>
          Evaluated the {evaluated} most recent qualifying candidates — older promoted outages may exist beyond this page; narrow the window to see them all.
        </div>
      )}
      {err && <div className="empty">{err}</div>}
      {!err && loaded && rows.length === 0 && (
        <div className="empty">
          No promoted outages in this window — candidates live in Correlations.
        </div>
      )}
      {!err && rows.length > 0 && (
        <DataTable<RcaLibraryReport>
          rows={rows}
          columns={columns}
          rowKey={(r) => r.correlation_id}
          height="62vh"
          ariaLabel="Promoted RCA reports"
        />
      )}
    </div>
  );
}
