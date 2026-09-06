// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import "./Security.css";
import { api, SecFacets, SecFinding, SecFindingQuery, SecSavedView } from "../../services/api";
import { useWorkspace } from "../../context/workspace";
import DataTable, { Column } from "../../components/DataTable";
import { Group, Panel } from "../../components/board/panels";
import { Segmented } from "../../components/ui";
import { fmtDateTime } from "../../lib/time";
import { FacetGroup, FindingDetail, SeverityBadge, VerdictBadge } from "./parts";
import {
  EMPTY_PAGE, HistoryMode, PageState, appendPage, evidenceClassLabel, historyQuery,
  mapFacetRows, severityFacetRows, severityRank, statusFacetRows, subjectLine, verdictOf,
} from "./model";
import AskIris from "../../components/AskIris";

// Exposures — the findings workbench (P3-T8). A faceted, cursor-paginated list
// over the tenant's own security findings, with the full Finding detail in the
// Inspector: observed vs intended, the by-reference evidence pointer, the
// remediation, and the standards chips.
//
// WORD SWEEP (2026-09-06, tracker 270): the scope, pagination and read-only
// facet explanations are ai/skills/explain/exposures.*.md behind the `(i)`.
//
// Honesty: an empty result says WHICH filter emptied it; "current" and
// "history" are an explicit, labelled choice (a history row is a past verdict,
// not a live one). Tenant isolation (§3a) is enforced server-side — this page
// sends no tenant and offers no cross-tenant control.

const PAGE_SIZE = 100;

type FilterState = {
  severity?: string;
  status?: string;
  seam?: string;
  framework?: string;
  q?: string;
};

const activeFilterNames = (f: FilterState): string[] => {
  const out: string[] = [];
  if (f.severity) out.push(`severity ${f.severity}`);
  if (f.status) out.push(`verdict ${f.status}`);
  if (f.seam) out.push(`seam ${f.seam}`);
  if (f.framework) out.push(`standard ${f.framework}`);
  if (f.q) out.push(`search "${f.q}"`);
  return out;
};

/** FilterState + mode → the wire query. One place, so page/facets never drift. */
export function buildQuery(f: FilterState, mode: HistoryMode, cursor?: string): SecFindingQuery {
  const base: SecFindingQuery = { limit: PAGE_SIZE };
  if (f.severity) base.severity = f.severity;
  if (f.status) base.status = f.status;
  if (f.seam) base.seam = f.seam;
  if (f.framework) base.framework = f.framework;
  if (f.q) base.q = f.q;
  if (cursor) base.cursor = cursor;
  return historyQuery(mode, base);
}

export default function Exposures() {
  const ws = useWorkspace();
  const [filters, setFilters] = useState<FilterState>({});
  const [mode, setMode] = useState<HistoryMode>("current");
  const [search, setSearch] = useState("");
  const [page, setPage] = useState<PageState>(EMPTY_PAGE);
  const [facets, setFacets] = useState<SecFacets | null>(null);
  const [views, setViews] = useState<SecSavedView[]>([]);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [selected, setSelected] = useState<SecFinding | null>(null);
  // Guards against an out-of-order response overwriting a newer one.
  const reqId = useRef(0);

  const load = useCallback(async (f: FilterState, m: HistoryMode, cursor?: string) => {
    const my = ++reqId.current;
    setBusy(true);
    try {
      const q = buildQuery(f, m, cursor);
      const [p, fx] = await Promise.all([
        api.securityFindings(q),
        cursor ? Promise.resolve(null) : api.securityFindingFacets({ ...q, cursor: undefined, limit: undefined }),
      ]);
      if (my !== reqId.current) return;
      setPage((prev) => appendPage(prev, p, !!cursor));
      if (fx) setFacets(fx);
      setErr(null);
    } catch (e) {
      if (my !== reqId.current) return;
      setErr((e as Error).message);
      if (!cursor) setPage(EMPTY_PAGE);
    } finally {
      if (my === reqId.current) { setBusy(false); setLoaded(true); }
    }
  }, []);

  useEffect(() => { void load(filters, mode); }, [filters, mode, load]);
  useEffect(() => {
    let alive = true;
    api.securityViews().then((v) => { if (alive) setViews(Array.isArray(v) ? v : []); }).catch(() => { /* saved views optional */ });
    return () => { alive = false; };
  }, []);

  const toggle = (key: keyof FilterState) => (value: string) =>
    setFilters((f) => ({ ...f, [key]: f[key] === value ? undefined : value }));

  const submitSearch = (e: React.FormEvent) => {
    e.preventDefault();
    setFilters((f) => ({ ...f, q: search.trim() || undefined }));
  };

  const openDetail = (f: SecFinding) => {
    setSelected(f);
    if (ws.enabled) {
      ws.openInspector(<FindingDetail finding={f} />, {
        title: f.control_title || f.control || f.raw_rule_id || "Finding",
        subtitle: `${subjectLine(f)}${f.time ? ` · ${fmtDateTime(f.time)}` : ""}`,
      });
    }
  };

  const applyView = (v: SecSavedView) => {
    const fl = v.filters ?? {};
    setFilters({
      severity: fl.severity, status: fl.status, seam: fl.seam,
      framework: fl.framework, q: fl.q,
    });
    setSearch(fl.q ?? "");
    if (fl.current !== undefined) setMode(fl.current ? "current" : "history");
  };

  const columns = useMemo<Column<SecFinding>[]>(() => [
    {
      key: "severity", header: "Severity", width: 100, sortable: true,
      text: (f) => f.severity ?? "", sortValue: (f) => severityRank(f.severity),
      render: (f) => <SeverityBadge severity={f.severity} />,
    },
    {
      key: "verdict", header: "Verdict", width: 108, sortable: true,
      text: (f) => verdictOf(f), sortValue: (f) => verdictOf(f),
      render: (f) => <VerdictBadge verdict={verdictOf(f)} />,
    },
    {
      key: "control", header: "Check", sortable: true,
      text: (f) => `${f.control_title ?? ""} ${f.control ?? ""} ${f.raw_rule_id ?? ""}`,
      render: (f) => <span title={f.status_detail || undefined}>{f.control_title || f.control || f.raw_rule_id || "—"}</span>,
    },
    {
      key: "asset", header: "Asset", width: 200, sortable: true,
      text: (f) => subjectLine(f), render: (f) => subjectLine(f),
    },
    {
      key: "seam", header: "Seam", width: 110, sortable: true,
      text: (f) => f.seam?.seam_type ?? "",
      render: (f) => (f.seam?.seam_type
        ? <span className="badge">{f.seam.seam_type}</span>
        : <span className="sec-unassessed">—</span>),
    },
    {
      key: "lane", header: "Lane", width: 150, sortable: true,
      text: (f) => evidenceClassLabel(f.evidence_class),
      render: (f) => evidenceClassLabel(f.evidence_class),
    },
    {
      key: "time", header: "Verdict at", width: 170, sortable: true,
      text: (f) => f.time ?? "", render: (f) => (f.time ? fmtDateTime(f.time) : "—"),
    },
  ], []);

  const chosen = activeFilterNames(filters);

  return (
    <div className="sec dm-board">
      <Group title="Exposures" hue="#e11d48">
        <div className="sec-toolbar">
          <Segmented
            value={mode}
            onChange={(m) => setMode(m)}
            options={[
              { value: "current" as HistoryMode, label: "Current verdicts" },
              { value: "history" as HistoryMode, label: "Full history" },
            ]}
            ariaLabel="Verdict scope"
          />
          <form onSubmit={submitSearch} style={{ display: "flex", gap: 6 }}>
            <label className="sr-only" htmlFor="sec-q">Search findings</label>
            <input
              id="sec-q" className="sec-input" style={{ width: 260 }}
              placeholder="Search observed, intended, remediation…"
              value={search} onChange={(e) => setSearch(e.target.value)}
            />
            <button className="btn" type="submit">Search</button>
          </form>
          {views.length > 0 && (
            <>
              <label className="sr-only" htmlFor="sec-view">Saved view</label>
              <select
                id="sec-view" className="sec-input" defaultValue=""
                onChange={(e) => {
                  const v = views.find((x) => x.id === e.target.value);
                  if (v) applyView(v);
                }}
              >
                <option value="">Saved view…</option>
                {views.map((v) => <option key={v.id} value={v.id}>{v.name}</option>)}
              </select>
            </>
          )}
          {chosen.length > 0 && (
            <button className="btn" type="button" onClick={() => { setFilters({}); setSearch(""); }}>
              Clear {chosen.length} filter{chosen.length === 1 ? "" : "s"}
            </button>
          )}
          <span className="sec-line" role="status" aria-live="polite">
            {busy ? "Loading…" : `${page.items.length.toLocaleString()} of ${page.total.toLocaleString()} shown`}
            <AskIris topic="exposures.scope" label={mode === "history" ? "Full history" : "Current verdicts"} />
          </span>
        </div>

        <div className="sec-work">
          <aside className="sec-facets" aria-label="Filters">
            <FacetGroup title="Severity" rows={severityFacetRows(facets, filters.severity)} onToggle={toggle("severity")} />
            <FacetGroup title="Verdict" rows={statusFacetRows(facets, filters.status)} onToggle={toggle("status")} />
            <FacetGroup title="Seam" rows={mapFacetRows(facets?.seam, filters.seam)} onToggle={toggle("seam")} />
            <FacetGroup title="Standard" rows={mapFacetRows(facets?.framework, filters.framework)} onToggle={toggle("framework")} />
            {/* Read-only: the findings query has no evidence-class filter, so
                this is a breakdown of what the CURRENT filter set contains, not
                a control. Making it look clickable would promise a narrowing
                the API cannot perform. */}
            <FacetGroup
              title="Evidence lane"
              rows={mapFacetRows(facets?.evidence_class, undefined, evidenceClassLabel)}
              topic="exposures.evidence-lane"
            />
          </aside>

          <div>
            {err ? (
              <div className="empty" role="alert" style={{ color: "var(--bad)" }}>{err}</div>
            ) : !loaded ? (
              <div className="empty" role="status">Loading…</div>
            ) : page.items.length === 0 ? (
              <div className="empty">
                {chosen.length > 0
                  ? `No finding matches ${chosen.join(" · ")}. Clear a filter to widen the search.`
                  : <>No findings recorded yet.<AskIris topic="exposures.none-recorded" label="an empty findings list" /></>}
              </div>
            ) : (
              <>
                <DataTable
                  rows={page.items}
                  columns={columns}
                  rowKey={(f) => f.id}
                  height={520}
                  onRowClick={openDetail}
                  rowSelected={(f) => f.id === selected?.id}
                  rowClassName={(f) => (f.id === selected?.id ? "is-selected" : "")}
                  rowAccent={(f) => {
                    const v = verdictOf(f);
                    if (v === "unassessed") return undefined;
                    const s = (f.severity ?? "").toLowerCase();
                    return s === "critical" || s === "high" ? "var(--bad)" : v === "fail" ? "var(--warn)" : undefined;
                  }}
                  ariaLabel="Security findings"
                />
                <div style={{ display: "flex", gap: 10, alignItems: "center", marginTop: 8 }}>
                  <button
                    className="btn" type="button" disabled={!page.hasMore || busy}
                    onClick={() => { void load(filters, mode, page.cursor ?? undefined); }}
                  >
                    {page.hasMore ? (busy ? "Loading…" : "Load more") : "All rows loaded"}
                  </button>
                  <AskIris topic="exposures.pagination" label="Load more" />
                </div>
              </>
            )}
          </div>
        </div>
      </Group>

      {!ws.enabled && selected && (
        <Panel title="Finding detail">
          <FindingDetail finding={selected} />
        </Panel>
      )}
    </div>
  );
}
