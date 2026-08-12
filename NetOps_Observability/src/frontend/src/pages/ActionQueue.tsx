// ActionQueue — Operations → Action Queue (2026-08 nav redesign). The Command
// Center's triage queue promoted to a first-class routed page: before this, the
// queue was a panel inside the Command Center with NO route of its own, so it
// could not be bookmarked, linked from a ticket, or set as a landing page.
//
// The view REUSES the Command Center's building blocks (FilterBar, queueColumns,
// ExpandPanel — exported from ./CommandCenter) and the same unit-tested triage
// model (./commandCenter.model), so the two surfaces can never disagree about
// what "needs action" means. The Command Center keeps its embedded copy with
// KPI-driven filtering; this page is the queue alone, full-height.

import { useCallback, useEffect, useMemo, useState } from "react";
import { api, CorrObject } from "../services/api";
import DataTable from "../components/DataTable";
import {
  type ActionItem, type CcFilters,
  buildItem, isActionableCorr, bySeverityThenAge, filterItems,
} from "./commandCenter.model";
import { FilterBar, queueColumns, ExpandPanel } from "./CommandCenter";

export default function ActionQueue() {
  const [corr, setCorr] = useState<CorrObject[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [open, setOpen] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [filters, setFilters] = useState<CcFilters>({});

  // Same source + actionability filter as the Command Center's embedded queue.
  // (The ITSM incident list is NOT fetched here — it only feeds the Command
  // Center's ticketing-gap KPIs, which stay on that page.)
  const load = useCallback(async () => {
    try {
      const cs = await api.correlations(200, 2592000, "open");
      setCorr((cs?.data ?? []).filter(isActionableCorr));
      setErr(null);
    } catch (e) { setErr((e as Error).message); }
    finally { setLoaded(true); }
  }, []);
  useEffect(() => { load(); const id = setInterval(load, 30_000); return () => clearInterval(id); }, [load]);

  const items = useMemo(() => corr.map((c) => buildItem(c)).sort(bySeverityThenAge), [corr]);
  const visible = useMemo(() => filterItems(items, filters), [items, filters]);
  const columns = useMemo(() => queueColumns(open), [open]);
  const queueHeight = useMemo(
    () => Math.min(720, visible.length * 34 + 40 + (open ? 300 : 0)),
    [visible.length, open],
  );

  return (
    <div className="dm-board cc-board">
      <div className="cc-panel">
        <div className="cc-panel-h">
          <h3 className="cc-panel-t">Action Queue</h3>
          <span className="cc-panel-meta">
            correlated incidents — what to work next · KPIs and the ticketing gap live in the{" "}
            <a href="#/overview/home">Command Center</a>
          </span>
        </div>
        {err && <p className="cc-err">{err}</p>}
        {loaded && items.length > 0 && (
          <FilterBar filters={filters} setFilters={setFilters} total={items.length} shown={visible.length} />
        )}
        {!loaded ? (
          <div className="cc-empty">Loading correlated incidents…</div>
        ) : err && items.length === 0 ? (
          // A failed read is NOT an empty queue — never render "nothing to do"
          // out of an API error (the same honesty rule the panels follow).
          <div className="cc-empty">The queue could not be loaded — correlated incidents are unknown, not absent.</div>
        ) : items.length === 0 ? (
          <div className="cc-empty">No correlated incidents require action. The queue groups raw alerts into incidents — none have correlated.</div>
        ) : visible.length === 0 ? (
          <div className="cc-empty">No incidents match the current filters. <button type="button" className="cc-filter-clear" onClick={() => setFilters({})}>Clear filters</button></div>
        ) : (
          <div className="cc-table-wrap">
            <DataTable<ActionItem>
              rows={visible}
              columns={columns}
              rowKey={(it) => it.corr.correlation_id}
              rowHeight={34}
              height={queueHeight}
              ariaLabel="Action Queue — correlated incidents"
              rowAccent={(it) => (it.sev === "crit" ? "var(--crit)" : it.sev === "major" ? "var(--warn)" : undefined)}
              onRowClick={(it) => setOpen((cur) => (cur === it.corr.correlation_id ? null : it.corr.correlation_id))}
              expandedKey={open}
              renderExpanded={(it) => <ExpandPanel it={it} />}
            />
          </div>
        )}
      </div>
    </div>
  );
}
