// Saved dashboards — native, composable dashboards built from panels
// (KPIs, log searches, flow charts, metric queries) and persisted as
// saved objects. Phase 1 reserves the slot; the curated self-monitoring
// boards remain available under Stack → Self-Monitoring in the meantime.

export default function SavedDashboards() {
  return (
    <div className="card empty-state">
      <div className="empty-state-icon">📊</div>
      <h2 style={{ textTransform: "none", color: "var(--fg)", fontSize: 18 }}>Saved dashboards</h2>
      <p style={{ color: "var(--muted)", maxWidth: 520, margin: "8px auto 0" }}>
        Compose your own dashboards from panels — KPI tiles, saved log
        searches, flow charts, and metric queries — and pin them here.
      </p>
      <p style={{ color: "var(--muted)", fontSize: 12, marginTop: 16 }}>
        Native dashboards persist as saved objects (Phase 2). For now, the
        curated operational boards live under <strong>Stack → Self-Monitoring</strong>.
      </p>
    </div>
  );
}
