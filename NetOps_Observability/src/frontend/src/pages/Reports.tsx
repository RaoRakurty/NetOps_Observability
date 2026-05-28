// Reports — saved searches + scheduled, delivered reports.
// Phase 1 ships the surface and IA slot; the saved-objects backend and
// scheduler land in a later phase (see CLAUDE.md / ARCHITECTURE roadmap).

export default function Reports() {
  return (
    <div className="card empty-state">
      <div className="empty-state-icon">📄</div>
      <h2 style={{ textTransform: "none", color: "var(--fg)", fontSize: 18 }}>Reports</h2>
      <p style={{ color: "var(--muted)", maxWidth: 520, margin: "8px auto 0" }}>
        Save a search or analytics view, put it on a schedule, and have it
        delivered via Slack, email, or PagerDuty using the existing notifier.
      </p>
      <p style={{ color: "var(--muted)", fontSize: 12, marginTop: 16 }}>
        Backed by a saved-objects store in Postgres + a server-side scheduler —
        arriving in a later phase. The navigation slot is reserved here so the
        product shape is stable.
      </p>
    </div>
  );
}
