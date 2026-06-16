import { C } from "./labels";

// CaseContext — the incident-workspace context strip: ticket/incident sync state,
// related changes, and similar past incidents. Honest empty states where no data
// source is wired yet (the prompt explicitly stubs similar/change). Operator-View:
// NOC language only. A NOT-CONFIRMED object never shows an auto-opened ticket.

export interface CaseContextProps {
  confirmed: boolean;
  ticketRef?: string;       // e.g. "INC0012345" when an incident is linked
  ticketStatus?: string;    // e.g. "Open"
  ticketSystem?: string;    // neutral label, e.g. "ITSM" (no vendor name in operator copy)
  similar?: { title: string; reason: string; resolution?: string }[];
  changes?: { summary: string; when?: string }[];
}

const panel: React.CSSProperties = {
  border: "1px solid var(--border,#2a2f3a)", borderRadius: 8, padding: "10px 13px",
  background: "var(--panel,#11151c)", display: "flex", flexDirection: "column", gap: 5, minWidth: 0, flex: 1,
};
const head: React.CSSProperties = { fontSize: 12, fontWeight: 700, letterSpacing: 0.6, textTransform: "uppercase", color: C.muted };
const emptyText: React.CSSProperties = { fontSize: 12.5, color: C.muted, lineHeight: 1.45 };

export default function CaseContext({ confirmed, ticketRef, ticketStatus, ticketSystem, similar = [], changes = [] }: CaseContextProps) {
  return (
    <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
      {/* Ticket / incident sync (§16) */}
      <div style={panel}>
        <span style={head}>Ticket</span>
        {ticketRef ? (
          <div style={{ fontSize: 13, color: C.fg, fontWeight: 600 }}>
            {ticketSystem ? `${ticketSystem}: ` : ""}<b>{ticketRef}</b>
            {ticketStatus ? <span style={{ color: C.muted, fontWeight: 400 }}> · {ticketStatus}</span> : null}
          </div>
        ) : confirmed ? (
          <div style={emptyText}>Not opened — <span style={{ color: C.info }}>create an evidence-backed ticket</span> to track resolution.</div>
        ) : (
          <div style={emptyText}>Not opened — <span style={{ color: C.faint }}>RCA not confirmed</span>. Auto-ticketing holds until customer impact is confirmed.</div>
        )}
      </div>

      {/* Related changes (§15) — candidate context, never auto-blamed as root cause */}
      <div style={panel}>
        <span style={head}>What changed?</span>
        {changes.length ? changes.slice(0, 3).map((ch, i) => (
          <div key={i} style={{ fontSize: 12.5, color: C.fg, lineHeight: 1.45 }}>
            <span style={{ color: C.info }}>Related change candidate:</span> {ch.summary}
            {ch.when ? <span style={{ color: C.muted }}> · {ch.when}</span> : null}
          </div>
        )) : (
          <div style={emptyText}>No related changes found in the event window.</div>
        )}
      </div>

      {/* Similar incidents (§14) — learning loop */}
      <div style={panel}>
        <span style={head}>Similar incidents</span>
        {similar.length ? similar.slice(0, 3).map((s, i) => (
          <div key={i} style={{ fontSize: 12.5, color: C.fg, lineHeight: 1.45 }}>
            <b>{s.title}</b> <span style={{ color: C.muted }}>— {s.reason}</span>
            {s.resolution ? <div style={{ color: C.muted }}>Resolved by: {s.resolution}</div> : null}
          </div>
        )) : (
          <div style={emptyText}>No similar confirmed incidents found.</div>
        )}
      </div>
    </div>
  );
}
