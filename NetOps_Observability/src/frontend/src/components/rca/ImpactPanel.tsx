import { C } from "./labels";

// ImpactPanel — the compact "blast radius" read: is there confirmed customer
// impact, and how far does it reach. Enterprise-safe wording — "No confirmed
// customer impact" rather than the too-absolute "nothing impacted". Operator-View
// component: NOC language only, no IDs/weights. Derived values passed in.

export interface ImpactProps {
  confirmed: boolean;
  device?: string;
  peer?: string;
  scopeType?: string;     // e.g. "Routing adjacency"
  notTied: string[];      // evidence classes not tied to this issue (drives the why)
}

function Row({ label, value, tone }: { label: string; value: string; tone?: string }) {
  return (
    <div style={{ display: "flex", gap: 8, fontSize: 13, lineHeight: 1.5, flexWrap: "wrap" }}>
      <span style={{ color: C.muted, minWidth: 120, flexShrink: 0 }}>{label}</span>
      <span style={{ color: tone ?? C.fg, fontWeight: tone ? 700 : 600, minWidth: 0, overflowWrap: "anywhere" }}>{value}</span>
    </div>
  );
}

// Join with commas + a trailing "and", and sentence-case the first word.
function andList(items: string[]): string {
  if (items.length === 0) return "";
  const cap = items.map((s, i) => (i === 0 ? s.charAt(0).toUpperCase() + s.slice(1) : s));
  if (cap.length === 1) return cap[0];
  return `${cap.slice(0, -1).join(", ")}, and ${cap[cap.length - 1]}`;
}

export default function ImpactPanel({ confirmed, device, peer, scopeType, notTied }: ImpactProps) {
  const card: React.CSSProperties = {
    border: "1px solid var(--border,#2a2f3a)", borderRadius: 8, padding: "11px 14px",
    background: "var(--panel,#11151c)", display: "flex", flexDirection: "column", gap: 6, minWidth: 0,
  };
  const head: React.CSSProperties = { fontSize: 12, fontWeight: 700, letterSpacing: 0.6, textTransform: "uppercase", color: C.muted };
  const verb = notTied.length > 1 ? "are" : "is";
  const why = !confirmed && notTied.length ? `${andList(notTied)} evidence ${verb} not tied to this issue.` : "";

  return (
    <div style={card}>
      <span style={head}>Impact &amp; blast radius</span>
      <Row label="Impact" value={confirmed ? "Confirmed customer-impacting issue" : "No confirmed customer impact"} tone={confirmed ? C.crit : C.warn} />
      {device && <Row label="Affected scope" value={`Device: ${device}`} />}
      {peer && <Row label="" value={`Peer: ${peer}`} />}
      {scopeType && <Row label="" value={`Scope type: ${scopeType}`} />}
      {!device && <Row label="Affected scope" value="Not yet localized" />}
      <Row label="Service / application" value={confirmed ? "Under assessment" : "Not confirmed"} />
      <Row label="Path impact" value={confirmed ? "Under assessment" : "Not confirmed"} />
      {why && (
        <div style={{ fontSize: 12.5, color: C.muted, lineHeight: 1.45 }}>
          <span style={{ color: C.muted }}>Why: </span>{why}
        </div>
      )}
    </div>
  );
}
