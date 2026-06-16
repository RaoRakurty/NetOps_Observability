import { C } from "./labels";

// ImpactPanel — the compact "blast radius" read: is there confirmed customer
// impact, and how far does it reach. Enterprise-safe wording — "No confirmed
// customer impact" rather than the too-absolute "nothing impacted". Operator-View
// component: NOC language only, no IDs/weights. Derived values passed in.

export interface ImpactProps {
  confirmed: boolean;
  affectedScope: string; // e.g. "Device area: leaf1"
  flowTied: boolean;     // is traffic-flow evidence tied to this issue?
  probeTied: boolean;    // is an independent active check tied?
}

function Row({ label, value, tone }: { label: string; value: string; tone?: string }) {
  return (
    <div style={{ display: "flex", gap: 8, fontSize: 13, lineHeight: 1.5, flexWrap: "wrap" }}>
      <span style={{ color: C.muted, minWidth: 120, flexShrink: 0 }}>{label}</span>
      <span style={{ color: tone ?? C.fg, fontWeight: tone ? 700 : 600, minWidth: 0, overflowWrap: "anywhere" }}>{value}</span>
    </div>
  );
}

export default function ImpactPanel({ confirmed, affectedScope, flowTied, probeTied }: ImpactProps) {
  const card: React.CSSProperties = {
    border: "1px solid var(--border,#2a2f3a)", borderRadius: 8, padding: "11px 14px",
    background: "var(--panel,#11151c)", display: "flex", flexDirection: "column", gap: 7, minWidth: 0,
  };
  const head: React.CSSProperties = { fontSize: 12, fontWeight: 700, letterSpacing: 0.6, textTransform: "uppercase", color: C.muted };

  // The "why" only applies while impact is unconfirmed: name the independent
  // evidence classes that aren't tied yet (traffic-flow / active check).
  const missing = [!flowTied ? "traffic-flow" : "", !probeTied ? "independent active-check" : ""].filter(Boolean);
  const why = missing.length
    ? `${missing.join(" and ")} evidence ${missing.length > 1 ? "are" : "is"} not tied to this issue.`
    : "";

  return (
    <div style={card}>
      <span style={head}>Impact &amp; blast radius</span>
      <Row label="Impact" value={confirmed ? "Confirmed customer-impacting issue" : "No confirmed customer impact"} tone={confirmed ? C.crit : C.warn} />
      <Row label="Affected scope" value={affectedScope || "Not yet localized"} />
      <Row label="Service / application" value={confirmed ? "Under assessment" : "Not confirmed"} />
      <Row label="Path impact" value={confirmed ? "Under assessment" : "Not confirmed"} />
      {!confirmed && why && (
        <div style={{ fontSize: 12.5, color: C.muted, lineHeight: 1.45 }}>
          <span style={{ color: C.muted }}>Why: </span>{why}
        </div>
      )}
    </div>
  );
}
