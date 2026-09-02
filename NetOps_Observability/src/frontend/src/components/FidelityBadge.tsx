// FidelityBadge — the ONE rendering of a parser-rule evidence tier (W1b/A3).
// Shared by the Telemetry Coverage rules table and the RCA evidence rows so both
// surfaces grade the same rule with the same word and the same colour.
//
// An absent/blank fidelity renders NOTHING: the platform does not know the tier,
// and inventing "unrated" ink where the engine said nothing would be a claim.
import { fidelityBadgeClass, fidelityLabel, fidelityTitle } from "../lib/fidelity";

export default function FidelityBadge({ fidelity }: { fidelity?: string | null }) {
  const f = (fidelity ?? "").trim();
  if (!f) return null;
  return <span className={fidelityBadgeClass(f)} title={fidelityTitle(f)}>{fidelityLabel(f)}</span>;
}
