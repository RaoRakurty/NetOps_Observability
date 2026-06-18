// FirewallNode.tsx — firewall card. Vendor-neutral icon: a brick wall. The red
// accent is the LEFT bar only — the card is never filled red (PDF §11).

import { type NodeProps } from "@xyflow/react";
import { memo } from "react";
import type { RFNodeData } from "../rfTypes";
import { NodeCard } from "./DeviceNode";

const ACCENT = "#dc2626";

function FirewallIcon() {
  return (
    <svg width={18} height={18} viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <rect x={3} y={5} width={18} height={14} rx={1.5} stroke="currentColor" strokeWidth={1.6} />
      {/* mortar rows */}
      <path d="M3 9.7h18M3 14.3h18" stroke="currentColor" strokeWidth={1.3} />
      {/* staggered brick joints */}
      <path
        d="M9 5v4.7M15 5v4.7M6 9.7v4.6M12 9.7v4.6M18 9.7v4.6M9 14.3V19M15 14.3V19"
        stroke="currentColor"
        strokeWidth={1.3}
      />
    </svg>
  );
}

function FirewallNodeBase(props: NodeProps) {
  const data = props.data as unknown as RFNodeData;
  return <NodeCard data={data} icon={<FirewallIcon />} accent={ACCENT} />;
}

export const FirewallNode = memo(FirewallNodeBase);
export default FirewallNode;
