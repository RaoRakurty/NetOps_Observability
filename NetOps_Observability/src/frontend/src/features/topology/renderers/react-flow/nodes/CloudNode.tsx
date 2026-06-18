// CloudNode.tsx — cloud / WAN card. Vendor-neutral cloud icon. Used for both the
// "cloud" and "wan" kinds (rfTypes maps both to cloudNode). Reuses <NodeCard>.

import { type NodeProps } from "@xyflow/react";
import { memo } from "react";
import type { RFNodeData } from "../rfTypes";
import { NodeCard } from "./DeviceNode";

const ACCENT = "#7c3aed";

function CloudIcon() {
  return (
    <svg width={18} height={18} viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path
        d="M7 18h10a4 4 0 0 0 .6-7.95A5.5 5.5 0 0 0 6.7 9.2 3.8 3.8 0 0 0 7 18Z"
        stroke="currentColor"
        strokeWidth={1.6}
        strokeLinejoin="round"
      />
    </svg>
  );
}

function CloudNodeBase(props: NodeProps) {
  const data = props.data as unknown as RFNodeData;
  return <NodeCard data={data} icon={<CloudIcon />} accent={ACCENT} />;
}

export const CloudNode = memo(CloudNodeBase);
export default CloudNode;
