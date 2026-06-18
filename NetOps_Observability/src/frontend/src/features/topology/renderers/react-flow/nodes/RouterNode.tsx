// RouterNode.tsx — router card. Vendor-neutral icon: a circle with four
// directional arrows (the classic routing glyph). Reuses <NodeCard>.

import { type NodeProps } from "@xyflow/react";
import { memo } from "react";
import type { RFNodeData } from "../rfTypes";
import { NodeCard } from "./DeviceNode";

const ACCENT = "#0ea5e9";

function RouterIcon() {
  return (
    <svg width={18} height={18} viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <circle cx={12} cy={12} r={8} stroke="currentColor" strokeWidth={1.6} />
      <path
        d="M12 4v6M12 14v6M4 12h6M14 12h6"
        stroke="currentColor"
        strokeWidth={1.4}
        strokeLinecap="round"
      />
      <path
        d="M12 4l-2 2.5M12 4l2 2.5M12 20l-2-2.5M12 20l2-2.5M4 12l2.5-2M4 12l2.5 2M20 12l-2.5-2M20 12l-2.5 2"
        stroke="currentColor"
        strokeWidth={1.3}
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

function RouterNodeBase(props: NodeProps) {
  const data = props.data as unknown as RFNodeData;
  return <NodeCard data={data} icon={<RouterIcon />} accent={ACCENT} />;
}

export const RouterNode = memo(RouterNodeBase);
export default RouterNode;
