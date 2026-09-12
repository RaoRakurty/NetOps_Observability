// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// SwitchNode.tsx — switch card. Vendor-neutral icon: a body with stacked
// horizontal port rows. Reuses the shared <NodeCard> shell.

import { type NodeProps } from "@xyflow/react";
import { memo } from "react";
import type { RFNodeData } from "../rfTypes";
import { NodeCard } from "./DeviceNode";

const ACCENT = "#6366f1";

function SwitchIcon() {
  return (
    <svg width={18} height={18} viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <rect x={3} y={6} width={18} height={12} rx={2} stroke="currentColor" strokeWidth={1.6} />
      <path
        d="M6 10h12M6 14h12"
        stroke="currentColor"
        strokeWidth={1.4}
        strokeLinecap="round"
      />
    </svg>
  );
}

function SwitchNodeBase(props: NodeProps) {
  const data = props.data as unknown as RFNodeData;
  return <NodeCard data={data} icon={<SwitchIcon />} accent={ACCENT} />;
}

export const SwitchNode = memo(SwitchNodeBase);
export default SwitchNode;
