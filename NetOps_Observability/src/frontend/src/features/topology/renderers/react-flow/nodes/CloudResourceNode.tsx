// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// CloudResourceNode.tsx — a CLOUD NETWORK resource card (VPC gateway / NVA /
// subnet / endpoint …). Distinct from CloudNode (the generic cloud/WAN glyph):
// this one wears the provider-tagged cloud glyph — ORIGINAL Correlix artwork
// (components/CloudGlyph.tsx), one silhouette with a plain letter tag AWS / AZ /
// GCP — so the card reads as a specific provider's resource. The providers'
// official trademark icons it used to render were removed by licence-audit D5
// (2026-09-04); an unrecognised provider falls back to the untagged generic
// cloud, never to another provider's mark.
//
// It composes the shared <NodeCard> shell — same fixed geometry, calm health
// ring, confidence chip and no-shake invariant as every other node. Only the
// icon (the cloud glyph) and the left-rule accent (a neutral PRODUCT accent,
// never a brand hue) differ.
// The specific network function (IGW/NAT/VGW/…) is carried in the node label
// and tags (drawer/tooltip) — the card face stays uniform per the skill.
//
// Registered as `cloudResourceNode` in the ONE shared registry; the adapter routes
// a node here only when it DECLARES a provider (a discovered cloud resource), so
// every on-prem cloud/WAN node keeps the generic glyph unchanged.

import { type NodeProps } from "@xyflow/react";
import { memo } from "react";
import type { RFNodeData } from "../rfTypes";
import { NodeCard } from "./DeviceNode";
import ProviderMark, { providerAccent } from "../../../components/ProviderMark";

function CloudResourceNodeBase(props: NodeProps) {
  const data = props.data as unknown as RFNodeData;
  const provider = (data.node.tags?.provider ?? String(data.node.metrics?.provider ?? "")) || undefined;
  return (
    <NodeCard
      data={data}
      icon={<ProviderMark provider={provider} size={18} />}
      accent={providerAccent(provider)}
    />
  );
}

export const CloudResourceNode = memo(CloudResourceNodeBase);
export default CloudResourceNode;
