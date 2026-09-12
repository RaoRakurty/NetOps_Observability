// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// index.ts — the React Flow nodeTypes registry. Keys MUST match
// NODE_TYPE_FOR_KIND in ../rfTypes.ts.

import { DeviceNode } from "./DeviceNode";
import { SwitchNode } from "./SwitchNode";
import { RouterNode } from "./RouterNode";
import { FirewallNode } from "./FirewallNode";
import { CloudNode } from "./CloudNode";
import { CloudResourceNode } from "./CloudResourceNode";
import { GroupNode } from "./GroupNode";
import { UnresolvedNode } from "./UnresolvedNode";

export const nodeTypes = {
  deviceNode: DeviceNode,
  switchNode: SwitchNode,
  routerNode: RouterNode,
  firewallNode: FirewallNode,
  cloudNode: CloudNode,
  // A cloud resource that DECLARES its provider gets the provider-marked card;
  // the generic cloud/WAN glyph (`cloudNode`) still covers everything else. The
  // adapter picks between them by FACT, so one registry serves the whole unified
  // canvas — there is no separate cloud renderer to keep in sync any more (#131).
  cloudResourceNode: CloudResourceNode,
  groupNode: GroupNode,
  unresolvedNode: UnresolvedNode,
};

export { DeviceNode, NodeCard } from "./DeviceNode";
export { SwitchNode } from "./SwitchNode";
export { RouterNode } from "./RouterNode";
export { FirewallNode } from "./FirewallNode";
export { CloudNode } from "./CloudNode";
export { CloudResourceNode } from "./CloudResourceNode";
export { GroupNode } from "./GroupNode";
export { UnresolvedNode } from "./UnresolvedNode";
