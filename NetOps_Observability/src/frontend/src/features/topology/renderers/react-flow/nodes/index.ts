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
  groupNode: GroupNode,
  unresolvedNode: UnresolvedNode,
};

// Cloud-tab node registry: the cloud NETWORK view swaps the generic cloud glyph
// for the official-provider-mark card. Kept SEPARATE from `nodeTypes` so the
// default canvas (and every non-cloud view) renders exactly as before.
export const cloudNodeTypes = {
  ...nodeTypes,
  cloudNode: CloudResourceNode,
};

export { DeviceNode, NodeCard } from "./DeviceNode";
export { SwitchNode } from "./SwitchNode";
export { RouterNode } from "./RouterNode";
export { FirewallNode } from "./FirewallNode";
export { CloudNode } from "./CloudNode";
export { CloudResourceNode } from "./CloudResourceNode";
export { GroupNode } from "./GroupNode";
export { UnresolvedNode } from "./UnresolvedNode";
