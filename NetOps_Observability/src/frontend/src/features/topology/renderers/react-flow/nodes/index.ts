// index.ts — the React Flow nodeTypes registry. Keys MUST match
// NODE_TYPE_FOR_KIND in ../rfTypes.ts.

import { DeviceNode } from "./DeviceNode";
import { SwitchNode } from "./SwitchNode";
import { RouterNode } from "./RouterNode";
import { FirewallNode } from "./FirewallNode";
import { CloudNode } from "./CloudNode";
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

export { DeviceNode, NodeCard } from "./DeviceNode";
export { SwitchNode } from "./SwitchNode";
export { RouterNode } from "./RouterNode";
export { FirewallNode } from "./FirewallNode";
export { CloudNode } from "./CloudNode";
export { GroupNode } from "./GroupNode";
export { UnresolvedNode } from "./UnresolvedNode";
