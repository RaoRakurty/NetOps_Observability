// topologyGraph.ts — a thin, render-agnostic wrapper over a TopologyView that
// precomputes id-maps and adjacency for O(1) lookups. No rendering, no React.
// Components and algorithms ask this object questions about structure; it never
// knows about React Flow / sigma / deck.gl.

import type { TopologyView, TopologyNode, TopologyEdge } from "../api/topologyTypes";

export class TopologyGraph {
  private readonly view: TopologyView;
  private readonly nodeById = new Map<string, TopologyNode>();
  private readonly edgeById = new Map<string, TopologyEdge>();
  /** node id → set of neighbour node ids (undirected). */
  private readonly adj = new Map<string, Set<string>>();

  constructor(view: TopologyView) {
    this.view = view;
    for (const n of view.nodes ?? []) this.nodeById.set(n.id, n);
    for (const e of view.edges ?? []) {
      this.edgeById.set(e.id, e);
      this.link(e.source, e.target);
      this.link(e.target, e.source);
    }
  }

  private link(a: string, b: string): void {
    if (!this.adj.has(a)) this.adj.set(a, new Set());
    this.adj.get(a)!.add(b);
  }

  /** Resolve a node by id, or undefined. */
  node(id: string): TopologyNode | undefined {
    return this.nodeById.get(id);
  }

  /** Resolve an edge by id, or undefined. */
  edge(id: string): TopologyEdge | undefined {
    return this.edgeById.get(id);
  }

  /** First-degree neighbour node ids (excludes self). */
  neighbors(id: string): string[] {
    return [...(this.adj.get(id) ?? [])];
  }

  /** Undirected degree (distinct neighbours) of a node. */
  degree(id: string): number {
    return this.adj.get(id)?.size ?? 0;
  }

  /** All nodes whose group_id matches, or that the group lists as a child. */
  nodesByGroup(groupId: string): TopologyNode[] {
    const group = (this.view.groups ?? []).find((g) => g.id === groupId);
    const childIds = new Set(group?.children ?? []);
    return (this.view.nodes ?? []).filter(
      (n) => n.group_id === groupId || childIds.has(n.id),
    );
  }
}
