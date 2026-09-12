# React Flow Patterns

## Rule

React Flow is the Phase 1 operator canvas renderer.

It must not own the domain model.

Use this flow:

TopologyView
-> topologyToReactFlow()
-> React Flow nodes/edges
-> canvas render

## Required components

- TopologyCanvas
- TopologyToolbar
- TopologySearch
- TopologySideDrawer
- TopologyLegend
- TopologyMiniMap
- OverlaySelector
- MapWorkflowSelector
- PathAnalysisPanel
- EvidencePanel
- ConfidencePanel

## Required nodes

- DeviceNode
- SwitchNode
- RouterNode
- FirewallNode
- CloudNode
- GroupNode
- UnresolvedNode

## Required edges

- TopologyEdge
- PathHighlightEdge
- InferredEdge
- DegradedEdge
- BundledEdge

## Layout

Use ELK.js.

Do not hardcode positions except mock fallback examples.

Do not recompute layout on every render.

## Selection

Selecting a node:
- highlight first-degree neighbors
- dim unrelated nodes and edges
- open side drawer

Selecting an edge:
- open evidence panel
- show confidence and source facts

## Performance

- memoize custom nodes
- keep selected IDs separate from node arrays
- avoid graph algorithms inside React components
- avoid animated edges unless selected or incident-critical
