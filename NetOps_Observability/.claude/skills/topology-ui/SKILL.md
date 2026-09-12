---
name: topology-ui
description: Use this skill for any Correlix topology, network map, path analysis, RCA canvas, dependency graph, or digital twin UI work.
---

# Correlix Topology UI Skill

Use this skill for any Correlix topology, network map, path analysis, RCA canvas, dependency graph, or digital twin UI work.

## Product goal

Build a topology operating canvas, not an LLDP visualizer.

The canvas must help operators:
- discover
- visualize
- search
- expand
- trace path
- overlay health
- compare change
- explain RCA
- assign owner

## Phase rule

Phase 1 must use:
- React
- React Flow / xyflow
- ELK.js
- Tailwind / shadcn / Radix
- custom SVG-style device nodes

Do not implement Sigma, cosmos.gl, MapLibre, or deck.gl in Phase 1.
Only create clean adapter boundaries for those future renderers.

## Core architecture

Frontend must consume a resolved topology contract.

Never consume raw LLDP, CDP, SNMP, BGP-LS, flow, syslog, or cloud rows directly in React components.

Required layers:
1. Raw facts
2. Identity resolution
3. Confidence scoring
4. Resolved topology graph
5. View builder
6. Layout adapter
7. Renderer adapter
8. Operator workflow

## Required behavior

Every node and edge must support:
- evidence
- confidence
- source facts
- first_seen
- last_seen
- health
- owner
- change_state

Every edge must be explainable.

## Forbidden

Do not:
- render raw LLDP tables as topology
- use random force layout as the default
- hardcode node positions
- show all labels at once
- hide unresolved nodes
- draw links without evidence
- mix API domain types with React Flow internals
- create a full-enterprise hairball by default
- over-animate the canvas
