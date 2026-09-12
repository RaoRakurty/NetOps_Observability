# Graph Scale Policy

## React Flow limits

0-250 nodes:
- rich custom cards
- full operator experience

250-1000 nodes:
- grouping
- collapse/expand
- simplified edges
- fewer labels

1000+ nodes:
- do not render full graph in React Flow
- use future WebGL overview renderer
- render selected subgraph in React Flow

## Required controls

- search-first navigation
- grouping
- expand-on-demand
- path focus
- incident focus
- neighbor depth control
- collapse low-priority access layers

## Rule

Never default to a full enterprise hairball.
