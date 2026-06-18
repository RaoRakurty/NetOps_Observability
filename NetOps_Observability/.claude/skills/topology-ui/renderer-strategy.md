# Renderer Strategy

## Phase 1

Use React Flow + ELK.js.

Purpose:
- scoped topology views
- rich custom nodes
- path analysis
- incident/RCA view
- evidence drawer
- premium NOC canvas

## Future renderer boundaries

Create placeholders only.

### Sigma / cosmos.gl

Purpose:
- large enterprise overview
- 1,000+ nodes
- dense dependency graphs
- WebGL exploration

### MapLibre / deck.gl

Purpose:
- WAN geo map
- branch map
- cloud region map
- latency and path overlays

## Rule

Do not implement future renderers until React Flow Phase 1 is stable.

But keep the domain contract renderer-agnostic.
