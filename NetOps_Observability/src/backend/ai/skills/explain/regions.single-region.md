---
topic: regions.single-region
question: Why does every region show as local?
keywords: single region, local stack, regional deployment, region routing
---
Every region on this installation currently routes to the local stack, so the
topology shows one data plane. The model is already the real one: to stand up
a genuine region you point that region's data plane at a regional deployment
and the routing layer sends its tenants there. No code change is involved —
the region rows, the tenant-to-region mapping and the per-region data planes
are already how requests are routed.
