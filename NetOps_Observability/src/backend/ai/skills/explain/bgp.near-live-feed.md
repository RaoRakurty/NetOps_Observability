---
topic: bgp.near-live-feed
question: How fresh is the BGP update feed?
keywords: near-live, ris live, update feed freshness, ripestat poll, not live
---
Near-live, not live. RIPE's RIS Live is WebSocket-only and no WebSocket client
is on this platform's dependency allowlist, so updates arrive from a bounded,
jittered read of RIPEstat's bgp-updates call every poll interval. The server
holds them in a fixed-size ring per tenant; when the ring wraps before this page
reads it, the page says the list is not continuous rather than pretending it is.
A dedicated BMP receiver — the on-device, truly live path — is a separate item.
