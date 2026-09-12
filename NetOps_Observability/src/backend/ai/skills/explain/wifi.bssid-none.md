---
topic: wifi.bssid-none
question: Why does an access point report no BSSID?
keywords: no bssid reported, controller publishes no bssid, bssid gap
---
The connector read the access points and the controller published no BSSID for
them. A controller that does not publish BSSIDs still serves clients perfectly
well; the platform records the gap and infers nothing from it. Where BSSIDs do
arrive, each one names the WLAN it serves and the radio it sits on, and a stale
row means the connector has not re-observed it inside its freshness window.
