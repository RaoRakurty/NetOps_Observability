---
topic: wifi.bssid-unread
question: Why were the BSSIDs not read?
keywords: bssid not read, bssid read failed, broadcast identities unknown
---
The BSSID read is separate from the access-point read and is allowed to fail on
its own, so a failure there does not take the inventory with it. What each
radio is broadcasting is therefore unknown on this page — it is not a claim
that the radios broadcast nothing. Retry the page; if it keeps failing, the
controller connector is refusing that call specifically.
