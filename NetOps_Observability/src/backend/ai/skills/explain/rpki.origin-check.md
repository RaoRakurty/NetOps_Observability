---
topic: rpki.origin-check
question: How is the prefix origin check done?
keywords: rpki, roa, route origin authorisation, routinator, validator unreachable, origin check
---
Each prefix is checked against the route origin authorisations, or ROAs,
published in RPKI, read through RIPE NCC's Routinator view. Valid means a ROA
authorises this origin AS for this prefix length. Invalid means an announcement
breaks a published ROA — a possible hijack, or a stale ROA of your own. Not
protected means no ROA covers the prefix at all. A prefix we could not check is
one whose validator was unreachable: that is not a verdict, and it is never
counted as authorised.
