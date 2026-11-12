---
topic: policy.pagerduty-key
question: What is this routing key used for?
keywords: pagerduty routing key, events api v2, tenant own key
---
This tenant's own Events API v2 integration key. It pages for the root causes
your PagerDuty incident policies open, and for cloud incidents when cloud
incident notices are on. Tick "Also page for my own watches" to add your own
watches: BGP prefix alerts on your watchlist (origin change, RPKI invalid,
bogon, route leak, visibility loss) and your cloud monitors — one page when the
alert starts, closed when it clears. Off unless you turn it on. Nothing else
reaches this key: not device or interface alerts, not BGP peer-down, never
another tenant's. Write-only: type a new key to replace it, or leave it blank.
