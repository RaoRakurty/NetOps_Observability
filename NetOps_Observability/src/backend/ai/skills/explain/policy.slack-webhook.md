---
topic: policy.slack-webhook
question: What is this webhook used for?
keywords: slack webhook, incoming webhook, tenant own channel
---
This tenant's own Slack incoming-webhook URL. It receives the root causes your
Slack incident policies open, cloud incidents when cloud incident notices are
on, and — unless you untick "Also post my own watches here" — your own watches:
BGP prefix alerts on your watchlist (origin change, RPKI invalid, bogon, route
leak, visibility loss) and your cloud monitors, one message when the alert
starts and one when it clears. Nothing else is posted: not device or interface
alerts, not BGP peer-down, never another tenant's. Messages only reach the
channel you point it at. Write-only: type a new URL to replace it, or leave it
blank.
