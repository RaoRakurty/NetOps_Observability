---
topic: policy.teams-webhook
question: What is this Teams webhook used for?
keywords: teams webhook, workflows webhook, incoming webhook, power automate, tenant own channel
---
This tenant's own Microsoft Teams webhook. Create it in Teams with the
Workflows app ("Post to a channel when a webhook request is received") and
paste the URL it gives you; a classic Incoming Webhook URL also works. It
receives the root causes your Teams incident policies open, cloud incidents
when cloud incident notices are on, and — unless you untick "Also post my own
watches here" — your own watches: BGP prefix alerts on your watchlist and your
cloud monitors, one message when the alert starts and one when it clears.
Nothing else is posted: not device or interface alerts, never another
tenant's. The URL must be https. Write-only: type a new URL to replace it, or
leave it blank.
