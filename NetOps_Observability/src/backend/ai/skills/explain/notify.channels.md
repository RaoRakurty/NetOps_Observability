---
topic: notify.channels
question: What are notification channels?
keywords: notification channels, delivery, email sms push slack pagerduty
---
Where alerts are delivered: email through your SMTP relay, SMS and push to
phones, Slack, PagerDuty, Microsoft Teams and Amazon SNS. Each channel carries
its own minimum severity, so a channel only sees alerts at or above the level
you set. Channels are platform-global plumbing — one set for the whole
installation — and every secret behind them is write-only.
