---
topic: policy.slack
question: What gets posted to Slack?
keywords: slack policy, message per root cause, lifecycle transition
---
One rich message per root-cause lifecycle transition — opened, materially
updated, resolved — in this tenant's own channel. Never one per raw alert: a
storm of correlated alerts is still a single thread. Connect the incoming
webhook in the Slack channel connection above; without it a Slack policy has
nowhere to deliver.
