---
topic: policy.teams
question: What gets posted to Microsoft Teams?
keywords: teams policy, card per root cause, lifecycle transition, microsoft teams
---
One card per root-cause lifecycle transition — opened, materially updated,
resolved — in this tenant's own Teams channel. Never one per raw alert: a
storm of correlated alerts is still a single problem. Each card leads with the
Problem ID, the verdict and its confidence, the scope and the recommended
action, with a link to the RCA. Connect the webhook in the Teams
channel connection under Integrations; without it a Teams policy has nowhere
to deliver.
