---
topic: policy.jira
question: How does Jira delivery work?
keywords: jira policy, issue per root cause, transitioned to done, opt in
---
One deduplicated Jira issue per root cause, updated in place and transitioned
to Done when the fault resolves — never one issue per raw alert. Jira policies
are strictly opt-in: with no Jira policy enabled, no issue is ever created.
Connect the Jira site, project and API token under Incident Response →
Integrations first; the policy decides what reaches it.
