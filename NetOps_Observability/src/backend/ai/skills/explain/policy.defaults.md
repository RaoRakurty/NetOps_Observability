---
topic: policy.defaults
question: What happens with no policy?
keywords: default policy, no policy, safe default, opt in destinations
---
ServiceNow gets a safe default: a customer-facing, confirmed fault opens an
incident, while internal, probe-only and undetermined ones are held. Every
other destination is strictly opt-in — no PagerDuty, Slack or Jira policy
means no delivery to them at all. At most one policy may be enabled per
destination; if two are, auto-ticketing is held for the tenant until you
disable one.
