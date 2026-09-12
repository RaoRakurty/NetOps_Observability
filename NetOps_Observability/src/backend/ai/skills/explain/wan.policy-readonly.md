---
topic: wan.policy-readonly
question: Why can I read but not change the measurement policy?
keywords: read only policy, infrastructure write access, cannot change policy
---
Changing what the WAN measures changes what the platform probes and what every
downstream verdict is based on, so it needs write access to infrastructure. You
have read access, which is why the current policy is fully visible. An
administrator for this tenant can grant the write permission; nothing about
the policy is hidden from you in the meantime.
