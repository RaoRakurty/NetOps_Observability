---
topic: telemetry.parser-coverage-scope
question: Why is parser coverage platform-admin only?
keywords: parser coverage, parser revision, rule inventory, promotion rate, platform admin only, platform global
---
The parser revision, the rule inventory and the semantic promotion rate are one
shared pipeline, not a per-tenant setting: every tenant's syslog and traps go
through the same rules, so these numbers describe the platform, not your
estate. Platform-global plumbing is visible to platform administrators only,
which is why a tenant admin gets this card instead of the numbers. It is an
answer, not an error. Your own unrecognized message shapes are scoped to your
devices and stay visible below with no platform access.
