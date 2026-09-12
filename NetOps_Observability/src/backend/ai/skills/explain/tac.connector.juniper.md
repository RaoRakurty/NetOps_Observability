---
topic: tac.connector.juniper
question: What does the Juniper Service Case connector need?
keywords: juniper service case, juniper createsr, customer source id, juniper entitlement
---
Juniper's Service Case API opens the case, attaches the bundle and reads the
status back. It is still a Beta API. Per-customer onboarding issues an appId and
a customerSourceID, and the userId must be a registered Customer Service Portal
user. The contact email must be a named human — Juniper rejects shared aliases
like noc@ or support@, so Correlix refuses them before the call rather than
after. Entitlement is hard-checked at create and returns errors 600 to 614 when
it fails. There is a hard limit of 1000 invocations per hour, case search covers
the last 90 days only, and the priority values come from Juniper's own /getlov
list. Checked 2026-09-05.
