---
topic: tac.connector.portal-fortinet
question: Why does Fortinet need the portal, and what do I configure?
keywords: fortinet forticare, fortinet ticket, execute tac report, fortinet portal
---
Fortinet publishes no case API. FortiCare's documented API family covers
assets, registration and licensing only, and its guide has no API section for
tickets. Checked 2026-09-05; FNDN is login-gated, so a private API cannot be
disproven, only shown to be undocumented. This path is chipped Manual, never
Ready: configuration cannot bring an API a vendor does not publish. What it does
bring is yours — the portal your contract routes you to, a support mailbox, your
support account, and the shape of a case number. Set those on Administration →
Ticket delivery. The device's own `execute tac report` bundle is still attached
by a human, and files are deleted 30 days after the ticket closes.
