---
topic: tac.connector.portal-fortinet
question: Why is Fortinet a copy-and-paste path?
keywords: fortinet forticare, fortinet ticket, execute tac report, fortinet portal
---
Fortinet publishes no case API. FortiCare's documented API family covers assets,
registration and licensing only; the FortiCare guide's contents list has no API
section and no ticket client_id is documented publicly. So Correlix prepares the
case text and the redacted bundle, and you open the ticket at
support.fortinet.com with a serial number, a request type, a P1–P4 priority and
a description. Fortinet also expects a diagnostic bundle produced on the device
itself, by `execute tac report` or the FortiCare Debug Report in the GUI — the
Correlix bundle supplements that, it does not replace it. Files are deleted 30
days after the ticket closes. FNDN is login-gated, so a private API cannot be
disproven. Checked 2026-09-05.
