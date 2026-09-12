---
topic: tac.connector.email-cisco
question: What does the Cisco support-email connector do?
keywords: attach at cisco, cisco attach email, cisco sr attachment, cisco email
---
This path attaches to an existing Cisco SR only — it cannot open one. Correlix
mails the redacted bundle to attach@cisco.com through your tenant's own SMTP
relay, with the SR number in the subject so Cisco files it against that case.
You need an SR that is already open, which means opening it in Support Case
Manager or through Smart Bonding first. The email profile trims the bundle to
about 14 MB so it survives mail gateways. If the bundle is larger than that,
use Cisco CXD instead: it attaches to the same SR and is the only path in this
study with no documented file-size limit at all. Checked 2026-09-05.
