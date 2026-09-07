---
topic: tac.connector.email-arista
question: How does Correlix open an Arista TAC case?
keywords: arista support email, arista tac, arista case ref id, support at arista
---
Email is the only path Arista publishes, so Correlix sends the case to
support@arista.com through your tenant's own SMTP relay — it opens the case and
attaches the bundle in one message. Arista asks for the problem description, a
compressed show tech-support, network diagrams, and a named contact; the bundle
and the case text cover the first three, and you supply the contact. To add to a
case that already exists, keep the case Ref. ID in the subject line: Arista
files the mail against that case automatically. The email profile trims the
bundle to about 14 MB so it survives mail gateways, because base64 expands an
attachment on the wire. Checked 2026-09-05.
