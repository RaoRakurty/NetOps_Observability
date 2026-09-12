---
topic: tac.mailbox-oauth
question: How does Correlix sign in to the mailbox that sends a case?
keywords: mailbox sign in, mailbox oauth, microsoft 365 mailbox, google workspace mailbox, xoauth2, smtp oauth, sign in to the mailbox
---
Pick the one your mail actually runs on. Password relay is an SMTP server that
still takes a username and password — usually on-prem. Microsoft 365 sends
through Graph as one mailbox, using an app registration your Entra admin
consents to Mail.Send; a message there is capped at 3 MB, so a bigger bundle
goes by relay or as a link. Google Workspace sends through Gmail with a service
account granted domain-wide delegation for gmail.send, capped at 25 MB. SMTP
with OAuth keeps your relay and swaps the password for a token from either
issuer. Microsoft and Google have retired password sign-in for most tenants.
Test asks the mailbox one read-only question and sends nothing.
