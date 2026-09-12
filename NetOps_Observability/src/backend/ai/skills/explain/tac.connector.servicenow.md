---
topic: tac.connector.servicenow
question: What can the ServiceNow connector do with a TAC bundle?
keywords: servicenow connector, servicenow attachment, servicenow incident, com.glide.attachment.max_size
---
ServiceNow opens the incident, attaches the redacted bundle and reads the case
status back, using the ITSM connection your tenant already has — no separate
vendor account. The attachment ceiling is the instance property
com.glide.attachment.max_size, whose default is 1024 MB; your instance's own
value wins, so ask your ServiceNow admin if a large bundle is refused. There is
no chunked or resumable upload, so an attachment either fits in one request or
fails. If you route incidents into ServiceNow by inbound email instead, the
limit is far stricter — 18 MiB for the whole message — and the email bundle
profile exists for exactly that. Checked 2026-09-05.
