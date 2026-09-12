---
topic: tac.connector.jira
question: What can the Jira connector do with a TAC bundle?
keywords: jira connector, jira attachment, jira issue, jira rate limit
---
Jira opens the issue, attaches the redacted bundle and reads the status back,
using the ITSM connection your tenant already has. Which Jira you run changes
both the limit and the API: Cloud defaults to 1 GB per attachment on
/rest/api/3, Data Center to 10 MB on /rest/api/2. Both are instance properties,
so the value your admin configured wins over the default. Jira Cloud also rate
limits writes to 20 per two seconds per issue — which is exactly the
create-then-attach pattern Correlix uses, so a very large escalation can be
slowed but not lost. Pick Data Center or Cloud in Ticket delivery so the right
ceiling is applied. Checked 2026-09-05.
