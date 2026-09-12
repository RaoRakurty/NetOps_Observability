---
topic: sso.default-role
question: What happens when no mapping matches?
keywords: default role, no match, federated read only, first match wins
---
The user gets the default role set on the connection. Rules are evaluated top
to bottom and the first match wins, so a user in several mapped groups lands
on the highest rule that matches, not on a merge of them. When no rule matches
at all, the default applies — which is why federated logins arrive read-only
on a connection whose mappings are missing or misspelt.
