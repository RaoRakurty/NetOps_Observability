---
topic: tac.connector.cisco-cxd
question: What is Cisco CXD and what does it need?
keywords: cisco cxd, cisco upload token, support case manager, existing sr
---
CXD is Cisco's Customer eXperience Drive: it attaches a file to an SR that is
already open, and it opens nothing. It needs two things from you, both copied
out of Support Case Manager: the SR number, and the per-case upload token Cisco
mints for it. The token is valid for 72 days, is used once and is never stored
by Correlix — you paste it at the moment you attach. In exchange it is the only
path in this study with no documented file-size limit, so the full bundle
profile goes up untrimmed. To open the SR itself, use Smart Bonding or the
Cisco portal. Checked 2026-09-05.
