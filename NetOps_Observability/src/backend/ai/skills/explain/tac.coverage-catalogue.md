---
topic: tac.coverage-catalogue
question: What does the Knowledge page cover?
keywords: knowledge page, coverage catalogue, vendor dialect, issue class, command intent, bound intents
---
Knowledge is what Correlix can plan and collect for each vendor dialect when an
incident is escalated. A dialect is one platform's command language — Cisco
IOS-XE and Junos are different dialects even where the question is the same. An
issue class is a symptom worth investigating; a command intent is one question
inside it ("which OSPF neighbours are up"). A dialect binds an intent when a
command on that platform answers it. The catalogue is version-pinned reference
data, identical for every tenant, and it says what is NOT bound as plainly as
what is: an unbound intent, an unverified command and an unplanned platform are
all named rather than left as a clean-looking blank.
