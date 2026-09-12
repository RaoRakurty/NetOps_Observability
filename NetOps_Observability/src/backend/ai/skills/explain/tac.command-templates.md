---
topic: tac.command-templates
question: What is a command template?
keywords: command template, command set, correlix default, tenant template, review step, based on
---
A command template is the list of commands an escalation can be run from.
Correlix's own defaults are generated from the authored per-dialect plans on
this page and are read-only. Your team's sets are saved from the review step of
an escalation, are visible only to your tenant, and are offered again on the
next escalation for that vendor. A saved set records the default it was forked
from, so opening it shows what your team changed. Every command in either kind
is output-only: nothing that changes configuration, restarts the device or
addresses a daemon is carried, on any platform, in any template.
