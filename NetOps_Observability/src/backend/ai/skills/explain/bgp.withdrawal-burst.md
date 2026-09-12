---
topic: bgp.withdrawal-burst
question: What does a burst of withdrawals mean?
keywords: withdrawal burst, routes withdrawn, bgp flap, withdrawals across collectors
---
A withdrawal is a route collector being told the prefix is no longer reachable
that way. One or two are normal churn. A burst of them arriving across many
collectors in the same hour is the signature of an outage or a flapping
session: your announcement stopped, or the upstream carrying it went away. The
churn strip on Route changes plots learned against withdrawn per hour precisely
so that shape is visible. A tall red bar with no matching blue one is the case
to chase first.
