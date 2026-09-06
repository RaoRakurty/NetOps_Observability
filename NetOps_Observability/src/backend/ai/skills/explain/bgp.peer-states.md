---
topic: bgp.peer-states
question: What do the BGP peer state numbers mean?
keywords: bgp peer state, idle connect active opensent openconfirm established, bgp fsm
---
A BGP session walks a fixed sequence, and the metric reports where it is: idle,
connect, active, open sent, open confirm, established. Only established carries
routes. Idle usually means the session is administratively down or is backing
off after a failure; active means it is trying and not succeeding, which is the
state that most often points at reachability or a mismatched address. A session
that keeps cycling is more informative than one that sits still.
