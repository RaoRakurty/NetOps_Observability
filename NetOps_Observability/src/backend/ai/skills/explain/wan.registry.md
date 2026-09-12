---
topic: wan.registry
question: What is the endpoint registry?
keywords: endpoint registry, wan endpoints, derived endpoints, interfaces measured
---
The registry is every interface the policy brought into scope — those on a
matched WAN device, plus those directly connected to one — with the address it
carries, the address the far end targets, and what it was derived to measure
to. It is derived, not stored: it fills as those interfaces report an address
and empties if the policy stops matching them. An interface with no target yet
is listed rather than dropped, so the gap is visible.
