---
topic: igp.coverage
question: Where do the OSPF and IS-IS adjacency facts on Protocol Monitoring come from, and what does "not collected" mean?
keywords: ospf is-is evidence, not collected, live state, adjacency events, lsdb, spf, needs attention, protocol monitoring
---
Each OSPF or IS-IS tab reads two kinds of evidence. Live state is sampled from
the router (SNMP or gNMI) and says whether an adjacency is up right now. Change
events are the router's own syslog lines and traps; they say when an adjacency
went down or came back, which is how flaps are counted. The chips under the
counts say which of the two is collected here.

"Not collected" means nothing measures that fact, so it is never shown as 0.
"Needs attention" lists adjacencies that are down now, went down as their last
reported change, or flapped in the window.
