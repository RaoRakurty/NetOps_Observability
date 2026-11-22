---
topic: paths.data
question: Where does the Paths page get its data?
keywords: path data, paths sources, path discovery off, tunnels empty, wan sla dash
---
The Path column comes from path discovery: the prober traces the targets your
workspace marked "trace the path" (Path data, What gets traced), and a
platform administrator turns it on under Platform, Features. Each path sits on
the WAN circuit or tunnel row it measures. Path SLA (delay, jitter and loss each way) comes from
the path SLA probes, on the same switch page. Tunnels come from your SD-WAN
controller once it is connected under Infrastructure, NMS Integrations; their
quality is the controller's own reading, 30 to 60 minutes behind. WAN circuit
SLA uses the same probes. A dash means nothing measured it, not that it is
healthy.
