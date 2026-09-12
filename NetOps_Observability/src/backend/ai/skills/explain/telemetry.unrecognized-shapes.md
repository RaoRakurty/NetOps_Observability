---
topic: telemetry.unrecognized-shapes
question: What are unrecognized message shapes?
keywords: unrecognized shapes, unrecognized message, masked template, admitted lines, no parser rule, catalog row, draft proposal
---
These are lines admitted from your devices over the last seven days that no
parser rule claimed. Identical messages differing only in values — hostnames,
counters, interface names — are grouped into one masked template, so a shape is
a pattern rather than a single log line. A shape with a high count is telemetry
the platform is receiving but cannot use yet. Drafting a catalog row turns one
shape into a proposed rule for review; it never applies a rule. Landing it
still needs a pull request.
