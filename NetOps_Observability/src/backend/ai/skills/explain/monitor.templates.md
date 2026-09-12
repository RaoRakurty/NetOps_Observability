---
topic: monitor.templates
question: What are the monitor templates?
keywords: monitor template, guided monitor, alerting monitor, supported signals
---
Each template is a monitor the platform already has the telemetry for, so
choosing one cannot produce an alert rule that will never evaluate. The
template supplies the query and sensible bounds; you supply the threshold, the
scope and how long the condition must hold before it fires. A signal this
install does not collect has no template, which is why the list is shorter than
the list of things a network can do.
