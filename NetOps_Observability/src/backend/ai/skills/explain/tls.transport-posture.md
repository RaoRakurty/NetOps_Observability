---
topic: tls.transport-posture
question: What is this transport security posture?
keywords: transport security, tls posture, declared tier, target tier, tls drift, accepted exception
---
Every internal path between two services — api to storage, router to bus,
collector to device — declares a TLS tier and has a target tier. This page
compares the two, adds what a live probe actually observed on the wire, and
lists the paths that drift from their target plus the exceptions someone
accepted in writing. It is read-only: nothing here changes a connection. A
tenant sees only the lanes carrying its own devices' telemetry; the
platform-internal paths are visible to platform administrators only.
