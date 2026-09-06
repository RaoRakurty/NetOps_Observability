---
topic: cloud.remediation
question: Where do I fix a source that is off?
keywords: remediation, connector, iam permissions, log bucket
---
At the connector, not here. A source that is off, stale or permission-denied
is fixed where the cloud account is configured: IAM permissions, whether the
source is enabled in the provider, and the log-bucket settings all live there.
The platform never fabricates a missing signal to cover the gap, which is why
the chip stays honest until the connector is fixed.
