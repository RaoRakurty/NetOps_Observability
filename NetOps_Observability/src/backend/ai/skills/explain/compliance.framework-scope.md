---
topic: compliance.framework-scope
question: Which frameworks are scored?
keywords: framework selection, scoped per customer, add framework, enabled framework
---
Compliance is scoped per customer. A framework is scored only while it is
turned on here; nothing else is assessed on this tenant's behalf. The tenant
runs the NIST 800-53 base plus CIS Controls by default and adds NIST CSF,
HIPAA or PCI DSS deliberately. Scores are computed by projecting each finding's
canonical 800-53 control onto the enabled framework's requirements — a
framework is never a tag on a finding, which is why a framework with no direct
checks can still report. If no selection has been saved, the shipped default
set is shown.
