---
topic: vulns.coverage
question: What does assessed mean here?
keywords: assessed devices, fleet exposure, affected devices, known exploited
---
Devices is every device in the inventory; assessed is how many had a parseable
vendor and OS version to match advisories against. Affected counts devices with
at least one matching advisory, findings counts the device-and-CVE pairs, and
known exploited counts findings listed in the CISA KEV catalog — those are the
ones with confirmed exploitation in the wild and should be fixed first. If
assessed is below devices, read the coverage gaps: nothing was concluded about
the difference.
