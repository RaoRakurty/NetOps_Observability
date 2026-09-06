---
topic: threats.scan-signature
question: What counts as a scan signature?
keywords: scan signature, horizontal scan, vertical scan, fan-out threshold
---
A single source touching many distinct hosts is a horizontal scan; one touching
many distinct ports on a host is a vertical scan. Both are counted from flow
records (IPFIX or NetFlow) already collected, so nothing new is captured. Bars
turn red past twenty-five distinct targets — a starting threshold, not a
verdict; tune it to what is normal in your environment. Backup servers, scanners
and monitoring hosts legitimately fan out.
