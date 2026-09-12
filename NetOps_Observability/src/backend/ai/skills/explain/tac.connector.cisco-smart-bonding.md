---
topic: tac.connector.cisco-smart-bonding
question: What does Cisco Smart Bonding need before it can open an SR?
keywords: cisco smart bonding, cco id, customer source id, cisco entitlement
---
Smart Bonding opens the SR, attaches the bundle and reads the status back — but
only after a per-customer onboarding project with Cisco, which runs analysis,
implementation, test and go-live. Once it is live you supply your CCO-ID,
the customer source id the project issued, and OAuth credentials. Cisco checks
entitlement on every create: a serial number for hardware, or a contract id plus
PID for software, and the CCO-ID in every case. Correlix will not guess a field
your onboarding named differently, so an unmapped required field fails closed
rather than filing a malformed case. The create response carries the CXD host
and token, so create and attach close the loop. Checked 2026-09-05.
