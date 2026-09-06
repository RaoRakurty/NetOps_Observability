---
topic: compliance.nothing-to-assess
question: Why is there nothing to assess?
keywords: no devices in inventory, onboard devices, nothing to compare
---
Compliance compares what is running against what is intended, and the inventory
is empty, so there is nothing to run either half against. Onboard devices under
Infrastructure, point a static inventory file at the stack, or connect the
Source of Truth under Automation. Policy baselines such as SNMP strength and
golden OS version run on the inventory alone; drift checks light up once the
Source of Truth is connected.
