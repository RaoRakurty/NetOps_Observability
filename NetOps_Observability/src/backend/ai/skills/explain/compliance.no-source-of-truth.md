---
topic: compliance.no-source-of-truth
question: Why are drift checks inactive?
keywords: no source of truth, declared inventory, intent drift, cmdb not connected
---
Drift compares the observed inventory against a declared one. With no external
Source of Truth connected there is nothing to compare against, so intent-drift
checks are inactive — the internal inventory cannot be drift-checked against
itself. Connect an external Source of Truth under Automation, in read or
two-way mode, to compare registration, name, management IP, serial and
platform. Policy baselines below run regardless.
