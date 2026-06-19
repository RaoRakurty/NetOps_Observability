---
name: rca-demo-review
description: Run a final enterprise demo-readiness review on RCA Inspector UI changes. Use before demo screenshots or commits.
---

# RCA Demo Review

Review the current RCA Inspector changes for demo readiness.

Check:
1. Operator View is concise.
2. RCA title matches evidence.
3. No "Correlix observed/needs/confirmed" language in Operator View.
4. NOT CONFIRMED objects do not say "Likely fault location."
5. "BGP session up" is not used as RCA evidence wording.
6. Ticket wording says "impact not confirmed" when appropriate.
7. Confirmation checklist has multiple valid paths.
8. Active/test checks do not confirm customer impact.
9. Debug values such as strength, raw IDs, topology tokens are hidden from Operator View.
10. The page can be understood in under 10 seconds.

Return:
- PASS/FAIL
- top 5 wording issues
- exact replacement strings
- files/components likely needing changes
- tests to add/update
