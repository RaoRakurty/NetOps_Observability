---
topic: vulns.feed
question: How do I load an advisory feed?
keywords: advisory feed, vulnerability feed, nvd feed, load a feed, kev catalog
---
Nothing is bundled or downloaded automatically, so the stack keeps working
offline: you supply the advisory data. Download one or more NVD yearly feeds
(nvdcve-2.0-YEAR.json.gz from nvd.nist.gov/feeds/json/cve/2.0/), optionally add
the CISA KEV catalog to flag actively exploited CVEs, then run
scripts/vuln-feed-prepare.py over them. The feed hot-reloads — the board lights
up on its next refresh with no restart. Re-run the script periodically to pick
up new advisories. Until a feed exists the platform reports "cannot assess",
never a clean fleet.
