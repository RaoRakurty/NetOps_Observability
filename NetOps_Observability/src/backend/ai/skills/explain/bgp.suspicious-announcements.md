---
topic: bgp.suspicious-announcements
question: What counts as a suspicious announcement?
keywords: suspicious announcement, wrong origin as, hijack, mis-origination, dash not zero
---
Suspicious is a measured definition, not a hunch: an announcement in the window
whose AS path ends on a different AS than the one this resource is currently
seen with. That is the shape of a hijack or a mis-origination. When the tile
shows a dash instead of a number it means we had nothing to compare against —
no current origin is known, or not one update carried an AS path. A dash is
therefore not a zero, and must not be read as a clean result.
