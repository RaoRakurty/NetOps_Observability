---
topic: bgp.rdap-record
question: Where does "Who owns this address space" come from?
keywords: rdap, registry holder, whois, address space owner, who owns this prefix
---
The holder and contacts on the BGP Operations ownership card are authoritative
registry data read over RDAP — the regional internet registry's own record for
this address space, not a third-party guess and not a scraped whois mirror. If
a contact looks wrong, the fix is with the registry object, not with this
platform. An empty contact list means the registry returned none, not that the
lookup failed; a failed lookup says so instead.
