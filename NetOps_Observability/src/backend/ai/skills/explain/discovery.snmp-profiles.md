---
topic: discovery.snmp-profiles
question: Which SNMP credentials does subnet discovery try?
keywords: subnet discovery credentials, discovery community, profiles discovery will try, sweep refused no profile
---
Subnet Discovery has no community of its own. For each address it tries the
platform-owned SNMP profiles — v1/v2c and v3 — in profile-name order until one
answers, and binds the device it finds to that profile so polling uses the
credential discovery proved works. Tenant-owned profiles are never tried: a
scanned device belongs to the platform until it is assigned. With no platform
profile the sweep is refused rather than guessing "public". Add or change
credentials in Administration → Data sources → SNMP Profiles.
