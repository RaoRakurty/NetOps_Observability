---
topic: snmp.credentials
question: What are these SNMP credentials?
keywords: snmp credentials, community string, snmpv3 usm profile, credential_ref, snmp_community
---
A profile is one set of credentials the collector polls a device with. For
SNMP v1 and v2c that is a community string — a shared password sent with every
poll. For v3 it is a USM profile: a security name plus the authentication and
privacy keys that sign and encrypt the exchange. This is the only place SNMP
credentials live: subnet discovery tries the platform-owned profiles, and a
device it finds is bound, through its credential_ref, to the profile that
answered. A device with no profile falls back to the global SNMP_COMMUNITY
default. Secrets are write-only: they are sent on save, stored encrypted, and
never returned to this screen again.
