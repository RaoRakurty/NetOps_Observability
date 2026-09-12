---
topic: snmp.credentials
question: What are these SNMP credentials?
keywords: snmp credentials, community string, snmpv3 usm profile, credential_ref, snmp_community
---
A profile is one set of credentials the collector polls a device with. For
SNMP v1 and v2c that is a community string — a shared password sent with every
poll. For v3 it is a USM profile: a security name plus the authentication and
privacy keys that sign and encrypt the exchange. Assign a profile to a device
through its credential_ref and the collector uses it instead of the global
SNMP_COMMUNITY default, so different device groups can hold different
secrets. Secrets are write-only: they are sent on save, stored encrypted, and
never returned to this screen again.
