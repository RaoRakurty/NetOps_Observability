---
topic: auth.ldap
question: How does LDAP sign-in work?
keywords: ldap, active directory, bind, directory groups, role mapping
---
The platform binds to your directory over LDAP (RFC 4511) using a service
account, finds the user with your filter, and then reads their group
memberships. Each directory group you map names a platform role; when a user
is in several mapped groups the highest-privilege match wins. Users in no
mapped group get the default role. The bind password is write-only — blank
keeps the stored one.
