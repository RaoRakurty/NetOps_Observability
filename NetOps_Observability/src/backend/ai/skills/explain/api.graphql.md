---
topic: api.graphql
question: What can the GraphQL explorer read?
keywords: graphql, typed endpoint, introspection, tenant scoped
---
One typed endpoint over devices, alerts, rules and health, plus schema
introspection. It answers exactly what REST answers and under exactly the same
authorization: results are tenant-scoped, so a query can only reach the rows
the signed-in principal could reach anyway. It is a read surface — nothing
here changes state.
