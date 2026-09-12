---
topic: admin.tenants
question: What is a tenant?
keywords: tenant, isolation unit, namespace, prod dev split
---
A tenant is an isolation unit inside an organization: its own namespace for
devices, dashboards, alerts, findings and users. Create one only when you need
to split something — production from development, or one region from another.
An organization works perfectly well with no tenants at all. Data never
crosses a tenant boundary: a query made inside a tenant can only ever see that
tenant's rows.
