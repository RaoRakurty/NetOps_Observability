---
topic: admin.regions
question: What does a region decide?
keywords: region, data residency, data plane, where data lives
---
A region is where a tenant's data physically lives. Each organization has a
home region, and each tenant is routed to that region automatically unless it
carries its own override. The control plane — organizations, identity, access,
tenants and billing — is global; only the data plane is regional. Changing a
tenant's region changes where its future data is written; it does not move
what has already been stored.
