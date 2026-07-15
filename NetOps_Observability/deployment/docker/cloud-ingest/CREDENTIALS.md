# cloud-ingest — least-privilege credentials (audit P1-15)

The poller is **read-only by design**. This file is the reviewable permission
contract; anything the poller code calls that is not listed here is a bug.

## AWS

Attach `iam-policy-aws.json` (in this directory) to a dedicated IAM user or —
prod shape — a role the poller assumes. What each statement powers:

| Statement | Lane |
|---|---|
| `CorrelixTelemetryInventory` | `discover.py` — inventory + route-table topology |
| `CorrelixTelemetryMetrics` | `cloudmetrics.py` — CloudWatch metric lane |
| `CorrelixTelemetryChangeAudit` | `poller.py` — CloudTrail → cloud_change |
| `CorrelixTelemetryFlowLogs*` | `poller.py` — VPC flow logs (CW Logs or S3 delivery) |

Lab interim: the compose override mounts the host `~/.aws` read-only. That
ambient profile is broader than this policy — acceptable in the lab only; a
production deploy must use a principal carrying exactly this policy.
`ec2:StartInstances`/`StopInstances` are deliberately absent: the telemetry
principal must never be able to change the fleet.

## Azure

**Correlix operates READ-ONLY.** It never requires Contributor, Owner, or
Tag-Contributor, and it never writes to your cloud — tags are optional enrichment
(their absence never fails discovery), and manual service overrides are stored
INSIDE Correlix, never written back as Azure tags. Service inference works with no
tags at all, from resource relationships the read roles already expose.

Service principal (env `AZURE_TENANT_ID` / `AZURE_CLIENT_ID` /
`AZURE_CLIENT_SECRET` / `AZURE_SUBSCRIPTION_ID`), two built-in roles scoped to the
subscription — no custom role needed. Optional capabilities may need one extra
read role; grant them only if you want that enrichment.

### Capability → permission matrix (all reads)

| Capability | Azure action (read) | Built-in role | Required? |
|---|---|---|---|
| Resource inventory | `Microsoft.Resources/subscriptions/resources/read` | Reader | **required** |
| Platform metrics | `Microsoft.Insights/metrics/read` | Monitoring Reader | **required** |
| Resource health | `Microsoft.ResourceHealth/availabilityStatuses/read` | Reader | optional |
| Activity log (changes) | `Microsoft.Insights/eventtypes/values/read` | Monitoring Reader | optional |
| Network topology | `Microsoft.Network/virtualNetworks/read` | Reader | optional |
| Network Watcher | `Microsoft.Network/networkWatchers/read` | Reader | optional |
| Diagnostic settings | `Microsoft.Insights/diagnosticSettings/read` | Reader | optional |
| Resource Graph | `Microsoft.ResourceGraph/resources/read` | Reader | optional |
| Cost management | `Microsoft.CostManagement/query/read` | Cost Management Reader | optional |
| Storage log lanes (VNet flow / LB / WAF / DNS) | `Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read` (data action) | Storage Blob Data Reader | optional |

The storage-log lanes (`azure_logs.py` — VNet flow logs + AppGW/Front Door
access, WAF and DNS `DnsResponse` logs delivered to a storage account) reuse
the SAME service principal with the **storage audience**
(`https://storage.azure.com/.default`) — deliberately no storage account key
and no SAS (no second secret to custody, no hand-rolled SharedKey HMAC).
That is a DATA-plane read: control-plane Reader is **not** sufficient; grant
**Storage Blob Data Reader** scoped to the one logs storage account:

```bash
az role assignment create --assignee <appId> --role "Storage Blob Data Reader" \
   --scope /subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Storage/storageAccounts/<logs-account>
```

A missing OPTIONAL capability is a coverage gap, not a failure — the two required
capabilities are the only hard gate. Correlix never auto-broadens its own grant;
the permission-test harness (`capabilities.py` / `azure_permissions.py`) reports
each capability's live status (Available / Missing permission / Scope not granted /
Not configured / API disabled / Not applicable) so gaps are visible, not silent.

### Grant (owner command, one-off — the two required roles)

```bash
az ad sp create-for-rbac --name correlix-telemetry --role "Monitoring Reader" \
   --scopes /subscriptions/<subscription-id>
az role assignment create --assignee <appId> --role Reader \
   --scope /subscriptions/<subscription-id>
```

### Sample custom read-only role (RBAC JSON)

If you prefer one narrow custom role over the two built-ins, this grants exactly
the required + common-optional reads and NO writes (`notActions`/`notDataActions`
empty; no `*/write`):

```json
{
  "Name": "Correlix Telemetry Reader",
  "IsCustom": true,
  "Description": "Read-only cloud discovery + telemetry for Correlix. No writes.",
  "Actions": [
    "Microsoft.Resources/subscriptions/resources/read",
    "Microsoft.Insights/metrics/read",
    "Microsoft.Insights/metricDefinitions/read",
    "Microsoft.Insights/eventtypes/values/read",
    "Microsoft.ResourceHealth/availabilityStatuses/read",
    "Microsoft.Network/virtualNetworks/read",
    "Microsoft.Network/networkInterfaces/read",
    "Microsoft.Network/publicIPAddresses/read",
    "Microsoft.Network/loadBalancers/read",
    "Microsoft.Compute/virtualMachines/read"
  ],
  "NotActions": [],
  "DataActions": [],
  "NotDataActions": [],
  "AssignableScopes": ["/subscriptions/<subscription-id>"]
}
```

Prod shape replaces the env-var secret with the tenant-scoped connector store
(encrypted Vault, Task #15).

## GCP (parity program #105)

Service account key file mounted read-only; env `GCP_PROJECT` +
`GOOGLE_APPLICATION_CREDENTIALS` (both empty = lane self-disabled). Roles,
scoped to the project — read-only, no mutation permission anywhere:

| Role | Lane |
|---|---|
| `roles/compute.viewer` | inventory writer (`gcp.write_inventory`) |
| `roles/monitoring.viewer` | Cloud Monitoring metric lane |
| `roles/logging.viewer` | admin-activity Audit Logs → cloud_change |
| `roles/logging.viewer` (same grant) | log-fidelity lanes (`gcp.poll_log_lanes`): VPC flow volume, Firewall Rules Logging DENIED (the GCP REJECT lane), LB request-log 5xx + Cloud Armor blocks, Cloud DNS query errors — each an explicit opt-in (`GCP_VPC_FLOW_LOGS` / `GCP_FIREWALL_LOGS` / `GCP_LB_LOGS` / `GCP_DNS_LOGS` = `on`) and dependent on the customer having enabled that logging in GCP |

Create (owner command, one-off):

```bash
gcloud iam service-accounts create correlix-telemetry --project <project>
for r in compute.viewer monitoring.viewer logging.viewer; do
  gcloud projects add-iam-policy-binding <project>     --member serviceAccount:correlix-telemetry@<project>.iam.gserviceaccount.com     --role roles/$r
done
gcloud iam service-accounts keys create correlix-gcp.json   --iam-account correlix-telemetry@<project>.iam.gserviceaccount.com
```
