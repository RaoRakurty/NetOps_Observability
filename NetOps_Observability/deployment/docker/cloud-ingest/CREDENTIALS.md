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

Service principal (env `AZURE_TENANT_ID` / `AZURE_CLIENT_ID` /
`AZURE_CLIENT_SECRET` / `AZURE_SUBSCRIPTION_ID`), two built-in roles scoped to
the subscription — no custom role needed:

| Role | Lane |
|---|---|
| `Reader` | inventory writer (`write_inventory`), Resource Health |
| `Monitoring Reader` | Azure Monitor metrics, Activity Log |

Create (owner command, one-off):

```bash
az ad sp create-for-rbac --name correlix-telemetry --role "Monitoring Reader" \
   --scopes /subscriptions/<subscription-id>
az role assignment create --assignee <appId> --role Reader \
   --scope /subscriptions/<subscription-id>
```

Prod shape replaces the env-var secret with the tenant-scoped connector store
(encrypted Vault, Task #15).
