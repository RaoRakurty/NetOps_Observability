# Cloud Demo — Terraform templates & deployed components

Every Terraform template used to stand up the tri-cloud edge demo, and the exact
component each one deploys. Derived from the real IaC — do not hand-edit to drift.

- **Source of truth:** separate repo `correlix-faultlab/correlix-faultlab-iac`
  (commit `8a46169`). This file documents it; the `.tf` is authoritative.
- **Environment:** `environments/edge-demo` — composes the per-cloud modules
  behind the `$10` lease reaper (`scripts/edge-demo-ttl.sh`). Local state (so the
  reaper's `has_state` works). Per-cloud `enable_*` toggles in `terraform.tfvars`.
- **This run (2026-07-16):** `enable_aws=true`, `enable_gcp=true`,
  `enable_azure=false` (Azure Front Door forbidden on the Free-Trial subscription
  + westus2 cores 4/4 — account-tier gap, not an IaC fault), `enable_public_dns=false`
  (DNS served by the standing env's durable zones). **59 resources applied.**

## Composition — `environments/edge-demo/main.tf`

| Module block | Template (`modules/…`) | Cloud | Deployed this run |
|---|---|---|---|
| `aws`      | `aws-alb-waf`        | AWS   | ✅ yes |
| `aws_dns`  | `aws-public-dns`     | AWS   | ⬜ off (`enable_public_dns=false`) |
| `gcp`      | `gcp-lb-armor`       | GCP   | ✅ yes |
| `gcp_dns`  | `gcp-public-dns`     | GCP   | ⬜ off |
| `azure`    | `azure-frontdoor-waf`| Azure | ❌ blocked (Free-Trial forbids Front Door) |
| `azure_dns`| `azure-public-dns`   | Azure | ❌ blocked |

Providers pinned: `hashicorp/aws`, `hashicorp/google`, `hashicorp/azurerm`.

---

## AWS edge chain — `modules/aws-alb-waf` (25 resources, self-contained VPC)

The whole public app plane in one module: its own network, an L7 load balancer,
a WAF, a backend app VM, and all three log sinks.

| Component (traffic-chain role) | Terraform resource(s) |
|---|---|
| **Network** — VPC + internet ingress | `aws_vpc.this`, `aws_internet_gateway.this`, `aws_subnet.public`, `aws_route_table.public`, `aws_route.default` (`0.0.0.0/0`→IGW), `aws_route_table_association.public` |
| **Security groups** | `aws_security_group.alb` (:80 from internet), `aws_security_group.backend` (:80 from the ALB SG only — the firewall-scenario deny target) |
| **App VM** (serves `/`, `/health`, `/boom`) | `aws_instance.backend` (`…-edge-app-host-01`) |
| **L7 load balancer** | `aws_lb.this` (ALB), `aws_lb_listener.http` (:80), `aws_lb_target_group.backend`, `aws_lb_target_group_attachment.backend` |
| **WAF** | `aws_wafv2_web_acl.this`, `aws_wafv2_web_acl_association.alb`, `aws_wafv2_web_acl_logging_configuration.this` |
| **Log sinks** (→ Correlix lanes) | `aws_s3_bucket.alb_logs` → `cloud_lb_log`; `aws_s3_bucket.waf_logs` (name forced `aws-waf-logs-*`) → `cloud_waf_log`; `aws_s3_bucket.flow_logs` + `aws_flow_log.vpc` → `cloud_flow_log`. Each with SSE + lifecycle + delivery bucket-policy. |

Buckets created: `correlix-edge-alb-logs-<acct>`, `aws-waf-logs-correlix-edge-<acct>`,
`correlix-edge-flow-logs-<acct>`. Endpoint output: `aws_alb_dns_name`.

---

## GCP edge chain — `modules/gcp-lb-armor` (13 resources)

Global external Application LB + Cloud Armor, its own VPC, backend instance, and
firewall-rule logging. GCP log lanes ride **Cloud Logging** (not buckets), read
project-wide by cloud-ingest (`GCP_LB_LOGS`/`GCP_FIREWALL_LOGS` on).

| Component | Terraform resource(s) |
|---|---|
| **Network** | `google_compute_network.this`, `google_compute_subnetwork.backend` |
| **Firewall** (+ logging) | `google_compute_firewall.lb_health`, `google_compute_firewall.deny_all_log` (logged deny-all → `cloud_flow_log`) |
| **App VM** | `google_compute_instance.backend`, `google_compute_instance_group.backend`, `google_compute_health_check.backend` |
| **WAF** | `google_compute_security_policy.this` (Cloud Armor `correlix-edge-armor`) → `cloud_waf_log` (verdicts ride the LB request log) |
| **L7 load balancer** | `google_compute_backend_service.this` (request logging on), `google_compute_url_map.this`, `google_compute_target_http_proxy.this`, `google_compute_global_address.this`, `google_compute_global_forwarding_rule.this` → `cloud_lb_log` |

Endpoint output: `gcp_lb_ip` (`136.68.5.183` this run). Armor policy output: `gcp_security_policy`.

---

## Azure edge chain — `modules/azure-frontdoor-waf` (19 resources, NOT deployed)

Authored and apply-ready, but **blocked on the Free-Trial subscription** this run
(`azurerm_cdn_frontdoor_profile` → `BadRequest: Free Trial … forbidden for Azure
Frontdoor`; `azurerm_linux_virtual_machine` → westus2 cores 4/4). Listed for
completeness; deploys with a Pay-As-You-Go subscription + a westus2 core-quota bump.

| Component | Terraform resource(s) |
|---|---|
| **Network** | `azurerm_virtual_network.this`, `azurerm_subnet.backend`, `azurerm_network_security_group.backend`, `azurerm_subnet_network_security_group_association.backend` |
| **App VM** | `azurerm_public_ip.backend`, `azurerm_network_interface.backend`, `azurerm_linux_virtual_machine.backend` |
| **Front Door (LB + WAF)** | `azurerm_cdn_frontdoor_profile.this`, `_endpoint`, `_origin_group`, `_origin.backend`, `_route.this`, `_firewall_policy.this`, `_security_policy.this` → `cloud_lb_log` + `cloud_waf_log` |
| **Log sinks** | `azurerm_storage_account.logs`, `azurerm_monitor_diagnostic_setting.frontdoor`, `azurerm_network_watcher_flow_log.vnet`, `azurerm_role_assignment.telemetry_blob_reader` |

---

## DNS templates (not deployed this run — `enable_public_dns=false`)

DNS is served by the **standing env's durable zones** (R53 resolver logging LIVE);
these edge modules are opt-in for a self-contained DNS demo.

- `modules/aws-public-dns` — Route 53 public zone + records + query logging.
- `modules/gcp-public-dns` — `google_dns_managed_zone.this`, `google_dns_record_set.app`.
- `modules/azure-public-dns` — `azurerm_dns_zone.this`, `azurerm_dns_cname_record.app`, `azurerm_monitor_diagnostic_setting.dns`.

---

## Log-sink → Correlix lane wiring

The edge modules write to **dedicated** buckets (`correlix-edge-*`), distinct from
the standing lab's buckets. cloud-ingest reads both via the multi-source poller
(`S3_LOG_SOURCES`, see `docs/design/cloud-ingestion.md §6`) — AWS lanes; GCP lanes
come project-wide from Cloud Logging. Lane map: `cloud_lb_log`, `cloud_waf_log`,
`cloud_flow_log` (+ `cloud_change` from CloudTrail/Audit, `cloud_metric` from host).

## Deploy / teardown

```bash
# from correlix-faultlab/ — plan+confirm+apply, arm the 6h lease + budget guard:
scripts/edge-demo-ttl.sh up 6
# tear down now (else auto-reaps at lease end / budget trip):
scripts/edge-demo-ttl.sh down
scripts/edge-demo-ttl.sh status
```

Key `terraform.tfvars`: `enable_{aws,azure,gcp}`, `waf_enforce` (false=observe-only
baseline; flip for the WAF drill), `enable_public_dns`, `aws_region`,
`gcp_project_id`/`gcp_region`/`gcp_zone`, `ssh_public_key`,
`azure_logs_storage_account_name` (globally unique). Azure auth (SP) +
`TF_VAR_azure_subscription_id` come from `~/.config/correlix/edge-demo-arm.env`;
GCP from `GOOGLE_APPLICATION_CREDENTIALS`; AWS from ambient `~/.aws`.
