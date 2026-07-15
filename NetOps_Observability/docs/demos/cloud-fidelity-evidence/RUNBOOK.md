# Cloud Demo — executable fault-campaign runbook

Copy-pasteable inject/revert for the 7 scenario families × 3 providers from
`docs/design/cloud-demo-traffic-program.md` §3. Every inject is **revertible**;
every revert is **verified** before the next scenario. Commands are derived from
the real IaC in `correlix-faultlab-iac/environments/edge-demo` (module resource
names below). This runs during the **live capture window** — instances up,
owner-driven. **Nothing here applies Terraform** (surgical CLI injects only);
the only exception is noted (WAF has an IaC-var alternative).

> **Honesty (program §7):** a screenshot enters the evidence book only from a
> real injection on real infra. If a lane is blocked/absent, record it as a gap
> in `01-inject.md`, don't paper over it.

---

## 0. Pre-flight — fetch the post-apply values (fill the placeholders)

Run once after `terraform apply`, from `environments/edge-demo`. These IDs are
only knowable post-apply; every `<PLACEHOLDER>` below maps to one of these:

```bash
cd correlix-faultlab-iac/environments/edge-demo

# --- endpoints the traffic generator targets (DNS off = default) ---
terraform output -raw aws_alb_dns_name          # <AWS_ENDPOINT>
terraform output -raw azure_frontdoor_hostname  # <AZURE_ENDPOINT>
terraform output -raw gcp_lb_ip                 # <GCP_ENDPOINT>
#   (with enable_public_dns=true, use *_app_fqdn instead)

# --- AWS ids (region default us-west-2) ---
export AWS_REGION=us-west-2
AWS_ACL_ID=$(aws wafv2 list-web-acls --scope REGIONAL --region $AWS_REGION \
  --query "WebACLs[?Name=='correlix-edge-acl'].Id" --output text)              # <AWS_ACL_ID>
AWS_APP_ID=$(aws ec2 describe-instances --region $AWS_REGION \
  --filters Name=tag:Name,Values=correlix-edge-app-host-01 Name=instance-state-name,Values=running \
  --query 'Reservations[0].Instances[0].InstanceId' --output text)            # <AWS_APP_ID>
AWS_BACKEND_SG=$(aws ec2 describe-security-groups --region $AWS_REGION \
  --filters Name=group-name,Values=correlix-edge-backend --query 'SecurityGroups[0].GroupId' --output text)
AWS_ALB_SG=$(aws ec2 describe-security-groups --region $AWS_REGION \
  --filters Name=group-name,Values=correlix-edge-alb --query 'SecurityGroups[0].GroupId' --output text)
# AWS_ZONE_ID (only if enable_public_dns): terraform output -raw aws_dns... / route53 list-hosted-zones

# --- Azure (RG is fixed: correlix-edge-demo) ---
export AZ_RG=correlix-edge-demo

# --- GCP (project from tfvars; zone default us-west1-a) ---
export GCP_ZONE=us-west1-a
```

Also note the **lab egress public IP** (the source Correlix demo traffic arrives
from) — run **on the lab client**: `curl -s https://checkip.amazonaws.com`. Call
it `<LAB_IP>` (used by the WAF/DNS-off scenarios).

---

## 1. Ordering & soak (binding — program §3)

Run **per provider**, one fault at a time:

```
3 (LB target)  →  2 (WAF)  →  4 (firewall)  →  1 (DNS)  →  5 (host stop)  →  6 (tunnel)
```

- **≥ 20 min soak** between injections (log-delivery latency: ALB access logs
  ~5 min, VPC/VNet flow logs to blob/S3 up to ~10 min; GCP LB/fw logs ~1-2 min).
- **Revert-verify before the next**: after each revert, confirm the traffic
  generator summary returns to `2xx` and the Correlix lane clears (`05-recovery`).
- Suggested provider order (program §6): **GCP → AWS → Azure**.

### Capture at each step (harness = `scripts/lab/evidence-capture/`)

```bash
# at fault peak:
./capture-scenario.sh <prov> <scenario-dir> all        # 03-signal + 04-rca
# after revert + soak:
./capture-scenario.sh <prov> <scenario-dir> recovery   # 05-recovery
# log-lane zoom (type the lane query into Log Search first):
node capture.mjs --route '#/logs/logs' --selector '.main' \
  --out ../../docs/demos/cloud-fidelity-evidence/<prov>/<scenario-dir>/03-correlix-signal.png
```

`<scenario-dir>` ∈ `3-lb-target 2-waf 4-firewall 1-dns 5-host-stop 6-tunnel 7-console-pivot`.

---

## Scenario 3 — LB target kill (`3-lb-target`)

Host stays **up**; app serves 500 on `/` while `/health` stays 200, so the LB
keeps the target "healthy" yet logs 5xx from it → the **LB-vs-target blame
split**. Driven by the traffic generator (no cloud API needed) — identical for
all three providers.

| | Command (run on the lab client, in `scripts/lab/cloud-edge-traffic/`) |
|---|---|
| **Inject** | `python3 cloud_edge_traffic.py --config endpoints.conf boom <aws\|azure\|gcp>` |
| **Revert** | `python3 cloud_edge_traffic.py --config endpoints.conf heal <aws\|azure\|gcp>` |
| **Verify** | generator summary `5xx` returns to 0; `curl http://<endpoint>/` → 200 |

**Expected Correlix evidence** (§2): `cloud_lb_log` 5xx spike + target-health
degradation; RCA splits LB vs target (app host, not the LB). Client-side
corroboration: the generator summary line shows `5xx` climbing.
Log Search query: `cloud_lb_log AND status:>=500`.

---

## Scenario 2 — WAF misfire (`2-waf`)

Add/flip **one** rule so the WAF blocks **legitimate** demo traffic (403),
proving Correlix names the offending rule. Revert removes exactly that rule.

### GCP — Cloud Armor `correlix-edge-armor`
```bash
# Inject: deny the demo root path (rides the LB request log as a WAF block).
gcloud compute security-policies rules create 900 \
  --security-policy=correlix-edge-armor \
  --expression="request.path.matches('/')" --action=deny-403 \
  --description="DEMO WAF misfire (revertible)"
# Revert:
gcloud compute security-policies rules delete 900 \
  --security-policy=correlix-edge-armor --quiet
```

### Azure — Front Door WAF policy `correlixedgewaf`
```bash
# Inject: Prevention mode + a rule matching the demo URI → Block.
az network front-door waf-policy update -g $AZ_RG --name correlixedgewaf --mode Prevention
az network front-door waf-policy rule create -g $AZ_RG --policy-name correlixedgewaf \
  --name demoMisfire --priority 5 --rule-type MatchRule --action Block --defer
az network front-door waf-policy rule match-condition add -g $AZ_RG \
  --policy-name correlixedgewaf --name demoMisfire \
  --match-variable RequestUri --operator Contains --values "/"
# Revert:
az network front-door waf-policy rule delete -g $AZ_RG --policy-name correlixedgewaf --name demoMisfire
az network front-door waf-policy update -g $AZ_RG --name correlixedgewaf --mode Detection
```
> Verify the CLI group post-apply: for Standard AFD (`azurerm_cdn_frontdoor_*`)
> the current Azure CLI uses `az network front-door waf-policy …`. If your CLI
> version exposes it under `az afd …`, translate accordingly.

### AWS — WebACL `correlix-edge-acl`
```bash
# Inject: add a Block rule matching URI path "/" (SearchString "Lw==" = base64 "/").
aws wafv2 get-web-acl --scope REGIONAL --region $AWS_REGION --name correlix-edge-acl --id $AWS_ACL_ID > /tmp/acl.json
LOCK=$(jq -r .LockToken /tmp/acl.json)
jq '.WebACL.Rules += [{"Name":"DemoMisfire","Priority":0,
  "Statement":{"ByteMatchStatement":{"SearchString":"Lw==","FieldToMatch":{"UriPath":{}},
  "TextTransformations":[{"Priority":0,"Type":"NONE"}],"PositionalConstraint":"STARTS_WITH"}},
  "Action":{"Block":{}},"VisibilityConfig":{"SampledRequestsEnabled":true,
  "CloudWatchMetricsEnabled":true,"MetricName":"DemoMisfire"}}]' /tmp/acl.json > /tmp/acl2.json
aws wafv2 update-web-acl --scope REGIONAL --region $AWS_REGION --name correlix-edge-acl --id $AWS_ACL_ID \
  --lock-token $LOCK --default-action Allow={} \
  --visibility-config SampledRequestsEnabled=true,CloudWatchMetricsEnabled=true,MetricName=correlix-edge-acl \
  --rules "$(jq -c '.WebACL.Rules' /tmp/acl2.json)"
# Revert: re-fetch lock token, drop the DemoMisfire rule, update again.
aws wafv2 get-web-acl --scope REGIONAL --region $AWS_REGION --name correlix-edge-acl --id $AWS_ACL_ID > /tmp/acl.json
LOCK=$(jq -r .LockToken /tmp/acl.json)
jq '.WebACL.Rules |= map(select(.Name!="DemoMisfire"))' /tmp/acl.json > /tmp/acl2.json
aws wafv2 update-web-acl --scope REGIONAL --region $AWS_REGION --name correlix-edge-acl --id $AWS_ACL_ID \
  --lock-token $LOCK --default-action Allow={} \
  --visibility-config SampledRequestsEnabled=true,CloudWatchMetricsEnabled=true,MetricName=correlix-edge-acl \
  --rules "$(jq -c '.WebACL.Rules' /tmp/acl2.json)"
```
> **IaC-var alternative** (whole managed group to enforce, not a single rule):
> `terraform apply -var waf_enforce=true` then `=false` to revert. Note this
> enforces AWS CRS, which does **not** block a plain `GET /`, so it will **not**
> reproduce a legit-traffic block — use the rule above for that.

**Expected Correlix evidence** (§2): `cloud_waf_log` BLOCK spike keyed by
`(ACL, rule=DemoMisfire)`; paired `cloud_change` audit event names the rule;
app-experience drop. Client-side: generator summary `4xx` climbs (403).
Log Search: `cloud_waf_log AND action:BLOCK`.

---

## Scenario 4 — Firewall block (`4-firewall`)

Insert a deny for the app port so the firewall-evidence lane shows REJECT.

### GCP — VPC firewall (`correlix-edge-vpc`)
```bash
# Inject: higher-priority DENY :80 to the backend tag (logged).
gcloud compute firewall-rules create correlix-edge-demo-deny80 \
  --network=correlix-edge-vpc --direction=INGRESS --action=DENY --rules=tcp:80 \
  --priority=900 --target-tags=correlix-edge-backend \
  --source-ranges=130.211.0.0/22,35.191.0.0/16 --enable-logging
# Revert:
gcloud compute firewall-rules delete correlix-edge-demo-deny80 --quiet
```

### Azure — NSG `correlix-edge-nsg`
```bash
# Inject: higher-priority (lower number) Deny inbound :80 from Front Door.
az network nsg rule create -g $AZ_RG --nsg-name correlix-edge-nsg \
  --name demoDeny80 --priority 90 --direction Inbound --access Deny --protocol Tcp \
  --destination-port-ranges 80 --source-address-prefixes AzureFrontDoor.Backend
# Revert:
az network nsg rule delete -g $AZ_RG --nsg-name correlix-edge-nsg --name demoDeny80
```

### AWS — backend SG `correlix-edge-backend` (SGs are allow-only → revoke the allow)
```bash
# Inject: remove the ALB→backend :80 allow (no allow == deny; flow log shows REJECT).
aws ec2 revoke-security-group-ingress --region $AWS_REGION \
  --group-id $AWS_BACKEND_SG --protocol tcp --port 80 --source-group $AWS_ALB_SG
# Revert:
aws ec2 authorize-security-group-ingress --region $AWS_REGION \
  --group-id $AWS_BACKEND_SG --protocol tcp --port 80 --source-group $AWS_ALB_SG
```

**Expected Correlix evidence** (§2): `cloud_flow_log` REJECT rollup naming the
rule/port + paired `cloud_change` event. GCP needs the **rule log** (flow logs
carry no deny records — the module ships a logged deny-all for exactly this).
Client-side: generator summary `fail` climbs (connection refused/timeout).
Log Search: `cloud_flow_log AND action:REJECT`.

---

## Scenario 1 — DNS fault family (`1-dns`) — Route 53 / Azure DNS / Cloud DNS

DNS is a **first-class, thoroughly-covered** test family, not one row. For each
provider's DNS service run the applicable cases below; **every case asserts BOTH
the `cloud_dns_log` signal AND that the paired provider change event correlates**
in Correlix:

- AWS Route 53 change → **CloudTrail** `ChangeResourceRecordSets` → `cloud_change`
- Azure DNS write → **Activity Log** (`Microsoft.Network/dnszones/.../write|delete`) → `cloud_change`
- GCP Cloud DNS change → **Audit Logs** `dns.changes.create` → `cloud_change`

Case types (each revertible):
1. **NXDOMAIN burst** (client-side) — query a non-existent name in the zone.
2. **Record deletion / blackhole** — remove the app record; RCA names the record.
3. **Record misdirection** — repoint to a wrong/valid-but-unreachable IP (DNS
   *resolves* but the target is wrong — distinct failure mode from #2).
4. **Health-check failover flip** (AWS Route 53) — trip the failover.
5. **TTL / propagation** — see the pre-flight note (governs soak & revert speed).

Most cases (2,3,4) require `enable_public_dns=true` (a public zone must exist to
log queries/changes); case 1 also needs the zone so the provider's authoritative
resolver logs the NXDOMAIN. If DNS is off, only the client-side lookup-failure
corroboration is available (no provider `cloud_dns_log`) — record that as a gap.

Sub-ordering within the DNS slot (least→most disruptive, ≥20 min soak, revert
each before the next): **1a NXDOMAIN → 1c misdirection → 1b deletion →
1d failover (AWS)**.

### 1e (pre-flight) — TTL / propagation note (do this BEFORE the campaign)

Record TTL sets how long a stale/blackholed answer lingers and how fast a revert
propagates. The modules provision **TTL = 60 s** on the mutable records (GCP A,
Azure CNAME); AWS uses an **A ALIAS** to the ALB (no explicit TTL — Route 53
answers with a short TTL derived from the target). Keep TTL low (≤ 60 s) so:
- evidence appears within ~1 soak interval of the inject, and
- revert clears the fault within ~1 TTL.

Soak guidance: allow **≥ 2× TTL + the DNS query-log delivery lag** (Route 53
query logs ~a few min; Cloud DNS `dns_queries` ~1-2 min; Azure DNS analytics via
diagnostic settings ~5 min) before capturing, and again before declaring revert.

---

### AWS — Route 53  (hosted zone `<AWS_ZONE_ID>`, record `app.<AWS_ZONE_NAME>`)

Baseline record is an **A ALIAS** → the ALB (`evaluate_target_health=true`).

**1a — NXDOMAIN burst** (run on the lab client; no infra change):
```bash
for i in $(seq 200); do getent hosts nx-$RANDOM.<AWS_ZONE_NAME> >/dev/null; done
# Revert: none (client-side only).
```
**1b — Record deletion / blackhole** (UPSERT the ALIAS → a plain A blackhole):
```bash
# Inject (blackhole; also demonstrates the change event):
aws route53 change-resource-record-sets --hosted-zone-id <AWS_ZONE_ID> --change-batch '{
  "Changes":[{"Action":"UPSERT","ResourceRecordSet":{"Name":"app.<AWS_ZONE_NAME>",
  "Type":"A","TTL":60,"ResourceRecords":[{"Value":"192.0.2.1"}]}}]}'
# Revert (restore the ALB ALIAS):
aws route53 change-resource-record-sets --hosted-zone-id <AWS_ZONE_ID> --change-batch '{
  "Changes":[{"Action":"UPSERT","ResourceRecordSet":{"Name":"app.<AWS_ZONE_NAME>","Type":"A",
  "AliasTarget":{"HostedZoneId":"<ALB_HOSTED_ZONE_ID>","DNSName":"<AWS_ENDPOINT>","EvaluateTargetHealth":true}}}]}'
#   <ALB_HOSTED_ZONE_ID> = terraform output -raw aws_alb ... alb_zone_id (module output)
```
> True *deletion* (Action `DELETE`) requires submitting the record's exact
> current RRset; the UPSERT-to-blackhole above is the clean revertible form.

**1c — Record misdirection** (resolves, wrong target — TEST-NET-3 `203.0.113.10`):
```bash
aws route53 change-resource-record-sets --hosted-zone-id <AWS_ZONE_ID> --change-batch '{
  "Changes":[{"Action":"UPSERT","ResourceRecordSet":{"Name":"app.<AWS_ZONE_NAME>",
  "Type":"A","TTL":60,"ResourceRecords":[{"Value":"203.0.113.10"}]}}]}'
# Revert: UPSERT back to the ALB ALIAS (as in 1b revert).
```
**1d — Health-check failover flip** (Route 53 failover routing):
```bash
# NOTE: the aws-public-dns module ships ONE simple ALIAS (no failover pair /
# health check) — this case needs a small setup (or an IaC extension: a PRIMARY
# failover ALIAS with a health check + a SECONDARY record). Ad-hoc, revertible:
HC=$(aws route53 create-health-check --caller-reference demo-$(date +%s) \
  --health-check-config '{"Type":"HTTP","ResourcePath":"/health","FullyQualifiedDomainName":"<AWS_ENDPOINT>","Port":80,"RequestInterval":10,"FailureThreshold":2}' \
  --query 'HealthCheck.Id' --output text)
# Create PRIMARY (alias, tied to $HC) + SECONDARY (blackhole) failover records,
# then TRIP by pointing the health check at /boom (unhealthy) — Route 53 flips to
# SECONDARY, visible in the query log + the ChangeResourceRecordSets change event.
# Revert: delete the failover records, delete the health check ($HC), restore 1-alias.
```
> If you prefer not to set up failover, note that the baseline ALIAS already has
> `evaluate_target_health=true`, so **Scenario 5 (host stop)** demonstrates a
> lightweight "alias stops answering when the target is unhealthy" behavior —
> record that cross-reference instead of a full failover flip, and flag 1d as a
> gap requiring the IaC failover extension.

**Change-event assertion (all AWS DNS cases):** confirm a `cloud_change` row
(source CloudTrail, `eventName=ChangeResourceRecordSets`, the zone id) correlates
with the `cloud_dns_log` signal in the same incident.

---

### Azure — Azure DNS  (zone `<AZURE_ZONE_NAME>`, record `app` CNAME → Front Door)

**1a — NXDOMAIN burst** (lab client):
```bash
for i in $(seq 200); do getent hosts nx-$RANDOM.<AZURE_ZONE_NAME> >/dev/null; done
```
**1b — Record deletion**:
```bash
az network dns record-set cname delete -g $AZ_RG --zone-name <AZURE_ZONE_NAME> --name app --yes
# Revert (recreate the CNAME → Front Door):
az network dns record-set cname set-record -g $AZ_RG --zone-name <AZURE_ZONE_NAME> \
  --record-set-name app --cname <AZURE_ENDPOINT> --ttl 60
```
**1c — Record misdirection** (valid CNAME, wrong/unreachable target):
```bash
az network dns record-set cname set-record -g $AZ_RG --zone-name <AZURE_ZONE_NAME> \
  --record-set-name app --cname wrong-target.example.net --ttl 60
# Revert: set-record --cname <AZURE_ENDPOINT>
```
**1d — Health-check failover**: **N/A for Azure public DNS** — Azure has no
built-in DNS-record health-check failover (that role is Traffic Manager / Front
Door origin health, which the `azure-frontdoor-waf` module already exercises via
health probes). Record 1d as N/A-by-design; the LB/target-kill scenario covers
Azure's failover surface.

**Change-event assertion:** confirm a `cloud_change` row (Azure Activity Log,
`Microsoft.Network/dnszones/CNAME/write|delete`) correlates with the DNS signal.

---

### GCP — Cloud DNS  (managed zone `correlix-edge`, record `app.<GCP_ZONE_NAME>`)

**1a — NXDOMAIN burst** (lab client):
```bash
for i in $(seq 200); do getent hosts nx-$RANDOM.<GCP_ZONE_NAME> >/dev/null; done
```
**1b — Record deletion**:
```bash
gcloud dns record-sets delete app.<GCP_ZONE_NAME> --type=A --zone=correlix-edge
# Revert (recreate → real LB IP):
gcloud dns record-sets create app.<GCP_ZONE_NAME> --type=A --zone=correlix-edge --ttl=60 --rrdatas=<GCP_ENDPOINT>
```
**1c — Record misdirection**:
```bash
gcloud dns record-sets update app.<GCP_ZONE_NAME> --type=A --zone=correlix-edge --ttl=60 --rrdatas=203.0.113.10
# Revert: --rrdatas=<GCP_ENDPOINT>
```
**1d — Health-check failover**: Cloud DNS supports failover **routing policies**
(`gcloud dns record-sets create … --routing-policy-type=FAILOVER …` with a
forwarding-rule health check), but the `gcp-public-dns` module ships a plain A
record (no routing policy). Treat 1d as requiring the routing-policy IaC
extension; until then record it as a gap (Cloud DNS failover routing policy not
provisioned).

**Change-event assertion:** confirm a `cloud_change` row (Cloud DNS Audit Log,
`dns.changes.create`) correlates with the DNS signal. (Admin-activity audit logs
are on by default; ensure the Cloud DNS API audit logs are ingested.)

---

**Expected Correlix evidence (whole family, §2):** `cloud_dns_log`
NXDOMAIN/resolution-failure or wrong-answer spike joins the app symptom; RCA
names the record; the paired `cloud_change` audit event correlates. Client-side
corroboration: the traffic generator summary `fail` climbs (name resolution
error for 1a/1b) or requests reach a wrong host (1c). Log Search:
`cloud_dns_log AND (rcode:NXDOMAIN OR response:SERVFAIL)` (1a/1b), and
`cloud_change AND service:dns` for the change correlation.

---

## Scenario 5 — Host stop (`5-host-stop`)

Stop the app VM. Correlix must show **power_state truth** (stopped ≠ broken):
metrics cease, honest degrade, no false "device down" alarm storm.

```bash
# AWS:
aws ec2 stop-instances  --region $AWS_REGION --instance-ids $AWS_APP_ID
#   revert: aws ec2 start-instances --region $AWS_REGION --instance-ids $AWS_APP_ID

# Azure:
az vm deallocate -g $AZ_RG -n correlix-edge-app-host-01
#   revert: az vm start -g $AZ_RG -n correlix-edge-app-host-01

# GCP:
gcloud compute instances stop  correlix-edge-app-host-01 --zone $GCP_ZONE
#   revert: gcloud compute instances start correlix-edge-app-host-01 --zone $GCP_ZONE
```
> Restarting AWS/GCP gives the app host a **new instance** boot; the app is a
> cloud-init systemd unit so it comes back on its own. On AWS the instance id is
> stable across stop/start (EBS-backed) — re-fetch `$AWS_APP_ID` only if you
> `terraform apply`-replaced the host.

**Expected Correlix evidence** (§2): `cloud_metric`/status → power_state=stopped,
metric series flatline (not "unreachable/critical"); paired `cloud_change`
(StopInstances / Deallocate / instances.stop). Client-side: generator `fail`
(host gone) — but the RCA must attribute to the **stopped host**, not the LB/WAF.

---

## Scenario 6 — Tunnel / underlay fault (`6-tunnel`)

Private plane (Plane B) — reuses the **already-validated** WU underlay-blackhole
drill on the IPsec NVA path (dual-cloud fault lab). No new build here.

```bash
# AWS / Azure (NVA applied): apply the existing WU-drill blackhole on the NVA,
# per the dual-cloud fault lab tooling (correlix-faultlab-iac lab-endpoint / NVA
# route+ICMP blackhole). Revert with the paired heal step.
#   (See netops-dualcloud-faultlab: ICMP allow + underlay blackhole, emitter
#    witness ON, debounced 2-poll — validated PASS 2026-07-13.)
```

**Expected Correlix evidence** (§2): seam blame (BGP/tunnel) + path evidence —
the existing validated family. **GAP:** the GCP NVA is IaC-ready but **not
applied** (owner-gated), so `6-tunnel` for **GCP** is a recorded gap until the
GCP NVA is applied — note it in `gcp/6-tunnel/01-inject.md`, don't fake it.

---

## Scenario 7 — Console pivot (`7-console-pivot`)

**No injection.** Assert that every evidence row deep-links out to the exact
provider console page for the resource.

1. In Correlix, open an incident/finding from a prior scenario
   (`#/monitoring/incidents` or Service View `#/monitoring/appobs`).
2. Click the resource's `cloud_ref` deep-link.
3. Confirm the browser lands on the **specific** AWS / Azure / GCP console page
   for that WAF ACL / LB / SG-NSG-fw-rule / VM.

**Evidence:** `02-provider-log.png` = the landed console page (owner-assisted,
real console session). This is the "operator lands on the exact page" proof.

---

## Placeholder index (all resolved in §0)

| Placeholder | Source |
|---|---|
| `<AWS_ENDPOINT>` `<AZURE_ENDPOINT>` `<GCP_ENDPOINT>` | `terraform output` (§0) |
| `<AWS_ACL_ID>` `$AWS_ACL_ID` | `wafv2 list-web-acls` (§0) |
| `<AWS_APP_ID>` `$AWS_APP_ID` | `ec2 describe-instances` tag (§0) |
| `$AWS_BACKEND_SG` `$AWS_ALB_SG` | `ec2 describe-security-groups` (§0) |
| `<AWS_ZONE_ID>` `<AWS_ZONE_NAME>` `<AZURE_ZONE_NAME>` `<GCP_ZONE_NAME>` | only if `enable_public_dns=true`; `terraform output` / provider list |
| `<LAB_IP>` | `curl checkip.amazonaws.com` on the lab client |
| `$AZ_RG` = `correlix-edge-demo`, `$GCP_ZONE` = `us-west1-a` | fixed / tfvars |
