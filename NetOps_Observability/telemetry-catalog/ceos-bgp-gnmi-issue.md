# Issue: cEOS leaf BGP session-state not delivered via persistent gnmic subscription

## Symptom
In the running gnmic container (netops-gnmic-1 on .122), canonical metric
`device_bgp_peer_state` appears for **spine1/spine2 (Nokia SRL)** and **wan-r2
(cEOS)** but NEVER for **leaf1-4 (cEOS)** — even though the leaves' INTERFACE
telemetry streams fine from the same subscription. 10 BGP series present, the
4 leaves contribute 0.

## Environment
- gnmic: netops-gnmic-1, host 10.70.245.122, config /app/gnmic.yaml
- cEOS (4.36.0.1F, insecure gNMI :6030): leaf1-4 = 172.40.40.21-24, wan-r2 = .32
- SRL (:57400): spine1/2 = 172.40.40.11/12
- OpenConfig BGP path:
  /network-instances/network-instance[name=default]/protocols/protocol[identifier=BGP][name=BGP]/bgp/neighbors/neighbor/state/session-state
- Subscription oc-interfaces: stream / sample / 30s, paths = 3 interface paths + the BGP path above

## Reproductions that WORK (data IS available from the leaves)
1. GET leaf1 BGP:
   gnmic -a 172.40.40.21:6030 -u admin -p $EOS_GNMI_PASS --insecure get \
     --path "<BGP path>"   => 10.0.0.1 & 10.0.0.2 = ESTABLISHED
2. Standalone single-target SUBSCRIBE leaf1 (sample 5s): ESTABLISHED streams every interval.
3. Standalone MULTI-target subscribe leaf1 + wan-r2, bundled iface+bgp, sample 15s, 35s:
   6 ESTABLISHED (leaf1) + 3 ACTIVE (wan-r2) — both deliver.

## Reproduction that FAILS
- The persistent container (all 7 targets): leaf BGP = 0 series in VictoriaMetrics,
  not even at subscribe-sync time. spine + wan-r2 BGP = 10 series present.

## Ruled out (traced hop-by-hop)
- WIRE: leaf1 and wan-r2 route identically from gnmic (via 172.18.0.1 dev eth0), both pingable.
- CONCURRENCY: standalone multi-target (leaf+wan-r2 together) works.
- BUFFER: global buffer-size bumped 100 -> 5000, no change.
- MODE: on-change, on-change+heartbeat-60s, sample-30s all tried — leaves never deliver.
- BUNDLING: BGP as its own named subscription AND folded into the interface
  subscription (one stream) — both fail for the leaves.

## Key discriminator (the live signal)
wan-r2's peer 192.168.100.5 is **ACTIVE** (constantly changing). The leaves'
peers 10.0.0.1/.2 are **ESTABLISHED** (static). The leaves' INTERFACE counters
(always changing) stream fine. => Only STATIC/unchanged state on the leaves goes
missing under the persistent subscription.

## Leading hypothesis
cEOS lazy / incomplete OpenConfig state streaming: under a long-lived multi-target
SubscribeRequest it omits the unchanged session-state leaf for ESTABLISHED
neighbors, but emits it (a) in a fresh short-lived subscription and (b) for
transitional (ACTIVE) neighbors. wan-r2 works because its peer keeps changing.

## Next diagnostics to try
1. Arista NATIVE EOS model path for BGP (eos_native) instead of OpenConfig.
2. Explicit updates_only=false / suppress_redundant=false on the subscription.
3. Fresh gnmic subscribed ONLY to the 4 leaves (persistent) vs full 7-target —
   isolate leaf-specific vs total-target-count/load.
4. On leaf1: `show management api gnmi` + EOS gNMI/Octa agent logs for sub state.
5. Diff leaf cEOS agent/version vs wan-r2.

## UPDATE 2 (2026-06-13, further diagnostics)
More hypotheses ELIMINATED:
- PAYLOAD SIZE ruled out: leaf1 and wan-r2 have the SAME interface count (4 each).
  The "leaves have many interfaces crowding out BGP" theory is dead.
- LAZY/OVER-TIME STREAMING ruled out: standalone leaf1 delivers ESTABLISHED every
  sample cycle (10 updates / 45s, sample 10s) and at on-change sync (4 / 65s). It
  does NOT fall silent over time.
- NEVER-IN-CONTAINER confirmed: leaf BGP = 0 from t+20s right after container
  restart through t+120s (earlier appear-then-vanish test) — it never appears,
  not "appears then stops".

REFINED CONCLUSION: not device payload, not timing, not lazy streaming. Standalone
gnmic (every mode/bundling/concurrency) delivers leaf established BGP immediately
and repeatedly. ONLY the persistent multi-target gnmic CONTAINER never delivers
leaf BGP — while it DOES deliver leaf interfaces and wan-r2 BGP. So the fault is
specific to how the long-lived, config-file, 7-target gnmic process handles the
leaf targets' BGP path (gnmic-internal subscription handling) OR a cEOS gNMI agent
behavior triggered only by the sustained multi-target session.

## Best next diagnostics (in priority order)
1. gnmic per-target/per-subscription PROMETHEUS metrics (enable gnmic api-server +
   /metrics): compare received-message counts for leaf BGP vs wan-r2 BGP vs leaf
   interfaces — proves whether gnmic RECEIVES leaf BGP and drops it, or never gets it.
2. pcap the gRPC between gnmic and leaf1 (tcpdump on the gnmic netns / clab bridge);
   inspect whether SubscribeResponse for the BGP path is on the wire from the leaf.
3. Minimal-repro container: a second gnmic instance with ONLY the 4 leaf targets
   (config-file, persistent) — does leaf BGP appear? Isolates target-count/load.
4. Try encoding proto vs json_ietf for the leaf BGP subscription in the container.
5. On the leaf device: cEOS `show management api gnmi` + EOS gNMI/Octa agent logs
   for the active subscription state on the established-neighbor leaf.
6. Diff the cEOS gNMI agent version/state between a leaf and wan-r2.

## UPDATE 3 (2026-06-13) — KEY ISOLATION RESULT
ISOLATED config-file persistent gnmic, 4 leaves ONLY, BGP as its OWN single-path
subscription (sample 10s, 35s, output=file): **WORKS — 32 rows, 8 per leaf, all
ESTABLISHED.** So: config-file + persistent + leaves + BGP-path are ALL FINE in
isolation. The differentiator vs the main container is therefore one of:
  (a) BGP bundled as a 4th PATH inside the multi-path interface subscription, OR
  (b) the 7-target mix / total subscription load in the main container.
Test config saved: /tmp/leaf-bgp-test.yaml (own-sub, WORKS),
/tmp/leaf-bgp-test2.yaml (BGP bundled into iface multipath — NOT yet run).

## DIAGNOSTIC PLAN (owner-directed order, in progress)
1. gNMIc api-server /metrics on MAIN container, BGP split into its OWN sub
   (oc-bgp/srl-bgp) so per-subscription counters isolate BGP. Compare received
   msg/update counts: leaf1 BGP / leaf1 ifaces / wan-r2 BGP / spine BGP.
   3-stage split: device-sends? gnmic-receives? lost-in-processor/output?
2. If received-not-emitted -> processor/normalization/output focus.
   If not-received -> minimal-repro 4-leaf container (started above: WORKS for
   own-sub, so next is the BUNDLED-path variant test2.yaml).
3. Raw-receive vs normalization split.
4. Update catalog fidelity row (KEEP degraded until persistent path validated).
5. THEN Phase 2 catalog expansion.

## CONFIG STATE
Main gnmic.yaml backed up to /tmp/gnmic.yaml.prebgpmetrics before the metrics
edit. Mid-edit when classifier hiccup hit — VERIFY gnmic.yaml state on resume
(api-server block + oc-bgp/srl-bgp subs + target sub-lists), audit must be green.

## UPDATE 4 (2026-06-13) — *** ROOT CAUSE STAGE IDENTIFIED via gNMIc /metrics ***
Enabled gnmic api-server :7890 /metrics, split BGP into own sub (oc-bgp/srl-bgp).
gnmic_subscribe_number_of_received_subscribe_response_messages_total:
  leaf1 oc-bgp=7   leaf2 oc-bgp=7   leaf3 oc-bgp=7   leaf4 oc-bgp=7
  wan-r2 oc-bgp=4  spine1 srl-bgp=9  spine2 srl-bgp=9
  leaf1 oc-interfaces=107 (etc)

=> STAGE 1 (cEOS sends leaf BGP): PASS. STAGE 2 (gnmic RECEIVES leaf BGP): PASS
   (7 msgs/leaf — matches 2 established peers x ~3 cycles + sync).
   THE FAILURE IS STAGE 3: received-but-not-emitted. NOT a cEOS/device issue,
   NOT a wire issue, NOT a gnmic-receive issue. Lost in PROCESSOR/OUTPUT.

Further split of Stage 3:
- RAW lane (gnmi_* victoria output, metric-prefix gnmi, NO processors): has ZERO
  BGP session-state for EVERYONE (incl. spine/wan-r2 that DO appear in canonical).
  Reason: session-state value is a STRING ("ESTABLISHED"); prometheus remote-write
  can only write NUMERIC — raw lane silently drops all string BGP. So the raw lane
  is not a useful comparator here; the canonical lane (enum->int) is the only BGP path.
- CANONICAL lane: spine1=5, spine2=4, wan-r2=1 BGP devices present; LEAVES ABSENT.

So: leaf BGP is RECEIVED by gnmic but DROPPED somewhere in the canonical
event-processor chain or the prometheus_write output — even though wan-r2 BGP
(identical cEOS OpenConfig path+value-type) survives the SAME chain. Only
difference: leaf peers = ESTABLISHED, wan-r2 peer = ACTIVE.

NEXT: dump canonical-chain output to a file to see if leaf BGP events survive
processing; inspect canon-bgp-enums / canon-convert handling; check prometheus_write
failed-write metrics. The bug is now in OUR config/processing, not the device.

## *** ROOT CAUSE CONFIRMED (2026-06-13) — STALE DEVICE TIMESTAMP ***
The leaf BGP events SURVIVE the full canonical processor chain perfectly
(device_bgp_peer_state:6, clean labels {device,peer,vrf,vendor,transport}). They
are dropped at the prometheus_write -> VictoriaMetrics step because of TIMESTAMP.

Per-device BGP event age (now - event.timestamp):
  leaf1-4 : 137 minutes old (EVERY sample)  <- REJECTED by VM as stale
  spine1/2: 0-1 min          <- accepted
  wan-r2  : 1-4 min          <- accepted

ROOT CAUSE: cEOS, for a STABLE *established* BGP session, stamps each sampled
SubscribeResponse with the session's LAST-TRANSITION time (~when it came up, i.e.
when fabric config was pushed ~2h ago), NOT the sample collection time. Nokia SRL
and the transitional (ACTIVE) wan-r2 peer report fresh timestamps, so they land.
VictoriaMetrics prometheus remote-write silently drops samples whose timestamp is
older than its staleness / out-of-order window. => leaf BGP silently vanishes.

Why earlier tests "worked": file output and stdout don't reject on timestamp; only
the TSDB write does. That's why standalone subscribe (to stdout/file) always showed
the data but the container (-> VM) never did.

THE 3-STAGE SPLIT, RESOLVED:
  Stage 1 device-sends: PASS    Stage 2 gnmic-receives: PASS (7 msgs/leaf)
  Stage 3 processor: PASS (events emit correctly from the chain)
  Stage 3b OUTPUT/INGEST: *** FAIL — VM rejects stale-timestamped samples ***

FIX: gnmic prometheus_write output `override-timestamps: true` (stamp with
collection time, not the device's stale value). Trade-off: loses the device's
real event time for static state — acceptable for sampled state (we want "is it
established NOW"); the event PLANE (syslog/notification) keeps true event time.

CATALOG IMPLICATION (foundation): this is precisely the failure class the
fidelity ladder exists for — a path that EXISTS, STREAMS, and NORMALIZES yet is
silently dropped downstream by timestamp semantics. "doc says supported" would
have lied. Only end-to-end live validation (series actually in the TSDB) caught it.
The catalog must validate to the STORE, not just to the collector output.

## *** RESOLVED + VALIDATED (2026-06-13) ***
FIX APPLIED: canon-override-ts processor (event-override-ts, precision ns) prepended
to the victoria-canonical prometheus_write event-processor chain. Stamps collection
time over the device's stale value-timestamp.
RESULT: device_bgp_peer_state now present for ALL 7 BGP targets — leaf1-4 (2 peers
each, established=6) + spine1/2 + wan-r2. 18 peer-series. 
gnmic version 0.46.0. Note: the OUTPUT-level `override-timestamps:` field is NOT a
thing in this version — must use the `event-override-ts` PROCESSOR in the chain.
Catalog row promoted degraded -> live_validated with requires:{output_processor:
event-override-ts} + fixture arista_ceos_4.36_bgp_leaf_established_once.jsonl.
Diagnostic api-server + bgpdiag file output removed; BGP kept as its own
oc-bgp/srl-bgp subscription (works now).
