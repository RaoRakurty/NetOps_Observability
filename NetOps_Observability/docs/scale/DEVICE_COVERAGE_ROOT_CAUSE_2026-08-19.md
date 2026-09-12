# The 927/1000 device-coverage gap — root cause

Diagnostic run `08192206q18i`, cleanup disabled, code frozen at `6b24f9a3`
(product) / `4e8c11a6` (harness). **Fully explained, and the explanation is a
product defect, not a test artefact.**

Three earlier explanations were wrong and are retired:

* *"backlog variance"* — the generator is strictly round-robin
  (`created_ids[(seq + j) % 1000]`), so every device appears within the first
  1000 events. Coverage cannot depend on how far the consumer got.
* *"something in `handle()`"* — the identical workload driven in-process gives
  **1000/1000**, 60 rows each, zero refusals.
* *"the cleanup refusals"* — those happen after accounting, and are a separate
  (real) finding.

## The measurement that settled it

Sampled during drain, while the backlog was still 480k:

```
ts        devices  rows     lag
22:17:48      927  109611  482268
22:18:54      927  116319  475914
```

Rows climb, device count is **pinned at exactly 927**. So 73 specific devices
never produce anything — it is not a timing effect.

The missing indices are **927–999: a contiguous tail**, the last 73 created.

## Root cause

`/data/enrichment/device_tenant.csv` at the moment of failure — 2000 rows:

| rows | content |
|---|---|
| 927 | `mlx-08192206q18i-00000 … 00926` — *this* run |
| **73** | **`mlx-081803170rns-00927 … 00999` — the 2026-08-18 run** |
| 1000 | `198.18.x.y` addresses |

The 2026-08-18 mini-ladder is the run whose cleanup crashed:

```
miniladder: WARNING: cleanup raised: TimeoutError('timed out')
miniladder: [FAIL] cleanup — cleanup crashed: TimeoutError('timed out')
```

It left its last 73 devices behind. The ladder derives a device address
deterministically from its index — `198.18.{i//250}.{i%250+1}` — so the stale
device at index *i* and this run's device at index *i* **share an IP**.

`dedupeDevices` (`internal/discovery/discovery.go:280`) runs union-find over
identity tokens, and `DeviceIdentities` includes the IP. Two devices with the
same address are therefore merged into one record. The candidate ids are
`sort.Strings`-ordered, so `mlx-0818…` sorts before `mlx-0819…` and **the stale
device deterministically wins the merge**. That is why 927 reproduced to the
digit across runs.

Consequence chain:

1. This run POSTs 1000 devices. All return **201 Created**.
2. 73 of them are merged away; the store holds 1000 devices, 73 under the *old*
   names. (Proof: if both survived it would hold 1073 names — it holds 1000.)
3. The enrichment export writes the surviving names, so the registry never
   learns `mlx-08192206q18i-00927…00999`.
4. Every syslog event from those 73 hostnames is unattributable forever.
5. No `corr_signal` is ever produced for them → **927/1000**.

## The defect worth fixing (filed as tracker 161)

Merging two records that share an IP is defensible — same IP usually is the same
device. **Returning `201 Created` for a device whose identity did not survive is
not.** The handler echoes the caller's own object back
(`writeJSON(w, http.StatusCreated, d)`), so the caller is told its device exists
under the name it chose. It does not, it is not retrievable under that name, and
everything keyed on that hostname is silently dropped downstream.

In a real deployment this is the re-provisioning case: replace a switch, give it
a new hostname on the same management IP, and its syslog is refused
indefinitely while the API reports success.

The fix is about honesty, not about disabling dedupe: a create whose identity is
absorbed must tell the caller — `200` with the surviving record, or `409` — and
the response must carry the identity that actually survived.

## Secondary findings from the same evidence

* **The burst's registry gate counts instead of verifying.** It waits for
  `registry_identities >= baseline + len(created_ids)`; the total reached 2000
  while 73 of *this run's* identities were absent. A count cannot prove the
  right identities are present.
* **`onboard` reports `devices_created: 1000` from HTTP status alone**, so the
  harness inherits the API's false success.
* **Stale residue from a failed cleanup silently corrupts later runs.** Nothing
  checks for it at preflight.

## Evidence preserved

`device_tenant_at_failure.csv`, `coverage_over_time.csv`, `present.txt`,
`FREEZE.txt` (build/image/container identity, BUS_PARTITIONS=4, 4 partitions),
`ladder_diag.log`, run dir `data/miniladder/20260819T220640Z-08192206q18i/`.
