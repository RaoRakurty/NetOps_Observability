# RCA hero demo — reset between runs

**Short answer: for this demo, `install-correlix.sh reset-demo-data` is the
right reset.** The reasoning below matters, because the other tool that looks
like a reset — `demo_lab.py teardown` — deliberately does **not** delete what
this demo creates.

---

## Which tool, and why

| tool | what it deletes | what it leaves | right for this demo? |
|---|---|---|---|
| **`install-correlix.sh reset-demo-data`** | Brings the stack down and wipes **all of `data/`** — PostgreSQL, ClickHouse, OpenSearch, Kafka, VictoriaMetrics — then reinstalls and restarts. Correlation objects, evidence, logs, flows and metrics all go. | `.env` — **secrets and identity are kept**, so the URL and the login are unchanged after the reset | **Yes.** This demo's state lives in the stores, and only this clears it. |
| `demo_lab.py teardown --run <id>` | Exactly the orgs / tenants / devices recorded in that run's **manifest**, via the API — nothing else, ever | All telemetry: the syslog, flows, metrics and **correlation objects** those devices produced stay in the stores | **No** — unless you also seeded an estate with `demo_lab.py seed`. It removes the inventory, not the incident. |
| `twin.py teardown --runid <id>` | A twin run's own created objects, verified clean | same caveat — the twin's *emitted* evidence remains in the stores | Only if Act 1 used the twin (`twin.py run`). Run it **in addition to**, not instead of, the store reset. |

### Why `demo_lab.py teardown` is not the answer here

`demo_lab.py` is manifest-driven on purpose: it only ever deletes ids it wrote
down at creation time, refuses to touch the Provider/global tenant, and refuses
to delete a device it did not create — so a demo teardown cannot reach real
inventory even if a real device happens to match the naming scheme. That safety
is exactly why it is the wrong reset for the RCA hero demo: the demo's residue
is *telemetry and correlation objects*, which were never in a manifest.

The RCA hero demo is driven by `seed_demo_data.py` + `demo_fill.py`, which push
into ClickHouse / VictoriaMetrics / the syslog and probe intakes directly. They
create no manifest, so there is nothing for a manifest teardown to delete.

---

## The reset

> ### ⚠ `reset-demo-data` destroys every store on the host
>
> It wipes `data/` wholesale. **Never run it on a host that carries real
> customer evidence, a pilot's data, or a scale-run you have not exported.**
> On a demo/lab box it is exactly right; anywhere else it is data loss.

```bash
cd NetOps_Observability

# Source checkout:
scripts/install-correlix.sh reset-demo-data

# Extracted offline bundle (run from the bundle root):
./install-correlix.sh reset-demo-data
```

What it does, in order:

1. `docker compose down --remove-orphans`
2. wipes every entry under `data/` (in a throwaway `alpine` container, so
   ownership does not matter)
3. re-runs `scripts/install.py` on the same `BASE_PORT` (adding `--offline` in
   bundle mode, so images are never rebuilt or re-pulled), which recreates the
   data directories with correct ownership and brings the stack back up
4. waits for health and reports **"Correlix reset — same URL and credentials as
   before."**

**Interactive equivalent:** `scripts/install-correlix.sh` → menu option **9)
Reset demo data**. It requires typing `yes` to confirm.

**Time:** allow several minutes — the stack fully restarts and re-bootstraps
(OpenSearch, Keycloak, Grafana). Do not schedule it inside the 15-minute
pre-flight window; run it **after** a demo, not before the next one.

---

## Between-run sequence

Right after a demo ends:

```bash
cd NetOps_Observability

# 1. stop any still-running generator (Ctrl-C the demo_fill terminal).
#    demo_fill.py is time-boxed by --duration and stops on its own, but a
#    --duration you set long will keep pushing.

# 2. twin only: tear down the twin run first, while the stack is still up
python3 scripts/lab/twin/twin.py teardown --runid <runid>

# 3. demo_lab only: if you seeded an estate for this demo
python3 scripts/demo_lab.py list
python3 scripts/demo_lab.py teardown --run <run-id>

# 4. the actual reset
scripts/install-correlix.sh reset-demo-data

# 5. confirm it came back
scripts/install-correlix.sh status
```

Then re-run the pre-flight block of [`REHEARSAL.md`](REHEARSAL.md) (A1–A13) for
the next demo. Steps 2 and 3 are only needed when Act 1 used those tools; step 4
alone is sufficient for the default `demo_fill.py` script.

---

## When *not* to reset

- **Back-to-back demos to different audiences, same day.** A second injection
  creates a new incident with a new id; the old one simply sits lower in the
  list. Resetting costs you a full stack restart and buys nothing. Reset once at
  the end of the day.
- **Debugging a demo that went wrong.** The residue *is* the evidence. Capture
  it first — the case JSON, the timeline, the logs (see
  `docs/runbooks/pilot-playbook.md` §5) — then reset.
- **On a pilot or customer host.** Never. Use it on demo/lab boxes only.

## If a reset leaves the stack unhealthy

1. `scripts/install-correlix.sh status` — read which service is unhealthy.
2. `scripts/install-correlix.sh logs <service>` — last 200 lines for that one.
3. Most common cause after a wipe is **disk**: the stores rebuild from empty and
   OpenSearch refuses to allocate below its watermark. Check free space first.
4. If `install.py` failed mid-reset, re-run it directly:
   `python3 scripts/install.py --port 8000` (add `--offline` in bundle mode). It
   is idempotent and `.env` was preserved, so credentials do not change.
