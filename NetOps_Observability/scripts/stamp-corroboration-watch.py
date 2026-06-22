#!/usr/bin/env python3
"""stamp-corroboration-watch.py — live validation harness for the trusted
customer-path STAMP probe corroboration feature (commit fc76f72).

It does NOT inject faults (that's the operator's job — bounce the WAN/DIA link so
BGP flaps AND the prober->reflector path degrades in the same window). It WATCHES
the live stack and tells you, in real time, whether the trusted prober customer-path
probe ever becomes the *decisive* second modality in a CONFIRMED verdict — i.e. a
single corr_object reaching `confirmed` with `active_probe` in trusted_modalities AND
`prober` among the observers. That is the end-to-end proof the feature fires.

Usage:
    NM_USER=admin NM_PASS=... NM_BASE=http://localhost:8000 \
        python3 scripts/stamp-corroboration-watch.py [--target 10.70.245.120] [--interval 15]

Reads creds from env (NM_USER/NM_PASS/NM_BASE) so no secret is hard-coded.
Press Ctrl-C to stop. Prints a one-line status each tick and a loud banner the
moment a probe-corroborated confirmation appears.
"""
import argparse, json, os, sys, time, urllib.request, urllib.error

BASE = os.environ.get("NM_BASE", "http://localhost:8000")
USER = os.environ.get("NM_USER", "admin")
PASS = os.environ.get("NM_PASS", "")


def _req(path, token=None, data=None):
    url = BASE + path
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    body = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=body, headers=headers, method="POST" if data else "GET")
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read().decode())


def login():
    if not PASS:
        sys.exit("set NM_PASS (and optionally NM_USER/NM_BASE) in the environment")
    r = _req("/api/auth/login", data={"username": USER, "password": PASS})
    tok = r.get("token") or r.get("access_token")
    if not tok:
        sys.exit("login failed: " + json.dumps(r)[:200])
    return tok


def metric(token, query):
    try:
        r = _req("/api/metrics/query?query=" + urllib.parse.quote(query), token=token)
        res = (r.get("data", {}) or {}).get("result", [])
        return float(res[0]["value"][1]) if res else None
    except Exception:
        return None


def probe_corroborated(token):
    """Return list of (id, reasons) for CONFIRMED verdicts where the trusted prober
    customer-path probe is a decisive modality (active_probe trusted + prober observer)."""
    hits = []
    try:
        lst = _req("/api/correlations?limit=50", token=token).get("data") or []
    except Exception:
        return hits
    for row in lst:
        if row.get("verdict_tier") != "confirmed":
            continue
        cid = row["correlation_id"]
        try:
            o = _req("/api/correlations/" + cid, token=token)["object"]
            v = json.loads(o.get("hypotheses", "{}"))["ranking"]["hypotheses"][0]["verdict"]
        except Exception:
            continue
        if "active_probe" in v.get("trusted_modalities", []) and "prober" in v.get("observer_coverage", []):
            hits.append((cid, v.get("reasons", [])))
    return hits


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="10.70.245.120", help="probe target host (the reflector)")
    ap.add_argument("--interval", type=int, default=15)
    args = ap.parse_args()

    token = login()
    seen = {cid for cid, _ in probe_corroborated(token)}
    print(f"[watch] base={BASE} target={args.target} interval={args.interval}s")
    print(f"[watch] baseline probe-corroborated CONFIRMED verdicts: {len(seen)}")
    print("[watch] inject a WAN/DIA fault that flaps BGP AND degrades the probe path; "
          "watching for a NEW confirmed verdict citing [control_plane ⊥ active_probe(prober)]…\n")

    tick = 0
    while True:
        tick += 1
        # re-auth every ~40 ticks (access token is short-lived)
        if tick % 40 == 0:
            try:
                token = login()
            except SystemExit:
                pass
        loss = metric(token, f'probe_loss_pct{{target="{args.target}"}}')
        if loss is None:
            loss = metric(token, "probe_loss_pct")
        rtt = metric(token, f'probe_rtt_ms{{target="{args.target}"}}')
        if rtt is None:
            rtt = metric(token, "probe_rtt_ms")
        hits = probe_corroborated(token)
        new = [h for h in hits if h[0] not in seen]
        ts = time.strftime("%H:%M:%S")
        lo = "n/a" if loss is None else f"{loss:.0f}%"
        rt = "n/a" if rtt is None else f"{rtt:.2f}ms"
        print(f"[{ts}] probe loss={lo} rtt={rt} | probe-corroborated confirmed={len(hits)}", flush=True)
        for cid, reasons in new:
            seen.add(cid)
            print("\n" + "=" * 72)
            print("  ✅  PROBE-CORROBORATED CONFIRMED VERDICT — feature fired end-to-end")
            print("      corr_object:", cid)
            for r in reasons:
                print("      ·", r)
            print("=" * 72 + "\n", flush=True)
        time.sleep(args.interval)


if __name__ == "__main__":
    import urllib.parse
    try:
        main()
    except KeyboardInterrupt:
        print("\n[watch] stopped")
