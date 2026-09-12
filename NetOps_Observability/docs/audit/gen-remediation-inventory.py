#!/usr/bin/env python3
"""Generate the canonical remediation inventory (Decision 0).

One row per finding, 11 fields. Single source of truth: the three JSON
artefacts produced by the review/triage/reflag passes, plus the git log of
the remediation branch for the fix-commit column.

Re-runnable: re-run after every merge so the document never disagrees with
the tracker or the code.
"""
import json, subprocess, sys, os, re, collections

SP = os.path.dirname(os.path.abspath(__file__))
REPO = "/home/rao/Projects/NetOps_Observability/NetOps_Observability"
BASE = "c83140ca"

inv = {f["id"]: f for f in json.load(open(SP + "/inventory.json"))}
tri = {f["id"]: f for f in json.load(open(SP + "/triage-results.json"))}
ref = {r["id"]: r for r in json.load(open(SP + "/reflag-results.json"))}

# Section 2 — the short list. 15 merged items carrying the 4 criticals and 21
# highs, i.e. 25 of the 181 findings. The triage/reflag passes only ever ran
# over section 3, so an inventory built from those three files alone silently
# omits the most severe quarter of the review. Fold them in here.
SEC2 = {f["id"]: f for f in json.load(open(SP + "/section2-inventory.json"))}
for fid, f in SEC2.items():
    inv[fid] = {"id": fid, "subsystem": f["subsystem"], "where": f["where"],
                "what": f["what"] + " — " + f["detail"], "orig_sev": f["severity"],
                "both_lenses": False}
    tri[fid] = {"id": fid, "where": f["where"], "orig_sev": f["severity"],
                "current_sev": f["severity"], "disposition": "CONFIRMED_FIX_REQUIRED",
                "reproduces": True, "rc1_blocking": True,
                "evidence": "review section 2, recommendation: " + f["recommendation"],
                "rationale": "", "suggested_fix": "", "shard": "2"}

# ---- overrides: dispositions settled after the reflag pass, by agent report.
OVR = {}
ovr_path = SP + "/disposition-overrides.json"
if os.path.exists(ovr_path):
    OVR = json.load(open(ovr_path))

# ---- fix commits: any commit on the branch whose message names a finding id.
log = subprocess.run(
    ["git", "-C", REPO, "log", "--format=%h%x00%s%x00%b%x1e", BASE + "..HEAD"],
    capture_output=True, text=True, check=True).stdout
fixcommit = collections.defaultdict(list)
for entry in log.split("\x1e"):
    if not entry.strip():
        continue
    sha, subj, body = (entry.strip().split("\x00") + ["", ""])[:3]
    for fid in set(re.findall(r"\b\d\.\d{1,2}-\d{2}\b", subj + " " + body)):
        fixcommit[fid].append(sha)

def sev(fid):
    if fid in OVR and OVR[fid].get("severity"):
        return OVR[fid]["severity"]
    if fid in ref:
        return ref[fid]["severity"]
    return tri[fid]["current_sev"]

def disp(fid):
    if fid in OVR and OVR[fid].get("disposition"):
        return OVR[fid]["disposition"]
    return tri[fid]["disposition"]

def blocking(fid):
    if fid in OVR and "rc1_blocking" in OVR[fid]:
        return OVR[fid]["rc1_blocking"]
    if fid in ref:
        return ref[fid]["rc1_blocking"]
    return tri[fid]["rc1_blocking"]

FLAGRE = re.compile(r"\b(?:FEATURE|ENABLE)_[A-Z0-9_]+\b")

def reach(fid):
    """Is this defect reachable in a DEFAULT install? One answer, one place.

    An earlier draft computed this twice — once for the table column and once
    for the summary prose — and the two disagreed by an order of magnitude
    (2 rows vs 26) because one honoured the "none" verdict in `feature_flag`
    and the other only looked at `flag_default`. Decision 0 says never carry
    two numbers; the fix is not to reconcile them but to have one.

    Returns (verdict, label) where verdict is one of:
      "live"    reachable in a default install (ungated, or flag ships on)
      "off"     behind a feature flag that ships false
      "unknown" the reflag pass did not settle it
    """
    r = ref.get(fid)
    if not r:
        return "unknown", "—"
    prose = (r.get("feature_flag") or "").strip()
    names = [] if prose.lower().startswith("none") else FLAGRE.findall(prose)
    if not names:
        return "live", "ungated"
    st = flagstate(r)
    shown = "`%s`" % names[0] + (" +%d" % (len(names) - 1) if len(names) > 1 else "")
    if st == "off":
        return "off", "%s ships off" % shown
    if st == "on":
        return "live", "%s ships on" % shown
    if st == "n/a":
        return "live", "ungated"
    return "unknown", "%s default unread" % shown


def flagstate(r):
    """Read the shipped default out of the reflag pass's prose.

    `flag_default` is not a boolean — it is a sentence with a citation, e.g.
    "false — deployment/docker/docker-compose.yml:1994 `FEATURE_...:-false`".
    Treating a non-True value as off would have called the 20 rows whose
    default is literally "n/a" gated-off. Parse the verdict word; never guess.
    """
    d = (r.get("flag_default") or "").strip().lower()
    if d.startswith(("false", "both false", "none")):
        return "off"
    if d.startswith(("true", "always on", "n/a (always on", "n/a (ships on")) or "on by default" in d:
        return "on"
    if d.startswith("n/a"):
        return "n/a"
    m = re.match(r"(?:feature|enable)_[a-z0-9_]+\s*=\s*(true|false)\b", d)
    if m:
        return "on" if m.group(1) == "true" else "off"
    if d.startswith("on ") or d == "on":
        return "on"
    return "unread"


def flag(fid):
    return reach(fid)[1]



WTRE = re.compile(r"/tmp/claude-1000/\S*?/wt-[^/]+/(?:NetOps_Observability/)?")

def where(fid):
    """Repo-relative location.

    Fourteen triage rows recorded an absolute path into a throwaway agent
    worktree instead of a repo path. Those worktrees are gone; the path is
    noise. Strip the prefix, and fall back to the review's own location if
    nothing usable survives.
    """
    w = tri[fid].get("where") or ""
    w = WTRE.sub("", w)
    if not w.strip() or "/tmp/" in w:
        w = inv[fid].get("where") or w
    return w


def cell(s, n=None):
    s = (s or "").replace("|", "\\|").replace("\n", " ").strip()
    return s[:n] + "…" if n and len(s) > n else s

ids = sorted(inv, key=lambda i: [int(x) for x in re.findall(r"\d+", i)])
SEVRANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
S2 = set(SEC2)
ids.sort(key=lambda i: (SEVRANK.get(sev(i), 9), i))

counts = collections.Counter(disp(i) for i in ids)
verified = [i for i in ids if i in OVR]
partial = sorted(i for i in ids if OVR.get(i, {}).get("was_partial"))
overturned = sorted(i for i in ids if OVR.get(i, {}).get("triage_overturned"))
sevc = collections.Counter(sev(i) for i in ids)
openblk = [i for i in ids
           if disp(i) == "CONFIRMED_FIX_REQUIRED" and blocking(i)]

out = []
w = out.append
w("# Remediation inventory — review of 2026-09-08")
w("")
w("Generated by `gen-remediation-inventory.py` beside it, from the review, triage and")
w("reflag artefacts plus the branch's own git log. **This document is the")
w("canonical count.** Where any summary, tracker row or commit message")
w("disagrees with it, this document is wrong or they are — reconcile, never")
w("carry two numbers.")
w("")
w("Review of record: [`REVIEW_2026-09-08.md`](REVIEW_2026-09-08.md). Base of")
w("the reviewed range: `%s`." % BASE)
w("")
w("## Counts")
w("")
w("| | |")
w("|---|---|")
n3 = len(inv) - len(S2)
w("| **Confirmed findings in the review** | **181** |")
w("| §2 the short list — 25 findings (4 critical, 21 high) merged | %d items |" % len(S2))
w("| §3 the body — 156 findings (48 medium, 108 low) | %d rows |" % n3)
w("| **Rows in this inventory** | **%d** |" % len(ids))
w("| Rows carrying a disposition | %d (100%%) |" % len(ids))
w("| Re-verified against the code as it stands | %d |" % len(verified))
w("| **Found NOT actually fixed by that re-verification** | **%d** |" % len(partial))
w("| **Triage verdicts overturned on re-check** | **%d** |" % len(overturned))
w("| **Open release-blocking FROM THIS REVIEW** | **%d** |" % len(openblk))
w("")
w("**That zero counts only this review, and it is not a statement that the")
w("tree is clean.** Remediation opened 18 new tracker rows (286, 288-303) that")
w("the review never found, several of them from reading the code around a")
w("finding rather than the finding itself. Three are verified live leaks and")
w("are being closed now; the rest are open in `docs/TRACKER.md`, which is the")
w("authority on what remains. Where this document and the tracker disagree,")
w("the tracker wins and this document is stale.")
w("")
w("**All 155 rows were re-read against the code as it stands.** The last 13 —")
w("the rows triage closed without a fix or deferred — were checked separately")
w("and last, because they are the ones that leave no artifact: a fix leaves a")
w("diff and a test to review, while a finding closed without code leaves one")
w("sentence, and if that sentence is wrong nothing catches it.")
w("")
w("That check overturned **%d of the 13**. Six deferrals should have been" % len(overturned))
w("fixes — two of them input validation at a trust boundary and one tenant")
w("isolation, none of which is deferrable. One INTENTIONAL had its intent")
w("written down on a false premise. In three cases the code's own doc comment")
w("PROMISED the protection that was missing, and no written rationale existed")
w("anywhere — those were not deferred, they were never examined.")
w("")
w("The three that close a finding without changing code were correct, and each")
w("now carries the perturbation proof it previously lacked.")
w("")
w("181 = 25 + 156, and the two sections do not overlap: §2 holds every")
w("critical and high, §3 holds every medium and low. The 16-row gap between")
w("§3's 140 rows and its 156 findings is 15 rows marked *(both lenses)* —")
w("reviewed twice under two different lenses and filed once — plus one row")
w("spanning two packages. None of it is missing work.")
w("")
w("**§2 was absent from the first draft of this inventory.** It was built")
w("from the triage and reflag artefacts, and those passes only ever ran over")
w("§3 — so the document omitted the most severe quarter of the review while")
w("presenting itself as canonical. That is exactly the failure Decision 0")
w("exists to prevent, and it is why the count table above starts at 181")
w("rather than at 140.")
w("")
w("### By disposition")
w("")
w("| Disposition | Rows |")
w("|---|---|")
for d, n in counts.most_common():
    w("| %s | %d |" % (d, n))
w("")
w("### By severity (post-calibration)")
w("")
w("| Severity | Rows |")
w("|---|---|")
for s in ("critical", "high", "medium", "low", "info"):
    if sevc.get(s):
        w("| %s | %d |" % (s, sevc[s]))
w("")
tri_blk = sum(1 for i in ids if tri[i].get("rc1_blocking"))
now_blk = sum(1 for i in ids if blocking(i))
off_rows = sum(1 for i in ids if reach(i)[0] == "off")
live_rows = [i for i in ids if reach(i)[0] == "live"]
unk_rows = [i for i in ids if reach(i)[0] == "unknown"]
w("Severities here are the **recalibrated** ones. The first triage pass")
w("marked every medium and high release-blocking — %d rows, zero" % tri_blk)
w("exceptions — because it never checked feature-flag defaults. A 13-claim")
w("calibration sample against three adversaries found the defects real and")
w("the code read accurately 13/13, but the blocking call overstated 12/13.")
w("Reflagging against the shipped defaults brought blocking from %d to %d."
  % (tri_blk, now_blk))
w("")
w("%d rows sit behind a feature flag that ships `false`, so they cannot be" % off_rows)
w("reached in a default install. **That is a reason to deprioritise, never a")
w("reason to close** — the flags are supported configurations and a customer")
w("who turns one on gets the defect. They are fixed, not waived.")
w("")
w("%d rows are reachable in a DEFAULT install — either ungated, or behind a" % len(live_rows))
w("flag that ships on. Those are the ones that decide whether RC1 ships.")
if unk_rows:
    w("")
    w("%d rows have no settled reachability and are treated as live until they" % len(unk_rows))
    w("do: %s." % ", ".join("`%s`" % i for i in unk_rows))
w("")
w("## The five that were recorded as fixed and were not")
w("")
w("Every confirmed finding was re-read against the code as it stands rather")
w("than trusted from the tracker, because the fix commits do not cite finding")
w("ids — nothing mechanically connected any commit to any finding, so \"all")
w("confirmed findings are fixed\" was an assertion, not evidence.")
w("")
w("Five did not survive that. **All five failed the same way: the fix closed")
w("the exact location the finding named and left the rest of the finding")
w("open.** That is a property of how the fixes were made, not five accidents.")
w("")
for i in partial:
    w("- **`%s`** — %s" % (i, cell(OVR[i]["rationale"])))
w("")
w("Three of the five were additionally hidden by a test that could not fail:")
w("a guard asserting the index name contains `netops-secfindings`, which is")
w("false for the wildcard `netops-*` it was actually given; a metrics fake")
w("answering \"one interface is down\" to any query beginning with that metric")
w("name, so a lane matching nothing on any fleet looked healthy; and a unit")
w("test pinning the broken query as its own expected value.")
w("")
w("## The nine triage verdicts that did not survive re-check")
w("")
for i in overturned:
    w("- **`%s`** — %s" % (i, cell(OVR[i]["rationale"])))
w("")
w("## Findings")
w("")
w("| ID | Sev | Subsystem | Where | What | Flag | Repro | Blocking | Disposition | Evidence / rationale | Fix |")
w("|---|---|---|---|---|---|---|---|---|---|---|")
for i in ids:
    f, t = inv[i], tri[i]
    ev = t.get("evidence") or t.get("rationale") or ""
    if i in OVR and OVR[i].get("rationale"):
        ev = OVR[i]["rationale"]
    w("| `%s` | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |" % (
        i, sev(i), cell(f.get("subsystem"), 28), cell(where(i), 90),
        cell(f.get("what"), 240), flag(i),
        "yes" if t.get("reproduces") else "no",
        "**yes**" if blocking(i) else "no",
        disp(i), cell(ev, 260),
        " ".join("`%s`" % s for s in fixcommit.get(i, [])) or "—"))
w("")
w("## Findings added after the review")
w("")
w("The review is a snapshot; remediation found more. Every one of these is")
w("tracked in `docs/TRACKER.md`, not here, because they were never review")
w("rows: tracker 279 (fix-agent follow-ups), 282 (the data-loss-on-failure")
w("family, five paths), 283 (security-lane test doubles), 284 (collector-panic")
w("alert rule), 285 (nil-store panic).")
w("")
w("Roughly one new defect surfaced per two fixed. The pattern was that a")
w("finding filed against one call site was true of a whole class: the")
w("unreadable-store defect filed against one store held in twenty; a filed")
w("pair of parsers was four; one hand-rolled fetch was five.")
w("")
w("## How to regenerate this document")
w("")
w("    python3 docs/audit/gen-remediation-inventory.py > docs/audit/REMEDIATION_INVENTORY_2026-09-12.md")
w("")
w("It reads its inputs from the same directory — `disposition-overrides.json`")
w("(the verdicts, one per finding), `inventory.json`, `triage-results.json`,")
w("`reflag-results.json` and `section2-inventory.json` — plus the branch's own")
w("git log. Re-run it after any change to a disposition so the document and the")
w("tracker cannot drift apart — and when they do disagree, `docs/TRACKER.md` is")
w("the authority and this document is the stale one.")
print("\n".join(out))
