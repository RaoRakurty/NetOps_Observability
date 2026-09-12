# `ai/tac/research` — vendor research, before it is merged

One file per vendor: `<vendor>.yaml`, where `<vendor>` is the
`internal/vendorprofile` vendor id (`cisco`, `arista`, `juniper`, `nokia`,
`huawei`, `fortinet`, `paloalto`).

**Nothing here is read at runtime.** The embedded knowledge is `../classes.yaml`
and `../plans/*.yaml`; this directory is INPUT to
`scripts/tac-merge-research.py`, which validates it and merges what passes.

The schema is `../README.md` §6, and the merge rules are §6's list — in short:

- an unknown field is a REFUSAL, not a silent drop;
- a command that is not a read-only show never lands;
- a detection cue naming an alert / signature / issue / skill that does not exist
  in this repository is DROPPED, with the reason printed;
- an existing binding is never silently overwritten — only a `verified: capture`
  record may replace a `doc_claimed` one.

```bash
python3 scripts/tac-merge-research.py           # merge and write
python3 scripts/tac-merge-research.py --check   # CI: fail if a merge would change anything
python3 scripts/tac-merge-research.py --vendor cisco
```

Every issue should carry `sources` (https, titled, dated). A command taken from
a vendor's documentation and never run here is `verified: doc_claimed`; that
label is shown to the operator and stamped into every bundle, so it is not a
lesser record — it is an honest one.
