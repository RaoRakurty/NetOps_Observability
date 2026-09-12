# Catalyst 9800 fixtures — fidelity: doc_claimed

Hand-authored from the published Cisco-IOS-XE-wireless-* YANG models
(IOS-XE 17.x): access-point-oper (capwap-data, radio-oper-data),
wlan-cfg (wlan-cfg-entries), client-oper (common-oper-data),
rrm-oper (rrm-measurement).

NO live Catalyst 9800 exists in the lab (Wireslessdesign.md B7), so these
fixtures are the transformer's contract at doc_claimed fidelity ONLY. Leaf
spellings and enum literals (e.g. "registered", "client-status-run",
"radio-80211a") MUST be verified against a real controller before any
capability is promoted to lab_validated/live_validated — replace these files
with captured RESTCONF responses at that point. Per the project fidelity rule:
nothing here was invented to fill a gap; unmapped leaves are absent, not
guessed.
