# Adaptive Card JSON schema 1.4 (test fixture)

`adaptive-card-1.4.0.json` is Microsoft's official Adaptive Card schema,
version 1.4.0 — the version every Correlix Teams card declares
(`notify/teams_card.go`). It is copied unmodified and is used only by tests
(`internal/adaptivecard`), so the Teams cards are validated offline.

- Source: <https://github.com/microsoft/AdaptiveCards>, file
  `schemas/1.4.0/adaptive-card.json`
- Pinned commit: `93695cf2df1117ab08e36ebe707d0ced18e4e9b3` (the last commit
  that touched the file, 2021-11-15)
- URL form: `https://raw.githubusercontent.com/microsoft/AdaptiveCards/93695cf2df1117ab08e36ebe707d0ced18e4e9b3/schemas/1.4.0/adaptive-card.json`
- Fetched: 2026-11-24
- sha256: `e1750b01c13459b1d937ae0a8792d825314d54ddd22b1c8159cfd809d2caab09`
- Licence: MIT, Copyright (c) 2017 Microsoft — the full text is
  `LICENSE.AdaptiveCards` beside this file (fetched from the same commit).

Not part of any Correlix image or binary: only test code imports
`internal/adaptivecard`. Listed in the project NOTICE.

To refresh: fetch the file at a newer commit, replace it, update the commit,
date and sha256 above, and re-run `go test ./internal/adaptivecard/...
./notify/... ./internal/ticketing/...`.
