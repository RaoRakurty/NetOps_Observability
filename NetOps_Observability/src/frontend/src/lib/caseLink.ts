// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// caseLink.ts — the ONE way to address a case on the Troubleshooting page.
//
// Troubleshooting already reads `?case=<id>` (pages/troubleshoot/
// investigationModel.ts parseInvestigationHash) and opens that correlation as
// the picked case, but nothing in the app produced the link, so an operator on
// an RCA had to find the same case again in the picker (Paths redesign P0,
// 2026-11-20). The id must pass the same opaque-token rule the parser applies;
// anything else yields "" and the caller renders no link — never a link the
// page would silently ignore.

const CASE_TOKEN = /^[A-Za-z0-9_-]{1,64}$/;

/** `#/investigate/troubleshooting?case=<id>`, or "" for an id the page would refuse. */
export function troubleshootingCaseHref(correlationId: string | undefined | null): string {
  const id = String(correlationId ?? "");
  if (!CASE_TOKEN.test(id)) return "";
  return `#/investigate/troubleshooting?case=${encodeURIComponent(id)}`;
}
