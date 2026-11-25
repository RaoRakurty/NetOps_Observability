// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// severityStatus — one mapping from any severity word or syslog number (read
// through theme/severity.ts) to the StatusChip kind, so every page shows a
// severity the same way: critical / error → red, warning → amber, notice /
// info → blue, debug → neutral, ok / cleared → green. The chip's label stays
// the severity word the page already shows.

import { severityKey, type SeverityKey } from "../../theme/severity";
import type { StatusKind } from "./StatusChip";

const KIND: Record<SeverityKey, StatusKind> = {
  critical: "critical", error: "error", warning: "warning",
  notice: "info", info: "info", debug: "neutral", ok: "ok",
};

export function severityStatus(raw: string | number | null | undefined): StatusKind {
  return KIND[severityKey(raw)];
}
