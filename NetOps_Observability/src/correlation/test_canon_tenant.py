# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Canonical global-tenant spelling (#113 slice 3 / #111 step 3).

The platform-global tenant had TWO spellings — "" (engine convention) and
"global" (Go canonicalCorrTenant, the path-observation exporter, CH policies).
The split broke every per-tenant join, most visibly path-attribution discovery
(tenant-"" incidents never matched "global"-stamped observations → NO live
object ever rendered a causality path). These tests pin the collapse to ONE
spelling ("global") at the live window-entry chokepoint and at the discovery
join, and that real tenant ids never collapse.
"""

from datetime import datetime, timezone

import main
from test_tenant_write_amp import _tenant_signal


def test_canon_tenant_collapses_global_spellings_only():
    assert main.canon_tenant("") == "global"
    assert main.canon_tenant("global") == "global"
    # Real tenant ids pass through byte-identical — never collapsed.
    assert main.canon_tenant("t_90892feb") == "t_90892feb"
    assert main.canon_tenant("t-rca-canary") == "t-rca-canary"
    assert main.canon_tenant("acme") == "acme"


def test_buffer_signal_canonicalizes_empty_tenant(monkeypatch):
    monkeypatch.setattr(main, "WINDOW_BUFFER", main.deque(maxlen=100))
    monkeypatch.setattr(main, "_BUFFERED_IDS", set())
    now = datetime.now(timezone.utc)
    main.buffer_signal(_tenant_signal("", "probe_loss", "edge-1", offset_s=-10, now=now))
    main.buffer_signal(_tenant_signal("global", "probe_loss", "edge-2", offset_s=-9, now=now))
    main.buffer_signal(_tenant_signal("t-a", "probe_loss", "edge-3", offset_s=-8, now=now))
    tenants = [s.tenant_id for s in main.WINDOW_BUFFER]
    assert tenants == ["global", "global", "t-a"]


def test_tenant_for_unmapped_device_is_canonical_global(tmp_path, monkeypatch):
    # No enrichment file at all → unmapped devices land on the CANONICAL global
    # spelling, not "" (the split that stranded corr objects on a tenant no
    # path observation matches).
    monkeypatch.setattr(main, "TENANT_ENRICHMENT_FILE", str(tmp_path / "absent.csv"))
    monkeypatch.setattr(main, "_tenant_map", {})
    monkeypatch.setattr(main, "_tenant_mtime", -1.0)
    assert main.tenant_for("some-unmapped-device") == "global"
    assert main.tenant_for("") == "global"
