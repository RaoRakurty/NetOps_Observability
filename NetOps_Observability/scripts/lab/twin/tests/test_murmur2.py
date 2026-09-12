# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Correlix

"""Tenant→partition keying pinned against the repo's Java-murmur2 reference.

The literal vectors below were produced by the INDEPENDENT reimplementation in
`src/correlation/test_scale_copartition.py::_java_murmur2` (the reference every
producer-side partitioner in the deployment claims compatibility with). The
twin's copy must agree bit-for-bit — a drift would silently void the
partition-spread proof (design §6).
"""
from murmur import java_murmur2, tenant_partition

# corpus → unsigned 32-bit murmur2 of (t or "global").encode("utf-8"),
# generated from the repo reference (see module docstring).
REFERENCE_VECTORS = {
    "global": 1597289159,
    "t_acme": 15325337,
    "t_9f31c2": 540329631,
    "rca-canary": 1224559264,
    "tenant-with-dash": 4029636163,
    "ünïcode-tenant": 560066532,
    "a": 2731586172,
    "ab": 316155434,
    "abc": 479470107,
    "abcd": 2971317748,
    "abcde": 461995741,
    "": 1597289159,  # empty folds to "global"
}


def test_java_murmur2_matches_repo_reference_vectors():
    for tenant, want in REFERENCE_VECTORS.items():
        got = java_murmur2((tenant or "global").encode("utf-8"))
        assert got == want, (tenant, got, want)


def test_tenant_partition_positive_mask_and_mod():
    for n in (1, 2, 3, 4, 6, 12, 16):
        for tenant, h in REFERENCE_VECTORS.items():
            want = (h & 0x7FFFFFFF) % n
            assert tenant_partition(tenant, n) == want, (tenant, n)


def test_empty_tenant_keys_as_global():
    for n in (2, 3, 4, 12):
        assert tenant_partition("", n) == tenant_partition("global", n)


def test_defensive_partition_floor():
    assert tenant_partition("anything", 1) == 0
    assert tenant_partition("anything", 0) == 0
