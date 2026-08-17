"""Java-compatible murmur2 + tenant→partition mapping (tracker 152, design §6).

This mirrors the bus keying contract every producer in the deployment honors
(Vector `murmur2_random`, kafka-python DefaultPartitioner, aiokafka) and the
engine's own `tenant_partition` in `src/correlation/main.py`. The algorithm is
the same independent reimplementation the co-partitioning tests pin
(`src/correlation/test_scale_copartition.py::_java_murmur2`) — reused, not
invented, so a drift there fails both suites identically.

The twin uses it to COMPUTE (not hope for) each scenario tenant's partition and
to derive the expected per-replica consumption share for the ±20% spread gate.
"""
from __future__ import annotations


def java_murmur2(data: bytes) -> int:
    """Kafka's Java murmur2 (org.apache.kafka.common.utils.Utils#murmur2),
    returned as the unsigned 32-bit value (the partitioner masks the sign)."""
    length = len(data)
    seed = 0x9747B28C
    m = 0x5BD1E995
    r = 24
    mask = 0xFFFFFFFF
    h = (seed ^ length) & mask
    n = (length // 4) * 4
    for i in range(0, n, 4):
        k = int.from_bytes(data[i:i + 4], "little", signed=False)
        k = (k * m) & mask
        k ^= k >> r
        k = (k * m) & mask
        h = (h * m) & mask
        h ^= k
    left = length % 4
    if left >= 3:
        h ^= (data[n + 2] & 0xFF) << 16
    if left >= 2:
        h ^= (data[n + 1] & 0xFF) << 8
    if left >= 1:
        h ^= data[n] & 0xFF
        h = (h * m) & mask
    h ^= h >> 13
    h = (h * m) & mask
    h ^= h >> 15
    return h


def tenant_partition(tenant: str, num_partitions: int) -> int:
    """The partition a tenant's records land on — byte-for-byte the engine's
    `tenant_partition` contract: empty tenant folds to "global", positive mask,
    mod N (defensive floor at 1)."""
    key = (tenant or "global").encode("utf-8")
    return (java_murmur2(key) & 0x7FFFFFFF) % max(1, int(num_partitions))
