"""Partition-spread math: expected shares from computed placement + journaled
counts vs consumed deltas, the ±20% gate, starvation, and the organic-rate
correction (design §6)."""
from spread import organic_rates, spread_report


def _sample(t, currents):
    return {"t_mono": t, "members": 2, "lag_total": 0,
            "partitions": {str(p): {"current": c, "end": c, "lag": 0}
                           for p, c in currents.items()}}


ASSIGNMENT = {"replicaA": [0, 1], "replicaB": [2, 3]}
# two tenants per replica pair, equal emission
TENANT_PARTS = {"t0": 0, "t1": 1, "t2": 2, "t3": 3}
EMITTED = {"t0": 100, "t1": 100, "t2": 100, "t3": 100}


def test_balanced_spread_passes():
    samples = [_sample(0.0, {0: 10, 1: 20, 2: 30, 3: 40}),
               _sample(600.0, {0: 110, 1: 121, 2: 128, 3: 141})]
    rep = spread_report(samples, ASSIGNMENT, TENANT_PARTS, EMITTED)
    assert rep["status"] == "PASS", rep["problems"]
    assert all(r["within_tolerance"] for r in rep["replicas"])
    assert rep["consumed_delta_by_partition"] == {
        "0": 100, "1": 101, "2": 98, "3": 101}


def test_starved_partition_fails():
    samples = [_sample(0.0, {0: 10, 1: 20, 2: 30, 3: 40}),
               _sample(600.0, {0: 210, 1: 120, 2: 130, 3: 40})]  # p3 starved
    rep = spread_report(samples, ASSIGNMENT, TENANT_PARTS, EMITTED)
    assert rep["status"] == "FAIL"
    assert any("starved" in p for p in rep["problems"])


def test_imbalance_outside_tolerance_fails():
    # replicaA consumes 3x its expected share
    samples = [_sample(0.0, {0: 0, 1: 0, 2: 0, 3: 0}),
               _sample(600.0, {0: 300, 1: 300, 2: 100, 3: 100})]
    rep = spread_report(samples, ASSIGNMENT, TENANT_PARTS, EMITTED)
    assert rep["status"] == "FAIL"
    assert any("outside" in p for p in rep["problems"])


def test_organic_correction_rescues_polluted_partition():
    # partition 3 carries 3 ev/s organic on top of its 100 twin events
    organic = {3: 3.0}
    samples = [_sample(0.0, {0: 0, 1: 0, 2: 0, 3: 0}),
               _sample(100.0, {0: 100, 1: 100, 2: 100, 3: 400})]
    uncorrected = spread_report(samples, ASSIGNMENT, TENANT_PARTS, EMITTED)
    assert uncorrected["status"] == "FAIL"
    corrected = spread_report(samples, ASSIGNMENT, TENANT_PARTS, EMITTED,
                              organic=organic)
    assert corrected["status"] == "PASS", corrected["problems"]
    assert corrected["consumed_delta_by_partition_raw"]["3"] == 400
    assert corrected["consumed_delta_by_partition"]["3"] == 100


def test_organic_rates_from_pre_run_window():
    samples = [_sample(0.0, {0: 0, 1: 0, 2: 0, 3: 0}),
               _sample(50.0, {0: 0, 1: 0, 2: 0, 3: 150})]
    rates = organic_rates(samples)
    assert rates == {0: 0.0, 1: 0.0, 2: 0.0, 3: 3.0}
