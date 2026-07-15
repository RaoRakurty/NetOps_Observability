"""Unit tests for built-in service inference (service_infer.py).

The inference must be GENERIC and HONEST: a resource-group name gives a
suspected guess, structure (shared subnet / name prefix) promotes it to strong,
a lone hostname is weak, and no signal yields NO inference (stays unknown). A
tagged resource is never overridden. Sample resource graphs in, expected
grouping + confidence out.

Run: python3 -m pytest test_service_infer.py
"""
import unittest

import service_infer as si

SUB = "/subscriptions/00000000-0000-0000-0000-000000000000"


def arm(rg: str, name: str) -> str:
    return f"{SUB}/resourceGroups/{rg}/providers/Microsoft.Compute/virtualMachines/{name}"


class TestParsing(unittest.TestCase):
    def test_resource_group_of(self):
        self.assertEqual(si.resource_group_of(arm("rg-payments", "web01")), "rg-payments")
        # case-insensitive segment, and "" when absent.
        self.assertEqual(si.resource_group_of("/subscriptions/x/RESOURCEGROUPS/Foo/y"), "Foo")
        self.assertEqual(si.resource_group_of("no-groups-here"), "")

    def test_service_name_from_rg_strips_affixes_and_env(self):
        self.assertEqual(si.service_name_from_rg("rg-payments-prod"), "payments")
        self.assertEqual(si.service_name_from_rg("payments-rg"), "payments")
        self.assertEqual(si.service_name_from_rg("rg_orders_westus2"), "orders")
        # pure convention / generic → no identity.
        self.assertEqual(si.service_name_from_rg("rg-prod"), "")
        self.assertEqual(si.service_name_from_rg("network-shared"), "")
        self.assertEqual(si.service_name_from_rg("default"), "")

    def test_hostname_role_collapses_ordinals(self):
        self.assertEqual(si.hostname_role("web01"), "web")
        self.assertEqual(si.hostname_role("payments-api-2"), "payments-api")
        self.assertEqual(si.hostname_role("db_03"), "db")
        # nothing but an ordinal / generic → "".
        self.assertEqual(si.hostname_role("vm-01"), "")
        self.assertEqual(si.hostname_role("server"), "")


class TestInference(unittest.TestCase):
    def test_no_tags_still_groups_by_resource_group(self):
        # The live Azure case: empty tags, read-only SP. Must still attribute.
        res = [
            {"resource_id": arm("rg-payments-prod", "web01"), "resource_name": "web01", "tags": {}},
            {"resource_id": arm("rg-payments-prod", "web02"), "resource_name": "web02", "tags": {}},
        ]
        got = si.infer_services(res)
        self.assertEqual(len(got), 2)
        for r in res:
            hit = got[r["resource_id"]]
            self.assertEqual(hit["service"], "payments")
            # RG name + shared "web" name prefix → strong.
            self.assertEqual(hit["confidence"], si.STRONG)
            self.assertIn("resource-group name", hit["basis"])

    def test_shared_subnet_promotes_to_strong(self):
        res = [
            {"resource_id": arm("rg-orders", "a1"), "resource_name": "a1",
             "tags": {}, "subnet_ids": ["/s/app-tier"]},
            {"resource_id": arm("rg-orders", "b2"), "resource_name": "b2",
             "tags": {}, "subnet_ids": ["/s/app-tier"]},
        ]
        got = si.infer_services(res)
        hit = got[res[0]["resource_id"]]
        self.assertEqual(hit["service"], "orders")
        self.assertEqual(hit["confidence"], si.STRONG)
        self.assertIn("share subnet 'app-tier'", hit["basis"])

    def test_rg_name_alone_is_suspected(self):
        # A single VM in a well-named RG: naming convention only → suspected.
        res = [{"resource_id": arm("rg-billing", "solo"), "resource_name": "solo", "tags": {}}]
        got = si.infer_services(res)
        hit = got[res[0]["resource_id"]]
        self.assertEqual(hit["service"], "billing")
        self.assertEqual(hit["confidence"], si.SUSPECTED)

    def test_structure_without_rg_name_is_suspected(self):
        # Generic RG, but two VMs share subnet AND a name prefix → a real tier.
        res = [
            {"resource_id": arm("rg-prod", "cache01"), "resource_name": "cache01",
             "tags": {}, "subnet_ids": ["/s/data"]},
            {"resource_id": arm("rg-prod", "cache02"), "resource_name": "cache02",
             "tags": {}, "subnet_ids": ["/s/data"]},
        ]
        got = si.infer_services(res)
        hit = got[res[0]["resource_id"]]
        self.assertEqual(hit["service"], "cache")
        self.assertEqual(hit["confidence"], si.SUSPECTED)

    def test_lone_hostname_is_weak(self):
        res = [{"resource_id": arm("rg-prod", "grafana01"), "resource_name": "grafana01", "tags": {}}]
        got = si.infer_services(res)
        hit = got[res[0]["resource_id"]]
        self.assertEqual(hit["service"], "grafana")
        self.assertEqual(hit["confidence"], si.WEAK)

    def test_no_signal_yields_no_inference(self):
        # Generic RG, generic name, singleton: honestly unknown (omitted).
        res = [{"resource_id": arm("rg-prod", "vm-01"), "resource_name": "vm-01", "tags": {}}]
        got = si.infer_services(res)
        self.assertEqual(got, {})

    def test_tagged_resource_is_never_overridden(self):
        # A tag is authoritative — inference must not touch it.
        res = [{"resource_id": arm("rg-payments", "web01"), "resource_name": "web01",
                "tags": {"app": "checkout"}}]
        got = si.infer_services(res)
        self.assertNotIn(res[0]["resource_id"], got)

    def test_partial_tags_only_untagged_inferred(self):
        res = [
            {"resource_id": arm("rg-payments", "web01"), "resource_name": "web01",
             "tags": {"app": "checkout"}},
            {"resource_id": arm("rg-payments", "web02"), "resource_name": "web02", "tags": {}},
        ]
        got = si.infer_services(res)
        self.assertNotIn(res[0]["resource_id"], got)  # tagged: skipped
        self.assertIn(res[1]["resource_id"], got)     # untagged: inferred
        self.assertEqual(got[res[1]["resource_id"]]["service"], "payments")


if __name__ == "__main__":
    unittest.main()
