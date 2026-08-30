#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import unittest

from sharehound.worker import _build_host_properties


class HostPropertiesTests(unittest.TestCase):
    def setUp(self):
        self.fqdn = "host1.corp.local"
        self.sid = "S-1-5-21-1-2-3-1001"
        self.sid_map = {self.fqdn: self.sid}

    def test_unresolved_fqdn_is_enriched(self):
        properties = _build_host_properties(
            self.fqdn, self.fqdn, "fqdn", self.sid_map
        ).get_all_properties()

        self.assertEqual(
            properties,
            {"name": self.fqdn, "fqdn": self.fqdn, "machineSid": self.sid},
        )

    def test_resolved_fqdn_keeps_ip_identity_and_is_enriched(self):
        properties = _build_host_properties(
            "10.0.0.1", self.fqdn, "fqdn", self.sid_map
        ).get_all_properties()

        self.assertEqual(
            properties,
            {"name": "10.0.0.1", "fqdn": self.fqdn, "machineSid": self.sid},
        )

    def test_ip_target_is_not_enriched(self):
        properties = _build_host_properties(
            "10.0.0.1", "10.0.0.1", "ipv4", self.sid_map
        ).get_all_properties()

        self.assertEqual(properties, {"name": "10.0.0.1"})

    def test_fqdn_without_sid_keeps_fqdn(self):
        properties = _build_host_properties(
            self.fqdn, self.fqdn, "fqdn", {}
        ).get_all_properties()

        self.assertEqual(properties, {"name": self.fqdn, "fqdn": self.fqdn})


if __name__ == "__main__":
    unittest.main()
