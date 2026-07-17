#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from sharehound.targets import (get_computers_with_sids_from_domain,
                                load_targets)


def _base_options(**overrides):
    opts = argparse.Namespace(
        auth_dc_ip=None,
        auth_user=None,
        auth_password=None,
        auth_hashes=None,
        auth_key=None,
        auth_domain="",
        use_kerberos=False,
        kdc_host=None,
        ldaps=False,
        subnets=False,
        targets_file=None,
        target=[],
    )
    for k, v in overrides.items():
        setattr(opts, k, v)
    return opts


class LoadTargetsMessagingTests(unittest.TestCase):
    def test_missing_targets_file_logs_error(self):
        logger = MagicMock()
        opts = _base_options(targets_file="/nonexistent/path.txt")
        result = load_targets(opts, MagicMock(), logger)
        self.assertEqual(result, [])
        logger.error.assert_called()
        msg = logger.error.call_args_list[0][0][0]
        self.assertIn("/nonexistent/path.txt", msg)
        self.assertIn("does not exist", msg)

    def test_targets_file_skips_blank_and_comment_lines(self):
        tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False
        )
        try:
            tmp.write("# a comment\n")
            tmp.write("\n")
            tmp.write("10.0.0.1\n")
            tmp.write("   \n")
            tmp.write("srv1.corp.example.com\n")
            tmp.close()

            logger = MagicMock()
            opts = _base_options(targets_file=tmp.name)
            result = load_targets(opts, MagicMock(), logger)

            self.assertIn(("ipv4", "10.0.0.1"), result)
            self.assertIn(("fqdn", "srv1.corp.example.com"), result)
        finally:
            os.unlink(tmp.name)

    def test_invalid_targets_warn_with_list(self):
        logger = MagicMock()
        opts = _base_options(target=["10.0.0.1", "not a host!!"])
        load_targets(opts, MagicMock(), logger)
        logger.warning.assert_called_once()
        msg = logger.warning.call_args_list[0][0][0]
        self.assertIn("Skipped 1", msg)
        self.assertIn("not a host!!", msg)

    def test_valid_targets_do_not_warn(self):
        logger = MagicMock()
        opts = _base_options(target=["10.0.0.1", "srv1.corp.example.com"])
        result = load_targets(opts, MagicMock(), logger)
        self.assertIn(("ipv4", "10.0.0.1"), result)
        self.assertIn(("fqdn", "srv1.corp.example.com"), result)
        logger.warning.assert_not_called()


class ComputerSidsTests(unittest.TestCase):
    @patch("sharehound.targets.parse_lm_nt_hashes", return_value=("", ""))
    @patch("sharehound.targets.init_ldap_session")
    def test_parses_name_and_sid_pairs(self, mock_session, _hashes):
        server = MagicMock()
        server.info.other = {"defaultNamingContext": "DC=corp,DC=local"}
        session = MagicMock()
        session.extend.standard.paged_search.return_value = [
            {"type": "searchResEntry", "attributes": {
                "dNSHostName": "host1.corp.local", "objectSid": "S-1-5-21-1-2-3-1001"}},
            {"type": "searchResEntry", "attributes": {
                "dNSHostName": ["host2.corp.local", "host3.corp.local"],
                "objectSid": "S-1-5-21-1-2-3-1002"}},
            {"type": "searchResEntry", "attributes": {
                "dNSHostName": "", "objectSid": "S-1-5-21-1-2-3-1003"}},
            {"type": "searchResEntry", "attributes": {
                "dNSHostName": "host4.corp.local", "objectSid": ""}},
            {"type": "searchResRef", "attributes": {}},
        ]
        mock_session.return_value = (server, session)
        opts = _base_options(
            auth_dc_ip="10.0.0.1", auth_user="u", auth_password="p"
        )
        self.assertEqual(
            get_computers_with_sids_from_domain(opts),
            [
                ("host1.corp.local", "S-1-5-21-1-2-3-1001"),
                ("host2.corp.local", "S-1-5-21-1-2-3-1002"),
                ("host3.corp.local", "S-1-5-21-1-2-3-1002"),
                ("host4.corp.local", ""),
            ],
        )

    @patch("sharehound.targets.get_servers_from_domain", return_value=[])
    @patch("sharehound.targets.get_computers_with_sids_from_domain")
    @patch("sharehound.targets.is_port_open", return_value=True)
    def test_ad_scan_targets_all_computers_maps_only_sid_bearing(
        self, _port, mock_comp, _srv
    ):
        mock_comp.return_value = [
            ("host1.corp.local", "S-1-5-21-1-2-3-1001"),
            ("host2.corp.local", ""),
        ]
        opts = _base_options(
            auth_dc_ip="10.0.0.1", auth_user="u", auth_password="p"
        )
        result = load_targets(opts, MagicMock(), MagicMock())
        self.assertEqual(
            opts.host_sid_map, {"host1.corp.local": "S-1-5-21-1-2-3-1001"}
        )
        self.assertIn(("fqdn", "host1.corp.local"), result)
        self.assertIn(("fqdn", "host2.corp.local"), result)

    @patch("sharehound.targets.get_computers_with_sids_from_domain")
    @patch("sharehound.targets.is_port_open", return_value=True)
    def test_explicit_ip_and_cidr_do_not_query_ad(self, _port, mock_comp):
        opts = _base_options(
            auth_dc_ip="10.0.0.1",
            auth_user="u",
            auth_password="p",
            target=["10.0.0.2", "10.0.0.3/32"],
        )

        result = load_targets(opts, MagicMock(), MagicMock())

        self.assertEqual(
            result,
            [("ipv4", "10.0.0.2"), ("ipv4", "10.0.0.3")],
        )
        self.assertEqual(opts.host_sid_map, {})
        mock_comp.assert_not_called()

    @patch("sharehound.targets.get_computers_with_sids_from_domain")
    @patch("sharehound.targets.is_port_open", return_value=True)
    def test_explicit_fqdn_queries_ad_once(self, _port, mock_comp):
        mock_comp.return_value = [
            ("host1.corp.local", "S-1-5-21-1-2-3-1001")
        ]
        opts = _base_options(
            auth_dc_ip="10.0.0.1",
            auth_user="u",
            auth_password="p",
            target=["host1.corp.local"],
        )

        result = load_targets(opts, MagicMock(), MagicMock())

        self.assertEqual(result, [("fqdn", "host1.corp.local")])
        self.assertEqual(
            opts.host_sid_map, {"host1.corp.local": "S-1-5-21-1-2-3-1001"}
        )
        mock_comp.assert_called_once_with(opts)


if __name__ == "__main__":
    unittest.main()
