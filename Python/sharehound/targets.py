#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : __main__.py
# Author             : Remi Gascou (@podalirius_)
# Date created       : 12 Aug 2025

import argparse
import os

from sectools.network.domains import is_fqdn
from sectools.network.ip import (expand_cidr, is_ipv4_addr, is_ipv4_cidr,
                                 is_ipv6_addr)
from sectools.windows.ldap.wrappers import (get_computers_from_domain,
                                            get_servers_from_domain,
                                            get_subnets, init_ldap_session,
                                            parse_lm_nt_hashes)

from sharehound.core.Config import Config
from sharehound.core.Logger import Logger
from sharehound.utils.utils import is_port_open


def get_computer_sids_from_domain(options: argparse.Namespace):
    lm_hash, nt_hash = parse_lm_nt_hashes(options.auth_hashes)
    ldap_server, ldap_session = init_ldap_session(
        auth_domain=options.auth_domain,
        auth_dc_ip=options.auth_dc_ip,
        auth_username=options.auth_user,
        auth_password=options.auth_password,
        auth_lm_hash=lm_hash,
        auth_nt_hash=nt_hash,
        auth_key=options.auth_key,
        use_kerberos=options.use_kerberos,
        kdcHost=options.kdc_host,
        use_ldaps=options.ldaps,
    )
    searchbase = ldap_server.info.other["defaultNamingContext"]
    sid_map = {}
    for entry in ldap_session.extend.standard.paged_search(
        searchbase, "(objectCategory=computer)", attributes=["dNSHostName", "objectSid"]
    ):
        if entry["type"] != "searchResEntry":
            continue
        dns_name = entry["attributes"]["dNSHostName"]
        object_sid = entry["attributes"]["objectSid"]
        if isinstance(dns_name, list):
            dns_name = dns_name[0] if dns_name else None
        if dns_name and object_sid:
            sid_map[dns_name.lower()] = object_sid
    return sid_map


def load_targets(options: argparse.Namespace, config: Config, logger: Logger):
    targets = []

    if (
        options.auth_dc_ip is not None
        and options.auth_user is not None
        and (options.auth_password is not None or options.auth_hashes is not None)
    ):
        if not is_port_open(
            options.auth_dc_ip, (389 if not options.ldaps else 636), timeout=10
        ):
            logger.error(
                "Domain controller %s is not reachable on port %d"
                % (options.auth_dc_ip, (389 if not options.ldaps else 636))
            )
            return []

    if options.targets_file is not None or len(options.target) != 0:
        # Loading targets line by line from a targets file
        if options.targets_file is not None:
            if os.path.exists(options.targets_file):
                logger.debug(
                    "[debug] Loading targets line by line from targets file '%s'"
                    % options.targets_file
                )
                try:
                    with open(options.targets_file, "r") as f:
                        for line in f:
                            entry = line.strip()
                            if not entry or entry.startswith("#"):
                                continue
                            targets.append(entry)
                except OSError as err:
                    logger.error(
                        "Could not read targets file '%s': %s"
                        % (options.targets_file, err)
                    )
            else:
                logger.error(
                    "Targets file '%s' does not exist" % options.targets_file
                )

        # Loading targets from a single --target option
        if len(options.target) != 0:
            logger.debug("[debug] Loading targets from --target options")
            for target in options.target:
                targets.append(target)
    else:
        # No explicit targets specified, load all computers from Active Directory
        if (
            options.auth_dc_ip is not None
            and options.auth_user is not None
            and (options.auth_password is not None or options.auth_hashes is not None)
        ):
            logger.info(
                "No target list specified, fetching all computers from Active Directory domain '%s'"
                % options.auth_domain
            )

            # Loading targets from domain computers
            logger.debug(
                "[debug] Loading targets from computers in the domain '%s'"
                % options.auth_domain
            )
            computers = get_computers_from_domain(
                auth_domain=options.auth_domain,
                auth_dc_ip=options.auth_dc_ip,
                auth_username=options.auth_user,
                auth_password=options.auth_password,
                auth_hashes=options.auth_hashes,
                auth_key=options.auth_key,
                use_kerberos=options.use_kerberos,
                kdcHost=options.kdc_host,
                use_ldaps=options.ldaps,
            )
            logger.info("Found %d computers in Active Directory" % len(computers))
            targets += computers

            # Loading targets from domain servers
            logger.debug(
                "[debug] Loading targets from servers in the domain '%s'"
                % options.auth_domain
            )
            servers = get_servers_from_domain(
                auth_domain=options.auth_domain,
                auth_dc_ip=options.auth_dc_ip,
                auth_username=options.auth_user,
                auth_password=options.auth_password,
                auth_hashes=options.auth_hashes,
                auth_key=options.auth_key,
                use_kerberos=options.use_kerberos,
                kdcHost=options.kdc_host,
                use_ldaps=options.ldaps,
            )
            logger.info("Found %d servers in Active Directory" % len(servers))
            targets += servers

        # Loading targets from subnetworks of the domain
        if (
            options.subnets
            and options.auth_dc_ip is not None
            and options.auth_user is not None
            and (options.auth_password is not None or options.auth_hashes is not None)
        ):
            logger.debug(
                "[debug] Loading targets from subnetworks of the domain '%s'"
                % options.auth_domain
            )
            targets += get_subnets(
                auth_domain=options.auth_domain,
                auth_dc_ip=options.auth_dc_ip,
                auth_username=options.auth_user,
                auth_password=options.auth_password,
                auth_hashes=options.auth_hashes,
                auth_key=options.auth_key,
                use_kerberos=options.use_kerberos,
                kdcHost=options.kdc_host,
                use_ldaps=options.ldaps,
            )

    # Sort uniq on targets list
    targets = sorted(list(set(targets)))

    final_targets = []
    skipped_targets = []
    # Parsing target to filter IP/DNS/CIDR
    for target in targets:
        if is_ipv4_cidr(target):
            final_targets += [("ipv4", ip) for ip in expand_cidr(target)]
        elif is_ipv4_addr(target):
            final_targets.append(("ipv4", target))
        elif is_ipv6_addr(target):
            final_targets.append(("ipv6", target))
        elif is_fqdn(target):
            final_targets.append(("fqdn", target))
        else:
            skipped_targets.append(target)

    if skipped_targets:
        logger.warning(
            "Skipped %d target(s) that did not parse as IPv4, IPv6, CIDR, or FQDN: %s"
            % (len(skipped_targets), ", ".join(repr(t) for t in skipped_targets))
        )

    options.host_sid_map = {}
    if (
        options.auth_dc_ip is not None
        and options.auth_user is not None
        and (options.auth_password is not None or options.auth_hashes is not None)
    ):
        options.host_sid_map = get_computer_sids_from_domain(options)

    final_targets = sorted(list(set(final_targets)))
    return final_targets
