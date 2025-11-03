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
                                            get_subnets)

from sharehound.core.Config import Config
from sharehound.core.Logger import Logger


def load_targets(options: argparse.Namespace, config: Config, logger: Logger):
    targets = []

    if options.targets_file is not None or len(options.target) != 0:

        # Loading targets line by line from a targets file
        if options.targets_file is not None:
            if os.path.exists(options.targets_file):
                logger.debug(
                    "[debug] Loading targets line by line from targets file '%s'"
                    % options.targets_file
                )
                f = open(options.targets_file, "r")
                for line in f.readlines():
                    targets.append(line.strip())
                f.close()
            else:
                print("[!] Could not open targets file '%s'" % options.targets_file)

        # Loading targets from a single --target option
        if len(options.target) != 0:
            logger.debug("[debug] Loading targets from --target options")
            for target in options.target:
                targets.append(target)
    else:
        # Loading targets from domain computers
        if (
            options.auth_dc_ip is not None
            and options.auth_user is not None
            and (options.auth_password is not None or options.auth_hashes is not None)
        ):
            logger.debug(
                "[debug] Loading targets from computers in the domain '%s'"
                % options.auth_domain
            )
            targets += get_computers_from_domain(
                auth_domain=options.auth_domain,
                auth_dc_ip=options.auth_dc_ip,
                auth_username=options.auth_user,
                auth_password=options.auth_password,
                auth_hashes=options.auth_hashes,
                auth_key=None,
                use_ldaps=options.ldaps,
            )

        # Loading targets from domain servers
        if (
            options.auth_dc_ip is not None
            and options.auth_user is not None
            and (options.auth_password is not None or options.auth_hashes is not None)
        ):
            logger.debug(
                "[debug] Loading targets from servers in the domain '%s'"
                % options.auth_domain
            )
            targets += get_servers_from_domain(
                auth_domain=options.auth_domain,
                auth_dc_ip=options.auth_dc_ip,
                auth_username=options.auth_user,
                auth_password=options.auth_password,
                auth_hashes=options.auth_hashes,
                auth_key=None,
                use_ldaps=options.ldaps,
            )

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
                auth_key=None,
                use_ldaps=options.ldaps,
            )

    # Sort uniq on targets list
    targets = sorted(list(set(targets)))

    final_targets = []
    # Parsing target to filter IP/DNS/CIDR
    for target in targets:
        if is_ipv4_cidr(target):
            final_targets += [("ip", ip) for ip in expand_cidr(target)]
        elif is_ipv4_addr(target):
            final_targets.append(("ipv4", target))
        elif is_ipv6_addr(target):
            final_targets.append(("ipv6", target))
        elif is_fqdn(target):
            final_targets.append(("fqdn", target))
        else:
            logger.debug("[debug] Target '%s' was not added." % target)

    final_targets = sorted(list(set(final_targets)))
    return final_targets
