#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : __main__.py
# Author             : Remi Gascou (@podalirius_)
# Date created       : 12 Aug 2025

import argparse
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from threading import Lock

import argcomplete
import ldap3.core.exceptions
from bhopengraph.OpenGraph import OpenGraph
from rich.console import Console
from shareql.ast.rule import Rule
from shareql.grammar.parser import RuleParser

import sharehound.kinds as kinds
from sharehound.__version__ import __version__
from sharehound.core.Config import Config
from sharehound.core.Logger import Logger
from sharehound.status import status
from sharehound.targets import load_targets
from sharehound.utils.delta_time import delta_time
from sharehound.utils.utils import filesize
from sharehound.worker import worker

DEFAULT_RULES = """
DEFAULT: ALLOW
DENY EXPLORATION IF SHARE.NAME IN ['c$','print$','admin$','ipc$']
ALLOW EXPLORATION
"""


def parse_rules(options: argparse.Namespace, logger: Logger) -> list[Rule]:
    """
    Parse the rules from the options.
    """

    logger.debug("Parsing rules")

    parsing_errors = []
    parsed_rules = []

    rp = RuleParser()

    # Setup default rules
    if len(options.rules_file) == 0 and len(options.rule_string) == 0:
        options.rule_string = DEFAULT_RULES.strip().split("\n")

    if len(options.rules_file) > 0:
        for rules_file in options.rules_file:
            if os.path.exists(rules_file):
                with open(rules_file, "r") as f:
                    rf_parsed_rules, rf_parsing_errors = rp.parse(f.read())
                    parsed_rules.extend(rf_parsed_rules)
                if len(rf_parsing_errors) > 0:
                    logger.error("Errors while parsing rules of file %s:" % rules_file)
                    for error in rf_parsing_errors:
                        for line in error.strip().split("\n"):
                            logger.error(line)
                    logger.info("Quitting ShareHound ...")
                    sys.exit(1)
            else:
                logger.error(f"Rules file {rules_file} does not exist")
                sys.exit(1)

    elif len(options.rule_string) > 0:
        rules_text = "\n".join(options.rule_string)
        parsed_rules, parsing_errors = rp.parse(rules_text)
        parsed_rules.extend(parsed_rules)
        parsing_errors.extend(parsing_errors)

    if len(parsing_errors) > 0:
        logger.error("Errors while parsing rules:")
        for multiline_error in parsing_errors:
            for line in multiline_error.strip().split("\n"):
                logger.error(line)

        logger.info("Quitting ShareHound ...")
        sys.exit(1)
    else:
        if len(parsed_rules) > 0:
            if len(parsed_rules) == 1:
                logger.debug("1 rule parsed successfully")
            else:
                logger.debug("%d rules parsed successfully" % len(parsed_rules))
            for rule_no, rule in enumerate(parsed_rules, start=1):
                logger.debug("Rule %d: %s" % (rule_no, rule))
        else:
            logger.debug("No rules parsed")

    return parsed_rules


def parseArgs():
    print("ShareHound v%s - by Remi Gascou (@podalirius_) @ SpecterOps\n" % __version__)

    parser = argparse.ArgumentParser(
        add_help=True,
        description="A Python script to generate a bloodhound opengraph of the rights of shares on a remote Windows machine.",
    )

    parser.add_argument(
        "-v",
        "--verbose",
        default=False,
        action="store_true",
        help="Verbose mode (default: False)",
    )
    parser.add_argument(
        "--debug",
        default=False,
        action="store_true",
        help="Debug mode (default: False)",
    )
    parser.add_argument(
        "--no-colors",
        default=False,
        action="store_true",
        help="Disable ANSI escape codes",
    )
    parser.add_argument("--logfile", default=None, help="Log file to write to")

    # Advanced Configuration
    group_advanced = parser.add_argument_group("Advanced Configuration")
    group_advanced.add_argument(
        "--advertised-name", default=None, help="Advertised name of the target machine"
    )
    group_advanced.add_argument(
        "--threads",
        type=int,
        default=os.cpu_count() * 8 if os.cpu_count() is not None else 1,
        help="Number of threads to use (default: %d)"
        % (os.cpu_count() * 8 if os.cpu_count() is not None else 1),
    )
    group_advanced.add_argument(
        "--max-workers-per-host",
        type=int,
        default=8,
        help="Maximum concurrent shares per host (default: 8)",
    )
    group_advanced.add_argument(
        "--global-max-workers",
        type=int,
        default=200,
        help="Global maximum workers across all hosts (default: 200)",
    )
    group_advanced.add_argument(
        "-ns",
        "--nameserver",
        default=None,
        help="Nameserver to use for DNS queries (default: None)",
    )
    group_advanced.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=2.5,
        help="Timeout in seconds for network operations (default: 2.5 seconds)",
    )

    # Rules Configuration
    group_rules = parser.add_argument_group("Rules")
    group_rules.add_argument(
        "-rf",
        "--rules-file",
        action="append",
        default=[],
        help="Path to file containing rules. If provided, --rules-string is ignored.",
        type=str,
    )
    group_rules.add_argument(
        "-rs",
        "--rule-string",
        default=[],
        action="append",
        help="Rules string to use. Can be used multiple times.",
        type=str,
    )

    # Share Exploration Configuration
    group_share_exploration = parser.add_argument_group("Share Exploration")
    group_share_exploration.add_argument(
        "--share", default=None, help="Share to enumerate (default: all shares)"
    )
    group_share_exploration.add_argument(
        "--depth",
        type=int,
        default=3,
        help="Maximum depth to traverse directories (default: 3)",
    )
    group_share_exploration.add_argument(
        "--include-common-shares",
        default=False,
        action="store_true",
        help="Include common shares (C$, ADMIN$, IPC$, PRINT$) in enumeration",
    )

    # Targets source
    group_targets_source = parser.add_argument_group("Targets")
    group_targets_source.add_argument(
        "-tf",
        "--targets-file",
        default=None,
        type=str,
        help="Path to file containing a line by line list of targets.",
    )
    group_targets_source.add_argument(
        "-tt",
        "--target",
        default=[],
        type=str,
        action="append",
        help="Target IP, FQDN or CIDR.",
    )
    group_targets_source.add_argument(
        "-ad",
        "--auth-domain",
        default="",
        type=str,
        help="Windows domain to authenticate to.",
    )
    group_targets_source.add_argument(
        "-ai",
        "--auth-dc-ip",
        default=None,
        type=str,
        help="IP of the domain controller.",
    )
    group_targets_source.add_argument(
        "-au",
        "--auth-user",
        default=None,
        type=str,
        help="Username of the domain account.",
    )
    group_targets_source.add_argument(
        "-ap",
        "--auth-password",
        default=None,
        type=str,
        help="Password of the domain account.",
    )
    group_targets_source.add_argument(
        "-ah",
        "--auth-hashes",
        default=None,
        type=str,
        help="LM:NT hashes to pass the hash for this user.",
    )
    group_targets_source.add_argument(
        "-ak",
        "--auth-key",
        default=None,
        type=str,
        help="Kerberos key to use for authentication.",
    )
    group_targets_source.add_argument(
        "-k",
        "--use-kerberos",
        default=False,
        action="store_true",
        help="Use Kerberos for authentication (default: False)",
    )
    group_targets_source.add_argument(
        "-kh",
        "--kdc-host",
        default=None,
        type=str,
        help="KDC host to use for Kerberos authentication (default: None)",
    )
    group_targets_source.add_argument(
        "--ldaps", default=False, action="store_true", help="Use LDAPS (default: False)"
    )
    group_targets_source.add_argument(
        "--subnets",
        default=False,
        action="store_true",
        help="Get all subnets from the domain and use them as targets (default: False)",
    )

    argcomplete.autocomplete(parser, always_complete_options=False)

    args = parser.parse_args()

    if (
        (args.targets_file is None)
        and (len(args.target) == 0)
        and (
            args.auth_user is None
            and (args.auth_password is None or args.auth_hashes is None)
        )
    ):
        parser.print_help()
        print("\n[!] No targets specified.")
        sys.exit(0)

    if (args.auth_password is not None) and (args.auth_hashes is not None):
        parser.print_help()
        print("\n[!] Options --auth-password/--auth-hashes are mutually exclusive.")
        sys.exit(0)

    if (args.auth_dc_ip is None) and (
        args.auth_user is not None
        and (args.auth_password is not None or args.auth_hashes is not None)
    ):
        parser.print_help()
        print(
            "\n[!] Option --auth-dc-ip is required when using --auth-domain/--auth-user/--auth-password/--auth-hashes/--auth-key/--use-kerberos/"
        )
        sys.exit(0)

    return args


def main():
    options = parseArgs()

    config = Config()
    config.debug = options.debug
    config.no_colors = options.no_colors

    # Setup the rich console
    console = Console()

    logger = Logger(config=config, logfile=options.logfile)

    parsed_rules = parse_rules(options, logger)

    logger.info("Starting ShareHound")
    timestamp_start = time.time()

    graph = OpenGraph(source_kind=kinds.node_kind_network_share_base)

    targets = []
    try:
        targets = load_targets(options, config, logger)
    except ldap3.core.exceptions.LDAPSocketOpenError as err:
        logger.error("Failed to connect to the LDAP server: %s" % str(err))
        sys.exit(1)
    except Exception:
        logger.error("Failed to load targets, domain controller not reachable?")
        sys.exit(1)
    logger.info("Targeting %d hosts" % len(targets))

    # Start the worker threads

    worker_results = {
        "success": 0,
        "errors": 0,
        "tasks": {
            "pending": 0,
            "total": 0,
            "finished": 0,
        },
        # Share counters
        "shares_total": 0,
        "shares_processed": 0,
        "shares_skipped": 0,
        "shares_pending": 0,
        # File counters
        "files_total": 0,
        "files_processed": 0,
        "files_skipped": 0,
        "files_pending": 0,
        # Directory counters
        "directories_total": 0,
        "directories_processed": 0,
        "directories_skipped": 0,
        "directories_pending": 0,
    }
    results_lock = Lock()
    with ThreadPoolExecutor(max_workers=options.threads) as executor:
        futures = [
            executor.submit(
                worker,
                options,
                config,
                graph,
                target,
                parsed_rules,
                worker_results,
                results_lock,
            )
            for target in targets
        ]
        status(console, worker_results, futures)

    # Export the graph to a file
    logger.info('Exporting graph to "%s"' % "opengraph.json")
    logger.increment_indent()
    logger.info("Nodes: %d" % graph.get_node_count())
    logger.info("Edges: %d" % graph.get_edge_count())
    graph.export_to_file("opengraph.json", include_metadata=False)
    logger.info(
        'Graph successfully exported to "%s" (%s)'
        % ("opengraph.json", filesize(os.path.getsize("opengraph.json")))
    )
    logger.decrement_indent()

    # Display final summary
    logger.info("Final Summary:")
    logger.increment_indent()
    logger.info(
        "Shares: %d processed, %d skipped (total: %d)"
        % (
            worker_results["shares_processed"],
            worker_results["shares_skipped"],
            worker_results["shares_total"],
        )
    )
    logger.info(
        "Files: %d processed, %d skipped (total: %d)"
        % (
            worker_results["files_processed"],
            worker_results["files_skipped"],
            worker_results["files_total"],
        )
    )
    logger.info(
        "Directories: %d processed, %d skipped (total: %d)"
        % (
            worker_results["directories_processed"],
            worker_results["directories_skipped"],
            worker_results["directories_total"],
        )
    )
    logger.decrement_indent()

    timestamp_stop = time.time()
    elapsed_time = delta_time(timestamp_stop - timestamp_start)
    logger.info("ShareHound completed, time elapsed: %s" % elapsed_time)


if __name__ == "__main__":
    main()
