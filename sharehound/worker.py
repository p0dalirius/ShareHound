#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : worker.py
# Author             : Remi Gascou (@podalirius_)
# Date created       : 12 Aug 2025

import argparse
import random
import time
import traceback
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from threading import Lock, Semaphore
from typing import Dict, Optional, Tuple

from bhopengraph.Node import Node
from bhopengraph.OpenGraph import OpenGraph
from bhopengraph.Properties import Properties
from shareql.ast.rule import Rule
from shareql.evaluate.evaluator import RulesEvaluator

import sharehound.kinds as kinds
from sharehound.collector.opengraph_context import OpenGraphContext
from sharehound.core.Config import Config
from sharehound.core.Credentials import Credentials
from sharehound.core.Logger import Logger, TaskLogger
from sharehound.core.SMBSession import SMBSession
from sharehound.utils.delta_time import delta_time
from sharehound.utils.utils import dns_resolve, is_port_open


class ConnectionPool:
    """
    Manages SMB session connections per host with connection reuse and concurrency limits.
    """

    def __init__(self, max_connections_per_host: int = 8):
        self.max_connections_per_host = max_connections_per_host
        self._connections: Dict[str, list] = defaultdict(list)
        self._semaphores: Dict[str, Semaphore] = defaultdict(
            lambda: Semaphore(max_connections_per_host)
        )
        self._lock = Lock()

    def get_connection(
        self, host: str, options: argparse.Namespace, config: Config, logger: Logger
    ) -> Optional[SMBSession]:
        """Get an available connection for the host, creating one if needed."""
        with self._lock:
            # Try to reuse an existing connection
            if self._connections[host]:
                connection = self._connections[host].pop()
                if connection.ping_smb_session():
                    return connection
                else:
                    # Connection is dead, close it
                    try:
                        connection.close_smb_session()
                    except Exception:
                        pass

            # Create new connection
            credentials = Credentials(
                domain=options.auth_domain,
                username=options.auth_user,
                password=options.auth_password,
                hashes=options.auth_hashes,
                use_kerberos=False,
                aesKey=None,
                kdcHost=None,
            )

            smb_session = SMBSession(
                host=host,
                port=445,
                timeout=10,
                credentials=credentials,
                advertisedName=options.advertised_name,
                config=config,
                logger=logger,
            )

            if smb_session.init_smb_session():
                return smb_session
            else:
                return None

    def return_connection(self, host: str, connection: SMBSession):
        """Return a connection to the pool for reuse."""
        with self._lock:
            if len(self._connections[host]) < self.max_connections_per_host:
                self._connections[host].append(connection)
            else:
                # Pool is full, close the connection
                try:
                    connection.close_smb_session()
                except Exception:
                    pass

    def close_all(self):
        """Close all connections in the pool."""
        with self._lock:
            for host_connections in self._connections.values():
                for connection in host_connections:
                    try:
                        connection.close_smb_session()
                    except Exception:
                        pass
            self._connections.clear()


def retry_with_exponential_backoff(func, max_retries: int = 3, base_delay: float = 1.0):
    """
    Retry a function with exponential backoff.

    Args:
        func: Function to retry
        max_retries: Maximum number of retries
        base_delay: Base delay in seconds

    Returns:
        Result of the function call or None if all retries failed
    """
    for attempt in range(max_retries + 1):
        try:
            return func()
        except Exception as e:
            if attempt == max_retries:
                raise e

            # Calculate delay with jitter
            delay = base_delay * (2**attempt) + random.uniform(0, 1)
            time.sleep(delay)


def process_share_task(
    share_name: str,
    share_data: dict,
    host: str,
    options: argparse.Namespace,
    config: Config,
    graph: OpenGraph,
    parsed_rules: list[Rule],
    connection_pool: ConnectionPool,
    host_semaphore: Semaphore,
    worker_results: dict,
    results_lock: Lock,
    logger: Logger,
) -> Tuple[int, int, int, int, int, int, int, int]:
    """
    Process a single share - this is the unit of work for the ThreadPoolExecutor.

    Returns:
        tuple: (total_share_count, skipped_shares_count, total_file_count, skipped_files_count,
                processed_files_count, total_directory_count, skipped_directories_count,
                processed_directories_count)
    """

    # Create a task-specific logger for this share
    task_logger = TaskLogger(base_logger=logger, task_id=f"{host}:{share_name}")

    def _process_share():
        with host_semaphore:  # Limit concurrency per host
            # Get connection from pool
            smb_session = connection_pool.get_connection(host, options, config, logger)
            if not smb_session:
                task_logger.debug(f"Failed to get connection for host {host}")
                return (0, 1, 0, 0, 0, 0, 0, 0)

            try:
                rules_evaluator = RulesEvaluator(rules=parsed_rules)

                # Evaluate the rules against the share
                from shareql.objects.share import RuleObjectShare

                rule_object_share = RuleObjectShare(
                    name=share_name,
                    description=share_data.get("description", ""),
                    hidden=share_name.endswith("$"),
                )
                rules_evaluator.context.set_share(rule_object_share)

                if not rules_evaluator.can_explore(rule_object_share):
                    task_logger.debug(f"[>] Skipping share: {share_name}")
                    return (0, 1, 0, 0, 0, 0, 0, 0)

                # Create share OpenGraph node
                ogc = OpenGraphContext(graph=graph)

                # Prepare host node
                host_node = Node(
                    kinds=[kinds.node_kind_network_share_host],
                    id=host,
                    properties=Properties(name=host),
                )
                ogc.set_host(host_node)

                # Create share node
                share_node = Node(
                    kinds=[kinds.node_kind_network_share_smb],
                    id=f"\\\\{host}\\{share_name}\\",
                    properties=Properties(
                        displayName=share_name,
                        description=share_data.get("description", ""),
                        hidden=share_name.endswith("$"),
                    ),
                )
                ogc.set_share(share_node)

                # Set the share in SMB session
                smb_session.set_share(share_name)

                # Collect share security descriptor
                from sharehound.collector.collect_share_rights import \
                    collect_share_rights

                share_rights = collect_share_rights(
                    smb_session=smb_session,
                    share_name=share_name,
                    rules_evaluator=rules_evaluator,
                    logger=task_logger,
                )
                ogc.set_share_rights(share_rights)

                if rules_evaluator.can_process(rule_object_share):
                    ogc.add_path_to_graph()

                # Collect contents of the share
                from sharehound.collector.collect_contents_in_share import \
                    collect_contents_in_share

                (
                    sub_total_file_count,
                    sub_skipped_files_count,
                    sub_processed_files_count,
                    sub_total_directory_count,
                    sub_skipped_directories_count,
                    sub_processed_directories_count,
                ) = collect_contents_in_share(
                    smb_session=smb_session,
                    ogc=ogc,
                    rules_evaluator=rules_evaluator,
                    worker_results=worker_results,
                    results_lock=results_lock,
                    logger=task_logger,
                )

                return (
                    1,
                    0,
                    sub_total_file_count,
                    sub_skipped_files_count,
                    sub_processed_files_count,
                    sub_total_directory_count,
                    sub_skipped_directories_count,
                    sub_processed_directories_count,
                )

            finally:
                # Return connection to pool
                connection_pool.return_connection(host, smb_session)

    try:
        result = retry_with_exponential_backoff(_process_share, max_retries=3)

        # Update task counters when share processing is complete
        with results_lock:
            worker_results["tasks"]["pending"] -= 1
            worker_results["tasks"]["finished"] += 1

        return result
    except Exception as e:
        task_logger.debug(f"Failed to process share {share_name} on {host}: {str(e)}")
        task_logger.debug(traceback.format_exc())

        # Update task counters even on failure
        with results_lock:
            worker_results["tasks"]["pending"] -= 1
            worker_results["tasks"]["finished"] += 1

        return (0, 1, 0, 0, 0, 0, 0, 0)


def multithreaded_share_worker(
    options: argparse.Namespace,
    config: Config,
    graph: OpenGraph,
    target: tuple[str, str],
    parsed_rules: list[Rule],
    worker_results: dict,
    results_lock: Lock,
    max_workers_per_host: int = 8,
    global_max_workers: int = 200,
):
    """
    Multithreaded worker function to collect shares and their contents.
    Each share gets its own task in the executor for optimal parallelism.

    Args:
        options: the argparse namespace that contains the options from the command line
        config: The config object (contains the debug and no_colors flags)
        graph: The graph object
        target: The target object (type, ip)
        parsed_rules: List of parsed rules
        worker_results: Shared results dictionary
        results_lock: Thread lock for shared resources
        max_workers_per_host: Maximum concurrent shares per host
        global_max_workers: Global maximum workers across all hosts
    """

    try:
        target_type = target[0]
        target_ip = target[1]

        logger = Logger(config=config, logfile=options.logfile)

        if target_type == "fqdn":
            if options.nameserver is not None:
                target_ip = dns_resolve(options, target[1])
                if target_ip is None:
                    logger.debug("Failed to resolve domain name '%s'" % target[1])
                    with results_lock:
                        worker_results["errors"] += 1
                        worker_results["tasks"]["total"] += 1
                        worker_results["tasks"]["finished"] += 1
                    return

        elif target_type == "ipv4" or target_type == "ipv6":
            target_ip = target[1]

        else:
            logger.debug("Invalid target type: %s" % target_type)
            with results_lock:
                worker_results["errors"] += 1
                worker_results["tasks"]["total"] += 1
                worker_results["tasks"]["finished"] += 1
            return

        port_open, error = is_port_open(target_ip, 445, timeout=options.timeout)
        if not port_open:
            logger.debug("Port 445 is not open on %s: %s" % (target_ip, error))
            with results_lock:
                worker_results["errors"] += 1
                worker_results["tasks"]["total"] += 1
                worker_results["tasks"]["finished"] += 1
            return

        # Create connection pool and host semaphore
        connection_pool = ConnectionPool(max_connections_per_host=max_workers_per_host)
        host_semaphore = Semaphore(max_workers_per_host)

        # Get initial connection to discover shares
        initial_connection = connection_pool.get_connection(
            target_ip, options, config, logger
        )
        if not initial_connection:
            logger.debug("Failed to initialize SMB session")
            with results_lock:
                worker_results["errors"] += 1
                worker_results["tasks"]["total"] += 1
                worker_results["tasks"]["finished"] += 1
            return

        try:
            # Discover shares
            shares = initial_connection.list_shares()
            logger.debug(f"Found {len(shares)} shares on {target_ip}")

            # Update task counters for discovered shares
            with results_lock:
                worker_results["tasks"]["total"] += len(shares)
                worker_results["tasks"]["pending"] += len(shares)
                worker_results["shares_pending"] += len(shares)

            if not shares:
                logger.debug(f"No shares found on {target_ip}")
                with results_lock:
                    worker_results["success"] += 1
                    worker_results["tasks"]["total"] += 1
                    worker_results["tasks"]["finished"] += 1
                return

            # Return initial connection to pool
            connection_pool.return_connection(target_ip, initial_connection)

            # Create tasks for each share
            share_tasks = []
            for share_name, share_data in shares.items():
                task = (
                    share_name,
                    share_data,
                    target_ip,
                    options,
                    config,
                    graph,
                    parsed_rules,
                    connection_pool,
                    host_semaphore,
                    worker_results,
                    results_lock,
                    logger,
                )
                share_tasks.append(task)

            # Process shares with ThreadPoolExecutor
            # Limit global concurrency to prevent overwhelming the system
            max_workers = min(len(share_tasks), global_max_workers)

            timestamp_start = time.time()
            total_share_count = 0
            skipped_shares_count = 0
            total_file_count = 0
            skipped_files_count = 0
            processed_files_count = 0
            total_directory_count = 0
            skipped_directories_count = 0
            processed_directories_count = 0

            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = [
                    executor.submit(process_share_task, *task) for task in share_tasks
                ]

                # Collect results
                for future in futures:
                    try:
                        result = future.result()
                        (
                            share_count,
                            skipped_count,
                            file_count,
                            skipped_files,
                            processed_files,
                            dir_count,
                            skipped_dirs,
                            processed_dirs,
                        ) = result

                        total_share_count += share_count
                        skipped_shares_count += skipped_count
                        total_file_count += file_count
                        skipped_files_count += skipped_files
                        processed_files_count += processed_files
                        total_directory_count += dir_count
                        skipped_directories_count += skipped_dirs
                        processed_directories_count += processed_dirs

                    except Exception as e:
                        logger.debug(f"Error processing share: {str(e)}")
                        skipped_shares_count += 1

            # Update global worker_results with aggregated counts
            with results_lock:
                worker_results["shares_total"] += (
                    total_share_count + skipped_shares_count
                )
                worker_results["shares_processed"] += total_share_count
                worker_results["shares_skipped"] += skipped_shares_count
                worker_results["shares_pending"] -= (
                    total_share_count + skipped_shares_count
                )
                worker_results["files_total"] += total_file_count + skipped_files_count
                worker_results["files_processed"] += processed_files_count
                worker_results["files_skipped"] += skipped_files_count
                worker_results["directories_total"] += (
                    total_directory_count + skipped_directories_count
                )
                worker_results["directories_processed"] += processed_directories_count
                worker_results["directories_skipped"] += skipped_directories_count

            timestamp_stop = time.time()
            elapsed_time = delta_time(timestamp_stop - timestamp_start)
            logger.info(
                f"  │ Target {target_ip} completed: {total_share_count} shares (skipped {skipped_shares_count}), {total_file_count} files (processed {processed_files_count}, skipped {skipped_files_count}), {total_directory_count} directories (processed {processed_directories_count}, skipped {skipped_directories_count}) in {elapsed_time}"
            )

        finally:
            # Clean up connection pool
            connection_pool.close_all()

        with results_lock:
            worker_results["success"] += 1
            worker_results["tasks"]["finished"] += 1

    except Exception as e:
        logger.debug(f"Error in multithreaded_share_worker: {str(e)}")
        logger.debug(traceback.format_exc())
        with results_lock:
            worker_results["errors"] += 1
            worker_results["tasks"]["finished"] += 1


def worker(
    options: argparse.Namespace,
    config: Config,
    graph: OpenGraph,
    target: tuple[str, str],
    parsed_rules: list[Rule],
    worker_results: dict,
    results_lock: Lock,
):
    """
    Legacy worker function - now delegates to multithreaded version.
    Kept for backward compatibility.
    """
    # Extract multithreading parameters from options
    max_workers_per_host = getattr(options, "max_workers_per_host", 8)
    global_max_workers = getattr(options, "global_max_workers", 200)

    return multithreaded_share_worker(
        options,
        config,
        graph,
        target,
        parsed_rules,
        worker_results,
        results_lock,
        max_workers_per_host,
        global_max_workers,
    )
