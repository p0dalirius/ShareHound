#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : StreamingOpenGraph.py
# Author             : Remi Gascou (@podalirius_)
# Date created       : 19 Apr 2026

import json
import os
import tempfile
import threading
from typing import Optional, Set

from bhopengraph.Edge import Edge
from bhopengraph.Node import Node
from bhopengraph.OpenGraph import OpenGraph


class StreamingOpenGraph(OpenGraph):
    """
    Disk-backed OpenGraph that keeps peak memory usage bounded regardless
    of graph size.

    Nodes and edges are serialized to NDJSON temporary files as they are
    added. Only a set of node-ID and edge-key strings is kept in memory
    for deduplication. Export streams from disk so the full graph is
    never materialized as Python objects again.

    This mirrors the approach taken by the Go implementation to handle
    file servers large enough to exhaust host memory when the full graph
    is held as in-memory Node/Edge objects.
    """

    def __init__(self, source_kind: Optional[str] = None):
        super().__init__(source_kind=source_kind)

        # Drop the parent's in-memory dicts; we won't use them.
        self.nodes = {}
        self.edges = {}

        self._node_ids: Set[str] = set()
        self._edge_keys: Set[str] = set()
        self._edge_count = 0

        self._lock = threading.Lock()

        fd_nodes, self._node_path = tempfile.mkstemp(
            prefix="sharehound-nodes-", suffix=".ndjson"
        )
        fd_edges, self._edge_path = tempfile.mkstemp(
            prefix="sharehound-edges-", suffix=".ndjson"
        )
        os.close(fd_nodes)
        os.close(fd_edges)

        self._node_file = open(self._node_path, "w", buffering=256 * 1024)
        self._edge_file = open(self._edge_path, "w", buffering=256 * 1024)
        self._closed = False

    # ---- add / count overrides -------------------------------------------------

    def add_node(self, node: Node) -> bool:
        if not isinstance(node, Node):
            return False
        with self._lock:
            if node.id in self._node_ids:
                return False

            if self.source_kind and self.source_kind not in node.kinds:
                node.add_kind(self.source_kind)

            self._node_ids.add(node.id)
            self._node_file.write(json.dumps(node.to_dict()))
            self._node_file.write("\n")
            return True

    def add_node_without_validation(self, node: Node) -> bool:
        return self.add_node(node)

    def add_edge(self, edge: Edge) -> bool:
        if not isinstance(edge, Edge):
            return False
        with self._lock:
            if edge.start_node not in self._node_ids:
                return False
            if edge.end_node not in self._node_ids:
                return False
            return self._write_edge_locked(edge)

    def add_edge_without_validation(self, edge: Edge) -> bool:
        if not isinstance(edge, Edge):
            return False
        with self._lock:
            return self._write_edge_locked(edge)

    def _write_edge_locked(self, edge: Edge) -> bool:
        edge_key = self._edge_key(edge)
        if edge_key in self._edge_keys:
            return False
        self._edge_keys.add(edge_key)
        self._edge_file.write(json.dumps(edge.to_dict()))
        self._edge_file.write("\n")
        self._edge_count += 1
        return True

    def get_node_count(self) -> int:
        with self._lock:
            return len(self._node_ids)

    def get_edge_count(self) -> int:
        with self._lock:
            return self._edge_count

    # ---- export ---------------------------------------------------------------

    def export_json(self, include_metadata: bool = True, indent=None) -> str:
        raise NotImplementedError(
            "StreamingOpenGraph does not support export_json; use export_to_file."
        )

    def export_to_file(
        self, filename: str, include_metadata: bool = True, indent=None
    ) -> bool:
        """
        Stream the graph to `filename` as BloodHound OpenGraph JSON.

        Reads nodes and edges one record at a time from the on-disk NDJSON
        buffers so peak memory stays bounded. The output is written
        atomically via a sibling ``<filename>.tmp`` and ``os.replace`` so
        concurrent readers (including periodic snapshots while collection
        is in progress) never observe a truncated file.
        """
        with self._lock:
            if self._closed:
                return False
            self._node_file.flush()
            self._edge_file.flush()
            node_path = self._node_path
            edge_path = self._edge_path
            # Snapshot sizes so concurrent writers past this point are
            # excluded from this export and picked up by the next one.
            node_limit = os.fstat(self._node_file.fileno()).st_size
            edge_limit = os.fstat(self._edge_file.fileno()).st_size

        tmp_path = filename + ".tmp"
        try:
            with open(tmp_path, "w", buffering=64 * 1024) as out:
                out.write("{\n")

                if include_metadata and self.source_kind:
                    out.write('  "metadata": {"source_kind": ')
                    out.write(json.dumps(self.source_kind))
                    out.write("},\n")

                out.write('  "graph": {\n')

                out.write('    "nodes": [')
                self._stream_ndjson(out, node_path, node_limit)
                out.write("\n    ],\n")

                out.write('    "edges": [')
                self._stream_ndjson(out, edge_path, edge_limit)
                out.write("\n    ]\n")

                out.write("  }\n")
                out.write("}\n")
            os.replace(tmp_path, filename)
            return True
        except (IOError, OSError, TypeError):
            try:
                os.remove(tmp_path)
            except OSError:
                pass
            return False

    @staticmethod
    def _stream_ndjson(out, path: str, byte_limit: Optional[int] = None) -> None:
        first = True
        read_so_far = 0
        with open(path, "r", buffering=256 * 1024) as src:
            for line in src:
                if byte_limit is not None:
                    read_so_far += len(line.encode("utf-8"))
                    if read_so_far > byte_limit:
                        break
                line = line.strip()
                if not line:
                    continue
                if first:
                    out.write("\n      ")
                    first = False
                else:
                    out.write(",\n      ")
                out.write(line)

    # ---- disabled methods -----------------------------------------------------

    def import_from_json(self, json_data: str) -> bool:
        raise NotImplementedError("StreamingOpenGraph does not support import.")

    def import_from_file(self, filename: str) -> bool:
        raise NotImplementedError("StreamingOpenGraph does not support import.")

    def import_from_dict(self, data) -> bool:
        raise NotImplementedError("StreamingOpenGraph does not support import.")

    def clear(self) -> None:
        with self._lock:
            self._node_ids.clear()
            self._edge_keys.clear()
            self._edge_count = 0
            self._node_file.seek(0)
            self._node_file.truncate()
            self._edge_file.seek(0)
            self._edge_file.truncate()

    # ---- lifecycle ------------------------------------------------------------

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            for f, path in (
                (self._node_file, self._node_path),
                (self._edge_file, self._edge_path),
            ):
                try:
                    f.close()
                except Exception:
                    pass
                try:
                    os.remove(path)
                except OSError:
                    pass
            self._node_ids.clear()
            self._edge_keys.clear()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass
