#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os
import tempfile
import threading
import time
import unittest

from bhopengraph.Edge import Edge
from bhopengraph.Node import Node
from bhopengraph.Properties import Properties

from sharehound.core.StreamingOpenGraph import StreamingOpenGraph


def _mknode(id_: str) -> Node:
    return Node(id=id_, kinds=["Thing"], properties=Properties(name=id_))


def _mkedge(a: str, b: str, k: str = "Has") -> Edge:
    return Edge(start_node=a, end_node=b, kind=k)


class StreamingSnapshotTests(unittest.TestCase):
    def test_export_writes_atomically_via_rename(self):
        g = StreamingOpenGraph()
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
        tmp.close()
        try:
            g.add_node_without_validation(_mknode("a"))
            g.add_edge_without_validation(_mkedge("a", "a"))
            self.assertTrue(g.export_to_file(tmp.name, include_metadata=False))
            # .tmp sibling must not remain after a successful export.
            self.assertFalse(os.path.exists(tmp.name + ".tmp"))
            with open(tmp.name) as f:
                data = json.load(f)
            self.assertEqual(len(data["graph"]["nodes"]), 1)
        finally:
            g.close()
            os.unlink(tmp.name)

    def test_snapshot_reflects_records_at_snapshot_time(self):
        g = StreamingOpenGraph()
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
        tmp.close()
        try:
            for i in range(3):
                g.add_node_without_validation(_mknode(f"n{i}"))

            # Take a snapshot with three nodes present.
            g.export_to_file(tmp.name, include_metadata=False)
            with open(tmp.name) as f:
                snap1 = json.load(f)
            self.assertEqual(len(snap1["graph"]["nodes"]), 3)

            # Add more nodes and re-snapshot.
            for i in range(3, 7):
                g.add_node_without_validation(_mknode(f"n{i}"))
            g.export_to_file(tmp.name, include_metadata=False)
            with open(tmp.name) as f:
                snap2 = json.load(f)
            self.assertEqual(len(snap2["graph"]["nodes"]), 7)
        finally:
            g.close()
            os.unlink(tmp.name)

    def test_snapshot_during_concurrent_writes_is_valid_json(self):
        g = StreamingOpenGraph()
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
        tmp.close()
        stop = threading.Event()
        exc = []

        def writer():
            i = 0
            while not stop.is_set():
                try:
                    g.add_node_without_validation(_mknode(f"n{i}"))
                    i += 1
                except Exception as e:
                    exc.append(e)
                    return

        try:
            t = threading.Thread(target=writer)
            t.start()
            # Let the writer get ahead.
            time.sleep(0.05)

            for _ in range(5):
                self.assertTrue(
                    g.export_to_file(tmp.name, include_metadata=False)
                )
                with open(tmp.name) as f:
                    # Must parse — no truncation, no mid-record cuts.
                    data = json.load(f)
                self.assertIn("graph", data)
                self.assertIn("nodes", data["graph"])
                time.sleep(0.02)

            stop.set()
            t.join(timeout=2)
            self.assertFalse(exc, f"writer saw errors: {exc}")
        finally:
            g.close()
            os.unlink(tmp.name)

    def test_export_after_close_returns_false(self):
        g = StreamingOpenGraph()
        g.add_node_without_validation(_mknode("a"))
        g.close()
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
        tmp.close()
        try:
            self.assertFalse(g.export_to_file(tmp.name))
        finally:
            os.unlink(tmp.name)


if __name__ == "__main__":
    unittest.main()
