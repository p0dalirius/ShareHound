#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

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
        # An unthrottled writer outruns the exporter by roughly 4x, and each
        # export snapshots the file size it sees on entry. Left to run flat
        # out the writer therefore grows the next snapshot geometrically
        # (~5x per export), so a handful of exports means minutes of work and
        # gigabytes of temp file. Pace the writer so the on-disk buffer stays
        # small while still being appended to throughout every export, which
        # is the interleaving this test exists to cover.
        WRITE_BATCH = 20
        BATCH_PAUSE = 0.002
        MAX_NODES = 200_000  # safety net so a wedged main thread can't run away

        g = StreamingOpenGraph()
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
        tmp.close()
        stop = threading.Event()
        exc = []

        def writer():
            i = 0
            while not stop.is_set() and i < MAX_NODES:
                try:
                    g.add_node_without_validation(_mknode(f"n{i}"))
                    i += 1
                    if i % WRITE_BATCH == 0:
                        time.sleep(BATCH_PAUSE)
                except Exception as e:
                    exc.append(e)
                    return

        t = threading.Thread(target=writer, daemon=True)
        try:
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

            # The writer outliving the loop is what makes every export above
            # a genuinely concurrent one.
            self.assertTrue(t.is_alive(), "writer stopped before the exports finished")

            stop.set()
            t.join(timeout=5)
            self.assertFalse(t.is_alive(), "writer did not stop")
            self.assertFalse(exc, f"writer saw errors: {exc}")
        finally:
            stop.set()
            t.join(timeout=5)
            g.close()
            os.unlink(tmp.name)

    def test_export_excludes_records_appended_after_the_snapshot(self):
        # export_to_file fstats the buffer under the lock, then streams
        # without it. A concurrent writer keeps appending during that read,
        # and its 256 KB buffer can auto-flush mid-record, so the bytes past
        # the snapshot may end in a torn line. Only records wholly inside the
        # snapshot may be emitted, or the output is not parseable JSON.
        g = StreamingOpenGraph()
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
        tmp.close()

        real_stream = StreamingOpenGraph._stream_ndjson

        def append_then_stream(out, path, byte_limit=None):
            with open(path, "a") as concurrent:
                concurrent.write(json.dumps(_mknode("late").to_dict()) + "\n")
                concurrent.write('{"id": "torn", "kinds"')  # flushed mid-record
            return real_stream(out, path, byte_limit)

        try:
            for i in range(5):
                g.add_node_without_validation(_mknode(f"n{i}"))

            with patch.object(
                StreamingOpenGraph, "_stream_ndjson",
                staticmethod(append_then_stream),
            ):
                self.assertTrue(
                    g.export_to_file(tmp.name, include_metadata=False)
                )

            with open(tmp.name) as f:
                data = json.load(f)

            ids = [n["id"] for n in data["graph"]["nodes"]]
            self.assertEqual(ids, [f"n{i}" for i in range(5)])
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
