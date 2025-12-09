#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : opengraph_context.py
# Author             : Remi Gascou (@podalirius_)
# Date created       : 12 Aug 2025


import ntpath
from typing import List, Optional, Tuple

from bhopengraph.Edge import Edge
from bhopengraph.Node import Node
from bhopengraph.OpenGraph import OpenGraph

import sharehound.kinds as kinds


class OpenGraphContext:
    """
    Context manager for building OpenGraph structures representing SMB share hierarchies.

    This class maintains the current context while traversing SMB shares, tracking the host,
    current share, directory path, and current element being processed. It provides methods
    to build the graph structure incrementally as the share is explored.

    Graph Structure:
        (Host) --[HasNetworkShare]--> (NetworkShareSMB|NetworkShareDFS) --[Contains]--> (Directory|File)*

    Attributes:
        graph (OpenGraph): The OpenGraph instance to populate
        host (Optional[Node]): The host node representing the SMB server
        share (Optional[Tuple[Node, dict]]): Current share node and its rights
        path (List[Tuple[Node, dict]]): List of directory nodes in current path with their rights
        element (Optional[Tuple[Node, dict]]): Current file/directory element and its rights

    Methods:
        set_host: Set the host node
        get_host: Get the host node
        set_share: Set the current share node and rights
        get_share: Get the current share node
        push_directory: Add a directory to the current path
        pop_directory: Remove the last directory from the current path
        set_element: Set the current element (file or directory)
        get_element: Get the current element
        add_path_to_graph: Add the current path structure to the graph
        add_rights_to_graph: Add access rights for a node to the graph

    """

    host: Optional[Node]
    share: Optional[Tuple[Node, dict]]
    path: List[Tuple[Node, dict]]
    element: Optional[Tuple[Node, dict]]

    def __init__(self, graph: OpenGraph):
        self.graph = graph
        self.host = (None, {})
        self.share = (None, {})
        self.path = []
        self.element = (None, {})

    def add_path_to_graph(self) -> None:
        """
        Add the path to the graph

        Args:
            None

        Returns:
            None
        """
        # Set base host and share nodes
        if self.host is None:
            return None
        self.graph.add_node_without_validation(self.host)

        share_node, share_rights = self.share
        if share_node is None:
            return None
        self.graph.add_node_without_validation(share_node)
        self.add_rights_to_graph(share_node.id, share_rights)

        # Add edge [HasNetworkShare] from host to share
        self.graph.add_edge_without_validation(
            Edge(
                start_node=self.host.id,
                end_node=share_node.id,
                kind=kinds.edge_kind_has_network_share,
            )
        )

        # At this point we have created
        # (Host) --[HasNetworkShare]--> ((NetworkShareSMB|NetworkShareDFS))

        # Add edges [Contains] from parent to directory
        parent_id = share_node.id
        for directory in self.path:
            directory_node, directory_rights = directory
            self.graph.add_node_without_validation(directory_node)
            self.add_rights_to_graph(directory_node.id, directory_rights)
            self.graph.add_edge_without_validation(
                Edge(
                    start_node=parent_id,
                    end_node=directory_node.id,
                    kind=kinds.edge_kind_contains,
                )
            )
            parent_id = directory_node.id

        # At this point we have created
        # (Host) --[Expose]--> ((NetworkShareSMB|NetworkShareDFS)) --[Contains]--> ((File)|(Directory))*

        # Add edge [Contains] from parent to element

        element_node, element_rights = self.element
        if element_node is None:
            return None
        self.graph.add_node_without_validation(element_node)
        self.add_rights_to_graph(element_node.id, element_rights)

        self.graph.add_edge_without_validation(
            Edge(
                start_node=parent_id,
                end_node=element_node.id,
                kind=kinds.edge_kind_contains,
            )
        )

        # At this point we have created
        # (Host) --[Expose]--> ((NetworkShareSMB|NetworkShareDFS)) --[Contains]--> ((File)|(Directory))* --[Contains]--> ((File)|(Directory))

    def add_rights_to_graph(self, element_id: str, rights: dict) -> None:
        """
        Add rights to the graph

        Args:
            element_id: The id of the element
            rights: The rights to add

        Returns:
            None
        """

        if rights is None:
            raise Exception("Rights are None in OpenGraphContext.add_rights_to_graph()")

        # existing_sids = []
        for sid, rights_edges in rights.items():
            # Check if the sid is already in the graph
            # And if not, add it
            # if sid not in existing_sids:
            #     # TODO: Needs to create nodes users and groups.
            #     self.graph.add_node(
            #         Node(
            #             kinds=[kinds.node_kind_principal],
            #             id=sid,
            #         )
            #     )
            #     existing_sids.append(sid)

            for right_edge in rights_edges:
                self.graph.add_edge_without_validation(
                    Edge(
                        start_node=sid,
                        end_node=element_id,
                        kind=right_edge,
                    )
                )

    def push_path(self, node: Node, rights: dict):
        """
        Add a node to the path stack

        Args:
            node: The node to add
            rights: The rights to add

        Returns:
            None
        """
        self.path.append((node, rights))

    def pop_path(self) -> Optional[Node]:
        """
        Remove and return the last node from the path stack

        Args:
            None

        Returns:
            The last node from the path stack
        """
        if self.path:
            return self.path.pop()[0]
        return None

    # Getter and setter

    def set_element(self, element: Node) -> None:
        """
        Set the element node

        Args:
            element: The element node to set

        Returns:
            None
        """
        self.element = (element, self.element[1])

    def set_element_rights(self, rights: dict) -> None:
        """
        Set the element rights

        Args:
            rights: The rights to set

        Returns:
            None
        """
        if rights is None:
            rights = {}
        self.element = (self.element[0], rights)

    def get_element_rights(self):
        """
        Get the element rights
        """
        return self.element[1]

    def get_element(self):
        """
        Get the element node
        """
        return self.element[0]

    def set_directory_rights(self, rights: dict) -> None:
        """
        Set rights for the last directory in the path

        Args:
            rights: The rights to set

        Returns:
            None
        """
        if self.path and rights is not None:
            node, _ = self.path[-1]
            self.path[-1] = (node, rights)

    def clear_element(self):
        """
        Clear the element

        Args:
            None

        Returns:
            None
        """
        self.element = (None, {})

    def get_path(self):
        """
        Get the path

        Args:
            None

        Returns:
            The path
        """
        return self.path

    def get_string_path_from_root(self) -> str:
        """
        Get the string path from the root

        Args:
            None

        Returns:
            The string path from the root
        """
        return ntpath.sep.join(
            [node.properties.get_property("name") for (node, _) in self.path]
        )

    def clear_path(self):
        """
        Clear the path

        Args:
            None

        Returns:
            None
        """
        self.path = []

    def set_host(self, host: Node):
        """
        Set the host

        Args:
            host: The host node to set

        Returns:
            None
        """
        self.host = host

    def get_host(self):
        """
        Get the host

        Args:
            None

        Returns:
            The host node
        """
        return self.host

    def clear_host(self):
        """
        Clear the host

        Args:
            None

        Returns:
            None
        """
        self.host = None

    def set_share(self, share: Node) -> None:
        """
        Set the share

        Args:
            share: The share node to set

        Returns:
            None
        """
        self.share = (share, self.share[1])

    def get_share(self):
        """
        Get the share

        Args:
            None

        Returns:
            The share node
        """
        return self.share[0]

    def set_share_rights(self, rights: dict) -> None:
        """
        Set the share rights

        Args:
            rights: The rights to set

        Returns:
            None
        """
        self.share = (self.share[0], rights)

    def get_share_rights(self) -> dict:
        """
        Get the share rights

        Args:
            None

        Returns:
            The share rights
        """
        return self.share[1]

    def clear_share(self):
        """
        Clear the share

        Args:
            None

        Returns:
            None
        """
        self.share = (None, {})
