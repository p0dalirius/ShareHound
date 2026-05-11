#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : collect_contents_at_depth.py
# Author             : Remi Gascou (@podalirius_)
# Date created       : 12 Aug 2025


# Base

node_kind_network_share_base = "NetworkShareBase"

# Contents

node_kind_network_share_host = "NetworkShareHost"

edge_kind_has_network_share = "HasNetworkShare"
edge_kind_hosts_network_share = "HostsNetworkShare"

node_kind_network_share_dfs = "NetworkShareDFS"
node_kind_network_share_smb = "NetworkShareSMB"

edge_kind_contains = "Contains"

node_kind_file = "File"
node_kind_directory = "Directory"

# Rights

node_kind_principal = "Principal"
node_kind_group = "Group"

# Edges kinds on Share rights

edge_kind_can_generic_execute = "CanGenericExecute"
edge_kind_can_generic_write = "CanGenericWrite"
edge_kind_can_generic_read = "CanGenericRead"
edge_kind_can_generic_all = "CanGenericAll"

edge_kind_can_ds_create_child = "CanDsCreateChild"
edge_kind_can_ds_delete_child = "CanDsDeleteChild"
edge_kind_can_ds_list_contents = "CanDsListContents"
edge_kind_can_ds_write_extended_properties = "CanDsWriteExtendedProperties"
edge_kind_can_ds_read_property = "CanDsReadProperty"
edge_kind_can_ds_write_property = "CanDsWriteProperty"
edge_kind_can_ds_delete_tree = "CanDsDeleteTree"
edge_kind_can_ds_list_object = "CanDsListObject"
edge_kind_can_ds_control_access = "CanDsControlAccess"

edge_kind_can_delete = "CanDelete"
edge_kind_can_read_control = "CanReadControl"
edge_kind_can_write_dac = "CanWriteDacl"
edge_kind_can_write_owner = "CanWriteOwner"


# Edges kinds on NTFS rights

edge_kind_can_ntfs_generic_read = "CanNTFSGenericRead"
edge_kind_can_ntfs_generic_write = "CanNTFSGenericWrite"
edge_kind_can_ntfs_generic_execute = "CanNTFSGenericExecute"
edge_kind_can_ntfs_generic_all = "CanNTFSGenericAll"

edge_kind_can_ntfs_maximum_allowed = "CanNTFSMaximumAllowed"
edge_kind_can_ntfs_access_system_security = "CanNTFSAccessSystemSecurity"
edge_kind_can_ntfs_synchronize = "CanNTFSSynchronize"
edge_kind_can_ntfs_write_owner = "CanNTFSWriteOwner"
edge_kind_can_ntfs_write_dacl = "CanNTFSWriteDacl"
edge_kind_can_ntfs_read_control = "CanNTFSReadControl"
edge_kind_can_ntfs_delete = "CanNTFSDelete"


# Kinds for contents

node_kind_content_file = "File"
node_kind_content_directory = "Directory"
