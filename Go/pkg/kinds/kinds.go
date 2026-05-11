// Package kinds defines all node and edge type constants for the ShareHound graph.
// These must match exactly with the Python implementation for BloodHound compatibility.
package kinds

// Base node kind
const NodeKindNetworkShareBase = "NetworkShareBase"

// Host and share node kinds
const (
	NodeKindNetworkShareHost = "NetworkShareHost"
	NodeKindNetworkShareDFS  = "NetworkShareDFS"
	NodeKindNetworkShareSMB  = "NetworkShareSMB"
)

// Content node kinds
const (
	NodeKindFile      = "File"
	NodeKindDirectory = "Directory"
)

// Principal node kinds (referenced from AD)
const (
	NodeKindPrincipal = "Principal"
	NodeKindGroup     = "Group"
)

// Containment edge kinds
const (
	EdgeKindHasNetworkShare   = "HasNetworkShare"
	EdgeKindHostsNetworkShare = "HostsNetworkShare"
	EdgeKindContains          = "Contains"
)

// Share-level permission edge kinds - Generic rights
const (
	EdgeKindCanGenericExecute = "CanGenericExecute"
	EdgeKindCanGenericWrite   = "CanGenericWrite"
	EdgeKindCanGenericRead    = "CanGenericRead"
	EdgeKindCanGenericAll     = "CanGenericAll"
)

// Share-level permission edge kinds - Directory Service rights
const (
	EdgeKindCanDsCreateChild             = "CanDsCreateChild"
	EdgeKindCanDsDeleteChild             = "CanDsDeleteChild"
	EdgeKindCanDsListContents            = "CanDsListContents"
	EdgeKindCanDsWriteExtendedProperties = "CanDsWriteExtendedProperties"
	EdgeKindCanDsReadProperty            = "CanDsReadProperty"
	EdgeKindCanDsWriteProperty           = "CanDsWriteProperty"
	EdgeKindCanDsDeleteTree              = "CanDsDeleteTree"
	EdgeKindCanDsListObject              = "CanDsListObject"
	EdgeKindCanDsControlAccess           = "CanDsControlAccess"
)

// Share-level permission edge kinds - Standard rights
const (
	EdgeKindCanDelete      = "CanDelete"
	EdgeKindCanReadControl = "CanReadControl"
	EdgeKindCanWriteDacl   = "CanWriteDacl"
	EdgeKindCanWriteOwner  = "CanWriteOwner"
)

// Share-level permission edge kinds - File-specific rights
// These correspond to the specific access bits (FILE_READ_DATA, FILE_WRITE_DATA,
// FILE_EXECUTE) that Windows uses in share DACLs instead of generic flags.
// A typical share "Read" permission uses mask 0x001200A9 which has FILE_READ_DATA
// (0x1) set but NOT GENERIC_READ (0x80000000).
const (
	EdgeKindCanShareRead    = "CanShareRead"    // FILE_READ_DATA (0x00000001) at share level
	EdgeKindCanShareWrite   = "CanShareWrite"   // FILE_WRITE_DATA (0x00000002) at share level
	EdgeKindCanShareExecute = "CanShareExecute" // FILE_EXECUTE (0x00000020) at share level
)

// NTFS-level permission edge kinds
const (
	EdgeKindCanNTFSGenericRead          = "CanNTFSGenericRead"
	EdgeKindCanNTFSGenericWrite         = "CanNTFSGenericWrite"
	EdgeKindCanNTFSGenericExecute       = "CanNTFSGenericExecute"
	EdgeKindCanNTFSGenericAll           = "CanNTFSGenericAll"
	EdgeKindCanNTFSAccessSystemSecurity = "CanNTFSAccessSystemSecurity"
	EdgeKindCanNTFSSynchronize          = "CanNTFSSynchronize"
	EdgeKindCanNTFSWriteOwner           = "CanNTFSWriteOwner"
	EdgeKindCanNTFSWriteDacl            = "CanNTFSWriteDacl"
	EdgeKindCanNTFSReadControl          = "CanNTFSReadControl"
	EdgeKindCanNTFSDelete               = "CanNTFSDelete"
)

// NTFS-level object-specific (file/directory) permission edge kinds
const (
	EdgeKindCanNTFSReadData        = "CanNTFSReadData"        // FILE_READ_DATA / FILE_LIST_DIRECTORY
	EdgeKindCanNTFSWriteData       = "CanNTFSWriteData"       // FILE_WRITE_DATA / FILE_ADD_FILE
	EdgeKindCanNTFSAppendData      = "CanNTFSAppendData"      // FILE_APPEND_DATA / FILE_ADD_SUBDIRECTORY
	EdgeKindCanNTFSReadEA          = "CanNTFSReadEA"          // FILE_READ_EA
	EdgeKindCanNTFSWriteEA         = "CanNTFSWriteEA"         // FILE_WRITE_EA
	EdgeKindCanNTFSExecute         = "CanNTFSExecute"         // FILE_EXECUTE / FILE_TRAVERSE
	EdgeKindCanNTFSDeleteChild     = "CanNTFSDeleteChild"     // FILE_DELETE_CHILD
	EdgeKindCanNTFSReadAttributes  = "CanNTFSReadAttributes"  // FILE_READ_ATTRIBUTES
	EdgeKindCanNTFSWriteAttributes = "CanNTFSWriteAttributes" // FILE_WRITE_ATTRIBUTES
)

// Effective access edge kinds — intersection of share-level and NTFS-level generic rights
// for the same SID. Represents what a principal can actually do when accessing a file
// over SMB (both permission layers must allow the operation).
const (
	EdgeKindCanEffectiveRead    = "CanEffectiveRead"
	EdgeKindCanEffectiveWrite   = "CanEffectiveWrite"
	EdgeKindCanEffectiveExecute = "CanEffectiveExecute"
)

// EdgeDescriptions maps edge kinds to human-readable descriptions.
var EdgeDescriptions = map[string]string{
	// Containment edges
	EdgeKindHasNetworkShare:   "The base domain exposes this network share.",
	EdgeKindHostsNetworkShare: "The host machine serves this network share.",
	EdgeKindContains:          "The parent share or directory contains this child item.",

	// Share-level generic rights
	EdgeKindCanGenericExecute: "Share-level DACL grants GENERIC_EXECUTE, allowing the principal to traverse directories on the share.",
	EdgeKindCanGenericWrite:   "Share-level DACL grants GENERIC_WRITE, allowing the principal to create and modify content on the share.",
	EdgeKindCanGenericRead:    "Share-level DACL grants GENERIC_READ, allowing the principal to list and read content on the share.",
	EdgeKindCanGenericAll:     "Share-level DACL grants GENERIC_ALL (full control) on the share.",

	// Share-level Directory Service rights
	EdgeKindCanDsCreateChild:             "Share-level DACL grants DS_CREATE_CHILD, allowing creation of child objects.",
	EdgeKindCanDsDeleteChild:             "Share-level DACL grants DS_DELETE_CHILD, allowing deletion of child objects.",
	EdgeKindCanDsListContents:            "Share-level DACL grants DS_LIST_CONTENTS, allowing directory listing.",
	EdgeKindCanDsWriteExtendedProperties: "Share-level DACL grants DS_WRITE_PROPERTY_EXTENDED, allowing modification of extended properties.",
	EdgeKindCanDsReadProperty:            "Share-level DACL grants DS_READ_PROPERTY, allowing reading of object properties.",
	EdgeKindCanDsWriteProperty:           "Share-level DACL grants DS_WRITE_PROPERTY, allowing modification of object properties.",
	EdgeKindCanDsDeleteTree:              "Share-level DACL grants DS_DELETE_TREE, allowing deletion of entire subtrees.",
	EdgeKindCanDsListObject:              "Share-level DACL grants DS_LIST_OBJECT, allowing listing of this object.",
	EdgeKindCanDsControlAccess:           "Share-level DACL grants DS_CONTROL_ACCESS, allowing extended right or validated write operations.",

	// Share-level standard rights
	EdgeKindCanDelete:      "Share-level DACL grants DELETE, allowing the principal to delete this object.",
	EdgeKindCanReadControl: "Share-level DACL grants READ_CONTROL, allowing the principal to read the security descriptor.",
	EdgeKindCanWriteDacl:   "Share-level DACL grants WRITE_DAC, allowing the principal to modify the DACL (change permissions).",
	EdgeKindCanWriteOwner:  "Share-level DACL grants WRITE_OWNER, allowing the principal to change the object owner.",

	// Share-level file-specific rights
	EdgeKindCanShareRead:    "Share-level DACL grants FILE_READ_DATA (0x00000001). This is the specific read bit used by standard Windows share permissions (Read = 0x001200A9, Change, Full Control).",
	EdgeKindCanShareWrite:   "Share-level DACL grants FILE_WRITE_DATA (0x00000002). This is the specific write bit used by standard Windows share permissions (Change = 0x001301BF, Full Control).",
	EdgeKindCanShareExecute: "Share-level DACL grants FILE_EXECUTE (0x00000020). This is the specific execute/traverse bit used by standard Windows share permissions.",

	// NTFS-level permission edges
	EdgeKindCanNTFSGenericRead:          "NTFS DACL grants GENERIC_READ (0x80000000). Rarely stored in on-disk ACEs — Windows normally maps this to specific rights (FILE_READ_DATA | FILE_READ_ATTRIBUTES | FILE_READ_EA | READ_CONTROL | SYNCHRONIZE) before writing. Kept as a defensive fallback.",
	EdgeKindCanNTFSGenericWrite:         "NTFS DACL grants GENERIC_WRITE (0x40000000). Rarely stored in on-disk ACEs — Windows normally maps this to specific rights (FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA | READ_CONTROL | SYNCHRONIZE) before writing. Kept as a defensive fallback.",
	EdgeKindCanNTFSGenericExecute:       "NTFS DACL grants GENERIC_EXECUTE (0x20000000). Rarely stored in on-disk ACEs — Windows normally maps this to specific rights (FILE_EXECUTE | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE) before writing. Kept as a defensive fallback.",
	EdgeKindCanNTFSGenericAll:           "NTFS DACL grants GENERIC_ALL (0x10000000). Rarely stored in on-disk ACEs — Windows normally maps this to FILE_ALL_ACCESS (0x001F01FF) before writing. Kept as a defensive fallback.",
	EdgeKindCanNTFSAccessSystemSecurity: "NTFS DACL grants ACCESS_SYSTEM_SECURITY, allowing the principal to read or modify the SACL (audit rules).",
	EdgeKindCanNTFSSynchronize:          "NTFS DACL grants SYNCHRONIZE, allowing the principal to use the object for synchronization.",
	EdgeKindCanNTFSWriteOwner:           "NTFS DACL grants WRITE_OWNER, allowing the principal to change the file or directory owner.",
	EdgeKindCanNTFSWriteDacl:            "NTFS DACL grants WRITE_DAC, allowing the principal to modify the NTFS DACL (change permissions).",
	EdgeKindCanNTFSReadControl:          "NTFS DACL grants READ_CONTROL, allowing the principal to read the NTFS security descriptor.",
	EdgeKindCanNTFSDelete:               "NTFS DACL grants DELETE, allowing the principal to delete the file or directory.",

	// NTFS-level object-specific (file/directory) permission edges
	EdgeKindCanNTFSReadData:        "NTFS DACL grants FILE_READ_DATA (FILE_LIST_DIRECTORY), allowing the principal to read file contents or list directory entries.",
	EdgeKindCanNTFSWriteData:       "NTFS DACL grants FILE_WRITE_DATA (FILE_ADD_FILE), allowing the principal to write data to a file or create files in a directory.",
	EdgeKindCanNTFSAppendData:      "NTFS DACL grants FILE_APPEND_DATA (FILE_ADD_SUBDIRECTORY), allowing the principal to append data to a file or create subdirectories.",
	EdgeKindCanNTFSReadEA:          "NTFS DACL grants FILE_READ_EA, allowing the principal to read extended attributes of the file or directory.",
	EdgeKindCanNTFSWriteEA:         "NTFS DACL grants FILE_WRITE_EA, allowing the principal to write extended attributes of the file or directory.",
	EdgeKindCanNTFSExecute:         "NTFS DACL grants FILE_EXECUTE (FILE_TRAVERSE), allowing the principal to execute a file or traverse a directory.",
	EdgeKindCanNTFSDeleteChild:     "NTFS DACL grants FILE_DELETE_CHILD, allowing the principal to delete child objects within the directory.",
	EdgeKindCanNTFSReadAttributes:  "NTFS DACL grants FILE_READ_ATTRIBUTES, allowing the principal to read basic attributes of the file or directory.",
	EdgeKindCanNTFSWriteAttributes: "NTFS DACL grants FILE_WRITE_ATTRIBUTES, allowing the principal to modify basic attributes of the file or directory.",

	// Effective access edges
	EdgeKindCanEffectiveRead:    "The principal can read this file or directory over SMB. Both the share-level and NTFS DACLs grant read access for this SID.",
	EdgeKindCanEffectiveWrite:   "The principal can write to this file or directory over SMB. Both the share-level and NTFS DACLs grant write access for this SID.",
	EdgeKindCanEffectiveExecute: "The principal can execute files or traverse this directory over SMB. Both the share-level and NTFS DACLs grant execute access for this SID.",
}

// AllNodeKinds returns all node kinds
func AllNodeKinds() []string {
	return []string{
		NodeKindNetworkShareBase,
		NodeKindNetworkShareHost,
		NodeKindNetworkShareDFS,
		NodeKindNetworkShareSMB,
		NodeKindFile,
		NodeKindDirectory,
		NodeKindPrincipal,
		NodeKindGroup,
	}
}

// AllEdgeKinds returns all edge kinds
func AllEdgeKinds() []string {
	return []string{
		// Containment
		EdgeKindHasNetworkShare,
		EdgeKindHostsNetworkShare,
		EdgeKindContains,
		// Share-level generic
		EdgeKindCanGenericExecute,
		EdgeKindCanGenericWrite,
		EdgeKindCanGenericRead,
		EdgeKindCanGenericAll,
		// Share-level DS
		EdgeKindCanDsCreateChild,
		EdgeKindCanDsDeleteChild,
		EdgeKindCanDsListContents,
		EdgeKindCanDsWriteExtendedProperties,
		EdgeKindCanDsReadProperty,
		EdgeKindCanDsWriteProperty,
		EdgeKindCanDsDeleteTree,
		EdgeKindCanDsListObject,
		EdgeKindCanDsControlAccess,
		// Share-level standard
		EdgeKindCanDelete,
		EdgeKindCanReadControl,
		EdgeKindCanWriteDacl,
		EdgeKindCanWriteOwner,
		// Share-level file-specific
		EdgeKindCanShareRead,
		EdgeKindCanShareWrite,
		EdgeKindCanShareExecute,
		// NTFS-level
		EdgeKindCanNTFSGenericRead,
		EdgeKindCanNTFSGenericWrite,
		EdgeKindCanNTFSGenericExecute,
		EdgeKindCanNTFSGenericAll,
		EdgeKindCanNTFSAccessSystemSecurity,
		EdgeKindCanNTFSSynchronize,
		EdgeKindCanNTFSWriteOwner,
		EdgeKindCanNTFSWriteDacl,
		EdgeKindCanNTFSReadControl,
		EdgeKindCanNTFSDelete,
		// NTFS-level object-specific
		EdgeKindCanNTFSReadData,
		EdgeKindCanNTFSWriteData,
		EdgeKindCanNTFSAppendData,
		EdgeKindCanNTFSReadEA,
		EdgeKindCanNTFSWriteEA,
		EdgeKindCanNTFSExecute,
		EdgeKindCanNTFSDeleteChild,
		EdgeKindCanNTFSReadAttributes,
		EdgeKindCanNTFSWriteAttributes,
		// Effective access (intersection of share-level and NTFS-level)
		EdgeKindCanEffectiveRead,
		EdgeKindCanEffectiveWrite,
		EdgeKindCanEffectiveExecute,
	}
}
