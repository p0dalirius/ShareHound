// Package graph provides OpenGraph structures for BloodHound integration.
package graph

import (
	"path/filepath"
	"strings"

	"github.com/specterops/sharehound/internal/logger"
	"github.com/specterops/sharehound/internal/smb"
	"github.com/specterops/sharehound/pkg/kinds"
)

// ShareRights maps SID to list of edge kinds.
type ShareRights map[string][]string

// PathEntry represents a directory in the path with its rights.
type PathEntry struct {
	Node   *Node
	Rights ShareRights
}

// OpenGraphContext maintains context while building the OpenGraph structure.
type OpenGraphContext struct {
	graph               *OpenGraph
	host                *Node
	share               *Node
	shareRights         ShareRights
	shareRootNTFSRights ShareRights // NTFS rights for the share root directory; used as fallback for first-level files
	path                []PathEntry
	element             *Node
	elementRights       ShareRights
	logger              logger.LoggerInterface
	totalEdgesCreated   int
	hostShareEmitted    bool                // true once host+share+share-rights have been added to graph
	emittedPathNodes    map[string]struct{} // directory node IDs already committed (edges + rights)
	domainSuffix        string              // domain FQDN used to prefix non-domain SIDs (e.g. "THIS.DOMAIN.COM")
	effectiveAccessOnly bool                // when true, skip granular NTFS rights edges for files/directories
}

// NewOpenGraphContext creates a new OpenGraphContext.
func NewOpenGraphContext(graph *OpenGraph, log logger.LoggerInterface) *OpenGraphContext {
	return &OpenGraphContext{
		graph:            graph,
		path:             make([]PathEntry, 0),
		shareRights:      make(ShareRights),
		elementRights:    make(ShareRights),
		logger:           log,
		emittedPathNodes: make(map[string]struct{}),
	}
}

// SetHost sets the host node.
func (c *OpenGraphContext) SetHost(host *Node) {
	c.host = host
}

// GetHost returns the host node.
func (c *OpenGraphContext) GetHost() *Node {
	return c.host
}

// SetDomainSuffix sets the domain FQDN used to prefix well-known SIDs
// so that BloodHound can resolve them (e.g. "CORP.COM-S-1-1-0").
func (c *OpenGraphContext) SetDomainSuffix(domain string) {
	c.domainSuffix = strings.ToUpper(domain)
}

// GetDomainSuffix returns the domain suffix.
func (c *OpenGraphContext) GetDomainSuffix() string {
	return c.domainSuffix
}

// SetEffectiveAccessOnly controls whether granular NTFS rights edges for files
// and directories are suppressed, keeping only CanEffectiveRead/Write/Execute.
func (c *OpenGraphContext) SetEffectiveAccessOnly(v bool) {
	c.effectiveAccessOnly = v
}

// SetShare sets the share node.
func (c *OpenGraphContext) SetShare(share *Node) {
	c.share = share
}

// GetShare returns the share node.
func (c *OpenGraphContext) GetShare() *Node {
	return c.share
}

// SetShareRights sets the share rights.
func (c *OpenGraphContext) SetShareRights(rights ShareRights) {
	c.shareRights = rights
}

// GetShareRights returns the share rights.
func (c *OpenGraphContext) GetShareRights() ShareRights {
	return c.shareRights
}

// SetShareRootNTFSRights stores the NTFS-level rights of the share root directory.
// These are used as a fallback when first-level files have no directly retrievable
// NTFS security descriptor.
func (c *OpenGraphContext) SetShareRootNTFSRights(rights ShareRights) {
	c.shareRootNTFSRights = rights
}

// GetShareRootNTFSRights returns the share root NTFS rights.
func (c *OpenGraphContext) GetShareRootNTFSRights() ShareRights {
	return c.shareRootNTFSRights
}

// PushPath adds a directory to the path stack.
func (c *OpenGraphContext) PushPath(node *Node, rights ShareRights) {
	c.path = append(c.path, PathEntry{Node: node, Rights: rights})
}

// PopPath removes and returns the last directory from the path stack.
func (c *OpenGraphContext) PopPath() *Node {
	if len(c.path) == 0 {
		return nil
	}
	entry := c.path[len(c.path)-1]
	c.path = c.path[:len(c.path)-1]
	return entry.Node
}

// GetPath returns the current path.
func (c *OpenGraphContext) GetPath() []PathEntry {
	return c.path
}

// ClearPath clears the path.
func (c *OpenGraphContext) ClearPath() {
	c.path = make([]PathEntry, 0)
}

// SetElement sets the current element (file or directory).
func (c *OpenGraphContext) SetElement(element *Node) {
	c.element = element
}

// GetElement returns the current element.
func (c *OpenGraphContext) GetElement() *Node {
	return c.element
}

// SetElementRights sets the element rights.
func (c *OpenGraphContext) SetElementRights(rights ShareRights) {
	if rights == nil {
		rights = make(ShareRights)
	}
	c.elementRights = rights
}

// GetElementRights returns the element rights.
func (c *OpenGraphContext) GetElementRights() ShareRights {
	return c.elementRights
}

// ClearElement clears the current element.
func (c *OpenGraphContext) ClearElement() {
	c.element = nil
	c.elementRights = make(ShareRights)
}

// SetDirectoryRights sets rights for the last directory in the path.
func (c *OpenGraphContext) SetDirectoryRights(rights ShareRights) {
	if len(c.path) > 0 && rights != nil {
		c.path[len(c.path)-1].Rights = rights
	}
}

// GetStringPathFromRoot returns the path as a string from the root.
func (c *OpenGraphContext) GetStringPathFromRoot() string {
	parts := make([]string, 0, len(c.path))
	for _, entry := range c.path {
		name := entry.Node.GetStringProperty("name")
		if name != "" {
			parts = append(parts, name)
		}
	}
	return strings.Join(parts, "\\")
}

// AddPathToGraph adds the current path structure to the graph.
func (c *OpenGraphContext) AddPathToGraph() {
	// Check host
	if c.host == nil {
		if c.logger != nil {
			c.logger.Debug("[add_path_to_graph] Host is None, skipping")
		}
		return
	}

	// Check share
	if c.share == nil {
		if c.logger != nil {
			c.logger.Debug("[add_path_to_graph] Share node is None, skipping")
		}
		return
	}

	// Emit host + share structure only once per context (per share)
	if !c.hostShareEmitted {
		c.hostShareEmitted = true

		// Add host node
		c.graph.AddNodeWithoutValidation(c.host)

		// Add HostsNetworkShare edge from BloodHound Computer to NetworkShareHost.
		// Use the "fqdn" property (plain FQDN) for the Computer lookup so it does
		// not collide with the NetworkShareHost node ID (which carries a prefix).
		hostName := c.host.GetStringProperty("fqdn")
		hostEdge := NewEdge(strings.ToUpper(hostName), c.host.ID, kinds.EdgeKindHostsNetworkShare)
		hostEdge.SetStartMatchBy("name")
		hostEdge.SetStartKind("Computer")
		hostEdge.SetEndMatchBy("id")
		hostEdge.SetEndKind(kinds.NodeKindNetworkShareHost)
		if desc, ok := kinds.EdgeDescriptions[kinds.EdgeKindHostsNetworkShare]; ok {
			hostEdge.SetProperty("description", desc)
		}
		if c.graph.AddEdgeWithoutValidation(hostEdge) {
			c.totalEdgesCreated++
		}

		if c.logger != nil {
			c.logger.Debug("[add_path_to_graph] Created edge HostsNetworkShare: Computer -> NetworkShareHost")
		}

		// Add share node
		c.graph.AddNodeWithoutValidation(c.share)

		// Add share rights
		c.AddRightsToGraph(c.share.ID, c.shareRights, "share", c.share.Kinds[0])

		// Add HasNetworkShare edge from host to share.
		// Match NetworkShareHost by id (prefixed) to avoid ambiguity with name.
		shareEdge := NewEdge(c.host.ID, c.share.ID, kinds.EdgeKindHasNetworkShare)
		shareEdge.SetStartMatchBy("id")
		shareEdge.SetStartKind(kinds.NodeKindNetworkShareHost)
		shareEdge.SetEndKind(c.share.Kinds[0])
		if desc, ok := kinds.EdgeDescriptions[kinds.EdgeKindHasNetworkShare]; ok {
			shareEdge.SetProperty("description", desc)
		}
		if c.graph.AddEdgeWithoutValidation(shareEdge) {
			c.totalEdgesCreated++
		}

		if c.logger != nil {
			c.logger.Debug("[add_path_to_graph] Created edge HasNetworkShare: host -> share")
		}
	}

	// Add path directories with Contains edges.
	// emittedPathNodes tracks which directories have already had their
	// node, rights, and Contains edge written.  This prevents duplicate
	// edges for directories that appear in the path of multiple files.
	parentID := c.share.ID
	parentKind := c.share.Kinds[0]
	for _, entry := range c.path {
		if _, already := c.emittedPathNodes[entry.Node.ID]; !already {
			c.emittedPathNodes[entry.Node.ID] = struct{}{}

			c.graph.AddNodeWithoutValidation(entry.Node)
			if !c.effectiveAccessOnly {
				c.AddRightsToGraph(entry.Node.ID, entry.Rights, "directory", kinds.NodeKindDirectory)
			}
			c.AddEffectiveRightsToGraph(entry.Node.ID, entry.Rights, kinds.NodeKindDirectory)

			containsEdge := NewEdge(parentID, entry.Node.ID, kinds.EdgeKindContains)
			containsEdge.SetStartKind(parentKind)
			containsEdge.SetEndKind(kinds.NodeKindDirectory)
			if desc, ok := kinds.EdgeDescriptions[kinds.EdgeKindContains]; ok {
				containsEdge.SetProperty("description", desc)
			}
			if c.graph.AddEdgeWithoutValidation(containsEdge) {
				c.totalEdgesCreated++
			}

			if c.logger != nil {
				c.logger.Debug("[add_path_to_graph] Created edge Contains: " + parentID + " -> " + entry.Node.ID)
			}
		}
		parentID = entry.Node.ID // always advance so child edges use the right parent
		parentKind = kinds.NodeKindDirectory
	}

	// Add element node with Contains edge
	if c.element == nil {
		return
	}

	// If the element is a directory that was already emitted as a path node,
	// skip re-emission to avoid duplicate nodes and Contains edges.
	if c.element.Kinds[0] == kinds.NodeKindDirectory {
		if _, already := c.emittedPathNodes[c.element.ID]; already {
			return
		}
	}

	c.graph.AddNodeWithoutValidation(c.element)

	elementType := "file"
	if c.element.Kinds[0] == kinds.NodeKindDirectory {
		elementType = "directory"
	}
	if !c.effectiveAccessOnly {
		c.AddRightsToGraph(c.element.ID, c.elementRights, elementType, c.element.Kinds[0])
	}
	c.AddEffectiveRightsToGraph(c.element.ID, c.elementRights, c.element.Kinds[0])

	elementEdge := NewEdge(parentID, c.element.ID, kinds.EdgeKindContains)
	elementEdge.SetStartKind(parentKind)
	elementEdge.SetEndKind(c.element.Kinds[0])
	if desc, ok := kinds.EdgeDescriptions[kinds.EdgeKindContains]; ok {
		elementEdge.SetProperty("description", desc)
	}
	if c.graph.AddEdgeWithoutValidation(elementEdge) {
		c.totalEdgesCreated++
	}

	// Track emitted directory elements so they are not re-emitted
	// when they later appear as path entries for child files.
	if c.element.Kinds[0] == kinds.NodeKindDirectory {
		c.emittedPathNodes[c.element.ID] = struct{}{}
	}

	if c.logger != nil {
		c.logger.Debug("[add_path_to_graph] Created edge Contains: " + parentID + " -> " + c.element.ID)
	}
}

// AddRightsToGraph adds rights edges to the graph.
func (c *OpenGraphContext) AddRightsToGraph(elementID string, rights ShareRights, elementType string, nodeKind string) {
	if rights == nil {
		if c.logger != nil {
			c.logger.Warning("[add_rights_to_graph] Rights is None for " + elementType + ": " + elementID)
		}
		return
	}

	if len(rights) == 0 {
		if c.logger != nil {
			c.logger.Debug("[add_rights_to_graph] No rights to add for " + elementType + ": " + elementID)
		}
		return
	}

	edgesCreated := 0
	for sid, edgeKinds := range rights {
		// Prefix non-domain SIDs with the domain FQDN so BloodHound can
		// resolve well-known and BUILTIN principals (e.g. "CORP.COM-S-1-1-0",
		// "CORP.COM-S-1-5-32-545"). Domain-relative SIDs (S-1-5-21-*) already
		// contain the domain identifier and are used as-is.
		edgeSID := sid
		if c.domainSuffix != "" && !smb.IsDomainSID(sid) {
			edgeSID = c.domainSuffix + "-" + sid
		}
		for _, edgeKind := range edgeKinds {
			edge := NewEdge(edgeSID, elementID, edgeKind)
			edge.SetEndKind(nodeKind)
			if desc, ok := kinds.EdgeDescriptions[edgeKind]; ok {
				edge.SetProperty("description", desc)
			}
			if c.graph.AddEdgeWithoutValidation(edge) {
				c.totalEdgesCreated++
				edgesCreated++
			}

			if c.logger != nil {
				c.logger.Debug("[add_rights_to_graph] Created edge: " + edgeSID + " --[" + edgeKind + "]--> " + elementID)
			}
		}
	}

	if c.logger != nil {
		c.logger.Debug("[add_rights_to_graph] Created " + string(rune(edgesCreated+'0')) + " rights edge(s)")
	}
}

// AddEffectiveRightsToGraph computes and emits effective access edges for a node.
//
// For each SID that appears in nodeRights (NTFS-level), it intersects that SID's
// share-level rights (from c.shareRights) with its NTFS rights using
// smb.ComputeEffectiveRights.  The resulting CanEffectiveRead / CanEffectiveWrite /
// CanEffectiveExecute edges are written to the graph with the supplied nodeKind on the
// end endpoint.
//
// Effective edges are only meaningful at the file/directory level, never at the share
// node itself (the share boundary is already represented by share-level rights edges).
func (c *OpenGraphContext) AddEffectiveRightsToGraph(nodeID string, nodeRights ShareRights, nodeKind string) {
	for sid, ntfsKinds := range nodeRights {
		shareKinds := c.shareRights[sid]
		effective := smb.ComputeEffectiveRights(shareKinds, ntfsKinds)
		if len(effective) == 0 {
			continue
		}

		edgeSID := sid
		if c.domainSuffix != "" && !smb.IsDomainSID(sid) {
			edgeSID = c.domainSuffix + "-" + sid
		}

		for _, edgeKind := range effective {
			edge := NewEdge(edgeSID, nodeID, edgeKind)
			edge.SetEndKind(nodeKind)
			if desc, ok := kinds.EdgeDescriptions[edgeKind]; ok {
				edge.SetProperty("description", desc)
			}
			if c.graph.AddEdgeWithoutValidation(edge) {
				c.totalEdgesCreated++
			}

			if c.logger != nil {
				c.logger.Debug("[add_effective_rights] Created edge: " + edgeSID + " --[" + edgeKind + "]--> " + nodeID)
			}
		}
	}
}

// GetTotalEdgesCreated returns the total number of edges created by this context.
func (c *OpenGraphContext) GetTotalEdgesCreated() int {
	return c.totalEdgesCreated
}

// BuildUNCPath builds a UNC path from components.
func BuildUNCPath(host, share, path string) string {
	base := "\\\\" + host + "\\" + share
	if path == "" {
		return base + "\\"
	}
	return base + "\\" + filepath.ToSlash(path)
}
