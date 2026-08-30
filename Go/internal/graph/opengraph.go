// Package graph provides OpenGraph structures for BloodHound integration.
package graph

import (
	"archive/zip"
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// OpenGraph represents a BloodHound OpenGraph structure.
//
// Nodes and edges are stored on disk in temporary NDJSON files so that
// memory usage stays bounded regardless of graph size.  Only node-ID strings
// and edge identity keys are kept in memory for deduplication.
type OpenGraph struct {
	SourceKind string

	// In-memory dedup – only IDs/keys, not full objects.
	nodeIDs   map[string]struct{}
	edgeKeys  map[edgeKey]struct{}
	edgeCount int

	// Disk-backed storage (NDJSON temp files).
	nodeFile *os.File
	edgeFile *os.File
	nodeBuf  *bufio.Writer
	edgeBuf  *bufio.Writer

	mu sync.Mutex
}

// NewOpenGraph creates a new OpenGraph instance with disk-backed storage.
// The caller must call Close() when done to release temporary files.
func NewOpenGraph(sourceKind string) (*OpenGraph, error) {
	nf, err := os.CreateTemp("", "sharehound-nodes-*.ndjson")
	if err != nil {
		return nil, fmt.Errorf("create node temp file: %w", err)
	}
	ef, err := os.CreateTemp("", "sharehound-edges-*.ndjson")
	if err != nil {
		nf.Close()
		os.Remove(nf.Name())
		return nil, fmt.Errorf("create edge temp file: %w", err)
	}

	return &OpenGraph{
		SourceKind: sourceKind,
		nodeIDs:    make(map[string]struct{}),
		edgeKeys:   make(map[edgeKey]struct{}),
		nodeFile:   nf,
		edgeFile:   ef,
		nodeBuf:    bufio.NewWriterSize(nf, 256*1024),
		edgeBuf:    bufio.NewWriterSize(ef, 256*1024),
	}, nil
}

// Close releases resources and removes temporary files.
func (g *OpenGraph) Close() error {
	g.mu.Lock()
	defer g.mu.Unlock()

	var firstErr error
	for _, f := range []*os.File{g.nodeFile, g.edgeFile} {
		if f != nil {
			name := f.Name()
			f.Close()
			if err := os.Remove(name); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}
	g.nodeIDs = nil
	g.edgeKeys = nil
	return firstErr
}

type edgeKey struct {
	startValue   string
	startMatchBy string
	startKind    string
	endValue     string
	endMatchBy   string
	endKind      string
	kind         string
}

func newEdgeKey(edge *Edge) edgeKey {
	return edgeKey{
		startValue:   edge.Start.Value,
		startMatchBy: edge.Start.MatchBy,
		startKind:    edge.Start.Kind,
		endValue:     edge.End.Value,
		endMatchBy:   edge.End.MatchBy,
		endKind:      edge.End.Kind,
		kind:         edge.Kind,
	}
}

// appendJSON marshals v as JSON and writes it as a single line to w.
func appendJSON(w *bufio.Writer, v interface{}) {
	data, err := json.Marshal(v)
	if err != nil {
		return // best-effort
	}
	w.Write(data)     //nolint:errcheck
	w.WriteByte('\n') //nolint:errcheck
}

// ---------- Mutators --------------------------------------------------

// AddNode adds a node to the graph if it doesn't already exist.
func (g *OpenGraph) AddNode(node *Node) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if _, exists := g.nodeIDs[node.ID]; exists {
		return
	}
	g.nodeIDs[node.ID] = struct{}{}
	appendJSON(g.nodeBuf, node)
}

// AddNodeWithoutValidation adds a node, deduplicating by ID.
// With disk-backed storage this behaves identically to AddNode because
// on-disk objects cannot be updated in place.
func (g *OpenGraph) AddNodeWithoutValidation(node *Node) {
	g.AddNode(node)
}

// AddEdge appends an edge to the on-disk store if it has not already been
// emitted. It returns true when the edge is written.
func (g *OpenGraph) AddEdge(edge *Edge) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.addEdgeLocked(edge)
}

func (g *OpenGraph) addEdgeLocked(edge *Edge) bool {
	key := newEdgeKey(edge)
	if _, exists := g.edgeKeys[key]; exists {
		return false
	}
	g.edgeKeys[key] = struct{}{}
	appendJSON(g.edgeBuf, edge)
	g.edgeCount++
	return true
}

// AddEdgeWithoutValidation appends an edge without additional checks.
func (g *OpenGraph) AddEdgeWithoutValidation(edge *Edge) bool {
	return g.AddEdge(edge)
}

// ---------- Accessors -------------------------------------------------

// GetNode looks up a node by ID.  This requires a linear scan of the
// temp file and should only be used for rare/diagnostic lookups.
func (g *OpenGraph) GetNode(id string) (*Node, bool) {
	g.mu.Lock()
	if _, exists := g.nodeIDs[id]; !exists {
		g.mu.Unlock()
		return nil, false
	}
	g.nodeBuf.Flush() //nolint:errcheck
	name := g.nodeFile.Name()
	g.mu.Unlock()

	f, err := os.Open(name)
	if err != nil {
		return nil, false
	}
	defer f.Close()

	dec := json.NewDecoder(bufio.NewReader(f))
	for {
		var node Node
		if err := dec.Decode(&node); err != nil {
			return nil, false
		}
		if node.ID == id {
			return &node, true
		}
	}
}

// GetNodeCount returns the number of unique nodes.
func (g *OpenGraph) GetNodeCount() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.nodeIDs)
}

// GetEdgeCount returns the number of edges.
func (g *OpenGraph) GetEdgeCount() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.edgeCount
}

// ---------- Serialisation helpers -------------------------------------

// openGraphData represents the graph portion of the output.
type openGraphData struct {
	Nodes []*Node `json:"nodes"`
	Edges []*Edge `json:"edges"`
}

// openGraphMetadata represents the metadata portion of the output.
type openGraphMetadata struct {
	SourceKind string `json:"source_kind,omitempty"`
}

// openGraphOutput represents the BloodHound OpenGraph JSON format.
type openGraphOutput struct {
	Metadata *openGraphMetadata `json:"metadata,omitempty"`
	Graph    openGraphData      `json:"graph"`
}

// ProgressFunc is a callback for export progress reporting.
type ProgressFunc func(phase string, current, total int)

// ---------- Export ----------------------------------------------------

// ExportToFile exports the graph to a JSON file in BloodHound OpenGraph
// format.  If the filename ends with .zip, the output will be ZIP
// compressed.  Data is streamed from disk so peak memory stays low.
func (g *OpenGraph) ExportToFile(filename string, includeMetadata bool) error {
	return g.ExportToFileWithProgress(filename, includeMetadata, nil)
}

// ExportToFileWithProgress exports the graph with progress reporting.
func (g *OpenGraph) ExportToFileWithProgress(filename string, includeMetadata bool, progress ProgressFunc) error {
	// Flush buffers and snapshot counts while holding the lock.
	g.mu.Lock()
	g.nodeBuf.Flush() //nolint:errcheck
	g.edgeBuf.Flush() //nolint:errcheck
	nodeCount := len(g.nodeIDs)
	edgeCount := g.edgeCount
	nodeFileName := g.nodeFile.Name()
	edgeFileName := g.edgeFile.Name()
	g.mu.Unlock()

	if progress != nil {
		progress("Creating output file", 0, 0)
	}

	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	bufWriter := bufio.NewWriterSize(file, 64*1024)

	if strings.HasSuffix(strings.ToLower(filename), ".zip") {
		if progress != nil {
			progress("Preparing ZIP archive", 0, 0)
		}
		zipWriter := zip.NewWriter(bufWriter)

		baseName := filepath.Base(filename)
		jsonName := strings.TrimSuffix(baseName, ".zip")
		if !strings.HasSuffix(jsonName, ".json") {
			jsonName += ".json"
		}

		header := &zip.FileHeader{
			Name:   jsonName,
			Method: zip.Deflate,
		}
		entryWriter, err := zipWriter.CreateHeader(header)
		if err != nil {
			return err
		}

		if err := streamJSON(entryWriter, g.SourceKind, includeMetadata, progress,
			nodeFileName, edgeFileName, nodeCount, edgeCount); err != nil {
			return err
		}

		if progress != nil {
			progress("Finalizing ZIP archive", 0, 0)
		}
		if err := zipWriter.Close(); err != nil {
			return err
		}
	} else {
		if err := streamJSON(bufWriter, g.SourceKind, includeMetadata, progress,
			nodeFileName, edgeFileName, nodeCount, edgeCount); err != nil {
			return err
		}
	}

	if progress != nil {
		progress("Flushing to disk", 0, 0)
	}
	return bufWriter.Flush()
}

// streamJSON writes the graph as JSON by reading nodes and edges from
// the NDJSON temp files.  Only one JSON object at a time is in memory.
func streamJSON(w io.Writer, sourceKind string, includeMetadata bool, progress ProgressFunc,
	nodeFileName, edgeFileName string, nodeCount, edgeCount int) error {

	if _, err := w.Write([]byte("{\n")); err != nil {
		return err
	}

	if includeMetadata && sourceKind != "" {
		if _, err := w.Write([]byte(`  "metadata": {"source_kind": "`)); err != nil {
			return err
		}
		if _, err := w.Write([]byte(sourceKind)); err != nil {
			return err
		}
		if _, err := w.Write([]byte("\"},\n")); err != nil {
			return err
		}
	}

	if _, err := w.Write([]byte("  \"graph\": {\n")); err != nil {
		return err
	}

	// ---- nodes ----
	if _, err := w.Write([]byte("    \"nodes\": [\n")); err != nil {
		return err
	}

	nodeReportInterval := progressInterval(nodeCount)
	if progress != nil {
		progress("Serializing nodes", 0, nodeCount)
	}

	nf, err := os.Open(nodeFileName)
	if err != nil {
		return err
	}
	nIdx, err := streamArray(w, nf, nodeCount, nodeReportInterval, "Serializing nodes", progress)
	nf.Close()
	if err != nil {
		return err
	}

	if nIdx > 0 {
		if _, err := w.Write([]byte("\n")); err != nil {
			return err
		}
	}
	if progress != nil {
		progress("Serializing nodes", nodeCount, nodeCount)
	}
	if _, err := w.Write([]byte("    ],\n")); err != nil {
		return err
	}

	// ---- edges ----
	if _, err := w.Write([]byte("    \"edges\": [\n")); err != nil {
		return err
	}

	edgeReportInterval := progressInterval(edgeCount)
	if progress != nil {
		progress("Serializing edges", 0, edgeCount)
	}

	ef, err := os.Open(edgeFileName)
	if err != nil {
		return err
	}
	eIdx, err := streamArray(w, ef, edgeCount, edgeReportInterval, "Serializing edges", progress)
	ef.Close()
	if err != nil {
		return err
	}

	if eIdx > 0 {
		if _, err := w.Write([]byte("\n")); err != nil {
			return err
		}
	}
	if progress != nil {
		progress("Serializing edges", edgeCount, edgeCount)
	}
	if _, err := w.Write([]byte("    ]\n")); err != nil {
		return err
	}

	if _, err := w.Write([]byte("  }\n")); err != nil {
		return err
	}
	if _, err := w.Write([]byte("}\n")); err != nil {
		return err
	}
	return nil
}

// streamArray reads NDJSON lines from src and writes them as a JSON
// array body (without the surrounding brackets) into w.
func streamArray(w io.Writer, src *os.File, total, reportInterval int, phase string, progress ProgressFunc) (int, error) {
	dec := json.NewDecoder(bufio.NewReaderSize(src, 256*1024))
	idx := 0
	for {
		var raw json.RawMessage
		if err := dec.Decode(&raw); err == io.EOF {
			break
		} else if err != nil {
			return idx, err
		}

		if idx > 0 {
			if _, err := w.Write([]byte(",\n")); err != nil {
				return idx, err
			}
		}
		if _, err := w.Write([]byte("      ")); err != nil {
			return idx, err
		}
		if _, err := w.Write(raw); err != nil {
			return idx, err
		}

		idx++
		if progress != nil && reportInterval > 0 && idx%reportInterval == 0 {
			progress(phase, idx, total)
		}
	}
	return idx, nil
}

// ---------- Checkpoint helpers ----------------------------------------

// GetNodesAndEdges reads all nodes and edges from disk for checkpointing.
// The returned slices are ephemeral – they should be serialised and
// discarded promptly to avoid holding everything in memory.
func (g *OpenGraph) GetNodesAndEdges() ([]*Node, []*Edge) {
	g.mu.Lock()
	g.nodeBuf.Flush() //nolint:errcheck
	g.edgeBuf.Flush() //nolint:errcheck
	nodeFileName := g.nodeFile.Name()
	edgeFileName := g.edgeFile.Name()
	capNodes := len(g.nodeIDs)
	capEdges := g.edgeCount
	g.mu.Unlock()

	nodes := make([]*Node, 0, capNodes)
	if nf, err := os.Open(nodeFileName); err == nil {
		dec := json.NewDecoder(bufio.NewReaderSize(nf, 256*1024))
		for {
			var node Node
			if err := dec.Decode(&node); err != nil {
				break
			}
			n := node // copy
			nodes = append(nodes, &n)
		}
		nf.Close()
	}

	edges := make([]*Edge, 0, capEdges)
	if ef, err := os.Open(edgeFileName); err == nil {
		dec := json.NewDecoder(bufio.NewReaderSize(ef, 256*1024))
		for {
			var edge Edge
			if err := dec.Decode(&edge); err != nil {
				break
			}
			e := edge // copy
			edges = append(edges, &e)
		}
		ef.Close()
	}

	return nodes, edges
}

// RestoreNodesAndEdges populates the graph from a checkpoint.
func (g *OpenGraph) RestoreNodesAndEdges(nodes []*Node, edges []*Edge) {
	g.mu.Lock()
	defer g.mu.Unlock()

	// Reset dedup state
	g.nodeIDs = make(map[string]struct{}, len(nodes))
	g.edgeKeys = make(map[edgeKey]struct{}, len(edges))
	g.edgeCount = 0

	// Truncate and rewrite node file
	g.nodeFile.Truncate(0)           //nolint:errcheck
	g.nodeFile.Seek(0, io.SeekStart) //nolint:errcheck
	g.nodeBuf.Reset(g.nodeFile)
	for _, node := range nodes {
		g.nodeIDs[node.ID] = struct{}{}
		appendJSON(g.nodeBuf, node)
	}

	// Truncate and rewrite edge file
	g.edgeFile.Truncate(0)           //nolint:errcheck
	g.edgeFile.Seek(0, io.SeekStart) //nolint:errcheck
	g.edgeBuf.Reset(g.edgeFile)
	for _, edge := range edges {
		g.addEdgeLocked(edge)
	}
}

// ---------- In-memory convenience (tests / small graphs) --------------

// ToJSON returns the graph as JSON bytes in BloodHound OpenGraph format.
// This loads the entire graph into memory – use ExportToFile for large
// graphs.
func (g *OpenGraph) ToJSON() ([]byte, error) {
	nodes, edges := g.GetNodesAndEdges()

	output := openGraphOutput{
		Graph: openGraphData{
			Nodes: nodes,
			Edges: edges,
		},
	}

	if g.SourceKind != "" {
		output.Metadata = &openGraphMetadata{
			SourceKind: g.SourceKind,
		}
	}

	return json.MarshalIndent(output, "", "  ")
}

// progressInterval returns how often to report progress.
func progressInterval(total int) int {
	if total <= 0 {
		return 1
	}
	interval := total / 25
	if interval < 1 {
		interval = 1
	}
	return interval
}
