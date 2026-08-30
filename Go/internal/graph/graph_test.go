package graph

import (
	"archive/zip"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestNodeMarshalJSON(t *testing.T) {
	node := NewNode("test-id", "NetworkShare", "Base")
	node.SetProperty("name", "Share1")
	node.SetProperty("path", "\\\\server\\share")

	data, err := json.Marshal(node)
	if err != nil {
		t.Fatalf("Failed to marshal node: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Failed to parse marshaled JSON: %v", err)
	}

	// Verify "id" field
	if id, ok := parsed["id"].(string); !ok || id != "test-id" {
		t.Errorf("Expected id='test-id', got %v", parsed["id"])
	}

	// Verify "kinds" is an array (BloodHound schema requirement)
	kinds, ok := parsed["kinds"].([]interface{})
	if !ok {
		t.Fatalf("Expected 'kinds' to be an array, got %T", parsed["kinds"])
	}
	if len(kinds) != 2 {
		t.Errorf("Expected 2 kinds, got %d", len(kinds))
	}
	if kinds[0].(string) != "NetworkShare" || kinds[1].(string) != "Base" {
		t.Errorf("Unexpected kinds: %v", kinds)
	}

	// Verify properties
	props, ok := parsed["properties"].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected 'properties' to be an object, got %T", parsed["properties"])
	}
	if props["name"].(string) != "Share1" {
		t.Errorf("Expected name='Share1', got %v", props["name"])
	}
}

func TestNodeUnmarshalJSON(t *testing.T) {
	// Test with "kinds" array (BloodHound schema)
	jsonWithKinds := `{"id":"node1","kinds":["TypeA","TypeB"],"properties":{"key":"value"}}`
	var node1 Node
	if err := json.Unmarshal([]byte(jsonWithKinds), &node1); err != nil {
		t.Fatalf("Failed to unmarshal node with kinds: %v", err)
	}
	if node1.ID != "node1" {
		t.Errorf("Expected ID='node1', got %s", node1.ID)
	}
	if len(node1.Kinds) != 2 || node1.Kinds[0] != "TypeA" || node1.Kinds[1] != "TypeB" {
		t.Errorf("Expected kinds [TypeA, TypeB], got %v", node1.Kinds)
	}

	// Test with "kind" string (legacy format)
	jsonWithKind := `{"id":"node2","kind":"SingleType","properties":{}}`
	var node2 Node
	if err := json.Unmarshal([]byte(jsonWithKind), &node2); err != nil {
		t.Fatalf("Failed to unmarshal node with kind: %v", err)
	}
	if len(node2.Kinds) != 1 || node2.Kinds[0] != "SingleType" {
		t.Errorf("Expected kinds [SingleType], got %v", node2.Kinds)
	}
}

func TestEdgeMarshalJSON(t *testing.T) {
	edge := NewEdge("node1", "node2", "HasAccess")
	edge.SetProperty("permissions", "read,write")

	data, err := json.Marshal(edge)
	if err != nil {
		t.Fatalf("Failed to marshal edge: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Failed to parse marshaled JSON: %v", err)
	}

	// Verify "start" is an object with "value" (BloodHound schema)
	start, ok := parsed["start"].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected 'start' to be an object, got %T", parsed["start"])
	}
	if start["value"].(string) != "node1" {
		t.Errorf("Expected start.value='node1', got %v", start["value"])
	}

	// Verify "end" is an object with "value"
	end, ok := parsed["end"].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected 'end' to be an object, got %T", parsed["end"])
	}
	if end["value"].(string) != "node2" {
		t.Errorf("Expected end.value='node2', got %v", end["value"])
	}

	// Verify "kind"
	if kind, ok := parsed["kind"].(string); !ok || kind != "HasAccess" {
		t.Errorf("Expected kind='HasAccess', got %v", parsed["kind"])
	}
}

func TestEdgeUnmarshalJSON(t *testing.T) {
	// Test with object format (BloodHound schema using "value")
	jsonEdge := `{"start":{"value":"a"},"end":{"value":"b"},"kind":"Related","properties":{"weight":5}}`
	var edge1 Edge
	if err := json.Unmarshal([]byte(jsonEdge), &edge1); err != nil {
		t.Fatalf("Failed to unmarshal edge: %v", err)
	}
	if edge1.Start.Value != "a" {
		t.Errorf("Expected start.value='a', got %s", edge1.Start.Value)
	}
	if edge1.End.Value != "b" {
		t.Errorf("Expected end.value='b', got %s", edge1.End.Value)
	}
	if edge1.Kind != "Related" {
		t.Errorf("Expected kind='Related', got %s", edge1.Kind)
	}

	// Test with legacy object format (using "id")
	jsonLegacyObj := `{"start":{"id":"m"},"end":{"id":"n"},"kind":"LegacyRelated"}`
	var edge2 Edge
	if err := json.Unmarshal([]byte(jsonLegacyObj), &edge2); err != nil {
		t.Fatalf("Failed to unmarshal legacy edge: %v", err)
	}
	if edge2.Start.Value != "m" {
		t.Errorf("Expected start.value='m', got %s", edge2.Start.Value)
	}
	if edge2.End.Value != "n" {
		t.Errorf("Expected end.value='n', got %s", edge2.End.Value)
	}

	// Test with string format (legacy/backward compatibility)
	jsonLegacy := `{"start":"x","end":"y","kind":"Connected"}`
	var edge3 Edge
	if err := json.Unmarshal([]byte(jsonLegacy), &edge3); err != nil {
		t.Fatalf("Failed to unmarshal legacy edge: %v", err)
	}
	if edge3.Start.Value != "x" {
		t.Errorf("Expected start.value='x', got %s", edge3.Start.Value)
	}
	if edge3.End.Value != "y" {
		t.Errorf("Expected end.value='y', got %s", edge3.End.Value)
	}
}

func TestOpenGraphOutputFormat(t *testing.T) {
	og, err := NewOpenGraph("ShareHound")
	if err != nil {
		t.Fatalf("Failed to create graph: %v", err)
	}
	defer og.Close()

	node1 := NewNode("share1", "NetworkShare")
	node1.SetProperty("name", "DataShare")
	og.AddNode(node1)

	node2 := NewNode("user1", "User")
	node2.SetProperty("name", "DOMAIN\\user")
	og.AddNode(node2)

	edge := NewEdge("user1", "share1", "CanRead")
	og.AddEdge(edge)

	data, err := og.ToJSON()
	if err != nil {
		t.Fatalf("Failed to serialize graph: %v", err)
	}

	var output map[string]interface{}
	if err := json.Unmarshal(data, &output); err != nil {
		t.Fatalf("Failed to parse output: %v", err)
	}

	// Verify BloodHound schema structure
	// 1. Must have "graph" object
	graph, ok := output["graph"].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected 'graph' object in output, got %T", output["graph"])
	}

	// 2. Graph must have "nodes" array
	nodes, ok := graph["nodes"].([]interface{})
	if !ok {
		t.Fatalf("Expected 'graph.nodes' array, got %T", graph["nodes"])
	}
	if len(nodes) != 2 {
		t.Errorf("Expected 2 nodes, got %d", len(nodes))
	}

	// 3. Graph must have "edges" array
	edges, ok := graph["edges"].([]interface{})
	if !ok {
		t.Fatalf("Expected 'graph.edges' array, got %T", graph["edges"])
	}
	if len(edges) != 1 {
		t.Errorf("Expected 1 edge, got %d", len(edges))
	}

	// 4. Should have metadata with source_kind
	metadata, ok := output["metadata"].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected 'metadata' object, got %T", output["metadata"])
	}
	if metadata["source_kind"].(string) != "ShareHound" {
		t.Errorf("Expected source_kind='ShareHound', got %v", metadata["source_kind"])
	}

	// 5. Verify node structure in output
	node := nodes[0].(map[string]interface{})
	if _, ok := node["id"]; !ok {
		t.Error("Node missing 'id' field")
	}
	if _, ok := node["kinds"]; !ok {
		t.Error("Node missing 'kinds' field")
	}

	// 6. Verify edge structure in output (BloodHound schema requires "value")
	edgeOut := edges[0].(map[string]interface{})
	startObj, ok := edgeOut["start"].(map[string]interface{})
	if !ok {
		t.Fatal("Edge 'start' should be an object")
	}
	if _, ok := startObj["value"]; !ok {
		t.Error("Edge start missing 'value' field")
	}
	endObj, ok := edgeOut["end"].(map[string]interface{})
	if !ok {
		t.Fatal("Edge 'end' should be an object")
	}
	if _, ok := endObj["value"]; !ok {
		t.Error("Edge end missing 'value' field")
	}
}

func TestOpenGraphDeduplicatesEdges(t *testing.T) {
	og, err := NewOpenGraph("ShareHound")
	if err != nil {
		t.Fatalf("Failed to create graph: %v", err)
	}
	defer og.Close()

	edge := NewEdge("node1", "node2", "HasAccess")
	if !og.AddEdge(edge) {
		t.Fatal("Expected first edge add to succeed")
	}
	if og.AddEdge(edge) {
		t.Fatal("Expected duplicate edge add to be skipped")
	}
	if og.AddEdgeWithoutValidation(NewEdge("node1", "node2", "HasAccess")) {
		t.Fatal("Expected duplicate edge add without validation to be skipped")
	}
	if !og.AddEdge(NewEdge("node1", "node2", "OtherAccess")) {
		t.Fatal("Expected distinct edge kind to be added")
	}

	if got := og.GetEdgeCount(); got != 2 {
		t.Fatalf("Expected 2 unique edges, got %d", got)
	}

	data, err := og.ToJSON()
	if err != nil {
		t.Fatalf("Failed to serialize graph: %v", err)
	}

	var output map[string]interface{}
	if err := json.Unmarshal(data, &output); err != nil {
		t.Fatalf("Failed to parse output: %v", err)
	}

	graph := output["graph"].(map[string]interface{})
	edges := graph["edges"].([]interface{})
	if len(edges) != 2 {
		t.Fatalf("Expected 2 exported edges, got %d", len(edges))
	}
}

func TestRestoreNodesAndEdgesDeduplicatesEdges(t *testing.T) {
	og, err := NewOpenGraph("ShareHound")
	if err != nil {
		t.Fatalf("Failed to create graph: %v", err)
	}
	defer og.Close()

	nodes := []*Node{
		NewNode("node1", "TestKind"),
		NewNode("node2", "TestKind"),
	}
	edges := []*Edge{
		NewEdge("node1", "node2", "HasAccess"),
		NewEdge("node1", "node2", "HasAccess"),
		NewEdge("node1", "node2", "OtherAccess"),
	}

	og.RestoreNodesAndEdges(nodes, edges)

	if got := og.GetEdgeCount(); got != 2 {
		t.Fatalf("Expected 2 unique restored edges, got %d", got)
	}

	_, restoredEdges := og.GetNodesAndEdges()
	if len(restoredEdges) != 2 {
		t.Fatalf("Expected 2 restored edge records, got %d", len(restoredEdges))
	}
}

func TestExportToFileZip(t *testing.T) {
	og, err := NewOpenGraph("ShareHound")
	if err != nil {
		t.Fatalf("Failed to create graph: %v", err)
	}
	defer og.Close()

	// Add some test data
	for i := 0; i < 100; i++ {
		node := NewNode("node"+string(rune('0'+i%10)), "TestType")
		node.SetProperty("index", i)
		og.AddNode(node)
	}

	for i := 0; i < 50; i++ {
		edge := NewEdge("node"+string(rune('0'+i%10)), "node"+string(rune('0'+(i+1)%10)), "TestEdge")
		og.AddEdge(edge)
	}

	// Create temp directory for test files
	tmpDir := t.TempDir()

	// Test regular JSON export
	jsonFile := filepath.Join(tmpDir, "test.json")
	if err := og.ExportToFile(jsonFile, true); err != nil {
		t.Fatalf("Failed to export to JSON: %v", err)
	}

	// Test ZIP export
	zipFile := filepath.Join(tmpDir, "test.zip")
	if err := og.ExportToFile(zipFile, true); err != nil {
		t.Fatalf("Failed to export to ZIP: %v", err)
	}

	// Verify JSON file is valid
	jsonData, err := os.ReadFile(jsonFile)
	if err != nil {
		t.Fatalf("Failed to read JSON file: %v", err)
	}
	var jsonOutput map[string]interface{}
	if err := json.Unmarshal(jsonData, &jsonOutput); err != nil {
		t.Fatalf("JSON file is not valid JSON: %v", err)
	}

	// Verify ZIP file can be opened and contains valid JSON
	zipReader, err := zip.OpenReader(zipFile)
	if err != nil {
		t.Fatalf("Failed to open ZIP file: %v", err)
	}
	defer zipReader.Close()

	if len(zipReader.File) != 1 {
		t.Fatalf("Expected 1 file in ZIP, got %d", len(zipReader.File))
	}

	// Read the JSON from the ZIP entry
	entry := zipReader.File[0]
	t.Logf("ZIP entry name: %s", entry.Name)

	entryReader, err := entry.Open()
	if err != nil {
		t.Fatalf("Failed to open ZIP entry: %v", err)
	}
	defer entryReader.Close()

	var zipOutput map[string]interface{}
	decoder := json.NewDecoder(entryReader)
	if err := decoder.Decode(&zipOutput); err != nil {
		t.Fatalf("ZIP file content is not valid JSON: %v", err)
	}

	// Verify both outputs have the same structure
	jsonGraph := jsonOutput["graph"].(map[string]interface{})
	zipGraph := zipOutput["graph"].(map[string]interface{})

	jsonNodes := jsonGraph["nodes"].([]interface{})
	zipNodes := zipGraph["nodes"].([]interface{})
	if len(jsonNodes) != len(zipNodes) {
		t.Errorf("Node count mismatch: JSON=%d, ZIP=%d", len(jsonNodes), len(zipNodes))
	}

	jsonEdges := jsonGraph["edges"].([]interface{})
	zipEdges := zipGraph["edges"].([]interface{})
	if len(jsonEdges) != len(zipEdges) {
		t.Errorf("Edge count mismatch: JSON=%d, ZIP=%d", len(jsonEdges), len(zipEdges))
	}

	// Verify ZIP file is smaller
	jsonStat, _ := os.Stat(jsonFile)
	zipStat, _ := os.Stat(zipFile)
	t.Logf("JSON size: %d bytes, ZIP size: %d bytes (%.1f%% of original)",
		jsonStat.Size(), zipStat.Size(), float64(zipStat.Size())/float64(jsonStat.Size())*100)

	if zipStat.Size() >= jsonStat.Size() {
		t.Log("Warning: ZIP file is not smaller than JSON (may be expected for small files)")
	}
}
