// Package mcptest holds reusable conformance assertions for keel MCP servers —
// sync-gates that fail a build when a published manifest or the text bundle
// drifts from the registered tools/resources. Apps call these from their own
// _test.go, passing their []mcp.ToolProvider / []mcp.ResourceProvider.
package mcptest

import (
	"encoding/json"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/nauticana/keel/mcp"
)

// Manifest mirrors the published mcp-server.json fields that duplicate values
// owned by the Go code. Marketing/transport fields are not modelled.
type Manifest struct {
	Name      string          `json:"name"`
	Version   string          `json:"version"`
	Tools     []ManifestEntry `json:"tools"`
	Resources []ManifestEntry `json:"resources"`
}

// ManifestEntry is one tool or resource listing. URI is empty for tools, Name
// empty for resources — ID returns whichever identifies the entry.
type ManifestEntry struct {
	Name        string `json:"name"`
	URI         string `json:"uri"`
	Description string `json:"description"`
}

func (e ManifestEntry) id() string {
	if e.URI != "" {
		return e.URI
	}
	return e.Name
}

// LoadManifest reads and parses a published manifest, failing t on any error.
func LoadManifest(t *testing.T, path string) Manifest {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return m
}

// AssertIdentityMatches checks the manifest's name/version against the in-code
// source of truth.
func AssertIdentityMatches(t *testing.T, m Manifest, name, version string) {
	t.Helper()
	if m.Name != name {
		t.Errorf("manifest name %q != code %q", m.Name, name)
	}
	if m.Version != version {
		t.Errorf("manifest version %q != code %q", m.Version, version)
	}
}

// AssertDescriptionsPresent checks every tool and resource carries a non-empty
// description — catches an accidentally dropped blurb.
func AssertDescriptionsPresent(t *testing.T, m Manifest) {
	t.Helper()
	for _, e := range append(append([]ManifestEntry{}, m.Tools...), m.Resources...) {
		if strings.TrimSpace(e.Description) == "" {
			t.Errorf("manifest entry %q has an empty description", e.id())
		}
	}
}

// AssertSameSet fails t when code and manifest are not the same set, reporting
// the precise difference in both directions.
func AssertSameSet(t *testing.T, label string, code, manifest []string) {
	t.Helper()
	inManifest := make(map[string]bool, len(manifest))
	for _, v := range manifest {
		inManifest[v] = true
	}
	inCode := make(map[string]bool, len(code))
	for _, v := range code {
		inCode[v] = true
	}
	var missing, extra []string
	for _, v := range code {
		if !inManifest[v] {
			missing = append(missing, v)
		}
	}
	for _, v := range manifest {
		if !inCode[v] {
			extra = append(extra, v)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	if len(missing) > 0 {
		t.Errorf("%s in code but missing from manifest: %v", label, missing)
	}
	if len(extra) > 0 {
		t.Errorf("%s in manifest but not registered in code: %v", label, extra)
	}
}

// AssertToolsMatchManifest checks that the registered tool names equal the tool
// names the manifest advertises.
func AssertToolsMatchManifest(t *testing.T, tools []mcp.ToolProvider, manifestTools []string) {
	t.Helper()
	code := make([]string, len(tools))
	for i, tp := range tools {
		code[i] = tp.Name()
	}
	AssertSameSet(t, "tool", code, manifestTools)
}

// AssertResourcesMatchManifest checks that the registered resource URIs equal
// the URIs the manifest advertises.
func AssertResourcesMatchManifest(t *testing.T, resources []mcp.ResourceProvider, manifestURIs []string) {
	t.Helper()
	code := make([]string, len(resources))
	for i, rp := range resources {
		code[i] = rp.URI()
	}
	AssertSameSet(t, "resource", code, manifestURIs)
}

// AssertToolTextComplete fails t when any registered tool lacks a non-empty
// description in bundle (orphaned copy or missing copy).
func AssertToolTextComplete(t *testing.T, tools []mcp.ToolProvider, bundle mcp.TextBundle) {
	t.Helper()
	for _, tp := range tools {
		if bundle.Tool(tp.Name()) == "" {
			t.Errorf("tool %q has no description in text bundle", tp.Name())
		}
	}
}
