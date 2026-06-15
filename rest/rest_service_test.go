package rest

import "testing"

func relNode(seq, parentSeq int, pascal string) *childNode {
	return &childNode{seq: seq, parentSeq: parentSeq, pascal: pascal,
		rel: RelationAPI{ChildServices: map[string]RelationAPI{}}}
}

// Existing single-level configs (every parent_seq = 0, the column default) must
// stay direct children of the master — the backward-compatible contract.
func TestLinkChildRelations_FlatSingleLevel(t *testing.T) {
	root := map[string]RelationAPI{}
	linkChildRelations(root, []*childNode{relNode(1, 0, "A"), relNode(2, 0, "B"), relNode(3, 0, "C")})
	if len(root) != 3 {
		t.Fatalf("expected 3 direct children, got %d", len(root))
	}
	for _, k := range []string{"A", "B", "C"} {
		if _, ok := root[k]; !ok {
			t.Fatalf("%s should be a direct child of the master", k)
		}
	}
}

// parent_seq > 0 nests under the referenced relation, recursively.
func TestLinkChildRelations_MultiLevelNesting(t *testing.T) {
	root := map[string]RelationAPI{}
	// Deliberately out of order to prove order-independence.
	linkChildRelations(root, []*childNode{
		relNode(16, 9, "Variants"),
		relNode(9, 8, "Items"),
		relNode(8, 0, "Offerings"),
	})
	if _, ok := root["Offerings"]; !ok {
		t.Fatal("Offerings should be a direct child of the master")
	}
	if _, ok := root["Items"]; ok {
		t.Fatal("Items must NOT be a direct child of the master")
	}
	items := root["Offerings"].ChildServices
	if _, ok := items["Items"]; !ok {
		t.Fatal("Items should nest under Offerings")
	}
	if _, ok := items["Items"].ChildServices["Variants"]; !ok {
		t.Fatal("Variants should nest under Items")
	}
}

// A parent_seq pointing at a missing seq degrades to the master, never errors.
func TestLinkChildRelations_UnresolvedParentFallsBackToRoot(t *testing.T) {
	root := map[string]RelationAPI{}
	linkChildRelations(root, []*childNode{relNode(9, 99, "Orphan")})
	if _, ok := root["Orphan"]; !ok {
		t.Fatal("orphan with unresolved parent_seq should fall back to the master")
	}
}
