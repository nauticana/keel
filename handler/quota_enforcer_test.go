package handler

import "testing"

func TestResourceExtractorLabel(t *testing.T) {
	ex := ResourceExtractor{Singular: "domain", Plural: "domains"}
	if ex.label(1) != "domain" || ex.label(2) != "domains" {
		t.Fatalf("labels = %q, %q", ex.label(1), ex.label(2))
	}
	if (ResourceExtractor{Plural: "domains"}).label(1) != "domains" {
		t.Fatal("missing singular should fall back to the plural")
	}
}
