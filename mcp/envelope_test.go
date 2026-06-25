package mcp

import (
	"strings"
	"testing"
	"time"

	mcpgo "github.com/mark3labs/mcp-go/mcp"
)

func fixedClock() Envelopes {
	return Envelopes{Source: "acme", now: func() time.Time {
		return time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	}}
}

func resultText(t *testing.T, res *mcpgo.CallToolResult) string {
	t.Helper()
	if len(res.Content) == 0 {
		t.Fatalf("empty content")
	}
	tc, ok := mcpgo.AsTextContent(res.Content[0])
	if !ok {
		t.Fatalf("first content is not text: %T", res.Content[0])
	}
	return tc.Text
}

func TestWrap_DefaultsSourceAndTimestamp(t *testing.T) {
	res := fixedClock().Wrap(map[string]int{"n": 1}, nil)
	if res.IsError {
		t.Fatalf("unexpected error result")
	}
	text := resultText(t, res)
	if !strings.Contains(text, `"source": "acme"`) {
		t.Errorf("source not stamped: %s", text)
	}
	if !strings.Contains(text, "2026-01-02T03:04:05Z") {
		t.Errorf("generated_at not stamped: %s", text)
	}
}

func TestWrapWithPagination_NextOffsetOnlyWhenHasMore(t *testing.T) {
	with := resultText(t, fixedClock().WrapWithPagination([]int{1, 2}, 2, 0, 2, true))
	if !strings.Contains(with, `"next_offset": 2`) {
		t.Errorf("expected next_offset when hasMore: %s", with)
	}

	without := resultText(t, fixedClock().WrapWithPagination([]int{1}, 2, 0, 1, false))
	if strings.Contains(without, "next_offset") {
		t.Errorf("next_offset must be omitted when !hasMore: %s", without)
	}
}
