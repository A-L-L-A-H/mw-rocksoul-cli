package agent

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStreamDiffParser(t *testing.T) {
	parser := NewStreamDiffParser()
	chunk := "--- a/file.txt\n+++ b/file.txt\n@@ -1,3 +1,3 @@\n context line\n-old line\n+new line\n context line 2\n"
	lines := parser.ParseChunk(chunk)

	if len(lines) != 7 {
		t.Fatalf("expected 7 diff lines, got %d", len(lines))
	}
	if lines[0].Type != DiffLineHeader || lines[1].Type != DiffLineHeader {
		t.Fatalf("unexpected headers: %+v", lines[:2])
	}
	if lines[2].Type != DiffLineHunk {
		t.Fatalf("expected hunk, got %+v", lines[2])
	}
	if lines[3].Type != DiffLineContext || lines[3].Text != "context line" {
		t.Fatalf("unexpected context: %+v", lines[3])
	}
	if lines[4].Type != DiffLineDelete || lines[4].Text != "old line" {
		t.Fatalf("unexpected delete: %+v", lines[4])
	}
	if lines[5].Type != DiffLineAdd || lines[5].Text != "new line" {
		t.Fatalf("unexpected add: %+v", lines[5])
	}

	// Test flush
	parser.ParseChunk("partial line")
	flushed := parser.Flush()
	if len(flushed) != 1 || flushed[0].Text != "partial line" {
		t.Fatalf("flush failed: %+v", flushed)
	}
}

func TestAtMentionParserAndResolver(t *testing.T) {
	prompt := "Please inspect @foo.go and @bar/baz.ts for issues."
	mentions := ParseAtMentions(prompt)
	if len(mentions) != 2 || mentions[0] != "foo.go" || mentions[1] != "bar/baz.ts" {
		t.Fatalf("parsed mentions failed: %+v", mentions)
	}

	tmpDir := t.TempDir()
	fooPath := filepath.Join(tmpDir, "foo.go")
	if err := os.WriteFile(fooPath, []byte("package foo\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	expanded, resolved, err := ResolveAtMentions(context.Background(), tmpDir, prompt)
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}
	if len(resolved) != 2 {
		t.Fatalf("expected 2 resolved mentions, got %d", len(resolved))
	}
	if !strings.Contains(expanded, "package foo") {
		t.Fatalf("expected expanded prompt to contain file content, got:\n%s", expanded)
	}
}

func TestTaskOSPlanLoop(t *testing.T) {
	tmpDir := t.TempDir()
	plan := &TaskOSPlan{
		ID:     "test-plan",
		Title:  "Test Plan",
		Status: "pending",
		Tasks: []TaskOSMicroTask{
			{
				ID:     "T01",
				Title:  "First Task",
				Status: "pending",
			},
			{
				ID:           "T02",
				Title:        "Second Task",
				Dependencies: []string{"T01"},
				Status:       "pending",
			},
		},
	}

	if err := SavePlan(tmpDir, plan); err != nil {
		t.Fatalf("save plan: %v", err)
	}

	loaded, err := LoadPlan(tmpDir)
	if err != nil || loaded == nil {
		t.Fatalf("load plan: %v", err)
	}

	ready := loaded.NextReadyTask()
	if ready == nil || ready.ID != "T01" {
		t.Fatalf("expected T01 to be ready, got %+v", ready)
	}

	ready.Status = "completed"
	_ = SavePlan(tmpDir, loaded)

	loaded2, _ := LoadPlan(tmpDir)
	nextReady := loaded2.NextReadyTask()
	if nextReady == nil || nextReady.ID != "T02" {
		t.Fatalf("expected T02 to be ready after T01 completed, got %+v", nextReady)
	}
}
