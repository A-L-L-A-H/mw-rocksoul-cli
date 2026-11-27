package agent

import (
	"context"
	"errors"
	"os"
	"os/exec"
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

func initGitTestRepo(t *testing.T, dir string) {
	t.Helper()
	run := func(args ...string) {
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v failed: %v\n%s", args, err, string(out))
		}
	}
	run("init")
	run("config", "user.email", "test@rocksoul.local")
	run("config", "user.name", "Rocksoul Test")
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("init\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", "README.md")
	run("commit", "-m", "init")
}

func TestTaskOSLoopSequentialVerifyAndPathScopedCommit(t *testing.T) {
	tmpDir := t.TempDir()
	initGitTestRepo(t, tmpDir)

	// Unrelated dirty file outside any task's OwnerFiles MUST NOT be committed.
	unrelatedPath := filepath.Join(tmpDir, "unrelated.txt")
	if err := os.WriteFile(unrelatedPath, []byte("keep unstaged\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	plan := &TaskOSPlan{
		ID:     "loop-commit-plan",
		Title:  "Sequential Loop Plan",
		Status: "pending",
		Tasks: []TaskOSMicroTask{
			{
				ID:         "T01",
				Title:      "Write alpha file",
				OwnerFiles: []string{"pkg/alpha.txt"},
				Status:     "pending",
			},
			{
				ID:           "T02",
				Title:        "Write beta file",
				OwnerFiles:   []string{"pkg/beta.txt"},
				Dependencies: []string{"T01"},
				Status:       "pending",
			},
		},
	}
	if err := SavePlan(tmpDir, plan); err != nil {
		t.Fatal(err)
	}

	var order []string
	res, err := RunTaskOSLoopWithOptions(context.Background(), nil, tmpDir, TaskOSLoopOptions{
		Loop:   true,
		Commit: true,
		Runner: func(_ context.Context, workDir string, task *TaskOSMicroTask, _ string, _ func(AgentEvent)) (string, error) {
			order = append(order, task.ID)
			target := filepath.Join(workDir, filepath.FromSlash(task.OwnerFiles[0]))
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return "", err
			}
			if err := os.WriteFile(target, []byte("done "+task.ID+"\n"), 0o644); err != nil {
				return "", err
			}
			return "ok " + task.ID, nil
		},
		VerifyFunc: func(_ context.Context, workDir string, task *TaskOSMicroTask) error {
			target := filepath.Join(workDir, filepath.FromSlash(task.OwnerFiles[0]))
			if _, statErr := os.Stat(target); statErr != nil {
				return statErr
			}
			return nil
		},
	})
	if err != nil {
		t.Fatalf("RunTaskOSLoopWithOptions failed: %v", err)
	}
	if strings.Join(order, ",") != "T01,T02" {
		t.Fatalf("unexpected execution order: %v", order)
	}
	if res.PlanStatus != "completed" || len(res.ExecutedTasks) != 2 || len(res.Commits) != 2 {
		t.Fatalf("unexpected loop result: %+v", res)
	}

	// Verify commits touched ONLY scoped owner files and left unrelated.txt dirty.
	logOut, err := exec.Command("git", "-C", tmpDir, "log", "--name-only", "--pretty=format:%s", "-n", "2").Output()
	if err != nil {
		t.Fatal(err)
	}
	logStr := string(logOut)
	if !strings.Contains(logStr, "plan(T02): Write beta file") || !strings.Contains(logStr, "pkg/beta.txt") ||
		!strings.Contains(logStr, "plan(T01): Write alpha file") || !strings.Contains(logStr, "pkg/alpha.txt") {
		t.Fatalf("unexpected git log:\n%s", logStr)
	}
	if strings.Contains(logStr, "unrelated.txt") {
		t.Fatalf("unrelated.txt leaked into path-scoped commit:\n%s", logStr)
	}
	statusOut, _ := exec.Command("git", "-C", tmpDir, "status", "--porcelain").Output()
	if !strings.Contains(string(statusOut), "?? unrelated.txt") {
		t.Fatalf("expected unrelated.txt to remain untracked/unstaged, got:\n%s", string(statusOut))
	}
}

func TestTaskOSLoopVerifyFailureStopsAndSkipsCommit(t *testing.T) {
	tmpDir := t.TempDir()
	initGitTestRepo(t, tmpDir)

	plan := &TaskOSPlan{
		ID:     "verify-fail-plan",
		Title:  "Verify Fail",
		Status: "pending",
		Tasks: []TaskOSMicroTask{
			{ID: "T01", Title: "Failing verify", OwnerFiles: []string{"bad.txt"}, Status: "pending"},
			{ID: "T02", Title: "Should not run", OwnerFiles: []string{"good.txt"}, Dependencies: []string{"T01"}, Status: "pending"},
		},
	}
	if err := SavePlan(tmpDir, plan); err != nil {
		t.Fatal(err)
	}

	headBefore, _ := exec.Command("git", "-C", tmpDir, "rev-parse", "HEAD").Output()

	res, err := RunTaskOSLoopWithOptions(context.Background(), nil, tmpDir, TaskOSLoopOptions{
		Loop:   true,
		Commit: true,
		Runner: func(_ context.Context, workDir string, _ *TaskOSMicroTask, _ string, _ func(AgentEvent)) (string, error) {
			return "wrote", os.WriteFile(filepath.Join(workDir, "bad.txt"), []byte("bad"), 0o644)
		},
		VerifyFunc: func(_ context.Context, _ string, _ *TaskOSMicroTask) error {
			return errors.New("unit test check failed")
		},
	})
	if err == nil || !strings.Contains(err.Error(), "verify task T01") {
		t.Fatalf("expected verify error on T01, got %v", err)
	}
	if res == nil || res.PlanStatus != "failed" || len(res.Commits) != 0 {
		t.Fatalf("expected failed plan with 0 commits, got %+v", res)
	}
	headAfter, _ := exec.Command("git", "-C", tmpDir, "rev-parse", "HEAD").Output()
	if strings.TrimSpace(string(headBefore)) != strings.TrimSpace(string(headAfter)) {
		t.Fatalf("expected no new git commit when verification fails")
	}
}
