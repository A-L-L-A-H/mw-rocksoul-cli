package agent

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func initRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if out, err := exec.Command("git", "-C", dir, "init", "-q").CombinedOutput(); err != nil {
		t.Skipf("git unavailable: %v %s", err, out)
	}
	return dir
}

func TestCheckpointUndoRestoresAndRemovesNewFiles(t *testing.T) {
	ctx := context.Background()
	dir := initRepo(t)
	target := filepath.Join(dir, "a.txt")
	if err := os.WriteFile(target, []byte("one"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := CreateCheckpoint(ctx, dir, "turn1"); err != nil {
		t.Fatal(err)
	}
	extra := filepath.Join(dir, "b.txt")
	_ = os.WriteFile(target, []byte("two"), 0o644)
	_ = os.WriteFile(extra, []byte("new"), 0o644)
	listed, err := ListCheckpoints(dir)
	if err != nil || len(listed) != 1 || listed[0].Label != "turn1" {
		t.Fatalf("list: %v %+v", err, listed)
	}
	if _, err := UndoLastCheckpoint(ctx, dir); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(target); string(got) != "one" {
		t.Fatalf("not restored: %q", got)
	}
	if _, err := os.Stat(extra); err == nil {
		t.Fatal("new file survived undo")
	}
	if _, err := UndoLastCheckpoint(ctx, dir); err == nil {
		t.Fatal("expected no checkpoints error")
	}
}

func TestCheckpointRequiresGit(t *testing.T) {
	if _, err := CreateCheckpoint(context.Background(), t.TempDir(), "x"); err == nil {
		t.Fatal("expected error")
	}
}
