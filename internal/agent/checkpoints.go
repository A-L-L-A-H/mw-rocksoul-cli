package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	checkpointDirName      = "rocksoul-checkpoints"
	checkpointMaxFileBytes = 1 << 20
	checkpointMaxFiles     = 5000
)

// Checkpoint describes one pre-turn workspace snapshot.
type Checkpoint struct {
	ID        string    `json:"id"`
	Label     string    `json:"label"`
	CreatedAt time.Time `json:"createdAt"`
	Files     []string  `json:"files"`
}

func checkpointRoot(workDir string) (string, error) {
	gitDir := filepath.Join(workDir, ".git")
	info, err := os.Stat(gitDir)
	if err != nil || !info.IsDir() {
		return "", fmt.Errorf("checkpoints require a git repository at %s", workDir)
	}
	return filepath.Join(gitDir, checkpointDirName), nil
}

func workspaceFiles(ctx context.Context, workDir string) ([]string, error) {
	cmd := exec.CommandContext(ctx, "git", "-C", workDir, "ls-files", "-co", "--exclude-standard", "-z")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git ls-files: %w", err)
	}
	var files []string
	for _, rel := range strings.Split(string(out), "\x00") {
		if rel != "" {
			files = append(files, filepath.FromSlash(rel))
		}
	}
	sort.Strings(files)
	return files, nil
}

// CreateCheckpoint snapshots every non-ignored workspace file before a turn writes.
func CreateCheckpoint(ctx context.Context, workDir, label string) (Checkpoint, error) {
	root, err := checkpointRoot(workDir)
	if err != nil {
		return Checkpoint{}, err
	}
	files, err := workspaceFiles(ctx, workDir)
	if err != nil {
		return Checkpoint{}, err
	}
	if len(files) > checkpointMaxFiles {
		return Checkpoint{}, fmt.Errorf("workspace has %d files, limit %d", len(files), checkpointMaxFiles)
	}
	now := time.Now().UTC()
	checkpoint := Checkpoint{ID: now.Format("20060102T150405.000000000"), Label: label, CreatedAt: now}
	snapDir := filepath.Join(root, checkpoint.ID, "files")
	if err := os.MkdirAll(snapDir, 0o755); err != nil {
		return Checkpoint{}, err
	}
	for _, rel := range files {
		src := filepath.Join(workDir, rel)
		info, statErr := os.Stat(src)
		if statErr != nil || !info.Mode().IsRegular() || info.Size() > checkpointMaxFileBytes {
			continue
		}
		content, readErr := os.ReadFile(src)
		if readErr != nil {
			continue
		}
		dst := filepath.Join(snapDir, rel)
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return Checkpoint{}, err
		}
		if err := os.WriteFile(dst, content, info.Mode().Perm()); err != nil {
			return Checkpoint{}, err
		}
		checkpoint.Files = append(checkpoint.Files, rel)
	}
	manifest, err := json.Marshal(checkpoint)
	if err != nil {
		return Checkpoint{}, err
	}
	if err := os.WriteFile(filepath.Join(root, checkpoint.ID, "manifest.json"), manifest, 0o644); err != nil {
		return Checkpoint{}, err
	}
	return checkpoint, nil
}

// ListCheckpoints returns checkpoints newest first.
func ListCheckpoints(workDir string) ([]Checkpoint, error) {
	root, err := checkpointRoot(workDir)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var checkpoints []Checkpoint
	for _, entry := range entries {
		raw, readErr := os.ReadFile(filepath.Join(root, entry.Name(), "manifest.json"))
		if readErr != nil {
			continue
		}
		var checkpoint Checkpoint
		if json.Unmarshal(raw, &checkpoint) == nil {
			checkpoints = append(checkpoints, checkpoint)
		}
	}
	sort.Slice(checkpoints, func(i, j int) bool { return checkpoints[i].ID > checkpoints[j].ID })
	return checkpoints, nil
}

// RestoreCheckpoint reverts the workspace to the snapshot and removes files created after it.
func RestoreCheckpoint(ctx context.Context, workDir, id string) (Checkpoint, error) {
	root, err := checkpointRoot(workDir)
	if err != nil {
		return Checkpoint{}, err
	}
	checkpoints, err := ListCheckpoints(workDir)
	if err != nil {
		return Checkpoint{}, err
	}
	var target *Checkpoint
	for index := range checkpoints {
		if checkpoints[index].ID == id {
			target = &checkpoints[index]
		}
	}
	if target == nil {
		return Checkpoint{}, fmt.Errorf("checkpoint %q not found", id)
	}
	kept := make(map[string]bool, len(target.Files))
	for _, rel := range target.Files {
		kept[rel] = true
		content, readErr := os.ReadFile(filepath.Join(root, id, "files", rel))
		if readErr != nil {
			return Checkpoint{}, readErr
		}
		dst := filepath.Join(workDir, rel)
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return Checkpoint{}, err
		}
		if err := os.WriteFile(dst, content, 0o644); err != nil {
			return Checkpoint{}, err
		}
	}
	current, err := workspaceFiles(ctx, workDir)
	if err != nil {
		return Checkpoint{}, err
	}
	for _, rel := range current {
		if kept[rel] {
			continue
		}
		info, statErr := os.Stat(filepath.Join(workDir, rel))
		if statErr == nil && info.Mode().IsRegular() && info.Size() <= checkpointMaxFileBytes {
			_ = os.Remove(filepath.Join(workDir, rel))
		}
	}
	return *target, nil
}

// UndoLastCheckpoint restores the newest checkpoint and discards it.
func UndoLastCheckpoint(ctx context.Context, workDir string) (Checkpoint, error) {
	checkpoints, err := ListCheckpoints(workDir)
	if err != nil {
		return Checkpoint{}, err
	}
	if len(checkpoints) == 0 {
		return Checkpoint{}, errors.New("no checkpoints")
	}
	restored, err := RestoreCheckpoint(ctx, workDir, checkpoints[0].ID)
	if err != nil {
		return Checkpoint{}, err
	}
	root, _ := checkpointRoot(workDir)
	_ = os.RemoveAll(filepath.Join(root, restored.ID))
	return restored, nil
}

func truncateCheckpointLabel(prompt string) string {
	label := strings.TrimSpace(prompt)
	if len(label) > 60 {
		label = label[:60]
	}
	return label
}
