package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// TaskOSPlan represents a structured cognitive plan bundle.
type TaskOSPlan struct {
	ID        string            `json:"id"`
	Title     string            `json:"title"`
	Status    string            `json:"status"` // pending | in_progress | completed | failed
	Tasks     []TaskOSMicroTask `json:"tasks"`
	UpdatedAt time.Time         `json:"updatedAt"`
}

// TaskOSMicroTask represents an atomic micro-task in the plan.
type TaskOSMicroTask struct {
	ID            string   `json:"id"`
	Title         string   `json:"title"`
	Description   string   `json:"description,omitempty"`
	OwnerFiles    []string `json:"ownerFiles,omitempty"`
	Dependencies  []string `json:"dependencies,omitempty"`
	VerifyCommand string   `json:"verifyCommand,omitempty"`
	Status        string   `json:"status"` // pending | in_progress | completed | failed
	Result        string   `json:"result,omitempty"`
	CommitSHA     string   `json:"commitSha,omitempty"`
	CompletedAt   string   `json:"completedAt,omitempty"`
}

// TaskRunner executes one micro-task and returns its summary/reply.
type TaskRunner func(ctx context.Context, workDir string, task *TaskOSMicroTask, model string, callback func(ev AgentEvent)) (string, error)

// TaskVerifyFunc verifies a micro-task before optional path-scoped commit.
type TaskVerifyFunc func(ctx context.Context, workDir string, task *TaskOSMicroTask) error

// TaskOSLoopOptions controls single-step or looped TaskOS execution, verification, and path-scoped commits.
type TaskOSLoopOptions struct {
	Model         string
	Loop          bool
	Commit        bool
	VerifyCommand string
	MaxTasks      int
	Runner        TaskRunner
	VerifyFunc    TaskVerifyFunc
	Callback      func(ev AgentEvent)
}

// TaskOSLoopResult summarizes one or more TaskOS micro-tasks executed in a run.
type TaskOSLoopResult struct {
	PlanStatus    string             `json:"planStatus"`
	ExecutedTasks []*TaskOSMicroTask `json:"executedTasks"`
	LastTask      *TaskOSMicroTask   `json:"lastTask,omitempty"`
	Commits       []string           `json:"commits,omitempty"`
}

// PlanFilePath returns the canonical .plan/plan.json path in the workspace.
func PlanFilePath(workDir string) string {
	return filepath.Join(workDir, ".plan", "plan.json")
}

// LoadPlan loads .plan/plan.json if it exists.
func LoadPlan(workDir string) (*TaskOSPlan, error) {
	p := PlanFilePath(workDir)
	data, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read plan: %w", err)
	}
	var plan TaskOSPlan
	if err := json.Unmarshal(data, &plan); err != nil {
		return nil, fmt.Errorf("unmarshal plan: %w", err)
	}
	return &plan, nil
}

// SavePlan writes .plan/plan.json atomically.
func SavePlan(workDir string, plan *TaskOSPlan) error {
	dir := filepath.Join(workDir, ".plan")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir .plan: %w", err)
	}
	plan.UpdatedAt = time.Now().UTC()
	data, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal plan: %w", err)
	}
	target := PlanFilePath(workDir)
	tmp := target + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o644); err != nil {
		return fmt.Errorf("write temp plan: %w", err)
	}
	if err := os.Rename(tmp, target); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("replace plan: %w", err)
	}
	return nil
}

// NextReadyTask selects the first pending micro-task whose dependencies are satisfied.
func (p *TaskOSPlan) NextReadyTask() *TaskOSMicroTask {
	completed := make(map[string]bool)
	for _, t := range p.Tasks {
		if t.Status == "completed" {
			completed[t.ID] = true
		}
	}

	for i := range p.Tasks {
		task := &p.Tasks[i]
		if task.Status != "pending" {
			continue
		}
		ready := true
		for _, dep := range task.Dependencies {
			if !completed[dep] {
				ready = false
				break
			}
		}
		if ready {
			return task
		}
	}
	return nil
}

// RunTaskOSLoop executes the next ready micro-task using the agent Engine.
func RunTaskOSLoop(ctx context.Context, engine *Engine, workDir string, model string, callback func(ev AgentEvent)) (*TaskOSMicroTask, error) {
	res, err := RunTaskOSLoopWithOptions(ctx, engine, workDir, TaskOSLoopOptions{
		Model:    model,
		Callback: callback,
	})
	if res == nil {
		return nil, err
	}
	return res.LastTask, err
}

// RunTaskOSLoopWithOptions executes one or all ready micro-tasks sequentially with verification and optional path-scoped git commits.
func RunTaskOSLoopWithOptions(ctx context.Context, engine *Engine, workDir string, opts TaskOSLoopOptions) (*TaskOSLoopResult, error) {
	plan, err := LoadPlan(workDir)
	if err != nil {
		return nil, err
	}
	if plan == nil {
		return nil, fmt.Errorf("no plan found at %s", PlanFilePath(workDir))
	}

	runner := opts.Runner
	if runner == nil {
		if engine == nil {
			return nil, errors.New("agent engine is required when custom TaskRunner is not provided")
		}
		runner = func(runCtx context.Context, dir string, task *TaskOSMicroTask, model string, cb func(ev AgentEvent)) (string, error) {
			prompt := fmt.Sprintf("Execute micro-task %s: %s\nDescription: %s\nOwner files: %s",
				task.ID, task.Title, task.Description, strings.Join(task.OwnerFiles, ", "))
			return engine.RunOneShot(runCtx, dir, DefaultAgentProfile, model, ModeAct, prompt, cb)
		}
	}

	result := &TaskOSLoopResult{
		PlanStatus:    plan.Status,
		ExecutedTasks: make([]*TaskOSMicroTask, 0),
	}

	maxTasks := opts.MaxTasks
	if maxTasks <= 0 {
		if opts.Loop {
			maxTasks = len(plan.Tasks) + 1
		} else {
			maxTasks = 1
		}
	}

	for count := 0; count < maxTasks; count++ {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		task := plan.NextReadyTask()
		if task == nil {
			break
		}

		task.Status = "in_progress"
		plan.Status = "in_progress"
		_ = SavePlan(workDir, plan)

		reply, runErr := runner(ctx, workDir, task, opts.Model, opts.Callback)
		if runErr != nil {
			task.Status = "failed"
			task.Result = runErr.Error()
			plan.Status = "failed"
			_ = SavePlan(workDir, plan)
			result.LastTask = cloneTask(task)
			result.ExecutedTasks = append(result.ExecutedTasks, cloneTask(task))
			result.PlanStatus = plan.Status
			return result, runErr
		}

		if verifyErr := verifyMicroTask(ctx, workDir, task, opts); verifyErr != nil {
			task.Status = "failed"
			task.Result = fmt.Sprintf("verification failed: %v", verifyErr)
			plan.Status = "failed"
			_ = SavePlan(workDir, plan)
			result.LastTask = cloneTask(task)
			result.ExecutedTasks = append(result.ExecutedTasks, cloneTask(task))
			result.PlanStatus = plan.Status
			return result, fmt.Errorf("verify task %s: %w", task.ID, verifyErr)
		}

		if opts.Commit {
			sha, commitErr := commitTaskScopedChanges(ctx, workDir, task)
			if commitErr != nil {
				task.Status = "failed"
				task.Result = fmt.Sprintf("commit failed: %v", commitErr)
				plan.Status = "failed"
				_ = SavePlan(workDir, plan)
				result.LastTask = cloneTask(task)
				result.ExecutedTasks = append(result.ExecutedTasks, cloneTask(task))
				result.PlanStatus = plan.Status
				return result, fmt.Errorf("commit task %s: %w", task.ID, commitErr)
			}
			if sha != "" {
				task.CommitSHA = sha
				result.Commits = append(result.Commits, sha)
			}
		}

		task.Status = "completed"
		task.Result = reply
		task.CompletedAt = time.Now().UTC().Format(time.RFC3339)
		plan.Status = computePlanStatus(plan.Tasks)
		if err := SavePlan(workDir, plan); err != nil {
			return result, fmt.Errorf("save completed task: %w", err)
		}

		snap := cloneTask(task)
		result.LastTask = snap
		result.ExecutedTasks = append(result.ExecutedTasks, snap)
		result.PlanStatus = plan.Status

		if !opts.Loop {
			break
		}
	}

	plan.Status = computePlanStatus(plan.Tasks)
	result.PlanStatus = plan.Status
	return result, nil
}

func cloneTask(task *TaskOSMicroTask) *TaskOSMicroTask {
	if task == nil {
		return nil
	}
	cp := *task
	cp.OwnerFiles = append([]string(nil), task.OwnerFiles...)
	cp.Dependencies = append([]string(nil), task.Dependencies...)
	return &cp
}

func computePlanStatus(tasks []TaskOSMicroTask) string {
	if len(tasks) == 0 {
		return "completed"
	}
	allDone := true
	for _, t := range tasks {
		if t.Status == "failed" {
			return "failed"
		}
		if t.Status != "completed" {
			allDone = false
		}
	}
	if allDone {
		return "completed"
	}
	return "in_progress"
}

func verifyMicroTask(ctx context.Context, workDir string, task *TaskOSMicroTask, opts TaskOSLoopOptions) error {
	if opts.VerifyFunc != nil {
		return opts.VerifyFunc(ctx, workDir, task)
	}
	verifyCmd := strings.TrimSpace(task.VerifyCommand)
	if verifyCmd == "" {
		verifyCmd = strings.TrimSpace(opts.VerifyCommand)
	}
	if verifyCmd == "" {
		return nil
	}
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "cmd", "/C", verifyCmd)
	} else {
		cmd = exec.CommandContext(ctx, "sh", "-c", verifyCmd)
	}
	cmd.Dir = workDir
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("command %q exited with %v: %s", verifyCmd, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// commitTaskScopedChanges stages and commits ONLY dirty/untracked paths owned by task.OwnerFiles
// (or non-protected workspace changes excluding .plan/plan.json when OwnerFiles is empty).
func commitTaskScopedChanges(ctx context.Context, workDir string, task *TaskOSMicroTask) (string, error) {
	check := exec.CommandContext(ctx, "git", "-C", workDir, "rev-parse", "--is-inside-work-tree")
	if out, err := check.CombinedOutput(); err != nil {
		return "", fmt.Errorf("not a git repository (%s): %w", strings.TrimSpace(string(out)), err)
	}

	dirtyPaths, err := listDirtyGitPaths(ctx, workDir)
	if err != nil {
		return "", err
	}
	if len(dirtyPaths) == 0 {
		return "", nil
	}

	scoped := filterScopedPaths(dirtyPaths, task.OwnerFiles)
	if len(scoped) == 0 {
		return "", nil
	}

	addArgs := append([]string{"-C", workDir, "add", "-A", "--"}, scoped...)
	addCmd := exec.CommandContext(ctx, "git", addArgs...)
	if out, err := addCmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("git add: %s: %w", strings.TrimSpace(string(out)), err)
	}

	// Check if anything in scoped paths is actually staged relative to HEAD/index.
	diffArgs := append([]string{"-C", workDir, "diff", "--cached", "--quiet", "--"}, scoped...)
	diffCmd := exec.CommandContext(ctx, "git", diffArgs...)
	if err := diffCmd.Run(); err == nil {
		return "", nil
	}

	msg := fmt.Sprintf("plan(%s): %s", task.ID, strings.TrimSpace(task.Title))
	if strings.TrimSpace(task.Title) == "" {
		msg = fmt.Sprintf("plan(%s): complete micro-task", task.ID)
	}
	commitArgs := append([]string{"-C", workDir, "commit", "--only", "-m", msg, "--"}, scoped...)
	commitCmd := exec.CommandContext(ctx, "git", commitArgs...)
	if out, err := commitCmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("git commit: %s: %w", strings.TrimSpace(string(out)), err)
	}

	shaCmd := exec.CommandContext(ctx, "git", "-C", workDir, "rev-parse", "HEAD")
	shaOut, err := shaCmd.Output()
	if err != nil {
		return "", fmt.Errorf("git rev-parse HEAD: %w", err)
	}
	return strings.TrimSpace(string(shaOut)), nil
}

func listDirtyGitPaths(ctx context.Context, workDir string) ([]string, error) {
	cmd := exec.CommandContext(ctx, "git", "-C", workDir, "status", "--porcelain=v1", "-z", "-uall")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git status: %w", err)
	}
	entries := bytes.Split(out, []byte{0})
	paths := make([]string, 0, len(entries))
	seen := make(map[string]bool)
	for i := 0; i < len(entries); i++ {
		raw := string(entries[i])
		if len(raw) < 4 {
			continue
		}
		statusCode := raw[:2]
		rel := filepath.ToSlash(raw[3:])
		if strings.Contains(statusCode, "R") || strings.Contains(statusCode, "C") {
			// In -z format, rename/copy records have the destination path next.
			if i+1 < len(entries) && len(entries[i+1]) > 0 {
				rel = filepath.ToSlash(string(entries[i+1]))
				i++
			}
		}
		cleaned := path.Clean(strings.TrimPrefix(rel, "./"))
		if cleaned != "" && cleaned != "." && !seen[cleaned] {
			seen[cleaned] = true
			paths = append(paths, cleaned)
		}
	}
	return paths, nil
}

func filterScopedPaths(dirtyPaths []string, ownerFiles []string) []string {
	normalizedOwners := make([]string, 0, len(ownerFiles))
	for _, owner := range ownerFiles {
		cleaned := path.Clean(strings.TrimPrefix(filepath.ToSlash(strings.TrimSpace(owner)), "./"))
		cleaned = strings.TrimSuffix(cleaned, "/**")
		cleaned = strings.TrimSuffix(cleaned, "/*")
		if cleaned != "" && cleaned != "." {
			normalizedOwners = append(normalizedOwners, cleaned)
		}
	}

	scoped := make([]string, 0, len(dirtyPaths))
	for _, candidate := range dirtyPaths {
		if isProtectedCommitPath(candidate) {
			continue
		}
		if len(normalizedOwners) == 0 {
			if candidate == ".plan/plan.json" {
				continue
			}
			scoped = append(scoped, candidate)
			continue
		}
		if matchesAnyOwner(candidate, normalizedOwners) {
			scoped = append(scoped, candidate)
		}
	}
	return scoped
}

func matchesAnyOwner(candidate string, owners []string) bool {
	for _, owner := range owners {
		if candidate == owner || strings.HasPrefix(candidate, owner+"/") {
			return true
		}
		if matched, err := path.Match(owner, candidate); err == nil && matched {
			return true
		}
	}
	return false
}

func isProtectedCommitPath(p string) bool {
	lower := strings.ToLower(p)
	base := path.Base(lower)
	return strings.HasPrefix(lower, ".githooks/") ||
		strings.HasPrefix(lower, ".github/workflows/") ||
		base == "codeowners"
}
