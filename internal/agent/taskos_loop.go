package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// TaskOSPlan represents a structured cognitive plan bundle.
type TaskOSPlan struct {
	ID        string           `json:"id"`
	Title     string           `json:"title"`
	Status    string           `json:"status"` // pending | in_progress | completed | failed
	Tasks     []TaskOSMicroTask `json:"tasks"`
	UpdatedAt time.Time        `json:"updatedAt"`
}

// TaskOSMicroTask represents an atomic micro-task in the plan.
type TaskOSMicroTask struct {
	ID           string   `json:"id"`
	Title        string   `json:"title"`
	Description  string   `json:"description,omitempty"`
	OwnerFiles   []string `json:"ownerFiles,omitempty"`
	Dependencies []string `json:"dependencies,omitempty"`
	Status       string   `json:"status"` // pending | in_progress | completed | failed
	Result       string   `json:"result,omitempty"`
	CompletedAt  string   `json:"completedAt,omitempty"`
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
	return os.WriteFile(PlanFilePath(workDir), append(data, '\n'), 0o644)
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
	plan, err := LoadPlan(workDir)
	if err != nil {
		return nil, err
	}
	if plan == nil {
		return nil, fmt.Errorf("no plan found at %s", PlanFilePath(workDir))
	}

	task := plan.NextReadyTask()
	if task == nil {
		return nil, nil // All tasks complete or blocked
	}

	task.Status = "in_progress"
	_ = SavePlan(workDir, plan)

	prompt := fmt.Sprintf("Execute micro-task %s: %s\nDescription: %s\nOwner files: %s",
		task.ID, task.Title, task.Description, strings.Join(task.OwnerFiles, ", "))

	reply, runErr := engine.RunOneShot(ctx, workDir, DefaultAgentProfile, model, ModeAct, prompt, callback)
	if runErr != nil {
		task.Status = "failed"
		task.Result = runErr.Error()
		_ = SavePlan(workDir, plan)
		return task, runErr
	}

	task.Status = "completed"
	task.Result = reply
	task.CompletedAt = time.Now().UTC().Format(time.RFC3339)

	allDone := true
	for _, t := range plan.Tasks {
		if t.Status != "completed" {
			allDone = false
			break
		}
	}
	if allDone {
		plan.Status = "completed"
	} else {
		plan.Status = "in_progress"
	}

	if err := SavePlan(workDir, plan); err != nil {
		return task, fmt.Errorf("save completed task: %w", err)
	}

	return task, nil
}
