package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/A-L-L-A-H/mw-rocksoul-cli/internal/agent"
	"github.com/A-L-L-A-H/mw-rocksoul-cli/internal/clients"
)

func TestVersionAndDoctorCommands(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runCLI(context.Background(), []string{"version"}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 || !strings.Contains(stdout.String(), "rocksoul "+Version) {
		t.Fatalf("version failed: code=%d out=%q err=%q", code, stdout.String(), stderr.String())
	}

	// Spin up healthy mock ecosystem endpoints for doctor.
	okSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/tags" {
			_, _ = w.Write([]byte(`{"models":[{"name":"qwen2.5-coder:7b"}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer okSrv.Close()

	cfgPath := filepath.Join(t.TempDir(), "config.json")
	t.Setenv("ROCKSOUL_CONFIG_PATH", cfgPath)
	t.Setenv("ROCKSOUL_TOKEN_PATH", filepath.Join(t.TempDir(), "token.json"))
	t.Setenv("ROCKSOUL_GATEWAY_URL", okSrv.URL)
	t.Setenv("ROCKSOUL_CORE_URL", okSrv.URL)
	t.Setenv("ROCKSOUL_MCP_URL", okSrv.URL)
	t.Setenv("ROCKSOUL_SANDBOX_URL", okSrv.URL)
	t.Setenv("ROCKSOUL_RID_URL", okSrv.URL)
	t.Setenv("OLLAMA_HOST", okSrv.URL)

	stdout.Reset()
	stderr.Reset()
	code = runCLI(context.Background(), []string{"doctor", "--json", "--strict"}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("doctor --strict failed: code=%d out=%q err=%q", code, stdout.String(), stderr.String())
	}
	var report doctorReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("decode doctor json: %v (raw=%q)", err, stdout.String())
	}
	if !report.AllOK || len(report.Probes) != 6 || report.Provider.Provider != clients.ProviderGateway {
		t.Fatalf("unexpected doctor report: %+v", report)
	}
	if report.DiskSweeper == nil {
		t.Fatalf("expected diskSweeper probe in doctor report")
	}
	if _, ok := report.DiskSweeper["available"]; !ok {
		t.Fatalf("expected diskSweeper.available field, got %+v", report.DiskSweeper)
	}
}

func TestLoginAndMCPListCommands(t *testing.T) {
	mcpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"tools":[{"name":"mw_xv.health","description":"Check mw-xv","server":"mw-xv"}]}`))
	}))
	defer mcpSrv.Close()

	t.Setenv("ROCKSOUL_CONFIG_PATH", filepath.Join(t.TempDir(), "config.json"))
	t.Setenv("ROCKSOUL_TOKEN_PATH", filepath.Join(t.TempDir(), "token.json"))
	t.Setenv("ROCKSOUL_MCP_URL", mcpSrv.URL)

	// login --start --json
	var stdout, stderr bytes.Buffer
	code := runCLI(context.Background(), []string{"login", "--start", "--json"}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 || !strings.Contains(stdout.String(), "code_challenge_method=S256") {
		t.Fatalf("login --start failed: code=%d out=%q err=%q", code, stdout.String(), stderr.String())
	}

	// login --status --json
	stdout.Reset()
	stderr.Reset()
	code = runCLI(context.Background(), []string{"login", "--status", "--json"}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 || !strings.Contains(stdout.String(), `"pkceMethod":"S256"`) {
		t.Fatalf("login --status failed: code=%d out=%q err=%q", code, stdout.String(), stderr.String())
	}

	// mcp list
	stdout.Reset()
	stderr.Reset()
	code = runCLI(context.Background(), []string{"mcp", "list"}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 || !strings.Contains(stdout.String(), "mw_xv.health") {
		t.Fatalf("mcp list failed: code=%d out=%q err=%q", code, stdout.String(), stderr.String())
	}
}

func TestDirectPromptAndBareInteractiveChatWithSlashCommands(t *testing.T) {
	mockGW := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/health" {
			_, _ = w.Write([]byte(`{"status":"ok"}`))
			return
		}
		_, _ = w.Write([]byte(`{"id":"c1","model":"rocksoul-test","choices":[{"index":0,"message":{"role":"assistant","content":"Direct coding reply."},"finish_reason":"stop"}],"usage":{"prompt_tokens":10,"completion_tokens":5}}`))
	}))
	defer mockGW.Close()

	cfgPath := filepath.Join(t.TempDir(), "config.json")
	t.Setenv("ROCKSOUL_CONFIG_PATH", cfgPath)
	t.Setenv("ROCKSOUL_TOKEN_PATH", filepath.Join(t.TempDir(), "token.json"))
	t.Setenv("ROCKSOUL_GATEWAY_URL", mockGW.URL)
	t.Setenv("ROCKSOUL_MCP_URL", "http://127.0.0.1:1")

	// 1. Direct `rocksoul "<prompt>"` one-shot shortcut (Codex/OpenCode UX).
	var stdout, stderr bytes.Buffer
	code := runCLI(context.Background(), []string{"Explain this workspace"}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 || !strings.Contains(stdout.String(), "Direct coding reply.") {
		t.Fatalf("direct prompt failed: code=%d out=%q err=%q", code, stdout.String(), stderr.String())
	}

	// 2. Bare `rocksoul` launches interactive chat with slash commands + persists ~/.rocksoul/config.json.
	chatInput := strings.Join([]string{
		"/help",
		"/model qwen2.5-coder:14b",
		"/risk",
		"/risk tier R1",
		"/risk approve write_file .env",
		"/diff",
		"/mcp",
		"/clear",
		"/doctor",
		"hello rocksoul",
		"/exit",
	}, "\n") + "\n"

	stdout.Reset()
	stderr.Reset()
	code = runCLI(context.Background(), nil, strings.NewReader(chatInput), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("bare rocksoul chat failed: code=%d out=%q err=%q", code, stdout.String(), stderr.String())
	}
	chatOut := stdout.String()
	for _, want := range []string{
		"Rocksoul " + Version,
		`Model set to "qwen2.5-coder:14b"`,
		"Risk Gate Policy",
		"auto-approval tier updated to R1",
		"Issued single-use approval token",
		"Cleared conversation history",
		"Rocksoul Doctor",
		"Direct coding reply.",
		"Bye.",
	} {
		if !strings.Contains(chatOut, want) {
			t.Fatalf("expected chat output to contain %q, got:\n%s", want, chatOut)
		}
	}

	// Verify ~/.rocksoul/config.json persistence.
	rawCfg, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("expected persisted config at %s: %v", cfgPath, err)
	}
	if !strings.Contains(string(rawCfg), `"model": "qwen2.5-coder:14b"`) || !strings.Contains(string(rawCfg), `"maxAutoTier": "R1"`) {
		t.Fatalf("unexpected persisted config contents: %s", string(rawCfg))
	}
}

func TestInitTUICommand(t *testing.T) {
	workDir := t.TempDir()
	t.Setenv("ROCKSOUL_CONFIG_PATH", filepath.Join(t.TempDir(), "config.json"))

	for _, tc := range []struct {
		target   string
		wantFile string
	}{
		{target: "opencode", wantFile: "opencode.json"},
		{target: "crush", wantFile: ".crush.json"},
		{target: "codex", wantFile: filepath.Join(".codex", "config.toml")},
	} {
		var stdout, stderr bytes.Buffer
		code := runCLI(
			context.Background(),
			[]string{"init-tui", "--target", tc.target, "--dir", workDir, "--json"},
			strings.NewReader(""),
			&stdout,
			&stderr,
		)
		if code != 0 {
			t.Fatalf("init-tui --target %s failed: code=%d out=%q err=%q", tc.target, code, stdout.String(), stderr.String())
		}
		raw, err := os.ReadFile(filepath.Join(workDir, tc.wantFile))
		if err != nil {
			t.Fatalf("expected generated %s: %v", tc.wantFile, err)
		}
		if !strings.Contains(string(raw), "http://127.0.0.1:4510/v1") || !strings.Contains(string(raw), "http://127.0.0.1:4530/mcp") {
			t.Fatalf("%s missing Rocksoul endpoints: %s", tc.wantFile, string(raw))
		}
	}
}

func TestPlanRunLoopAndCommitSubcommand(t *testing.T) {
	workDir := t.TempDir()
	for _, args := range [][]string{
		{"init"},
		{"config", "user.email", "cli@rocksoul.local"},
		{"config", "user.name", "Rocksoul CLI"},
	} {
		cmd := exec.Command("git", append([]string{"-C", workDir}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, string(out))
		}
	}
	if err := os.WriteFile(filepath.Join(workDir, "README.md"), []byte("root\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_ = exec.Command("git", "-C", workDir, "add", "README.md").Run()
	_ = exec.Command("git", "-C", workDir, "commit", "-m", "initial").Run()

	// Create two files that represent work owned by T01 and T02.
	if err := os.WriteFile(filepath.Join(workDir, "one.txt"), []byte("task one\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workDir, "two.txt"), []byte("task two\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	plan := &agent.TaskOSPlan{
		ID:     "cli-plan",
		Title:  "CLI Loop Plan",
		Status: "pending",
		Tasks: []agent.TaskOSMicroTask{
			{ID: "T01", Title: "Commit one.txt", OwnerFiles: []string{"one.txt"}, Status: "pending"},
			{ID: "T02", Title: "Commit two.txt", OwnerFiles: []string{"two.txt"}, Dependencies: []string{"T01"}, Status: "pending"},
		},
	}
	if err := agent.SavePlan(workDir, plan); err != nil {
		t.Fatal(err)
	}

	mockGW := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/health" {
			_, _ = w.Write([]byte(`{"status":"ok"}`))
			return
		}
		_, _ = w.Write([]byte(`{"id":"c1","model":"rocksoul-test","choices":[{"index":0,"message":{"role":"assistant","content":"task completed"},"finish_reason":"stop"}],"usage":{"prompt_tokens":5,"completion_tokens":3}}`))
	}))
	defer mockGW.Close()

	t.Setenv("ROCKSOUL_CONFIG_PATH", filepath.Join(t.TempDir(), "config.json"))
	t.Setenv("ROCKSOUL_TOKEN_PATH", filepath.Join(t.TempDir(), "token.json"))
	t.Setenv("ROCKSOUL_GATEWAY_URL", mockGW.URL)

	var stdout, stderr bytes.Buffer
	code := runCLI(
		context.Background(),
		[]string{"plan", "run", "--loop", "--commit", "--dir", workDir, "--json"},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if code != 0 {
		t.Fatalf("plan run --loop --commit failed: code=%d out=%q err=%q", code, stdout.String(), stderr.String())
	}
	var res agent.TaskOSLoopResult
	if err := json.Unmarshal(stdout.Bytes(), &res); err != nil {
		t.Fatalf("decode plan run json: %v (%s)", err, stdout.String())
	}
	if res.PlanStatus != "completed" || len(res.ExecutedTasks) != 2 || len(res.Commits) != 2 {
		t.Fatalf("expected 2 completed tasks and 2 commits, got %+v", res)
	}
}

func TestInstallScriptSyntaxAndChecksumVerification(t *testing.T) {
	scriptPath := filepath.Clean(filepath.Join("..", "..", "scripts", "install.sh"))
	if _, err := os.Stat(scriptPath); err != nil {
		t.Fatalf("expected scripts/install.sh at %s: %v", scriptPath, err)
	}
	raw, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, want := range []string{
		"verify_sha256",
		"sha256sum",
		"shasum -a 256",
		"install_release_binary \"rocksoul\"",
		"install_release_binary \"mw-ww-cli\"",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("scripts/install.sh missing %q", want)
		}
	}
}
