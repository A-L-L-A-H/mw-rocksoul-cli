package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/A-L-L-A-H/mw-rocksoul-cli/internal/agent"
	"github.com/A-L-L-A-H/mw-rocksoul-cli/internal/clients"
)

func findWorkingBash(t *testing.T) string {
	t.Helper()
	var candidates []string
	if runtime.GOOS == "windows" {
		candidates = append(candidates,
			`C:\Program Files\Git\bin\bash.exe`,
			`C:\Program Files\Git\usr\bin\bash.exe`,
		)
	}
	if p, err := exec.LookPath("bash"); err == nil {
		candidates = append(candidates, p)
	}
	for _, candidate := range candidates {
		if _, err := os.Stat(candidate); err != nil {
			continue
		}
		out, err := exec.Command(candidate, "-c", "echo ok").CombinedOutput()
		if err == nil && strings.TrimSpace(string(out)) == "ok" {
			return candidate
		}
	}
	return ""
}

func TestC24SelfHostDoctorStrict(t *testing.T) {
	okSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/tags" {
			_, _ = w.Write([]byte(`{"models":[{"name":"qwen2.5-coder:7b"}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer okSrv.Close()

	t.Setenv("ROCKSOUL_CONFIG_PATH", filepath.Join(t.TempDir(), "config.json"))
	t.Setenv("ROCKSOUL_TOKEN_PATH", filepath.Join(t.TempDir(), "token.json"))
	t.Setenv("ROCKSOUL_GATEWAY_URL", okSrv.URL)
	t.Setenv("ROCKSOUL_CORE_URL", okSrv.URL)
	t.Setenv("ROCKSOUL_MCP_URL", okSrv.URL)
	t.Setenv("ROCKSOUL_SANDBOX_URL", okSrv.URL)
	t.Setenv("ROCKSOUL_RID_URL", okSrv.URL)
	t.Setenv("OLLAMA_HOST", okSrv.URL)

	var stdout, stderr bytes.Buffer
	args := []string{"doctor", "--json", "--strict"}
	code := runCLI(context.Background(), args, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("doctor --strict failed: code=%d out=%q err=%q", code, stdout.String(), stderr.String())
	}
	var report doctorReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("decode doctor json: %v (raw=%q)", err, stdout.String())
	}
	if !report.AllOK || report.Provider.Provider != clients.ProviderGateway {
		t.Fatalf("unexpected doctor report: %+v", report)
	}
}

func initC24PlanRepo(t *testing.T) string {
	t.Helper()
	workDir := t.TempDir()
	for _, args := range [][]string{
		{"init"},
		{"config", "user.email", "c24@rocksoul.local"},
		{"config", "user.name", "Rocksoul C24"},
	} {
		cmd := exec.Command("git", append([]string{"-C", workDir}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, string(out))
		}
	}
	for name, body := range map[string]string{
		"README.md": "c24 selfhost\n",
		"alpha.txt": "alpha\n",
		"beta.txt":  "beta\n",
	} {
		if err := os.WriteFile(filepath.Join(workDir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	_ = exec.Command("git", "-C", workDir, "add", "README.md").Run()
	_ = exec.Command("git", "-C", workDir, "commit", "-m", "initial").Run()

	plan := &agent.TaskOSPlan{
		ID:     "c24-selfhost",
		Title:  "C24 Self-Host Loop Plan",
		Status: "pending",
		Tasks: []agent.TaskOSMicroTask{
			{ID: "T01", Title: "Commit alpha", OwnerFiles: []string{"alpha.txt"}, Status: "pending"},
			{
				ID: "T02", Title: "Commit beta", OwnerFiles: []string{"beta.txt"},
				Dependencies: []string{"T01"}, Status: "pending",
			},
		},
	}
	if err := agent.SavePlan(workDir, plan); err != nil {
		t.Fatal(err)
	}
	return workDir
}

func TestC24SelfHostPlanRunLoopCommit(t *testing.T) {
	workDir := initC24PlanRepo(t)
	reply := `{"id":"c24-1","model":"rocksoul-test","choices":[{"index":0,` +
		`"message":{"role":"assistant","content":"completed"},"finish_reason":"stop"}],` +
		`"usage":{"prompt_tokens":6,"completion_tokens":4}}`
	mockGW := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/health" {
			_, _ = w.Write([]byte(`{"status":"ok"}`))
			return
		}
		_, _ = w.Write([]byte(reply))
	}))
	defer mockGW.Close()

	t.Setenv("ROCKSOUL_CONFIG_PATH", filepath.Join(t.TempDir(), "config.json"))
	t.Setenv("ROCKSOUL_TOKEN_PATH", filepath.Join(t.TempDir(), "token.json"))
	t.Setenv("ROCKSOUL_GATEWAY_URL", mockGW.URL)

	var stdout, stderr bytes.Buffer
	args := []string{"plan", "run", "--loop", "--commit", "--dir", workDir, "--json"}
	code := runCLI(context.Background(), args, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("plan run failed: code=%d out=%q err=%q", code, stdout.String(), stderr.String())
	}
	var res agent.TaskOSLoopResult
	if err := json.Unmarshal(stdout.Bytes(), &res); err != nil {
		t.Fatalf("decode plan run json: %v (%s)", err, stdout.String())
	}
	if res.PlanStatus != "completed" || len(res.ExecutedTasks) != 2 || len(res.Commits) != 2 {
		t.Fatalf("expected 2 completed tasks and 2 commits, got %+v", res)
	}
}

func startC24ReleaseServer(t *testing.T, artifactName string, payload []byte, checksum *string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/checksums.txt":
			_, _ = fmt.Fprintf(w, "%s  %s\n", *checksum, artifactName)
		case "/" + artifactName:
			_, _ = w.Write(payload)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestC24SelfHostInstallScriptSHA256(t *testing.T) {
	bashPath := findWorkingBash(t)
	if bashPath == "" {
		t.Skip("no working bash interpreter available")
	}
	scriptPath, err := filepath.Abs(filepath.Join("..", "..", "scripts", "install.sh"))
	if err != nil {
		t.Fatal(err)
	}
	ext := ""
	if runtime.GOOS == "windows" {
		ext = ".exe"
	}
	artifactName := fmt.Sprintf("rocksoul-%s-%s%s", runtime.GOOS, runtime.GOARCH, ext)
	payload := []byte("#!/bin/sh\necho rocksoul-v1.0.0\n")
	sum := sha256.Sum256(payload)
	serveChecksum := hex.EncodeToString(sum[:])
	releaseSrv := startC24ReleaseServer(t, artifactName, payload, &serveChecksum)

	runInstall := func(dir string) ([]byte, error) {
		cmd := exec.Command(bashPath, scriptPath, "--no-ww", "--dir", dir, "--version", "v1.0.0")
		cmd.Env = append(os.Environ(), "ROCKSOUL_BASE_URL="+releaseSrv.URL)
		return cmd.CombinedOutput()
	}

	okDir := t.TempDir()
	okOut, err := runInstall(okDir)
	if err != nil || !strings.Contains(string(okOut), "verified SHA-256") {
		t.Fatalf("install.sh happy path failed: err=%v\n%s", err, string(okOut))
	}
	gotBytes, err := os.ReadFile(filepath.Join(okDir, "rocksoul"+ext))
	if err != nil || !bytes.Equal(gotBytes, payload) {
		t.Fatalf("installed binary mismatch: err=%v", err)
	}

	serveChecksum = strings.Repeat("0", 64)
	badDir := t.TempDir()
	badOut, err := runInstall(badDir)
	if err == nil || !strings.Contains(string(badOut), "SHA-256 mismatch") {
		t.Fatalf("expected SHA-256 mismatch failure: err=%v\n%s", err, string(badOut))
	}
	if _, statErr := os.Stat(filepath.Join(badDir, "rocksoul"+ext)); !os.IsNotExist(statErr) {
		t.Fatalf("binary must not be installed on SHA-256 mismatch")
	}
}
