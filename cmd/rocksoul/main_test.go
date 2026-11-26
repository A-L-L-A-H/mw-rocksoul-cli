package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
