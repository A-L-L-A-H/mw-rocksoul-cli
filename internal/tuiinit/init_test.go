package tuiinit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateAllTUIConfigs(t *testing.T) {
	workDir := t.TempDir()

	files, err := Generate(Options{
		Target: TargetAll,
		Dir:    workDir,
		Model:  "qwen2.5-coder",
	})
	if err != nil {
		t.Fatalf("Generate(all): %v", err)
	}
	if len(files) != 3 {
		t.Fatalf("expected 3 generated files, got %d", len(files))
	}

	// 1. Validate opencode.json
	ocBytes, err := os.ReadFile(filepath.Join(workDir, "opencode.json"))
	if err != nil {
		t.Fatalf("read opencode.json: %v", err)
	}
	var ocDoc map[string]any
	if err := json.Unmarshal(ocBytes, &ocDoc); err != nil {
		t.Fatalf("parse opencode.json: %v", err)
	}
	if !strings.Contains(string(ocBytes), DefaultGatewayV1URL) || !strings.Contains(string(ocBytes), DefaultMCPEndpoint) {
		t.Fatalf("opencode.json missing gateway/mcp endpoints: %s", string(ocBytes))
	}
	if !strings.Contains(string(ocBytes), "./plugins/opencode-rocksoul") {
		t.Fatalf("opencode.json missing rocksoul plugin entry: %s", string(ocBytes))
	}

	// 2. Validate .crush.json
	crushBytes, err := os.ReadFile(filepath.Join(workDir, ".crush.json"))
	if err != nil {
		t.Fatalf("read .crush.json: %v", err)
	}
	var crushDoc map[string]any
	if err := json.Unmarshal(crushBytes, &crushDoc); err != nil {
		t.Fatalf("parse .crush.json: %v", err)
	}
	if !strings.Contains(string(crushBytes), DefaultGatewayV1URL) || !strings.Contains(string(crushBytes), DefaultMCPEndpoint) {
		t.Fatalf(".crush.json missing gateway/mcp endpoints: %s", string(crushBytes))
	}

	// 3. Validate .codex/config.toml
	codexBytes, err := os.ReadFile(filepath.Join(workDir, ".codex", "config.toml"))
	if err != nil {
		t.Fatalf("read .codex/config.toml: %v", err)
	}
	codexStr := string(codexBytes)
	for _, want := range []string{
		`model_provider = "rocksoul"`,
		`model = "qwen2.5-coder"`,
		`base_url = "http://127.0.0.1:4510/v1"`,
		`url = "http://127.0.0.1:4530/mcp"`,
	} {
		if !strings.Contains(codexStr, want) {
			t.Fatalf(".codex/config.toml missing %q:\n%s", want, codexStr)
		}
	}

	// 4. Refuse overwrite without --force, allow with --force.
	if _, err := Generate(Options{Target: TargetOpenCode, Dir: workDir}); err == nil {
		t.Fatalf("expected error when overwriting without Force")
	}
	if _, err := Generate(Options{Target: TargetOpenCode, Dir: workDir, Force: true}); err != nil {
		t.Fatalf("expected Force overwrite to succeed: %v", err)
	}
}

func TestGenerateRejectsInvalidTarget(t *testing.T) {
	if _, err := Generate(Options{Target: "unknown", Dir: t.TempDir()}); err == nil {
		t.Fatalf("expected error for unsupported target")
	}
}
