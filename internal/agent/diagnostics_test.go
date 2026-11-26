package agent

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestDiagnosticsCommandByExtension(t *testing.T) {
	cases := map[string]string{"a.go": "go", "b.tsx": "tsc", "c.rs": "cargo"}
	for file, want := range cases {
		name, _, ok := DiagnosticsCommand(file)
		if !ok || name != want {
			t.Fatalf("%s: got %q %v", file, name, ok)
		}
	}
	if _, _, ok := DiagnosticsCommand("x.md"); ok {
		t.Fatal("md must be unsupported")
	}
}

func TestRunDiagnosticsGoVet(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module x\n\ngo 1.24\n"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "m.go"), []byte("package x\n\nfunc F() int { return 1 }\n"), 0o644)
	result, err := RunDiagnostics(context.Background(), dir, "m.go")
	if err != nil || !result.OK {
		t.Fatalf("vet: %v %+v", err, result)
	}
	_ = os.WriteFile(filepath.Join(dir, "m.go"), []byte("package x\n\nfunc F() int { return }\n"), 0o644)
	result, _ = RunDiagnostics(context.Background(), dir, "m.go")
	if result.OK || result.Output == "" {
		t.Fatalf("expected failure: %+v", result)
	}
	if _, err := RunDiagnostics(context.Background(), dir, "x.md"); err == nil {
		t.Fatal("expected unsupported error")
	}
}
