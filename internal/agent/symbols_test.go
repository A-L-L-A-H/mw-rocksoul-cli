package agent_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/A-L-L-A-H/mw-rocksoul-cli/internal/agent"
)

func TestSearchWorkspaceSymbols(t *testing.T) {
	workspaceDir := t.TempDir()

	goFile := filepath.Join(workspaceDir, "example.go")
	if err := os.WriteFile(goFile, []byte(`package example

// Foo is a function declaration
func Foo(x int) string {
	return "hello"
}

// Bar is a struct declaration
type Bar struct {
	Name string
}`), 0o644); err != nil {
		t.Fatalf("write example.go: %v", err)
	}

	tsFile := filepath.Join(workspaceDir, "client.ts")
	if err := os.WriteFile(tsFile, []byte(`export interface RocksoulConfig {
  endpoint: string;
}

export async function connectGateway(): Promise<void> {}
`), 0o644); err != nil {
		t.Fatalf("write client.ts: %v", err)
	}

	symbols, err := agent.SearchWorkspaceSymbols(workspaceDir, "Foo", 50)
	if err != nil {
		t.Fatalf("SearchWorkspaceSymbols(Foo) failed: %v", err)
	}
	foundFoo := false
	for _, sym := range symbols {
		if sym.Name == "Foo" {
			foundFoo = true
			if sym.Kind != "func" || sym.Language != "go" {
				t.Fatalf("unexpected Foo symbol metadata: %+v", sym)
			}
		}
	}
	if !foundFoo {
		t.Fatalf("expected to find symbol 'Foo'")
	}

	barSymbols, err := agent.SearchWorkspaceSymbols(workspaceDir, "Bar", 50)
	if err != nil {
		t.Fatalf("SearchWorkspaceSymbols(Bar) failed: %v", err)
	}
	foundBar := false
	for _, sym := range barSymbols {
		if sym.Name == "Bar" && sym.Kind == "struct" {
			foundBar = true
		}
	}
	if !foundBar {
		t.Fatalf("expected to find struct symbol 'Bar'")
	}

	tsSymbols, err := agent.SearchWorkspaceSymbols(workspaceDir, "RocksoulConfig", 50)
	if err != nil {
		t.Fatalf("SearchWorkspaceSymbols(RocksoulConfig) failed: %v", err)
	}
	if len(tsSymbols) != 1 || tsSymbols[0].Language != "ts" || tsSymbols[0].Kind != "interface" {
		t.Fatalf("unexpected TypeScript symbol results: %+v", tsSymbols)
	}

	noneSymbols, err := agent.SearchWorkspaceSymbols(workspaceDir, "NonExistent", 50)
	if err != nil {
		t.Fatalf("SearchWorkspaceSymbols(NonExistent) failed: %v", err)
	}
	if len(noneSymbols) != 0 {
		t.Fatalf("expected 0 symbols for NonExistent, got %d", len(noneSymbols))
	}
}
