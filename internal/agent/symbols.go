package agent

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const (
	defaultSymbolLimit = 50
	hardSymbolLimit    = 200
	maxSymbolFileBytes = 2 * 1024 * 1024
)

// WorkspaceSymbol represents a single indexed code declaration in the workspace.
type WorkspaceSymbol struct {
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	Language  string `json:"language"`
	FilePath  string `json:"filePath"`
	Line      int    `json:"line"`
	Signature string `json:"signature"`
}

type symbolPattern struct {
	kind  string
	regex *regexp.Regexp
}

var symbolPatternsByLang = map[string][]symbolPattern{
	"go": {
		{kind: "func", regex: regexp.MustCompile(`^\s*func\s+(?:\([^)]*\)\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*(?:\[|\()`)},
		{kind: "struct", regex: regexp.MustCompile(`^\s*type\s+([A-Za-z_][A-Za-z0-9_]*)(?:\[[^\]]*\])?\s+struct\b`)},
		{kind: "interface", regex: regexp.MustCompile(`^\s*type\s+([A-Za-z_][A-Za-z0-9_]*)(?:\[[^\]]*\])?\s+interface\b`)},
		{kind: "type", regex: regexp.MustCompile(`^\s*type\s+([A-Za-z_][A-Za-z0-9_]*)\b`)},
	},
	"ts": {
		{kind: "func", regex: regexp.MustCompile(`^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*(?:<|\()`)},
		{kind: "class", regex: regexp.MustCompile(`^\s*(?:export\s+)?(?:default\s+)?(?:abstract\s+)?class\s+([A-Za-z_$][A-Za-z0-9_$]*)\b`)},
		{kind: "interface", regex: regexp.MustCompile(`^\s*(?:export\s+)?interface\s+([A-Za-z_$][A-Za-z0-9_$]*)\b`)},
		{kind: "type", regex: regexp.MustCompile(`^\s*(?:export\s+)?type\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*(?:<|=)`)},
		{kind: "enum", regex: regexp.MustCompile(`^\s*(?:export\s+)?(?:const\s+)?enum\s+([A-Za-z_$][A-Za-z0-9_$]*)\b`)},
		{kind: "const", regex: regexp.MustCompile(`^\s*export\s+(?:const|let)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*(?::|=)`)},
	},
	"js": {
		{kind: "func", regex: regexp.MustCompile(`^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\(`)},
		{kind: "class", regex: regexp.MustCompile(`^\s*(?:export\s+)?(?:default\s+)?class\s+([A-Za-z_$][A-Za-z0-9_$]*)\b`)},
		{kind: "const", regex: regexp.MustCompile(`^\s*export\s+(?:const|let)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=`)},
	},
	"rust": {
		{kind: "func", regex: regexp.MustCompile(`^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)\b`)},
		{kind: "struct", regex: regexp.MustCompile(`^\s*(?:pub(?:\([^)]*\))?\s+)?struct\s+([A-Za-z_][A-Za-z0-9_]*)\b`)},
		{kind: "enum", regex: regexp.MustCompile(`^\s*(?:pub(?:\([^)]*\))?\s+)?enum\s+([A-Za-z_][A-Za-z0-9_]*)\b`)},
		{kind: "trait", regex: regexp.MustCompile(`^\s*(?:pub(?:\([^)]*\))?\s+)?(?:unsafe\s+)?trait\s+([A-Za-z_][A-Za-z0-9_]*)\b`)},
		{kind: "type", regex: regexp.MustCompile(`^\s*(?:pub(?:\([^)]*\))?\s+)?type\s+([A-Za-z_][A-Za-z0-9_]*)\b`)},
	},
	"python": {
		{kind: "func", regex: regexp.MustCompile(`^\s*(?:async\s+)?def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(`)},
		{kind: "class", regex: regexp.MustCompile(`^\s*class\s+([A-Za-z_][A-Za-z0-9_]*)\b`)},
	},
}

func languageForExtension(ext string) string {
	switch strings.ToLower(ext) {
	case ".go":
		return "go"
	case ".ts", ".tsx":
		return "ts"
	case ".js":
		return "js"
	case ".rs":
		return "rust"
	case ".py":
		return "python"
	default:
		return ""
	}
}

// SearchWorkspaceSymbols scans supported source files under rootDir and returns declarations
// matching query (case-insensitive substring), skipping vendor/build directories.
func SearchWorkspaceSymbols(rootDir, query string, limit int) ([]WorkspaceSymbol, error) {
	trimmedRoot := strings.TrimSpace(rootDir)
	if trimmedRoot == "" {
		return nil, errors.New("workspace root directory is required")
	}
	absRoot, err := filepath.Abs(trimmedRoot)
	if err != nil {
		return nil, fmt.Errorf("resolve workspace root: %w", err)
	}

	effectiveLimit := limit
	if effectiveLimit <= 0 {
		effectiveLimit = defaultSymbolLimit
	}
	if effectiveLimit > hardSymbolLimit {
		effectiveLimit = hardSymbolLimit
	}

	needle := strings.ToLower(strings.TrimSpace(query))
	matches := make([]WorkspaceSymbol, 0, min(effectiveLimit, 32))

	walkErr := filepath.WalkDir(absRoot, func(currentPath string, entry fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if entry.IsDir() {
			if currentPath != absRoot && skippedDirectoryNames[entry.Name()] {
				return filepath.SkipDir
			}
			return nil
		}

		lang := languageForExtension(filepath.Ext(entry.Name()))
		if lang == "" {
			return nil
		}
		info, infoErr := entry.Info()
		if infoErr != nil || info.Size() > maxSymbolFileBytes {
			return nil
		}

		relPath, relErr := filepath.Rel(absRoot, currentPath)
		if relErr != nil {
			return nil
		}
		slashRel := filepath.ToSlash(relPath)

		fileSymbols := extractFileSymbols(currentPath, slashRel, lang, needle)
		matches = append(matches, fileSymbols...)
		return nil
	})
	if walkErr != nil {
		return nil, fmt.Errorf("walk workspace symbols: %w", walkErr)
	}

	sort.Slice(matches, func(left, right int) bool {
		if matches[left].FilePath != matches[right].FilePath {
			return matches[left].FilePath < matches[right].FilePath
		}
		return matches[left].Line < matches[right].Line
	})

	if len(matches) > effectiveLimit {
		matches = matches[:effectiveLimit]
	}
	return matches, nil
}

func extractFileSymbols(absPath, relPath, lang, lowerNeedle string) []WorkspaceSymbol {
	patterns := symbolPatternsByLang[lang]
	if len(patterns) == 0 {
		return nil
	}

	fileHandle, err := os.Open(absPath)
	if err != nil {
		return nil
	}
	defer fileHandle.Close()

	var symbols []WorkspaceSymbol
	scanner := bufio.NewScanner(fileHandle)
	scanner.Buffer(make([]byte, 0, 32*1024), 512*1024)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		rawLine := scanner.Text()
		trimmedLine := strings.TrimSpace(rawLine)
		if trimmedLine == "" || strings.HasPrefix(trimmedLine, "//") || strings.HasPrefix(trimmedLine, "#") {
			continue
		}

		for _, pat := range patterns {
			groups := pat.regex.FindStringSubmatch(rawLine)
			if len(groups) < 2 {
				continue
			}
			symbolName := groups[1]
			if lowerNeedle != "" && !strings.Contains(strings.ToLower(symbolName), lowerNeedle) {
				break
			}
			signature := trimmedLine
			if len(signature) > 140 {
				signature = signature[:140] + "..."
			}
			symbols = append(symbols, WorkspaceSymbol{
				Name:      symbolName,
				Kind:      pat.kind,
				Language:  lang,
				FilePath:  relPath,
				Line:      lineNum,
				Signature: signature,
			})
			break
		}
	}
	return symbols
}

func executeSearchSymbols(workDir, query string, limit int) (string, error) {
	symbols, err := SearchWorkspaceSymbols(workDir, query, limit)
	if err != nil {
		return "", err
	}
	if len(symbols) == 0 {
		return "no matching workspace symbols found", nil
	}
	var builder strings.Builder
	for _, sym := range symbols {
		fmt.Fprintf(&builder, "%s:%d [%s/%s] %s — %s\n", sym.FilePath, sym.Line, sym.Language, sym.Kind, sym.Name, sym.Signature)
	}
	return strings.TrimRight(builder.String(), "\n"), nil
}
