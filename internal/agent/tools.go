package agent

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/A-L-L-A-H/mw-rocksoul-cli/internal/risk"
)

const (
	maxReadLinesPerCall = 400
	maxReadFileBytes    = 4 * 1024 * 1024
	maxGrepFileBytes    = 2 * 1024 * 1024
	defaultGrepMaxHits  = 50
	hardGrepMaxHits     = 200
	defaultListDepth    = 2
	hardListDepth       = 5
	hardListEntries     = 300
	defaultShellTimeout = 30
	hardShellTimeout    = 120
	maxShellOutputBytes = 12 * 1024
)

var skippedDirectoryNames = map[string]bool{
	".git":         true,
	"node_modules": true,
	"dist":         true,
	"target":       true,
	"vendor":       true,
}

// RiskBlockedError signals that a tool call was denied by the R0-R4 Risk Gate.
type RiskBlockedError struct {
	Action   risk.Action
	Decision risk.Decision
}

func (err *RiskBlockedError) Error() string {
	return fmt.Sprintf("blocked by risk gate (%s): %s", err.Decision.TierLabel, err.Decision.Reason)
}

// ToolSpecs returns the canonical OpenAI-compatible tool specifications exposed by Rocksoul.
func (e *Engine) ToolSpecs() []ToolSpec {
	specs := []ToolSpec{
		{
			Name:        "read_file",
			Description: "Read a text file inside the workspace with 1-based line numbers (capped at 400 lines per read).",
			ReadOnly:    true,
			Parameters: map[string]any{
				"type":     "object",
				"required": []string{"path"},
				"properties": map[string]any{
					"path":       map[string]any{"type": "string", "description": "Workspace-relative file path to read."},
					"start_line": map[string]any{"type": "integer", "description": "Optional 1-based starting line number."},
					"end_line":   map[string]any{"type": "integer", "description": "Optional 1-based inclusive ending line number."},
				},
			},
		},
		{
			Name:        "write_file",
			Description: "Create or overwrite a file inside the workspace, creating parent directories automatically. Blocked in plan mode.",
			ReadOnly:    false,
			Parameters: map[string]any{
				"type":     "object",
				"required": []string{"path", "content"},
				"properties": map[string]any{
					"path":    map[string]any{"type": "string", "description": "Workspace-relative file path to write."},
					"content": map[string]any{"type": "string", "description": "Full file contents to write."},
				},
			},
		},
		{
			Name:        "edit_file",
			Description: "Replace an exact target snippet inside an existing workspace file and return a unified diff preview. Blocked in plan mode.",
			ReadOnly:    false,
			Parameters: map[string]any{
				"type":     "object",
				"required": []string{"path", "target", "replacement"},
				"properties": map[string]any{
					"path":        map[string]any{"type": "string", "description": "Workspace-relative file path to edit."},
					"target":      map[string]any{"type": "string", "description": "Exact unique substring to locate in the file."},
					"replacement": map[string]any{"type": "string", "description": "Replacement text for the matched target snippet."},
				},
			},
		},
		{
			Name:        "list_dir",
			Description: "List files and subdirectories inside the workspace, skipping .git, node_modules, dist, target, and vendor.",
			ReadOnly:    true,
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"path":  map[string]any{"type": "string", "description": "Optional workspace-relative directory path (defaults to workspace root)."},
					"depth": map[string]any{"type": "integer", "description": "Optional traversal depth (1-5, default 2)."},
				},
			},
		},
		{
			Name:        "grep_search",
			Description: "Search workspace text files using a regular expression or substring and return relPath:line:text matches.",
			ReadOnly:    true,
			Parameters: map[string]any{
				"type":     "object",
				"required": []string{"pattern"},
				"properties": map[string]any{
					"pattern":     map[string]any{"type": "string", "description": "Regular expression or literal substring to search for."},
					"path":        map[string]any{"type": "string", "description": "Optional workspace-relative file or directory path to scope search."},
					"max_results": map[string]any{"type": "integer", "description": "Maximum matches to return (default 50, max 200)."},
				},
			},
		},
		{
			Name:        "search_symbols",
			Description: "Index and search code declarations (Go, TypeScript, JavaScript, Rust, Python) across the workspace.",
			ReadOnly:    true,
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"query": map[string]any{"type": "string", "description": "Case-insensitive symbol substring filter."},
					"limit": map[string]any{"type": "integer", "description": "Maximum declarations to return (default 50, max 200)."},
				},
			},
		},
		{
			Name:        "run_shell",
			Description: "Execute a shell command inside the workspace directory (capped at 30s default, max 120s, 12KB output). Blocked in plan mode.",
			ReadOnly:    false,
			Parameters: map[string]any{
				"type":     "object",
				"required": []string{"command"},
				"properties": map[string]any{
					"command":     map[string]any{"type": "string", "description": "Shell command to execute."},
					"timeout_sec": map[string]any{"type": "integer", "description": "Optional timeout in seconds (default 30, max 120)."},
				},
			},
		},
	}

	if e.opts.MCPCaller != nil {
		specs = append(specs, ToolSpec{
			Name:        "mcp_call",
			Description: "Invoke a remote tool exposed by mw-rocksoul-mcp (R3 remote egress gated).",
			ReadOnly:    false,
			Parameters: map[string]any{
				"type":     "object",
				"required": []string{"name"},
				"properties": map[string]any{
					"name":      map[string]any{"type": "string", "description": "MCP tool name to execute."},
					"arguments": map[string]any{"type": "object", "description": "Optional JSON object arguments for the MCP tool."},
				},
			},
		})
	}
	return specs
}

func (e *Engine) openAIToolSchemas() []map[string]any {
	specs := e.ToolSpecs()
	schemas := make([]map[string]any, 0, len(specs))
	for _, spec := range specs {
		schemas = append(schemas, map[string]any{
			"type": "function",
			"function": map[string]any{
				"name":        spec.Name,
				"description": spec.Description,
				"parameters":  spec.Parameters,
			},
		})
	}
	return schemas
}

// resolveSafePath canonicalizes workDir and targetPath, ensuring the resolved path cannot escape workDir.
func resolveSafePath(workDir, targetPath string) (string, error) {
	trimmedRoot := strings.TrimSpace(workDir)
	if trimmedRoot == "" {
		return "", errors.New("workspace directory is required")
	}
	if strings.ContainsRune(targetPath, 0) {
		return "", errors.New("path contains invalid null byte")
	}

	absRoot, err := filepath.Abs(trimmedRoot)
	if err != nil {
		return "", fmt.Errorf("resolve workspace root: %w", err)
	}
	canonicalRoot := filepath.Clean(absRoot)
	if resolvedRoot, symErr := filepath.EvalSymlinks(canonicalRoot); symErr == nil {
		canonicalRoot = filepath.Clean(resolvedRoot)
	}

	trimmedTarget := strings.TrimSpace(targetPath)
	if trimmedTarget == "" || trimmedTarget == "." {
		return canonicalRoot, nil
	}

	// Reject POSIX-style root absolute paths on Windows (e.g. "/etc/passwd") that filepath.IsAbs treats as relative.
	if runtime.GOOS == "windows" && strings.HasPrefix(trimmedTarget, "/") {
		return "", fmt.Errorf("path %q escapes workspace root", targetPath)
	}

	var candidatePath string
	if filepath.IsAbs(trimmedTarget) {
		candidatePath = filepath.Clean(trimmedTarget)
	} else {
		candidatePath = filepath.Clean(filepath.Join(canonicalRoot, trimmedTarget))
	}

	if err := ensureWithinRoot(canonicalRoot, candidatePath, targetPath); err != nil {
		return "", err
	}

	resolvedCandidate, err := resolveThroughExistingAncestor(candidatePath)
	if err != nil {
		return "", err
	}
	if err := ensureWithinRoot(canonicalRoot, resolvedCandidate, targetPath); err != nil {
		return "", err
	}

	return resolvedCandidate, nil
}

func ensureWithinRoot(canonicalRoot, candidatePath, rawTarget string) error {
	relPath, err := filepath.Rel(canonicalRoot, candidatePath)
	if err != nil {
		return fmt.Errorf("path %q escapes workspace root", rawTarget)
	}
	if relPath == ".." || strings.HasPrefix(relPath, ".."+string(filepath.Separator)) || filepath.IsAbs(relPath) {
		return fmt.Errorf("path %q escapes workspace root", rawTarget)
	}
	return nil
}

func resolveThroughExistingAncestor(targetPath string) (string, error) {
	probe := filepath.Clean(targetPath)
	var trailingParts []string
	for {
		if _, err := os.Lstat(probe); err == nil {
			resolvedAnchor, symErr := filepath.EvalSymlinks(probe)
			if symErr != nil {
				return filepath.Clean(targetPath), nil
			}
			fullPath := resolvedAnchor
			for idx := len(trailingParts) - 1; idx >= 0; idx-- {
				fullPath = filepath.Join(fullPath, trailingParts[idx])
			}
			return filepath.Clean(fullPath), nil
		}
		parent := filepath.Dir(probe)
		if parent == probe {
			return filepath.Clean(targetPath), nil
		}
		trailingParts = append(trailingParts, filepath.Base(probe))
		probe = parent
	}
}

// ExecuteTool dispatches a single named coding tool under workspace sandbox, mode policy, and R0-R4 risk gate.
func (e *Engine) ExecuteTool(ctx context.Context, session Session, toolName, rawArgs string) (string, error) {
	output, _, err := e.executeToolWithMeta(ctx, session, toolName, rawArgs)
	return output, err
}

func (e *Engine) checkRiskGate(ctx context.Context, action risk.Action) (string, error) {
	tier, _ := risk.Classify(action)
	if e.opts.RiskGate == nil {
		return tier.String(), nil
	}
	decision := e.opts.RiskGate.Evaluate(action, "")
	if decision.Allowed {
		return decision.TierLabel, nil
	}
	if decision.RequiresApproval && e.opts.ApprovalResolver != nil {
		token, resolveErr := e.opts.ApprovalResolver(ctx, action, decision)
		if resolveErr != nil {
			return decision.TierLabel, &RiskBlockedError{Action: action, Decision: decision}
		}
		if strings.TrimSpace(token) != "" {
			reDecision := e.opts.RiskGate.Evaluate(action, token)
			if reDecision.Allowed {
				return reDecision.TierLabel, nil
			}
			return reDecision.TierLabel, &RiskBlockedError{Action: action, Decision: reDecision}
		}
	}
	return decision.TierLabel, &RiskBlockedError{Action: action, Decision: decision}
}

func (e *Engine) executeToolWithMeta(ctx context.Context, session Session, toolName, rawArgs string) (string, string, error) {
	cleanName := strings.TrimSpace(toolName)
	if strings.EqualFold(session.Mode, ModePlan) {
		switch cleanName {
		case "write_file", "edit_file", "run_shell", "mcp_call":
			return "", "", fmt.Errorf("blocked in plan mode: %s is disabled while mode=plan; switch to /act to modify workspace or run shell commands", cleanName)
		}
	}

	trimmedArgs := strings.TrimSpace(rawArgs)
	if trimmedArgs == "" {
		trimmedArgs = "{}"
	}

	switch cleanName {
	case "read_file":
		var args struct {
			Path      string `json:"path"`
			StartLine int    `json:"start_line"`
			EndLine   int    `json:"end_line"`
		}
		if err := json.Unmarshal([]byte(trimmedArgs), &args); err != nil {
			return "", "", fmt.Errorf("invalid read_file arguments: %w", err)
		}
		tierLabel, gateErr := e.checkRiskGate(ctx, risk.Action{Tool: cleanName, Path: args.Path, WorkDir: session.WorkDir})
		if gateErr != nil {
			return "", tierLabel, gateErr
		}
		out, err := executeReadFile(session.WorkDir, args.Path, args.StartLine, args.EndLine)
		return out, tierLabel, err

	case "write_file":
		var args struct {
			Path    string `json:"path"`
			Content string `json:"content"`
		}
		if err := json.Unmarshal([]byte(trimmedArgs), &args); err != nil {
			return "", "", fmt.Errorf("invalid write_file arguments: %w", err)
		}
		tierLabel, gateErr := e.checkRiskGate(ctx, risk.Action{Tool: cleanName, Path: args.Path, WorkDir: session.WorkDir})
		if gateErr != nil {
			return "", tierLabel, gateErr
		}
		out, err := executeWriteFile(session.WorkDir, args.Path, args.Content)
		return out, tierLabel, err

	case "edit_file":
		var args struct {
			Path        string `json:"path"`
			Target      string `json:"target"`
			Replacement string `json:"replacement"`
		}
		if err := json.Unmarshal([]byte(trimmedArgs), &args); err != nil {
			return "", "", fmt.Errorf("invalid edit_file arguments: %w", err)
		}
		tierLabel, gateErr := e.checkRiskGate(ctx, risk.Action{Tool: cleanName, Path: args.Path, WorkDir: session.WorkDir})
		if gateErr != nil {
			return "", tierLabel, gateErr
		}
		out, err := executeEditFile(session.WorkDir, args.Path, args.Target, args.Replacement)
		return out, tierLabel, err

	case "list_dir":
		var args struct {
			Path  string `json:"path"`
			Depth int    `json:"depth"`
		}
		if err := json.Unmarshal([]byte(trimmedArgs), &args); err != nil {
			return "", "", fmt.Errorf("invalid list_dir arguments: %w", err)
		}
		tierLabel, gateErr := e.checkRiskGate(ctx, risk.Action{Tool: cleanName, Path: args.Path, WorkDir: session.WorkDir})
		if gateErr != nil {
			return "", tierLabel, gateErr
		}
		out, err := executeListDir(session.WorkDir, args.Path, args.Depth)
		return out, tierLabel, err

	case "grep_search":
		var args struct {
			Pattern    string `json:"pattern"`
			Path       string `json:"path"`
			MaxResults int    `json:"max_results"`
		}
		if err := json.Unmarshal([]byte(trimmedArgs), &args); err != nil {
			return "", "", fmt.Errorf("invalid grep_search arguments: %w", err)
		}
		tierLabel, gateErr := e.checkRiskGate(ctx, risk.Action{Tool: cleanName, Path: args.Path, WorkDir: session.WorkDir})
		if gateErr != nil {
			return "", tierLabel, gateErr
		}
		out, err := executeGrepSearch(ctx, session.WorkDir, args.Pattern, args.Path, args.MaxResults)
		return out, tierLabel, err

	case "search_symbols":
		var args struct {
			Query string `json:"query"`
			Limit int    `json:"limit"`
		}
		if err := json.Unmarshal([]byte(trimmedArgs), &args); err != nil {
			return "", "", fmt.Errorf("invalid search_symbols arguments: %w", err)
		}
		tierLabel, gateErr := e.checkRiskGate(ctx, risk.Action{Tool: cleanName, WorkDir: session.WorkDir})
		if gateErr != nil {
			return "", tierLabel, gateErr
		}
		out, err := executeSearchSymbols(session.WorkDir, args.Query, args.Limit)
		return out, tierLabel, err

	case "run_shell":
		var args struct {
			Command    string `json:"command"`
			TimeoutSec int    `json:"timeout_sec"`
		}
		if err := json.Unmarshal([]byte(trimmedArgs), &args); err != nil {
			return "", "", fmt.Errorf("invalid run_shell arguments: %w", err)
		}
		tierLabel, gateErr := e.checkRiskGate(ctx, risk.Action{Tool: cleanName, Command: args.Command, WorkDir: session.WorkDir})
		if gateErr != nil {
			return "", tierLabel, gateErr
		}
		out, err := executeRunShell(ctx, session.WorkDir, args.Command, args.TimeoutSec)
		return out, tierLabel, err

	case "mcp_call":
		if e.opts.MCPCaller == nil {
			return "", "", errors.New("mcp_call is unavailable: no MCP client configured")
		}
		var args struct {
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments"`
		}
		if err := json.Unmarshal([]byte(trimmedArgs), &args); err != nil {
			return "", "", fmt.Errorf("invalid mcp_call arguments: %w", err)
		}
		if strings.TrimSpace(args.Name) == "" {
			return "", "", errors.New("mcp_call requires name")
		}
		tierLabel, gateErr := e.checkRiskGate(ctx, risk.Action{Tool: cleanName, RemoteTarget: args.Name, WorkDir: session.WorkDir})
		if gateErr != nil {
			return "", tierLabel, gateErr
		}
		out, err := e.opts.MCPCaller.CallTool(ctx, args.Name, args.Arguments)
		return out, tierLabel, err

	default:
		return "", "", fmt.Errorf("unknown tool %q", cleanName)
	}
}

func executeReadFile(workDir, targetPath string, startLine, endLine int) (string, error) {
	if strings.TrimSpace(targetPath) == "" {
		return "", errors.New("path is required")
	}
	safePath, err := resolveSafePath(workDir, targetPath)
	if err != nil {
		return "", err
	}
	statInfo, err := os.Stat(safePath)
	if err != nil {
		return "", fmt.Errorf("stat %s: %w", targetPath, err)
	}
	if statInfo.IsDir() {
		return "", fmt.Errorf("%s is a directory; use list_dir instead", targetPath)
	}
	if statInfo.Size() > maxReadFileBytes {
		return "", fmt.Errorf("%s exceeds max readable size (%d bytes)", targetPath, maxReadFileBytes)
	}

	rawBytes, err := os.ReadFile(safePath)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", targetPath, err)
	}
	if looksBinary(rawBytes) {
		return "", fmt.Errorf("%s appears to be a binary file (%d bytes)", targetPath, len(rawBytes))
	}

	normalizedText := strings.ReplaceAll(string(rawBytes), "\r\n", "\n")
	allLines := strings.Split(normalizedText, "\n")
	if len(allLines) > 0 && allLines[len(allLines)-1] == "" {
		allLines = allLines[:len(allLines)-1]
	}

	relDisplay := relativeDisplayPath(workDir, safePath)
	totalLines := len(allLines)
	if totalLines == 0 {
		return fmt.Sprintf("File: %s (empty, 0 lines)", relDisplay), nil
	}

	if startLine <= 0 {
		startLine = 1
	}
	if startLine > totalLines {
		return "", fmt.Errorf("start_line %d exceeds total lines (%d) in %s", startLine, totalLines, relDisplay)
	}

	effectiveEnd := endLine
	if effectiveEnd <= 0 || effectiveEnd > totalLines {
		effectiveEnd = totalLines
	}
	if effectiveEnd < startLine {
		return "", fmt.Errorf("end_line %d is less than start_line %d", effectiveEnd, startLine)
	}

	truncated := false
	if effectiveEnd-startLine+1 > maxReadLinesPerCall {
		effectiveEnd = startLine + maxReadLinesPerCall - 1
		truncated = true
	}

	var out strings.Builder
	fmt.Fprintf(&out, "File: %s (lines %d-%d of %d)\n", relDisplay, startLine, effectiveEnd, totalLines)
	for lineNo := startLine; lineNo <= effectiveEnd; lineNo++ {
		fmt.Fprintf(&out, "%4d | %s\n", lineNo, allLines[lineNo-1])
	}
	if truncated {
		fmt.Fprintf(&out, "... (truncated at %d lines; call read_file with start_line=%d to continue)", maxReadLinesPerCall, effectiveEnd+1)
	}
	return strings.TrimRight(out.String(), "\n"), nil
}

func executeWriteFile(workDir, targetPath, content string) (string, error) {
	if strings.TrimSpace(targetPath) == "" {
		return "", errors.New("path is required")
	}
	safePath, err := resolveSafePath(workDir, targetPath)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(safePath), 0o755); err != nil {
		return "", fmt.Errorf("create parent directories: %w", err)
	}
	if err := os.WriteFile(safePath, []byte(content), 0o644); err != nil {
		return "", fmt.Errorf("write %s: %w", targetPath, err)
	}

	lineCount := 0
	if content != "" {
		lineCount = strings.Count(content, "\n") + 1
		if strings.HasSuffix(content, "\n") {
			lineCount--
		}
	}
	relDisplay := relativeDisplayPath(workDir, safePath)
	return fmt.Sprintf("Wrote %s (%d bytes, %d lines)", relDisplay, len(content), lineCount), nil
}

func executeEditFile(workDir, targetPath, target, replacement string) (string, error) {
	if strings.TrimSpace(targetPath) == "" {
		return "", errors.New("path is required")
	}
	if target == "" {
		return "", errors.New("target snippet must not be empty")
	}
	safePath, err := resolveSafePath(workDir, targetPath)
	if err != nil {
		return "", err
	}
	rawBytes, err := os.ReadFile(safePath)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", targetPath, err)
	}

	originalText := string(rawBytes)
	effectiveTarget := target
	effectiveReplacement := replacement

	matchCount := strings.Count(originalText, effectiveTarget)
	if matchCount == 0 && strings.Contains(originalText, "\r\n") && !strings.Contains(target, "\r\n") {
		crlfTarget := strings.ReplaceAll(target, "\n", "\r\n")
		if crlfCount := strings.Count(originalText, crlfTarget); crlfCount > 0 {
			effectiveTarget = crlfTarget
			effectiveReplacement = strings.ReplaceAll(replacement, "\n", "\r\n")
			matchCount = crlfCount
		}
	}

	relDisplay := relativeDisplayPath(workDir, safePath)
	if matchCount == 0 {
		return "", fmt.Errorf("target snippet not found in %s", relDisplay)
	}
	if matchCount > 1 {
		return "", fmt.Errorf("target snippet matched %d times in %s; provide more surrounding context for a unique match", matchCount, relDisplay)
	}

	matchIdx := strings.Index(originalText, effectiveTarget)
	updatedText := originalText[:matchIdx] + effectiveReplacement + originalText[matchIdx+len(effectiveTarget):]
	if err := os.WriteFile(safePath, []byte(updatedText), 0o644); err != nil {
		return "", fmt.Errorf("write edited %s: %w", relDisplay, err)
	}

	diffSnippet := buildUnifiedSnippet(relDisplay, originalText, updatedText, matchIdx, effectiveTarget, effectiveReplacement)
	return fmt.Sprintf("Edited %s (%d bytes -> %d bytes)\n%s", relDisplay, len(originalText), len(updatedText), diffSnippet), nil
}

func buildUnifiedSnippet(relPath, originalText, updatedText string, matchIdx int, target, replacement string) string {
	prefix := strings.ReplaceAll(originalText[:matchIdx], "\r\n", "\n")
	startLine := strings.Count(prefix, "\n") + 1

	oldLines := splitLinesForDiff(target)
	newLines := splitLinesForDiff(replacement)
	allOrigLines := strings.Split(strings.ReplaceAll(originalText, "\r\n", "\n"), "\n")
	allNewLines := strings.Split(strings.ReplaceAll(updatedText, "\r\n", "\n"), "\n")

	ctxBefore := startLine - 3
	if ctxBefore < 1 {
		ctxBefore = 1
	}

	var diffBuf strings.Builder
	fmt.Fprintf(&diffBuf, "--- a/%s\n+++ b/%s\n@@ -%d,%d +%d,%d @@\n",
		relPath, relPath, startLine, len(oldLines), startLine, len(newLines))

	for lineNo := ctxBefore; lineNo < startLine && lineNo <= len(allOrigLines); lineNo++ {
		fmt.Fprintf(&diffBuf, " %s\n", allOrigLines[lineNo-1])
	}
	for _, oldLine := range oldLines {
		fmt.Fprintf(&diffBuf, "-%s\n", oldLine)
	}
	for _, newLine := range newLines {
		fmt.Fprintf(&diffBuf, "+%s\n", newLine)
	}

	afterStart := startLine + len(newLines)
	for offset := 0; offset < 2; offset++ {
		lineNo := afterStart + offset
		if lineNo >= 1 && lineNo <= len(allNewLines) {
			fmt.Fprintf(&diffBuf, " %s\n", allNewLines[lineNo-1])
		}
	}
	return strings.TrimRight(diffBuf.String(), "\n")
}

func splitLinesForDiff(snippet string) []string {
	normalized := strings.ReplaceAll(snippet, "\r\n", "\n")
	parts := strings.Split(normalized, "\n")
	if len(parts) > 1 && parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}
	return parts
}

func executeListDir(workDir, targetPath string, depth int) (string, error) {
	if depth <= 0 {
		depth = defaultListDepth
	}
	if depth > hardListDepth {
		depth = hardListDepth
	}
	safeDir, err := resolveSafePath(workDir, targetPath)
	if err != nil {
		return "", err
	}
	statInfo, err := os.Stat(safeDir)
	if err != nil {
		return "", fmt.Errorf("stat directory %s: %w", targetPath, err)
	}
	if !statInfo.IsDir() {
		return "", fmt.Errorf("%s is not a directory", targetPath)
	}

	type dirListingRow struct {
		relPath string
		isDir   bool
		size    int64
	}
	entries := make([]dirListingRow, 0, 64)
	truncated := false

	walkErr := filepath.WalkDir(safeDir, func(currentPath string, entry fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if currentPath == safeDir {
			return nil
		}
		relToBase, relErr := filepath.Rel(safeDir, currentPath)
		if relErr != nil {
			return nil
		}
		slashRel := filepath.ToSlash(relToBase)
		currentDepth := strings.Count(slashRel, "/") + 1

		if entry.IsDir() {
			if skippedDirectoryNames[entry.Name()] {
				return filepath.SkipDir
			}
			if len(entries) >= hardListEntries {
				truncated = true
				return filepath.SkipAll
			}
			entries = append(entries, dirListingRow{relPath: slashRel + "/", isDir: true})
			if currentDepth >= depth {
				return filepath.SkipDir
			}
			return nil
		}

		if currentDepth > depth {
			return nil
		}
		if len(entries) >= hardListEntries {
			truncated = true
			return filepath.SkipAll
		}
		var fileSize int64
		if info, infoErr := entry.Info(); infoErr == nil {
			fileSize = info.Size()
		}
		entries = append(entries, dirListingRow{relPath: slashRel, isDir: false, size: fileSize})
		return nil
	})
	if walkErr != nil {
		return "", walkErr
	}

	sort.Slice(entries, func(left, right int) bool {
		return entries[left].relPath < entries[right].relPath
	})

	relHeader := relativeDisplayPath(workDir, safeDir)
	var out strings.Builder
	fmt.Fprintf(&out, "Directory: %s (depth=%d, entries=%d)\n", relHeader, depth, len(entries))
	for _, row := range entries {
		if row.isDir {
			fmt.Fprintf(&out, "%s\n", row.relPath)
		} else {
			fmt.Fprintf(&out, "%s (%d B)\n", row.relPath, row.size)
		}
	}
	if len(entries) == 0 {
		out.WriteString("(empty directory)\n")
	}
	if truncated {
		fmt.Fprintf(&out, "... (truncated at %d entries)", hardListEntries)
	}
	return strings.TrimRight(out.String(), "\n"), nil
}

func executeGrepSearch(ctx context.Context, workDir, pattern, targetPath string, maxResults int) (string, error) {
	if strings.TrimSpace(pattern) == "" {
		return "", errors.New("pattern is required")
	}
	if maxResults <= 0 {
		maxResults = defaultGrepMaxHits
	}
	if maxResults > hardGrepMaxHits {
		maxResults = hardGrepMaxHits
	}

	safeTarget, err := resolveSafePath(workDir, targetPath)
	if err != nil {
		return "", err
	}

	matcher, err := regexp.Compile(pattern)
	if err != nil {
		matcher = regexp.MustCompile(regexp.QuoteMeta(pattern))
	}

	statInfo, err := os.Stat(safeTarget)
	if err != nil {
		return "", fmt.Errorf("stat %s: %w", targetPath, err)
	}

	matches := make([]string, 0, minInt(maxResults, 64))
	scanFile := func(filePath string) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		info, statErr := os.Stat(filePath)
		if statErr != nil || info.IsDir() || info.Size() > maxGrepFileBytes {
			return nil
		}
		fileHandle, openErr := os.Open(filePath)
		if openErr != nil {
			return nil
		}
		defer fileHandle.Close()

		probeBuf := make([]byte, 512)
		probeLen, _ := fileHandle.Read(probeBuf)
		if looksBinary(probeBuf[:probeLen]) {
			return nil
		}
		if _, seekErr := fileHandle.Seek(0, io.SeekStart); seekErr != nil {
			return nil
		}

		relDisplay := relativeDisplayPath(workDir, filePath)
		scanner := bufio.NewScanner(fileHandle)
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		lineNo := 0
		for scanner.Scan() {
			lineNo++
			lineText := scanner.Text()
			if matcher.MatchString(lineText) {
				trimmedLine := strings.TrimRight(lineText, "\r")
				if len(trimmedLine) > 400 {
					trimmedLine = trimmedLine[:400] + "..."
				}
				matches = append(matches, fmt.Sprintf("%s:%d:%s", relDisplay, lineNo, trimmedLine))
				if len(matches) >= maxResults {
					return filepath.SkipAll
				}
			}
		}
		return nil
	}

	if !statInfo.IsDir() {
		if err := scanFile(safeTarget); err != nil && !errors.Is(err, filepath.SkipAll) {
			return "", err
		}
	} else {
		walkErr := filepath.WalkDir(safeTarget, func(currentPath string, entry fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if entry.IsDir() {
				if currentPath != safeTarget && skippedDirectoryNames[entry.Name()] {
					return filepath.SkipDir
				}
				return nil
			}
			return scanFile(currentPath)
		})
		if walkErr != nil && !errors.Is(walkErr, filepath.SkipAll) {
			return "", walkErr
		}
	}

	if len(matches) == 0 {
		return fmt.Sprintf("No matches for %q", pattern), nil
	}
	return strings.Join(matches, "\n"), nil
}

func executeRunShell(ctx context.Context, workDir, command string, timeoutSec int) (string, error) {
	trimmedCmd := strings.TrimSpace(command)
	if trimmedCmd == "" {
		return "", errors.New("command is required")
	}
	safeWorkDir, err := resolveSafePath(workDir, ".")
	if err != nil {
		return "", err
	}

	if timeoutSec <= 0 {
		timeoutSec = defaultShellTimeout
	}
	if timeoutSec > hardShellTimeout {
		timeoutSec = hardShellTimeout
	}

	cmdCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSec)*time.Second)
	defer cancel()

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(cmdCtx, "powershell", "-NoProfile", "-NonInteractive", "-Command", trimmedCmd)
	} else {
		cmd = exec.CommandContext(cmdCtx, "sh", "-c", trimmedCmd)
	}
	cmd.Dir = safeWorkDir

	outputSink := &cappedBuffer{limit: maxShellOutputBytes}
	cmd.Stdout = outputSink
	cmd.Stderr = outputSink

	runErr := cmd.Run()
	exitCode := 0
	timedOut := false
	if runErr != nil {
		if errors.Is(cmdCtx.Err(), context.DeadlineExceeded) {
			timedOut = true
			exitCode = -1
		} else if errors.Is(ctx.Err(), context.Canceled) {
			return "", context.Canceled
		} else {
			var exitErr *exec.ExitError
			if errors.As(runErr, &exitErr) {
				exitCode = exitErr.ExitCode()
			} else {
				exitCode = -1
			}
		}
	}

	var report strings.Builder
	fmt.Fprintf(&report, "exit_code: %d\n", exitCode)
	if timedOut {
		fmt.Fprintf(&report, "timed_out: true (limit %ds)\n", timeoutSec)
	}
	captured := strings.TrimSpace(outputSink.String())
	if captured != "" {
		report.WriteString(captured)
	} else {
		report.WriteString("(no output)")
	}
	if outputSink.truncated {
		fmt.Fprintf(&report, "\n... (output truncated at %d bytes)", maxShellOutputBytes)
	}
	return report.String(), nil
}

type cappedBuffer struct {
	buf       bytes.Buffer
	limit     int
	truncated bool
}

func (c *cappedBuffer) Write(chunk []byte) (int, error) {
	remaining := c.limit - c.buf.Len()
	if remaining <= 0 {
		c.truncated = true
		return len(chunk), nil
	}
	if len(chunk) > remaining {
		_, _ = c.buf.Write(chunk[:remaining])
		c.truncated = true
		return len(chunk), nil
	}
	_, _ = c.buf.Write(chunk)
	return len(chunk), nil
}

func (c *cappedBuffer) String() string {
	return c.buf.String()
}

func looksBinary(sample []byte) bool {
	checkLen := len(sample)
	if checkLen > 512 {
		checkLen = 512
	}
	for idx := 0; idx < checkLen; idx++ {
		if sample[idx] == 0 {
			return true
		}
	}
	return false
}

func relativeDisplayPath(workDir, resolvedPath string) string {
	absRoot, err := filepath.Abs(workDir)
	if err != nil {
		return filepath.ToSlash(resolvedPath)
	}
	canonicalRoot := filepath.Clean(absRoot)
	if symRoot, symErr := filepath.EvalSymlinks(canonicalRoot); symErr == nil {
		canonicalRoot = filepath.Clean(symRoot)
	}
	relPath, relErr := filepath.Rel(canonicalRoot, resolvedPath)
	if relErr != nil || relPath == "." {
		return "."
	}
	return filepath.ToSlash(relPath)
}

func minInt(left, right int) int {
	if left < right {
		return left
	}
	return right
}
