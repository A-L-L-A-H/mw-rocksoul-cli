package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/A-L-L-A-H/mw-rocksoul-cli/internal/risk"
)

func makeCompletionPayload(modelName, content string, toolCalls []ToolCall, promptTok, completionTok int) map[string]any {
	msgObj := map[string]any{
		"role":    "assistant",
		"content": content,
	}
	if len(toolCalls) > 0 {
		msgObj["tool_calls"] = toolCalls
	}
	return map[string]any{
		"id":      "chatcmpl_mock",
		"object":  "chat.completion",
		"created": time.Now().UTC().Unix(),
		"model":   modelName,
		"choices": []map[string]any{
			{
				"index":         0,
				"message":       msgObj,
				"finish_reason": "stop",
			},
		},
		"usage": map[string]int{
			"prompt_tokens":     promptTok,
			"completion_tokens": completionTok,
			"total_tokens":      promptTok + completionTok,
		},
	}
}

func TestReActMultiTurnToolLoopAndGatewayHeaders(t *testing.T) {
	workDir := t.TempDir()

	mainPath := filepath.Join(workDir, "app.go")
	if err := os.WriteFile(mainPath, []byte("package main\n\nconst Greeting = \"hello\"\n"), 0o644); err != nil {
		t.Fatalf("seed app.go: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(workDir, ".git"), 0o755); err != nil {
		t.Fatalf("seed .git: %v", err)
	}
	if err := os.WriteFile(filepath.Join(workDir, ".git", "HEAD"), []byte("ref: refs/heads/main\n"), 0o644); err != nil {
		t.Fatalf("seed .git/HEAD: %v", err)
	}

	var stepCounter atomic.Int32
	var seenAgentHeaders []string
	var seenAuthHeader string
	var headerMu sync.Mutex

	mockGateway := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, req *http.Request) {
		headerMu.Lock()
		seenAgentHeaders = append(seenAgentHeaders, req.Header.Get(headerAgentProfile))
		seenAuthHeader = req.Header.Get("Authorization")
		headerMu.Unlock()

		var decodedReq struct {
			Model    string           `json:"model"`
			Messages []map[string]any `json:"messages"`
			Tools    []map[string]any `json:"tools"`
		}
		if err := json.NewDecoder(req.Body).Decode(&decodedReq); err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		if len(decodedReq.Tools) < 7 {
			http.Error(writer, "expected at least 7 tool definitions", http.StatusBadRequest)
			return
		}

		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set(headerRocksoulProvider, "rocksoul-local")
		writer.Header().Set(headerRocksoulModel, "mock-coder-1")
		writer.Header().Set(headerRocksoulCache, "MISS")
		writer.Header().Set(headerRocksoulRTKSaved, "42")

		turnNum := stepCounter.Add(1)
		switch turnNum {
		case 1:
			_ = json.NewEncoder(writer).Encode(makeCompletionPayload("mock-coder-1", "", []ToolCall{
				{
					ID:   "call_list_1",
					Type: "function",
					Function: ToolCallFunction{
						Name:      "list_dir",
						Arguments: `{"path":"."}`,
					},
				},
			}, 120, 25))
		case 2:
			_ = json.NewEncoder(writer).Encode(makeCompletionPayload("mock-coder-1", "", []ToolCall{
				{
					ID:   "call_read_2",
					Type: "function",
					Function: ToolCallFunction{
						Name:      "read_file",
						Arguments: `{"path":"app.go"}`,
					},
				},
			}, 160, 20))
		case 3:
			_ = json.NewEncoder(writer).Encode(makeCompletionPayload("mock-coder-1", "", []ToolCall{
				{
					ID:   "call_edit_3",
					Type: "function",
					Function: ToolCallFunction{
						Name:      "edit_file",
						Arguments: `{"path":"app.go","target":"const Greeting = \"hello\"","replacement":"const Greeting = \"hello world\""}`,
					},
				},
			}, 210, 35))
		default:
			_ = json.NewEncoder(writer).Encode(makeCompletionPayload("mock-coder-1", "Updated Greeting constant in app.go.", nil, 250, 18))
		}
	}))
	defer mockGateway.Close()

	gate := risk.NewGate(risk.Policy{MaxAutoTier: risk.TierR1, BlockR4WithoutToken: true, AllowR4OverrideToken: true})
	engine, err := NewEngine(Options{
		DefaultGatewayURL: mockGateway.URL + "/v1/chat/completions",
		AuthToken:         "rid-test-jwt",
		HTTPClient:        mockGateway.Client(),
		RiskGate:          gate,
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	var observedTypes []string
	reply, err := engine.RunOneShot(context.Background(), workDir, "", "", ModeAct, "Update Greeting in app.go", func(ev AgentEvent) {
		observedTypes = append(observedTypes, ev.Type)
	})
	if err != nil {
		t.Fatalf("RunOneShot failed: %v", err)
	}
	if reply != "Updated Greeting constant in app.go." {
		t.Fatalf("unexpected final reply: %q", reply)
	}

	updatedBytes, err := os.ReadFile(mainPath)
	if err != nil {
		t.Fatalf("read mutated app.go: %v", err)
	}
	if !strings.Contains(string(updatedBytes), `const Greeting = "hello world"`) {
		t.Fatalf("app.go was not updated: %s", string(updatedBytes))
	}

	headerMu.Lock()
	if len(seenAgentHeaders) != 4 {
		t.Fatalf("expected 4 gateway calls, got %d", len(seenAgentHeaders))
	}
	for idx, headerVal := range seenAgentHeaders {
		if headerVal != DefaultAgentProfile {
			t.Fatalf("call %d expected X-MW-Agent=%q, got %q", idx+1, DefaultAgentProfile, headerVal)
		}
	}
	if seenAuthHeader != "Bearer rid-test-jwt" {
		t.Fatalf("expected Bearer auth header, got %q", seenAuthHeader)
	}
	headerMu.Unlock()

	sessions, err := engine.ListSessions(context.Background(), 10)
	if err != nil || len(sessions) != 1 {
		t.Fatalf("expected 1 persisted session, got %d (err=%v)", len(sessions), err)
	}
	sess := sessions[0]
	if sess.TotalTokensIn != 120+160+210+250 {
		t.Fatalf("expected TotalTokensIn=740, got %d", sess.TotalTokensIn)
	}
	if sess.TotalTokensOut != 25+20+35+18 {
		t.Fatalf("expected TotalTokensOut=98, got %d", sess.TotalTokensOut)
	}
	if sess.RTKTokensSaved != 42*4 {
		t.Fatalf("expected RTKTokensSaved=168, got %d", sess.RTKTokensSaved)
	}

	messages, err := engine.ListMessages(context.Background(), sess.ID)
	if err != nil {
		t.Fatalf("ListMessages: %v", err)
	}
	foundListTool := false
	for _, msg := range messages {
		if msg.Role == "tool" && msg.ToolName == "list_dir" {
			foundListTool = true
			if strings.Contains(msg.Content, ".git") {
				t.Fatalf("list_dir should skip .git, got: %s", msg.Content)
			}
			if !strings.Contains(msg.Content, "app.go") {
				t.Fatalf("list_dir should contain app.go, got: %s", msg.Content)
			}
		}
	}
	if !foundListTool {
		t.Fatalf("expected persisted list_dir tool message")
	}

	joinedEvents := strings.Join(observedTypes, ",")
	for _, requiredEvent := range []string{"turn_start", "step", "tool_call", "tool_result", "assistant_message", "turn_end"} {
		if !strings.Contains(joinedEvents, requiredEvent) {
			t.Fatalf("expected event %q in stream: %s", requiredEvent, joinedEvents)
		}
	}
}

func TestPlanModeBlocksMutatingToolsAndAllowsReadOnly(t *testing.T) {
	workDir := t.TempDir()
	sampleFile := filepath.Join(workDir, "notes.txt")
	if err := os.WriteFile(sampleFile, []byte("alpha\nbeta needle\ngamma\n"), 0o644); err != nil {
		t.Fatalf("seed notes.txt: %v", err)
	}

	engine, err := NewEngine(Options{})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	session, err := engine.CreateSession(context.Background(), SessionCreateInput{
		Title:   "Plan Verification",
		WorkDir: workDir,
		Mode:    ModePlan,
	})
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	if _, err := engine.ExecuteTool(context.Background(), session, "write_file", `{"path":"new.txt","content":"nope"}`); err == nil || !strings.Contains(err.Error(), "plan mode") {
		t.Fatalf("expected write_file to be blocked in plan mode, got err=%v", err)
	}
	if _, err := engine.ExecuteTool(context.Background(), session, "edit_file", `{"path":"notes.txt","target":"alpha","replacement":"ALPHA"}`); err == nil || !strings.Contains(err.Error(), "plan mode") {
		t.Fatalf("expected edit_file to be blocked in plan mode, got err=%v", err)
	}
	if _, err := engine.ExecuteTool(context.Background(), session, "run_shell", `{"command":"echo blocked"}`); err == nil || !strings.Contains(err.Error(), "plan mode") {
		t.Fatalf("expected run_shell to be blocked in plan mode, got err=%v", err)
	}

	readOut, err := engine.ExecuteTool(context.Background(), session, "read_file", `{"path":"notes.txt","start_line":1,"end_line":3}`)
	if err != nil || !strings.Contains(readOut, "beta needle") {
		t.Fatalf("expected read_file to succeed in plan mode, out=%q err=%v", readOut, err)
	}
	grepOut, err := engine.ExecuteTool(context.Background(), session, "grep_search", `{"pattern":"needle"}`)
	if err != nil || !strings.Contains(grepOut, "notes.txt:2:beta needle") {
		t.Fatalf("expected grep_search to succeed in plan mode, out=%q err=%v", grepOut, err)
	}

	actOutcome, err := engine.RunPrompt(context.Background(), session.ID, "/act")
	if err != nil || actOutcome.Session.Mode != ModeAct {
		t.Fatalf("expected /act slash command to switch mode to act, got mode=%q err=%v", actOutcome.Session.Mode, err)
	}
	planOutcome, err := engine.RunPrompt(context.Background(), session.ID, "/plan")
	if err != nil || planOutcome.Session.Mode != ModePlan {
		t.Fatalf("expected /plan slash command to switch mode to plan, got mode=%q err=%v", planOutcome.Session.Mode, err)
	}
}

func TestPathTraversalSandboxBlocksEscape(t *testing.T) {
	parentDir := t.TempDir()
	workDir := filepath.Join(parentDir, "workspace")
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		t.Fatalf("mkdir workspace: %v", err)
	}
	outsideFile := filepath.Join(parentDir, "secret.txt")
	if err := os.WriteFile(outsideFile, []byte("top-secret"), 0o644); err != nil {
		t.Fatalf("write outside secret: %v", err)
	}

	engine, err := NewEngine(Options{})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	session, err := engine.CreateSession(context.Background(), SessionCreateInput{
		WorkDir: workDir,
		Mode:    ModeAct,
	})
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	escapeTargets := []string{
		"../../etc/passwd",
		"../secret.txt",
		outsideFile,
	}
	for _, escapeTarget := range escapeTargets {
		if _, err := resolveSafePath(workDir, escapeTarget); err == nil {
			t.Fatalf("expected resolveSafePath to block %q", escapeTarget)
		}
		readArgs, _ := json.Marshal(map[string]string{"path": escapeTarget})
		if _, err := engine.ExecuteTool(context.Background(), session, "read_file", string(readArgs)); err == nil {
			t.Fatalf("expected read_file to block %q", escapeTarget)
		}
		writeArgs, _ := json.Marshal(map[string]string{"path": escapeTarget, "content": "pwn"})
		if _, err := engine.ExecuteTool(context.Background(), session, "write_file", string(writeArgs)); err == nil {
			t.Fatalf("expected write_file to block %q", escapeTarget)
		}
	}

	checkBytes, err := os.ReadFile(outsideFile)
	if err != nil || string(checkBytes) != "top-secret" {
		t.Fatalf("outside file was modified: %q err=%v", string(checkBytes), err)
	}
}

func TestForkSessionAndCompactSession(t *testing.T) {
	workDir := t.TempDir()

	var callCount atomic.Int32
	mockGateway := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, req *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		turn := callCount.Add(1)
		_ = json.NewEncoder(writer).Encode(makeCompletionPayload("mock-model", "Reply #"+string(rune('0'+turn)), nil, 50, 15))
	}))
	defer mockGateway.Close()

	engine, err := NewEngine(Options{
		DefaultGatewayURL: mockGateway.URL,
		HTTPClient:        mockGateway.Client(),
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	session, err := engine.CreateSession(context.Background(), SessionCreateInput{
		Title:   "Origin Session",
		WorkDir: workDir,
	})
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	for idx := 0; idx < 4; idx++ {
		if _, err := engine.RunPrompt(context.Background(), session.ID, "Question turn"); err != nil {
			t.Fatalf("RunPrompt %d: %v", idx+1, err)
		}
	}

	origMsgs, err := engine.ListMessages(context.Background(), session.ID)
	if err != nil || len(origMsgs) != 8 {
		t.Fatalf("expected 8 messages in origin session, got %d (err=%v)", len(origMsgs), err)
	}

	partialFork, err := engine.ForkSession(context.Background(), session.ID, "Branch At 4", 4)
	if err != nil {
		t.Fatalf("ForkSession upToSeq=4: %v", err)
	}
	partialMsgs, err := engine.ListMessages(context.Background(), partialFork.ID)
	if err != nil || len(partialMsgs) != 4 {
		t.Fatalf("expected 4 messages in partial fork, got %d (err=%v)", len(partialMsgs), err)
	}

	fullFork, err := engine.ForkSession(context.Background(), session.ID, "Full Branch")
	if err != nil {
		t.Fatalf("ForkSession full: %v", err)
	}
	fullMsgs, err := engine.ListMessages(context.Background(), fullFork.ID)
	if err != nil || len(fullMsgs) != 8 {
		t.Fatalf("expected 8 messages in full fork, got %d (err=%v)", len(fullMsgs), err)
	}

	compacted, err := engine.CompactSession(context.Background(), session.ID)
	if err != nil {
		t.Fatalf("CompactSession: %v", err)
	}
	if !compacted.Compacted || compacted.KeptMessages != 5 {
		t.Fatalf("unexpected compaction result: %+v", compacted)
	}

	afterMsgs, err := engine.ListMessages(context.Background(), session.ID)
	if err != nil || len(afterMsgs) != 5 {
		t.Fatalf("expected 5 messages after compact, got %d (err=%v)", len(afterMsgs), err)
	}
	if afterMsgs[0].Role != "system" || afterMsgs[0].Seq != 1 || afterMsgs[0].Meta == nil || !afterMsgs[0].Meta.Compacted {
		t.Fatalf("expected compacted system summary at seq 1, got %+v", afterMsgs[0])
	}

	fullMsgsAfter, err := engine.ListMessages(context.Background(), fullFork.ID)
	if err != nil || len(fullMsgsAfter) != 8 {
		t.Fatalf("expected full fork untouched with 8 messages, got %d", len(fullMsgsAfter))
	}
}

func TestRunShellSearchSymbolsAndAbort(t *testing.T) {
	workDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(workDir, "service.go"), []byte("package svc\n\nfunc ComputeDigest() string { return \"ok\" }\n"), 0o644); err != nil {
		t.Fatalf("seed service.go: %v", err)
	}

	gateEntered := make(chan struct{}, 1)
	releaseSlow := make(chan struct{})
	slowGateway := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, req *http.Request) {
		select {
		case gateEntered <- struct{}{}:
		default:
		}
		select {
		case <-req.Context().Done():
		case <-releaseSlow:
		}
	}))
	defer func() {
		close(releaseSlow)
		slowGateway.CloseClientConnections()
		slowGateway.Close()
	}()

	engine, err := NewEngine(Options{
		DefaultGatewayURL: slowGateway.URL,
		HTTPClient:        slowGateway.Client(),
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	session, err := engine.CreateSession(context.Background(), SessionCreateInput{
		WorkDir: workDir,
		Project: "rocksoul",
		Mode:    ModeAct,
	})
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	symOut, err := engine.ExecuteTool(context.Background(), session, "search_symbols", `{"query":"ComputeDigest"}`)
	if err != nil || !strings.Contains(symOut, "service.go:3 [go/func] ComputeDigest") {
		t.Fatalf("search_symbols unexpected result: out=%q err=%v", symOut, err)
	}

	shellOut, err := engine.ExecuteTool(context.Background(), session, "run_shell", `{"command":"echo rocksoul-shell-ok","timeout_sec":10}`)
	if err != nil || !strings.Contains(shellOut, "exit_code: 0") || !strings.Contains(shellOut, "rocksoul-shell-ok") {
		t.Fatalf("run_shell unexpected result: out=%q err=%v", shellOut, err)
	}

	doneErrCh := make(chan error, 1)
	go func() {
		_, runErr := engine.RunPrompt(context.Background(), session.ID, "long running turn")
		doneErrCh <- runErr
	}()

	select {
	case <-gateEntered:
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for gateway request to start")
	}

	if !engine.AbortSession(session.ID) {
		t.Fatalf("expected AbortSession to return true for active turn")
	}

	select {
	case runErr := <-doneErrCh:
		if !errors.Is(runErr, context.Canceled) {
			t.Fatalf("expected context.Canceled after abort, got %v", runErr)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for aborted turn to finish")
	}
}

func TestRiskGateEnforcedOnToolExecutionAndSingleUseToken(t *testing.T) {
	workDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(workDir, ".env"), []byte("SECRET=123\n"), 0o644); err != nil {
		t.Fatalf("seed .env: %v", err)
	}

	gate := risk.NewGate(risk.DefaultPolicy())
	var pendingToken string
	engine, err := NewEngine(Options{
		RiskGate: gate,
		ApprovalResolver: func(_ context.Context, _ risk.Action, _ risk.Decision) (string, error) {
			tok := pendingToken
			pendingToken = ""
			return tok, nil
		},
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	session, err := engine.CreateSession(context.Background(), SessionCreateInput{WorkDir: workDir, Mode: ModeAct})
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	// Protected .env read is R4 and blocked by default.
	if _, err := engine.ExecuteTool(context.Background(), session, "read_file", `{"path":".env"}`); err == nil {
		t.Fatalf("expected .env read to be blocked by R4 risk gate")
	}

	// Protected .githooks write is R4 and blocked by default.
	if _, err := engine.ExecuteTool(context.Background(), session, "write_file", `{"path":".githooks/pre-commit","content":"#!/bin/sh\n"}`); err == nil {
		t.Fatalf("expected .githooks write to be blocked by R4 risk gate")
	}

	// R1 write without token is blocked under DefaultPolicy (MaxAutoTier=R0).
	if _, err := engine.ExecuteTool(context.Background(), session, "write_file", `{"path":"ok.txt","content":"hello"}`); err == nil {
		t.Fatalf("expected write_file to be blocked under DefaultPolicy without approval token")
	}

	// Issue single-use token for ok.txt and verify it allows exactly one write.
	tok, err := gate.IssueApprovalToken(risk.Action{Tool: "write_file", Path: "ok.txt", WorkDir: workDir}, time.Minute, "test")
	if err != nil {
		t.Fatalf("IssueApprovalToken: %v", err)
	}
	pendingToken = tok.Token
	if out, err := engine.ExecuteTool(context.Background(), session, "write_file", `{"path":"ok.txt","content":"hello"}`); err != nil || !strings.Contains(out, "Wrote ok.txt") {
		t.Fatalf("expected write_file with valid single-use token to succeed, out=%q err=%v", out, err)
	}

	// Replaying the same token MUST fail.
	pendingToken = tok.Token
	if _, err := engine.ExecuteTool(context.Background(), session, "write_file", `{"path":"ok.txt","content":"replay"}`); err == nil {
		t.Fatalf("expected replayed single-use token to fail")
	}
}

func TestJSONFileStorePersistence(t *testing.T) {
	storePath := filepath.Join(t.TempDir(), "sessions.json")
	store1, err := NewJSONFileStore(storePath)
	if err != nil {
		t.Fatalf("NewJSONFileStore(1): %v", err)
	}
	engine1, err := NewEngine(Options{Store: store1})
	if err != nil {
		t.Fatalf("NewEngine(1): %v", err)
	}
	sess, err := engine1.CreateSession(context.Background(), SessionCreateInput{
		Title:   "Persisted Session",
		WorkDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if _, err := engine1.RunPrompt(context.Background(), sess.ID, "/plan"); err != nil {
		t.Fatalf("RunPrompt /plan: %v", err)
	}

	// Reload from disk into a fresh store & engine.
	store2, err := NewJSONFileStore(storePath)
	if err != nil {
		t.Fatalf("NewJSONFileStore(2): %v", err)
	}
	engine2, err := NewEngine(Options{Store: store2})
	if err != nil {
		t.Fatalf("NewEngine(2): %v", err)
	}
	loadedSess, loadedMsgs, err := engine2.GetSessionWithMessages(context.Background(), sess.ID)
	if err != nil {
		t.Fatalf("GetSessionWithMessages: %v", err)
	}
	if loadedSess.Mode != ModePlan || len(loadedMsgs) != 2 {
		t.Fatalf("unexpected reloaded session=%+v msgs=%d", loadedSess, len(loadedMsgs))
	}
}
