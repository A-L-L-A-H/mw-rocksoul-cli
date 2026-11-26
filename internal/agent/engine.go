package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// --- Session Store & Lifecycle Operations ---

// CreateSession persists a new coding agent session.
func (e *Engine) CreateSession(ctx context.Context, input SessionCreateInput) (Session, error) {
	workDir := strings.TrimSpace(input.WorkDir)
	if workDir == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return Session{}, fmt.Errorf("resolve working directory: %w", err)
		}
		workDir = cwd
	}
	absWorkDir, err := filepath.Abs(workDir)
	if err != nil {
		return Session{}, fmt.Errorf("resolve workDir %q: %w", workDir, err)
	}
	absWorkDir = filepath.Clean(absWorkDir)

	mode, err := normalizeMode(input.Mode)
	if err != nil {
		return Session{}, err
	}

	profile := strings.TrimSpace(input.AgentProfile)
	if profile == "" {
		profile = e.opts.DefaultAgentProfile
	}

	title := strings.TrimSpace(input.Title)
	if title == "" {
		baseName := filepath.Base(absWorkDir)
		if baseName != "" && baseName != "." && baseName != string(filepath.Separator) {
			title = "Session: " + baseName
		} else {
			title = "New Coding Session"
		}
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	session := Session{
		ID:           generateRecordID("cs"),
		Title:        title,
		WorkDir:      absWorkDir,
		Project:      strings.TrimSpace(input.Project),
		AgentProfile: profile,
		Model:        strings.TrimSpace(input.Model),
		Mode:         mode,
		Status:       StatusIdle,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := e.store.InsertSession(ctx, session); err != nil {
		return Session{}, fmt.Errorf("insert coding session: %w", err)
	}
	return session, nil
}

// ListSessions returns persisted coding sessions ordered by most recently updated first.
func (e *Engine) ListSessions(ctx context.Context, limit int) ([]Session, error) {
	return e.store.ListSessions(ctx, limit)
}

// GetSession retrieves a single coding session by ID.
func (e *Engine) GetSession(ctx context.Context, sessionID string) (Session, error) {
	return e.store.GetSession(ctx, sessionID)
}

// ListMessages retrieves all messages for a coding session ordered by sequence ascending.
func (e *Engine) ListMessages(ctx context.Context, sessionID string) ([]Message, error) {
	return e.store.ListMessages(ctx, sessionID)
}

// GetSessionWithMessages retrieves a session along with its full ordered message history.
func (e *Engine) GetSessionWithMessages(ctx context.Context, sessionID string) (Session, []Message, error) {
	session, err := e.GetSession(ctx, sessionID)
	if err != nil {
		return Session{}, nil, err
	}
	messages, err := e.ListMessages(ctx, session.ID)
	if err != nil {
		return Session{}, nil, err
	}
	return session, messages, nil
}

// UpdateSession applies partial configuration updates to an existing coding session.
func (e *Engine) UpdateSession(ctx context.Context, sessionID string, patch SessionPatchInput) (Session, error) {
	existing, err := e.GetSession(ctx, sessionID)
	if err != nil {
		return Session{}, err
	}

	if patch.Title != nil {
		trimmedTitle := strings.TrimSpace(*patch.Title)
		if trimmedTitle != "" {
			existing.Title = trimmedTitle
		}
	}
	if patch.WorkDir != nil {
		trimmedDir := strings.TrimSpace(*patch.WorkDir)
		if trimmedDir == "" {
			return Session{}, errors.New("workDir cannot be empty")
		}
		absDir, absErr := filepath.Abs(trimmedDir)
		if absErr != nil {
			return Session{}, fmt.Errorf("resolve workDir: %w", absErr)
		}
		existing.WorkDir = filepath.Clean(absDir)
	}
	if patch.Project != nil {
		existing.Project = strings.TrimSpace(*patch.Project)
	}
	if patch.AgentProfile != nil {
		trimmedProfile := strings.TrimSpace(*patch.AgentProfile)
		if trimmedProfile != "" {
			existing.AgentProfile = trimmedProfile
		}
	}
	if patch.Model != nil {
		existing.Model = strings.TrimSpace(*patch.Model)
	}
	if patch.Mode != nil {
		normalizedMode, modeErr := normalizeMode(*patch.Mode)
		if modeErr != nil {
			return Session{}, modeErr
		}
		existing.Mode = normalizedMode
	}
	existing.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)

	if err := e.store.UpdateSession(ctx, existing); err != nil {
		return Session{}, err
	}
	return existing, nil
}

// DeleteSession aborts any running turn and removes the session and all of its messages.
func (e *Engine) DeleteSession(ctx context.Context, sessionID string) error {
	cleanID := strings.TrimSpace(sessionID)
	e.AbortSession(cleanID)
	return e.store.DeleteSession(ctx, cleanID)
}

// ForkSession creates a branched copy of an existing session and its messages up to latest (or optional upToSeq).
func (e *Engine) ForkSession(ctx context.Context, sessionID, title string, upToSeq ...int) (Session, error) {
	parent, err := e.GetSession(ctx, sessionID)
	if err != nil {
		return Session{}, err
	}
	parentMessages, err := e.ListMessages(ctx, parent.ID)
	if err != nil {
		return Session{}, err
	}

	maxSeq := 0
	if len(upToSeq) > 0 && upToSeq[0] > 0 {
		maxSeq = upToSeq[0]
	}

	copiedMessages := make([]Message, 0, len(parentMessages))
	for _, msg := range parentMessages {
		if maxSeq > 0 && msg.Seq > maxSeq {
			continue
		}
		msg.ID = generateRecordID("cm")
		copiedMessages = append(copiedMessages, msg)
	}

	forkTitle := strings.TrimSpace(title)
	if forkTitle == "" {
		forkTitle = parent.Title + " (fork)"
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	forked := Session{
		ID:           generateRecordID("cs"),
		Title:        forkTitle,
		WorkDir:      parent.WorkDir,
		Project:      parent.Project,
		AgentProfile: parent.AgentProfile,
		Model:        parent.Model,
		Mode:         parent.Mode,
		Status:       StatusIdle,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := e.store.InsertSession(ctx, forked); err != nil {
		return Session{}, fmt.Errorf("insert forked session: %w", err)
	}
	if len(copiedMessages) > 0 {
		if err := e.store.ReplaceMessages(ctx, forked.ID, copiedMessages, now); err != nil {
			return Session{}, fmt.Errorf("copy forked messages: %w", err)
		}
	}
	return forked, nil
}

// CompactSession summarizes older messages into a concise system context block while preserving recent turns cleanly.
func (e *Engine) CompactSession(ctx context.Context, sessionID string) (CompactResult, error) {
	session, err := e.GetSession(ctx, sessionID)
	if err != nil {
		return CompactResult{}, err
	}
	messages, err := e.ListMessages(ctx, session.ID)
	if err != nil {
		return CompactResult{}, err
	}

	totalCount := len(messages)
	if totalCount <= 2 {
		return CompactResult{
			Compacted:    false,
			Summary:      "Session has too few messages to compact.",
			KeptMessages: totalCount,
		}, nil
	}

	splitIdx := chooseCompactionSplitIndex(messages)
	if splitIdx < 2 {
		return CompactResult{
			Compacted:    false,
			Summary:      "No safe compaction boundary found without splitting active tool calls.",
			KeptMessages: totalCount,
		}, nil
	}

	olderMessages := messages[:splitIdx]
	recentMessages := messages[splitIdx:]
	summaryText := buildCompactionSummary(olderMessages)

	now := time.Now().UTC().Format(time.RFC3339Nano)
	summaryMsg := Message{
		ID:        generateRecordID("cm"),
		SessionID: session.ID,
		Seq:       1,
		Role:      "system",
		Content:   summaryText,
		Meta:      &MessageMeta{Compacted: true},
		CreatedAt: now,
	}

	compactedSlice := make([]Message, 0, 1+len(recentMessages))
	compactedSlice = append(compactedSlice, summaryMsg)
	compactedSlice = append(compactedSlice, recentMessages...)

	if err := e.store.ReplaceMessages(ctx, session.ID, compactedSlice, now); err != nil {
		return CompactResult{}, err
	}

	return CompactResult{
		Compacted:    true,
		Summary:      summaryText,
		KeptMessages: len(compactedSlice),
	}, nil
}

func chooseCompactionSplitIndex(messages []Message) int {
	totalCount := len(messages)
	keepTarget := 2
	if totalCount > 6 {
		keepTarget = 4
	} else if totalCount <= 3 {
		keepTarget = 1
	}

	splitIdx := totalCount - keepTarget
	// Never leave an orphaned tool response message at the beginning of the kept slice.
	for splitIdx < totalCount && messages[splitIdx].Role == "tool" {
		splitIdx++
	}
	if splitIdx >= totalCount {
		splitIdx = totalCount - keepTarget
		for splitIdx > 0 && messages[splitIdx].Role == "tool" {
			splitIdx--
		}
	}
	return splitIdx
}

func buildCompactionSummary(older []Message) string {
	var userNotes []string
	var assistantNotes []string
	var toolTrace []string

	for _, msg := range older {
		switch msg.Role {
		case "user":
			if condensed := condenseText(msg.Content, 160); condensed != "" {
				userNotes = append(userNotes, condensed)
			}
		case "assistant":
			if len(msg.ToolCalls) > 0 {
				for _, call := range msg.ToolCalls {
					toolTrace = append(toolTrace, fmt.Sprintf("%s(%s)", call.Function.Name, condenseText(call.Function.Arguments, 80)))
				}
			}
			if condensed := condenseText(msg.Content, 180); condensed != "" {
				assistantNotes = append(assistantNotes, condensed)
			}
		case "tool":
			statusTag := "ok"
			if msg.Meta != nil && msg.Meta.IsError {
				statusTag = "error"
			}
			toolTrace = append(toolTrace, fmt.Sprintf("%s -> %s: %s", msg.ToolName, statusTag, condenseText(msg.Content, 90)))
		case "system":
			if condensed := condenseText(msg.Content, 200); condensed != "" {
				assistantNotes = append(assistantNotes, condensed)
			}
		}
	}

	var summary strings.Builder
	fmt.Fprintf(&summary, "[Compacted Conversation Summary â€” %d earlier messages]\n", len(older))
	if len(userNotes) > 0 {
		summary.WriteString("User requests:\n")
		for _, note := range limitSlice(userNotes, 6) {
			fmt.Fprintf(&summary, "- %s\n", note)
		}
	}
	if len(toolTrace) > 0 {
		summary.WriteString("Tool activity:\n")
		for _, trace := range limitSlice(toolTrace, 10) {
			fmt.Fprintf(&summary, "- %s\n", trace)
		}
	}
	if len(assistantNotes) > 0 {
		summary.WriteString("Prior findings & replies:\n")
		for _, note := range limitSlice(assistantNotes, 6) {
			fmt.Fprintf(&summary, "- %s\n", note)
		}
	}
	return strings.TrimRight(summary.String(), "\n")
}

func condenseText(raw string, maxChars int) string {
	collapsed := strings.Join(strings.Fields(strings.TrimSpace(raw)), " ")
	if len(collapsed) <= maxChars {
		return collapsed
	}
	if maxChars <= 3 {
		return collapsed[:maxChars]
	}
	return collapsed[:maxChars-3] + "..."
}

func limitSlice(values []string, maxLen int) []string {
	if len(values) <= maxLen {
		return values
	}
	return values[len(values)-maxLen:]
}

// --- Live Event Bus & Cancellation ---

// Subscribe registers an event listener for the given sessionID.
func (e *Engine) Subscribe(sessionID string) (<-chan AgentEvent, func()) {
	cleanID := strings.TrimSpace(sessionID)
	eventCh := make(chan AgentEvent, 64)

	e.mu.Lock()
	e.nextSubID++
	subID := e.nextSubID
	if e.subscribers[cleanID] == nil {
		e.subscribers[cleanID] = make(map[uint64]chan AgentEvent)
	}
	e.subscribers[cleanID][subID] = eventCh
	e.mu.Unlock()

	var unsubscribeOnce bool
	unsubscribe := func() {
		e.mu.Lock()
		defer e.mu.Unlock()
		if unsubscribeOnce {
			return
		}
		unsubscribeOnce = true
		if listeners := e.subscribers[cleanID]; listeners != nil {
			delete(listeners, subID)
			if len(listeners) == 0 {
				delete(e.subscribers, cleanID)
			}
		}
	}
	return eventCh, unsubscribe
}

func (e *Engine) emitEvent(event AgentEvent, onEvent func(AgentEvent)) {
	if event.Timestamp == "" {
		event.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if onEvent != nil {
		onEvent(event)
	}

	e.mu.RLock()
	listeners := e.subscribers[event.SessionID]
	targets := make([]chan AgentEvent, 0, len(listeners))
	for _, listenerCh := range listeners {
		targets = append(targets, listenerCh)
	}
	e.mu.RUnlock()

	for _, listenerCh := range targets {
		select {
		case listenerCh <- event:
		default:
		}
	}
}

// AbortSession cancels any in-flight LLM request or shell command for sessionID.
func (e *Engine) AbortSession(sessionID string) bool {
	cleanID := strings.TrimSpace(sessionID)
	e.mu.Lock()
	handle, running := e.activeTurns[cleanID]
	e.mu.Unlock()
	if !running || handle.cancel == nil {
		return false
	}
	handle.cancel()
	return true
}

func (e *Engine) acquireTurn(parentCtx context.Context, sessionID string) (context.Context, func(), error) {
	cleanID := strings.TrimSpace(sessionID)
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, busy := e.activeTurns[cleanID]; busy {
		return nil, nil, ErrSessionBusy
	}
	turnCtx, cancel := context.WithCancel(parentCtx)
	e.activeTurns[cleanID] = turnHandle{cancel: cancel}
	release := func() {
		cancel()
		e.mu.Lock()
		delete(e.activeTurns, cleanID)
		e.mu.Unlock()
	}
	return turnCtx, release, nil
}

// --- ReAct Agent Execution Loop ---

// RunPrompt executes a full coding agent turn for sessionID and returns the updated session, messages, and final reply.
func (e *Engine) RunPrompt(ctx context.Context, sessionID, prompt string) (TurnResult, error) {
	return e.RunPromptWithCallback(ctx, sessionID, prompt, nil)
}

// RunPromptWithCallback executes a prompt turn while streaming AgentEvents to onEvent and subscribers.
func (e *Engine) RunPromptWithCallback(ctx context.Context, sessionID, prompt string, onEvent func(AgentEvent)) (TurnResult, error) {
	turnCtx, release, err := e.acquireTurn(ctx, sessionID)
	if err != nil {
		return TurnResult{}, err
	}
	defer release()
	if session, getErr := e.GetSession(ctx, sessionID); getErr == nil && session.Mode == ModeAct && !strings.HasPrefix(strings.TrimSpace(prompt), "/") {
		_, _ = CreateCheckpoint(ctx, session.WorkDir, truncateCheckpointLabel(prompt))
	}
	return e.executeAcquiredTurn(turnCtx, sessionID, prompt, onEvent)
}

// StartPromptAsync reserves the session turn synchronously and launches execution in a background goroutine.
func (e *Engine) StartPromptAsync(sessionID, prompt string) error {
	if _, err := e.GetSession(context.Background(), sessionID); err != nil {
		return err
	}
	if strings.TrimSpace(prompt) == "" {
		return errors.New("prompt is required")
	}
	turnCtx, release, err := e.acquireTurn(context.Background(), sessionID)
	if err != nil {
		return err
	}
	go func() {
		defer release()
		_, _ = e.executeAcquiredTurn(turnCtx, sessionID, prompt, nil)
	}()
	return nil
}

// RunOneShot creates an ephemeral session and runs a single coding agent prompt for CLI workflows (`rocksoul run`).
func (e *Engine) RunOneShot(ctx context.Context, workDir, agentProfile, model, mode, prompt string, onEvent func(AgentEvent)) (string, error) {
	trimmedPrompt := strings.TrimSpace(prompt)
	if trimmedPrompt == "" {
		return "", errors.New("prompt is required")
	}
	session, err := e.CreateSession(ctx, SessionCreateInput{
		Title:        condenseText(trimmedPrompt, 64),
		WorkDir:      workDir,
		AgentProfile: agentProfile,
		Model:        model,
		Mode:         mode,
	})
	if err != nil {
		return "", err
	}
	outcome, err := e.RunPromptWithCallback(ctx, session.ID, trimmedPrompt, onEvent)
	if err != nil {
		return outcome.Reply, err
	}
	return outcome.Reply, nil
}

func (e *Engine) executeAcquiredTurn(turnCtx context.Context, sessionID, rawPrompt string, onEvent func(AgentEvent)) (TurnResult, error) {
	trimmedPrompt := strings.TrimSpace(rawPrompt)
	if trimmedPrompt == "" {
		return TurnResult{}, errors.New("prompt is required")
	}

	session, err := e.GetSession(turnCtx, sessionID)
	if err != nil {
		return TurnResult{}, err
	}

	// Handle built-in slash commands (/plan, /act, /compact).
	handled, commandResult, nextPrompt, session, slashErr := e.handleSlashCommand(turnCtx, session, trimmedPrompt, onEvent)
	if slashErr != nil {
		return TurnResult{}, slashErr
	}
	if handled {
		return commandResult, nil
	}
	trimmedPrompt = nextPrompt

	if err := e.setSessionStatus(context.Background(), session.ID, StatusRunning); err != nil {
		return TurnResult{}, err
	}
	session.Status = StatusRunning

	userMsg, err := e.appendMessage(context.Background(), session.ID, Message{
		Role:    "user",
		Content: trimmedPrompt,
	})
	if err != nil {
		_ = e.setSessionStatus(context.Background(), session.ID, StatusError)
		return TurnResult{}, err
	}
	if strings.HasPrefix(session.Title, "Session:") || session.Title == "New Coding Session" {
		if userMsg.Seq == 1 {
			derivedTitle := condenseText(trimmedPrompt, 64)
			if derivedTitle != "" {
				session.Title = derivedTitle
				_, _ = e.UpdateSession(context.Background(), session.ID, SessionPatchInput{Title: &derivedTitle})
			}
		}
	}

	e.emitEvent(AgentEvent{
		Type:      "turn_start",
		SessionID: session.ID,
		Mode:      session.Mode,
		Message:   &userMsg,
	}, onEvent)

	toolSchemas := e.openAIToolSchemas()
	finalReply := ""
	executedSteps := 0

	for step := 1; step <= e.opts.MaxSteps; step++ {
		if turnCtx.Err() != nil {
			return e.finishAbortedTurn(session.ID, executedSteps, onEvent)
		}

		executedSteps = step
		e.emitEvent(AgentEvent{
			Type:      "step",
			SessionID: session.ID,
			Step:      step,
			Mode:      session.Mode,
		}, onEvent)

		history, histErr := e.ListMessages(turnCtx, session.ID)
		if histErr != nil {
			return e.finishErroredTurn(session.ID, executedSteps, histErr, onEvent)
		}

		gatewayMessages := buildGatewayMessages(session, history)
		completion, gwMeta, callErr := e.callGatewayCompletion(turnCtx, session, gatewayMessages, toolSchemas)
		if callErr != nil {
			if errors.Is(turnCtx.Err(), context.Canceled) || errors.Is(callErr, context.Canceled) {
				return e.finishAbortedTurn(session.ID, executedSteps, onEvent)
			}
			return e.finishErroredTurn(session.ID, executedSteps, callErr, onEvent)
		}

		if err := e.addSessionTelemetry(context.Background(), session.ID, int64(gwMeta.TokensIn), int64(gwMeta.TokensOut), int64(gwMeta.RTKTokensSaved)); err != nil {
			return e.finishErroredTurn(session.ID, executedSteps, err, onEvent)
		}

		gwMeta.Step = step
		assistantText := completion.Content
		assistantCalls := completion.ToolCalls

		assistantMsg, appendErr := e.appendMessage(context.Background(), session.ID, Message{
			Role:      "assistant",
			Content:   assistantText,
			ToolCalls: assistantCalls,
			Meta:      &gwMeta,
		})
		if appendErr != nil {
			return e.finishErroredTurn(session.ID, executedSteps, appendErr, onEvent)
		}

		e.emitEvent(AgentEvent{
			Type:           "assistant_message",
			SessionID:      session.ID,
			Step:           step,
			Role:           "assistant",
			Content:        assistantText,
			Message:        &assistantMsg,
			Reply:          assistantText,
			Provider:       gwMeta.Provider,
			Model:          gwMeta.Model,
			Cache:          gwMeta.Cache,
			RTKSaved:       gwMeta.RTKTokensSaved,
			RTKTokensSaved: gwMeta.RTKTokensSaved,
			TokensIn:       gwMeta.TokensIn,
			TokensOut:      gwMeta.TokensOut,
			Mode:           session.Mode,
		}, onEvent)

		if len(assistantCalls) == 0 {
			finalReply = assistantText
			if err := e.setSessionStatus(context.Background(), session.ID, StatusIdle); err != nil {
				return TurnResult{}, err
			}
			updatedSession, updatedMessages, loadErr := e.GetSessionWithMessages(context.Background(), session.ID)
			if loadErr != nil {
				return TurnResult{}, loadErr
			}
			e.emitEvent(AgentEvent{
				Type:           "turn_end",
				SessionID:      session.ID,
				Step:           step,
				Role:           "assistant",
				Content:        finalReply,
				Reply:          finalReply,
				Provider:       gwMeta.Provider,
				Model:          gwMeta.Model,
				Cache:          gwMeta.Cache,
				RTKSaved:       gwMeta.RTKTokensSaved,
				RTKTokensSaved: gwMeta.RTKTokensSaved,
				TokensIn:       gwMeta.TokensIn,
				TokensOut:      gwMeta.TokensOut,
				Mode:           updatedSession.Mode,
			}, onEvent)
			return TurnResult{
				Session:  updatedSession,
				Messages: updatedMessages,
				Reply:    finalReply,
				Steps:    executedSteps,
			}, nil
		}

		for _, call := range assistantCalls {
			if turnCtx.Err() != nil {
				return e.finishAbortedTurn(session.ID, executedSteps, onEvent)
			}

			callCopy := call
			e.emitEvent(AgentEvent{
				Type:       "tool_call",
				SessionID:  session.ID,
				Step:       step,
				Role:       "assistant",
				ToolCall:   &callCopy,
				ToolCallID: call.ID,
				ToolName:   call.Function.Name,
				Arguments:  call.Function.Arguments,
				Content:    call.Function.Arguments,
				Mode:       session.Mode,
			}, onEvent)

			toolStarted := time.Now()
			toolOutput, riskTier, toolErr := e.executeToolWithMeta(turnCtx, session, call.Function.Name, call.Function.Arguments)
			durationMS := time.Since(toolStarted).Milliseconds()

			if errors.Is(turnCtx.Err(), context.Canceled) || errors.Is(toolErr, context.Canceled) {
				return e.finishAbortedTurn(session.ID, executedSteps, onEvent)
			}

			isToolErr := false
			if toolErr != nil {
				isToolErr = true
				toolOutput = "ERROR: " + toolErr.Error()
				var blockedErr *RiskBlockedError
				if errors.As(toolErr, &blockedErr) {
					e.emitEvent(AgentEvent{
						Type:       "risk_blocked",
						SessionID:  session.ID,
						Step:       step,
						ToolCallID: call.ID,
						ToolName:   call.Function.Name,
						RiskTier:   blockedErr.Decision.TierLabel,
						Error:      blockedErr.Error(),
						Mode:       session.Mode,
					}, onEvent)
				}
			}

			toolMsg, saveToolErr := e.appendMessage(context.Background(), session.ID, Message{
				Role:       "tool",
				Content:    toolOutput,
				ToolCallID: call.ID,
				ToolName:   call.Function.Name,
				Meta: &MessageMeta{
					Step:       step,
					DurationMS: durationMS,
					IsError:    isToolErr,
					RiskTier:   riskTier,
				},
			})
			if saveToolErr != nil {
				return e.finishErroredTurn(session.ID, executedSteps, saveToolErr, onEvent)
			}

			e.emitEvent(AgentEvent{
				Type:       "tool_result",
				SessionID:  session.ID,
				Step:       step,
				Role:       "tool",
				ToolCall:   &callCopy,
				ToolCallID: call.ID,
				ToolName:   call.Function.Name,
				Output:     toolOutput,
				ToolOutput: toolOutput,
				Content:    toolOutput,
				Message:    &toolMsg,
				RiskTier:   riskTier,
				Mode:       session.Mode,
			}, onEvent)
		}
	}

	finalReply = fmt.Sprintf("Reached maximum step limit (%d steps) before final assistant response.", e.opts.MaxSteps)
	wrapMsg, _ := e.appendMessage(context.Background(), session.ID, Message{
		Role:    "assistant",
		Content: finalReply,
		Meta:    &MessageMeta{Step: executedSteps},
	})
	_ = e.setSessionStatus(context.Background(), session.ID, StatusIdle)
	updatedSession, updatedMessages, loadErr := e.GetSessionWithMessages(context.Background(), session.ID)
	if loadErr != nil {
		return TurnResult{}, loadErr
	}
	e.emitEvent(AgentEvent{
		Type:      "turn_end",
		SessionID: session.ID,
		Step:      executedSteps,
		Message:   &wrapMsg,
		Reply:     finalReply,
		Mode:      updatedSession.Mode,
	}, onEvent)

	return TurnResult{
		Session:  updatedSession,
		Messages: updatedMessages,
		Reply:    finalReply,
		Steps:    executedSteps,
	}, nil
}

func (e *Engine) handleSlashCommand(ctx context.Context, session Session, prompt string, onEvent func(AgentEvent)) (bool, TurnResult, string, Session, error) {
	if !strings.HasPrefix(prompt, "/") {
		return false, TurnResult{}, prompt, session, nil
	}

	fields := strings.Fields(prompt)
	if len(fields) == 0 {
		return false, TurnResult{}, prompt, session, nil
	}
	cmd := strings.ToLower(fields[0])
	remainder := strings.TrimSpace(strings.TrimPrefix(prompt, fields[0]))

	switch cmd {
	case "/plan", "/act":
		targetMode := ModeAct
		if cmd == "/plan" {
			targetMode = ModePlan
		}
		updated, err := e.UpdateSession(ctx, session.ID, SessionPatchInput{Mode: &targetMode})
		if err != nil {
			return false, TurnResult{}, "", session, err
		}
		if remainder != "" {
			return false, TurnResult{}, remainder, updated, nil
		}

		ackReply := "Switched session to act mode (full tool access enabled)."
		if targetMode == ModePlan {
			ackReply = "Switched session to plan mode (read-only: write_file, edit_file, and run_shell are blocked)."
		}
		userMsg, err := e.appendMessage(ctx, updated.ID, Message{Role: "user", Content: prompt})
		if err != nil {
			return false, TurnResult{}, "", updated, err
		}
		e.emitEvent(AgentEvent{Type: "turn_start", SessionID: updated.ID, Mode: updated.Mode, Message: &userMsg}, onEvent)
		ackMsg, err := e.appendMessage(ctx, updated.ID, Message{Role: "assistant", Content: ackReply})
		if err != nil {
			return false, TurnResult{}, "", updated, err
		}
		e.emitEvent(AgentEvent{Type: "assistant_message", SessionID: updated.ID, Role: "assistant", Mode: updated.Mode, Message: &ackMsg, Content: ackReply, Reply: ackReply}, onEvent)
		e.emitEvent(AgentEvent{Type: "turn_end", SessionID: updated.ID, Role: "assistant", Mode: updated.Mode, Content: ackReply, Reply: ackReply}, onEvent)

		latestSession, latestMsgs, err := e.GetSessionWithMessages(ctx, updated.ID)
		if err != nil {
			return false, TurnResult{}, "", updated, err
		}
		return true, TurnResult{Session: latestSession, Messages: latestMsgs, Reply: ackReply}, "", latestSession, nil

	case "/compact":
		e.emitEvent(AgentEvent{Type: "turn_start", SessionID: session.ID, Mode: session.Mode}, onEvent)
		compacted, err := e.CompactSession(ctx, session.ID)
		if err != nil {
			return false, TurnResult{}, "", session, err
		}
		ackReply := fmt.Sprintf("Compacted session history (%d messages kept).\n%s", compacted.KeptMessages, compacted.Summary)
		if !compacted.Compacted {
			ackReply = compacted.Summary
		}
		e.emitEvent(AgentEvent{Type: "assistant_message", SessionID: session.ID, Role: "assistant", Mode: session.Mode, Content: ackReply, Reply: ackReply}, onEvent)
		e.emitEvent(AgentEvent{Type: "turn_end", SessionID: session.ID, Role: "assistant", Mode: session.Mode, Content: ackReply, Reply: ackReply}, onEvent)

		latestSession, latestMsgs, err := e.GetSessionWithMessages(ctx, session.ID)
		if err != nil {
			return false, TurnResult{}, "", session, err
		}
		return true, TurnResult{Session: latestSession, Messages: latestMsgs, Reply: ackReply}, "", latestSession, nil

	default:
		return false, TurnResult{}, prompt, session, nil
	}
}

func (e *Engine) finishAbortedTurn(sessionID string, steps int, onEvent func(AgentEvent)) (TurnResult, error) {
	_ = e.setSessionStatus(context.Background(), sessionID, StatusAborted)
	session, messages, _ := e.GetSessionWithMessages(context.Background(), sessionID)
	e.emitEvent(AgentEvent{
		Type:      "aborted",
		SessionID: sessionID,
		Step:      steps,
		Mode:      session.Mode,
		Error:     "turn aborted",
	}, onEvent)
	return TurnResult{
		Session:  session,
		Messages: messages,
		Steps:    steps,
		Aborted:  true,
	}, context.Canceled
}

func (e *Engine) finishErroredTurn(sessionID string, steps int, turnErr error, onEvent func(AgentEvent)) (TurnResult, error) {
	_ = e.setSessionStatus(context.Background(), sessionID, StatusError)
	session, messages, _ := e.GetSessionWithMessages(context.Background(), sessionID)
	e.emitEvent(AgentEvent{
		Type:      "error",
		SessionID: sessionID,
		Step:      steps,
		Mode:      session.Mode,
		Error:     turnErr.Error(),
	}, onEvent)
	return TurnResult{
		Session:  session,
		Messages: messages,
		Steps:    steps,
	}, turnErr
}

func (e *Engine) setSessionStatus(ctx context.Context, sessionID, status string) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	return e.store.SetStatus(ctx, sessionID, status, now)
}

func (e *Engine) addSessionTelemetry(ctx context.Context, sessionID string, tokensIn, tokensOut, rtkSaved int64) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	return e.store.AddTelemetry(ctx, sessionID, tokensIn, tokensOut, rtkSaved, now)
}

func (e *Engine) appendMessage(ctx context.Context, sessionID string, msg Message) (Message, error) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	msg.ID = generateRecordID("cm")
	msg.SessionID = sessionID
	msg.CreatedAt = now
	return e.store.AppendMessage(ctx, sessionID, msg)
}

// --- OpenAI AI Gateway Wire Transport ---

type gatewayChatMessage struct {
	Role       string     `json:"role"`
	Content    any        `json:"content"`
	Name       string     `json:"name,omitempty"`
	ToolCallID string     `json:"tool_call_id,omitempty"`
	ToolCalls  []ToolCall `json:"tool_calls,omitempty"`
}

type gatewayCompletionRequest struct {
	Model      string               `json:"model"`
	Messages   []gatewayChatMessage `json:"messages"`
	Tools      []map[string]any     `json:"tools,omitempty"`
	ToolChoice string               `json:"tool_choice,omitempty"`
}

type parsedAssistantTurn struct {
	Content   string
	ToolCalls []ToolCall
}

func buildSystemPrompt(session Session) string {
	modeNote := "ACT mode (workspace read, write, edit, symbols, and shell tools are subject to R0-R4 risk policy)."
	if strings.EqualFold(session.Mode, ModePlan) {
		modeNote = "PLAN mode (read-only analysis: write_file, edit_file, and run_shell are blocked)."
	}
	return fmt.Sprintf(
		"You are Rocksoul Coding Agent operating inside workspace %q in %s "+
			"Inspect relevant files before modifying them, make minimal verified edits within the workspace sandbox, "+
			"and provide concise technical answers citing exact file paths.",
		session.WorkDir, modeNote,
	)
}

func buildGatewayMessages(session Session, history []Message) []gatewayChatMessage {
	outbound := make([]gatewayChatMessage, 0, len(history)+1)
	outbound = append(outbound, gatewayChatMessage{
		Role:    "system",
		Content: buildSystemPrompt(session),
	})
	for _, msg := range history {
		wire := gatewayChatMessage{
			Role:       msg.Role,
			Content:    msg.Content,
			ToolCallID: msg.ToolCallID,
			ToolCalls:  msg.ToolCalls,
		}
		if msg.Role == "tool" && msg.ToolName != "" {
			wire.Name = msg.ToolName
		}
		outbound = append(outbound, wire)
	}
	return outbound
}

func firstNonEmptyHeader(headers http.Header, keys ...string) string {
	for _, key := range keys {
		if val := strings.TrimSpace(headers.Get(key)); val != "" {
			return val
		}
	}
	return ""
}

func (e *Engine) callGatewayCompletion(
	ctx context.Context,
	session Session,
	messages []gatewayChatMessage,
	toolSchemas []map[string]any,
) (parsedAssistantTurn, MessageMeta, error) {
	targetModel := strings.TrimSpace(session.Model)
	if targetModel == "" {
		targetModel = "auto"
	}

	reqBody := gatewayCompletionRequest{
		Model:      targetModel,
		Messages:   messages,
		Tools:      toolSchemas,
		ToolChoice: "auto",
	}
	encodedReq, err := json.Marshal(reqBody)
	if err != nil {
		return parsedAssistantTurn{}, MessageMeta{}, fmt.Errorf("marshal gateway request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, e.opts.DefaultGatewayURL, bytes.NewReader(encodedReq))
	if err != nil {
		return parsedAssistantTurn{}, MessageMeta{}, fmt.Errorf("create gateway HTTP request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	agentProfile := strings.TrimSpace(session.AgentProfile)
	if agentProfile == "" {
		agentProfile = e.opts.DefaultAgentProfile
	}
	httpReq.Header.Set(headerAgentProfile, agentProfile)
	if e.opts.AuthToken != "" {
		httpReq.Header.Set("Authorization", "Bearer "+e.opts.AuthToken)
	}
	if e.opts.DataClassification != "" {
		httpReq.Header.Set(headerDataClassification, e.opts.DataClassification)
	}

	httpResp, err := e.httpClient.Do(httpReq)
	if err != nil {
		return parsedAssistantTurn{}, MessageMeta{}, fmt.Errorf("gateway request failed: %w", err)
	}
	defer httpResp.Body.Close()

	respBody, readErr := io.ReadAll(io.LimitReader(httpResp.Body, 16*1024*1024))
	if readErr != nil {
		return parsedAssistantTurn{}, MessageMeta{}, fmt.Errorf("read gateway response: %w", readErr)
	}
	if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
		return parsedAssistantTurn{}, MessageMeta{}, fmt.Errorf("gateway HTTP %d: %s", httpResp.StatusCode, condenseText(string(respBody), 300))
	}

	var envelope struct {
		Model   string `json:"model"`
		Choices []struct {
			Message struct {
				Role         string            `json:"role"`
				Content      any               `json:"content"`
				ToolCalls    []ToolCall        `json:"tool_calls"`
				FunctionCall *ToolCallFunction `json:"function_call"`
			} `json:"message"`
			FinishReason string `json:"finish_reason"`
		} `json:"choices"`
		Usage struct {
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(respBody, &envelope); err != nil {
		return parsedAssistantTurn{}, MessageMeta{}, fmt.Errorf("decode gateway response JSON: %w", err)
	}
	if len(envelope.Choices) == 0 {
		return parsedAssistantTurn{}, MessageMeta{}, errors.New("gateway returned empty choices array")
	}

	primaryMsg := envelope.Choices[0].Message
	textReply := extractContentText(primaryMsg.Content)

	parsedCalls := make([]ToolCall, 0, len(primaryMsg.ToolCalls))
	for idx, call := range primaryMsg.ToolCalls {
		cleanName := strings.TrimSpace(call.Function.Name)
		if cleanName == "" {
			continue
		}
		if strings.TrimSpace(call.ID) == "" {
			call.ID = fmt.Sprintf("call_%d_%s", idx+1, generateRecordID("tc"))
		}
		if strings.TrimSpace(call.Type) == "" {
			call.Type = "function"
		}
		call.Function.Name = cleanName
		parsedCalls = append(parsedCalls, call)
	}

	if len(parsedCalls) == 0 && primaryMsg.FunctionCall != nil && strings.TrimSpace(primaryMsg.FunctionCall.Name) != "" {
		parsedCalls = append(parsedCalls, ToolCall{
			ID:       generateRecordID("call"),
			Type:     "function",
			Function: *primaryMsg.FunctionCall,
		})
	}

	rtkSaved, _ := strconv.Atoi(firstNonEmptyHeader(httpResp.Header, headerRocksoulRTKSaved, headerEchoRTKSaved))
	resolvedModel := firstNonEmptyHeader(httpResp.Header, headerRocksoulModel, headerEchoModel)
	if resolvedModel == "" {
		resolvedModel = strings.TrimSpace(envelope.Model)
	}

	meta := MessageMeta{
		Provider:       firstNonEmptyHeader(httpResp.Header, headerRocksoulProvider, headerEchoProvider),
		Model:          resolvedModel,
		Cache:          firstNonEmptyHeader(httpResp.Header, headerRocksoulCache, headerEchoCache),
		RTKTokensSaved: rtkSaved,
		TokensIn:       envelope.Usage.PromptTokens,
		TokensOut:      envelope.Usage.CompletionTokens,
	}

	return parsedAssistantTurn{
		Content:   textReply,
		ToolCalls: parsedCalls,
	}, meta, nil
}

func extractContentText(rawContent any) string {
	switch typedVal := rawContent.(type) {
	case nil:
		return ""
	case string:
		return typedVal
	case []any:
		parts := make([]string, 0, len(typedVal))
		for _, block := range typedVal {
			blockMap, ok := block.(map[string]any)
			if !ok {
				continue
			}
			if textStr, hasText := blockMap["text"].(string); hasText && textStr != "" {
				parts = append(parts, textStr)
			}
		}
		return strings.Join(parts, "\n")
	default:
		encoded, err := json.Marshal(typedVal)
		if err != nil {
			return ""
		}
		return string(encoded)
	}
}
