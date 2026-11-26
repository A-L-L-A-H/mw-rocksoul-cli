package agent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/A-L-L-A-H/mw-rocksoul-cli/internal/risk"
)

const (
	DefaultGatewayURL   = "http://127.0.0.1:4510/v1/chat/completions"
	DefaultAgentProfile = "rocksoul"
	DefaultMaxSteps     = 16

	ModeAct  = "act"
	ModePlan = "plan"

	StatusIdle    = "idle"
	StatusRunning = "running"
	StatusError   = "error"
	StatusAborted = "aborted"

	headerAgentProfile       = "X-MW-Agent"
	headerDataClassification = "X-Rocksoul-Data-Classification"
	headerRocksoulProvider   = "X-Rocksoul-Provider"
	headerRocksoulModel      = "X-Rocksoul-Model"
	headerRocksoulCache      = "X-Rocksoul-Cache"
	headerRocksoulRTKSaved   = "X-Rocksoul-RTK-Saved"
	headerEchoProvider       = "X-MW-Echo-Provider"
	headerEchoModel          = "X-MW-Echo-Model"
	headerEchoCache          = "X-MW-Echo-Cache"
	headerEchoRTKSaved       = "X-MW-Echo-RTK-Saved"
)

var (
	// ErrSessionBusy indicates a prompt turn is already executing on the target session.
	ErrSessionBusy = errors.New("session is already running; abort the active turn first")
	// ErrSessionNotFound indicates the requested session ID does not exist in the store.
	ErrSessionNotFound = errors.New("coding session not found")
)

// MCPToolCaller decouples remote MCP tool invocation from the core agent engine.
type MCPToolCaller interface {
	CallTool(ctx context.Context, toolName string, arguments map[string]any) (string, error)
}

// ApprovalResolver supplies a single-use approval token when the RiskGate requires interactive or external approval.
type ApprovalResolver func(ctx context.Context, action risk.Action, decision risk.Decision) (string, error)

// Options configures the standalone Rocksoul coding agent engine.
type Options struct {
	DefaultGatewayURL   string
	DefaultAgentProfile string
	AuthToken           string
	DataClassification  string
	HTTPClient          *http.Client
	MaxSteps            int
	Store               SessionStore
	RiskGate            *risk.Gate
	ApprovalResolver    ApprovalResolver
	MCPCaller           MCPToolCaller
}

// Engine manages coding agent sessions, sandboxed workspace tools, ReAct turns, risk enforcement, and live subscribers.
type Engine struct {
	store      SessionStore
	opts       Options
	httpClient *http.Client

	mu          sync.RWMutex
	activeTurns map[string]turnHandle
	subscribers map[string]map[uint64]chan AgentEvent
	nextSubID   uint64
}

type turnHandle struct {
	cancel func()
}

// Session represents a coding agent conversation bound to a workspace directory.
type Session struct {
	ID             string `json:"id"`
	Title          string `json:"title"`
	WorkDir        string `json:"workDir"`
	Project        string `json:"project"`
	AgentProfile   string `json:"agentProfile"`
	Model          string `json:"model"`
	Mode           string `json:"mode"`
	Status         string `json:"status"`
	TotalTokensIn  int64  `json:"totalTokensIn"`
	TotalTokensOut int64  `json:"totalTokensOut"`
	RTKTokensSaved int64  `json:"rtkTokensSaved"`
	CreatedAt      string `json:"createdAt"`
	UpdatedAt      string `json:"updatedAt"`
}

// SessionCreateInput carries parameters for creating a new coding session.
type SessionCreateInput struct {
	Title        string `json:"title"`
	WorkDir      string `json:"workDir"`
	Project      string `json:"project"`
	AgentProfile string `json:"agentProfile"`
	Model        string `json:"model"`
	Mode         string `json:"mode"`
}

// SessionPatchInput carries partial updates for an existing coding session.
type SessionPatchInput struct {
	Title        *string `json:"title,omitempty"`
	WorkDir      *string `json:"workDir,omitempty"`
	Project      *string `json:"project,omitempty"`
	AgentProfile *string `json:"agentProfile,omitempty"`
	Model        *string `json:"model,omitempty"`
	Mode         *string `json:"mode,omitempty"`
}

// ToolCallFunction encodes the OpenAI tool call function name and JSON arguments string.
type ToolCallFunction struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

// ToolCall represents a single OpenAI-compatible function call emitted by an assistant turn.
type ToolCall struct {
	ID       string           `json:"id"`
	Type     string           `json:"type"`
	Function ToolCallFunction `json:"function"`
}

// MessageMeta captures gateway telemetry, step metadata, and execution flags attached to a message.
type MessageMeta struct {
	Provider       string `json:"provider,omitempty"`
	Model          string `json:"model,omitempty"`
	Cache          string `json:"cache,omitempty"`
	RTKTokensSaved int    `json:"rtkTokensSaved,omitempty"`
	TokensIn       int    `json:"tokensIn,omitempty"`
	TokensOut      int    `json:"tokensOut,omitempty"`
	Step           int    `json:"step,omitempty"`
	DurationMS     int64  `json:"durationMs,omitempty"`
	IsError        bool   `json:"isError,omitempty"`
	Compacted      bool   `json:"compacted,omitempty"`
	RiskTier       string `json:"riskTier,omitempty"`
}

// Message represents a single persisted turn entry in a coding session.
type Message struct {
	ID            string       `json:"id"`
	SessionID     string       `json:"sessionId"`
	Seq           int          `json:"seq"`
	Role          string       `json:"role"`
	Content       string       `json:"content"`
	ToolCalls     []ToolCall   `json:"toolCalls,omitempty"`
	ToolCallsJSON string       `json:"toolCallsJson,omitempty"`
	ToolCallID    string       `json:"toolCallId,omitempty"`
	ToolName      string       `json:"toolName,omitempty"`
	Meta          *MessageMeta `json:"meta,omitempty"`
	MetaJSON      string       `json:"metaJson,omitempty"`
	CreatedAt     string       `json:"createdAt"`
}

// AgentEvent is emitted to subscribers and CLI callbacks during a coding agent turn.
type AgentEvent struct {
	Type           string    `json:"type"`
	SessionID      string    `json:"sessionId"`
	Step           int       `json:"step,omitempty"`
	Role           string    `json:"role,omitempty"`
	Content        string    `json:"content,omitempty"`
	Message        *Message  `json:"message,omitempty"`
	ToolCall       *ToolCall `json:"toolCall,omitempty"`
	ToolCallID     string    `json:"toolCallId,omitempty"`
	ToolName       string    `json:"toolName,omitempty"`
	Arguments      string    `json:"arguments,omitempty"`
	Output         string    `json:"output,omitempty"`
	ToolOutput     string    `json:"toolOutput,omitempty"`
	Reply          string    `json:"reply,omitempty"`
	Provider       string    `json:"provider,omitempty"`
	Model          string    `json:"model,omitempty"`
	Cache          string    `json:"cache,omitempty"`
	RTKSaved       int       `json:"rtkSaved,omitempty"`
	RTKTokensSaved int       `json:"rtkTokensSaved,omitempty"`
	TokensIn       int       `json:"tokensIn,omitempty"`
	TokensOut      int       `json:"tokensOut,omitempty"`
	Mode           string    `json:"mode,omitempty"`
	RiskTier       string    `json:"riskTier,omitempty"`
	Error          string    `json:"error,omitempty"`
	Timestamp      string    `json:"timestamp"`
}

// TurnResult returns the updated session snapshot, persisted history, and final reply for a prompt turn.
type TurnResult struct {
	Session  Session   `json:"session"`
	Messages []Message `json:"messages"`
	Reply    string    `json:"reply"`
	Steps    int       `json:"steps"`
	Aborted  bool      `json:"aborted,omitempty"`
}

// CompactResult summarizes the outcome of compacting a session's message history.
type CompactResult struct {
	Compacted    bool   `json:"compacted"`
	Summary      string `json:"summary"`
	KeptMessages int    `json:"keptMessages"`
}

// ToolSpec describes a workspace or external tool exposed to the LLM.
type ToolSpec struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	ReadOnly    bool           `json:"readOnly"`
	Parameters  map[string]any `json:"parameters"`
}

// NewEngine initializes a standalone Rocksoul Engine backed by the configured SessionStore (defaulting to in-memory).
func NewEngine(opts Options) (*Engine, error) {
	resolvedOpts := Options{
		DefaultGatewayURL:   strings.TrimSpace(opts.DefaultGatewayURL),
		DefaultAgentProfile: strings.TrimSpace(opts.DefaultAgentProfile),
		AuthToken:           strings.TrimSpace(opts.AuthToken),
		DataClassification:  strings.TrimSpace(opts.DataClassification),
		HTTPClient:          opts.HTTPClient,
		MaxSteps:            opts.MaxSteps,
		Store:               opts.Store,
		RiskGate:            opts.RiskGate,
		ApprovalResolver:    opts.ApprovalResolver,
		MCPCaller:           opts.MCPCaller,
	}
	if resolvedOpts.DefaultGatewayURL == "" {
		resolvedOpts.DefaultGatewayURL = DefaultGatewayURL
	}
	if resolvedOpts.DefaultAgentProfile == "" {
		resolvedOpts.DefaultAgentProfile = DefaultAgentProfile
	}
	if resolvedOpts.MaxSteps <= 0 {
		resolvedOpts.MaxSteps = DefaultMaxSteps
	}
	httpClient := resolvedOpts.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 120 * time.Second}
	}
	sessionStore := resolvedOpts.Store
	if sessionStore == nil {
		sessionStore = NewMemoryStore()
	}

	return &Engine{
		store:       sessionStore,
		opts:        resolvedOpts,
		httpClient:  httpClient,
		activeTurns: make(map[string]turnHandle),
		subscribers: make(map[string]map[uint64]chan AgentEvent),
	}, nil
}

// RiskGate returns the attached RiskGate (nil if unconfigured).
func (e *Engine) RiskGate() *risk.Gate {
	return e.opts.RiskGate
}

func generateRecordID(prefix string) string {
	randomBytes := make([]byte, 8)
	if _, err := rand.Read(randomBytes); err != nil {
		return fmt.Sprintf("%s_%x", prefix, time.Now().UTC().UnixNano())
	}
	return prefix + "_" + hex.EncodeToString(randomBytes)
}

func normalizeMode(rawMode string) (string, error) {
	cleaned := strings.ToLower(strings.TrimSpace(rawMode))
	if cleaned == "" {
		return ModeAct, nil
	}
	switch cleaned {
	case ModeAct, ModePlan:
		return cleaned, nil
	default:
		return "", fmt.Errorf("invalid mode %q; must be %q or %q", rawMode, ModeAct, ModePlan)
	}
}

func marshalToolCalls(calls []ToolCall) string {
	if len(calls) == 0 {
		return "[]"
	}
	encoded, err := json.Marshal(calls)
	if err != nil {
		return "[]"
	}
	return string(encoded)
}

func marshalMessageMeta(meta *MessageMeta) string {
	if meta == nil {
		return "{}"
	}
	encoded, err := json.Marshal(meta)
	if err != nil {
		return "{}"
	}
	return string(encoded)
}
