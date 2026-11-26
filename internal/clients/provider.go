package clients

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	ProviderAuto      = "auto"
	ProviderGateway   = "gateway"
	ProviderOpenAI    = "openai"
	ProviderAnthropic = "anthropic"
	ProviderGemini    = "gemini"
	ProviderOllama    = "ollama"

	defaultOpenAIBaseURL    = "https://api.openai.com"
	defaultAnthropicBaseURL = "https://api.anthropic.com"
	defaultGeminiOpenAIURL  = "https://generativelanguage.googleapis.com/v1beta/openai"
)

// ProviderResolution describes the resolved zero-config inference backend for the coding agent loop.
type ProviderResolution struct {
	Provider      string       `json:"provider"`
	CompletionURL string       `json:"completionUrl"`
	Model         string       `json:"model"`
	AuthToken     string       `json:"-"`
	HTTPClient    *http.Client `json:"-"`
	Reachable     bool         `json:"reachable"`
	Source        string       `json:"source"`
}

// ProviderResolveOptions controls auto-fallback resolution order and env/probe overrides.
type ProviderResolveOptions struct {
	PreferredProvider  string
	PreferredModel     string
	GatewayOverrideURL string
	Endpoints          Endpoints
	RIDToken           string
	DataClassification string
	ProbeClient        *http.Client
	EnvLookup          func(string) string
}

// ResolveProvider implements zero-config auto-fallback:
//  1. Explicit gateway override or healthy mw-rocksoul-gateway (:4510)
//  2. OPENAI_API_KEY (unless DataClassification == "local_only")
//  3. ANTHROPIC_API_KEY (unless DataClassification == "local_only")
//  4. GEMINI_API_KEY / GOOGLE_API_KEY (unless DataClassification == "local_only")
//  5. Local Ollama (127.0.0.1:11434) with automatic first installed model detection
func ResolveProvider(ctx context.Context, opts ProviderResolveOptions) ProviderResolution {
	envFn := opts.EnvLookup
	if envFn == nil {
		envFn = os.Getenv
	}
	probeClient := opts.ProbeClient
	if probeClient == nil {
		probeClient = &http.Client{Timeout: 800 * time.Millisecond}
	}
	baseClient := &http.Client{Timeout: 120 * time.Second}

	endpoints := opts.Endpoints
	if endpoints.Gateway == "" {
		endpoints.Gateway = DefaultGatewayBaseURL
	}
	if endpoints.Ollama == "" {
		endpoints.Ollama = DefaultOllamaBaseURL
	}

	preferred := strings.ToLower(strings.TrimSpace(opts.PreferredProvider))
	if preferred == "" {
		preferred = ProviderAuto
	}
	localOnly := strings.EqualFold(strings.TrimSpace(opts.DataClassification), "local_only")

	// Explicit gateway override flag always targets the specified URL directly.
	if override := strings.TrimSpace(opts.GatewayOverrideURL); override != "" {
		completionURL := normalizeChatCompletionsURL(override)
		return ProviderResolution{
			Provider:      ProviderGateway,
			CompletionURL: completionURL,
			Model:         firstNonEmpty(opts.PreferredModel, "auto"),
			AuthToken:     strings.TrimSpace(opts.RIDToken),
			HTTPClient:    baseClient,
			Reachable:     true,
			Source:        "flag --gateway",
		}
	}

	// Handle explicit non-auto provider selections first.
	switch preferred {
	case ProviderGateway:
		return buildGatewayResolution(endpoints.Gateway, opts.PreferredModel, opts.RIDToken, baseClient, probeHealthy(ctx, probeClient, endpoints.Gateway+"/health"), "configured gateway")
	case ProviderOpenAI:
		return buildOpenAIResolution(envFn, opts.PreferredModel, baseClient)
	case ProviderAnthropic:
		return buildAnthropicResolution(envFn, opts.PreferredModel, baseClient)
	case ProviderGemini:
		return buildGeminiResolution(envFn, opts.PreferredModel, baseClient)
	case ProviderOllama:
		ollamaModel, ok := probeOllamaModel(ctx, probeClient, endpoints.Ollama)
		return buildOllamaResolution(endpoints.Ollama, firstNonEmpty(opts.PreferredModel, ollamaModel, "llama3.2"), baseClient, ok)
	}

	// 1. Try mw-rocksoul-gateway (:4510) first.
	if probeHealthy(ctx, probeClient, endpoints.Gateway+"/health") {
		return buildGatewayResolution(endpoints.Gateway, opts.PreferredModel, opts.RIDToken, baseClient, true, "mw-rocksoul-gateway (:4510)")
	}

	// 2-4. Cloud API keys (skipped when air-gapped local_only is requested).
	if !localOnly {
		if strings.TrimSpace(envFn("OPENAI_API_KEY")) != "" {
			return buildOpenAIResolution(envFn, opts.PreferredModel, baseClient)
		}
		if strings.TrimSpace(envFn("ANTHROPIC_API_KEY")) != "" {
			return buildAnthropicResolution(envFn, opts.PreferredModel, baseClient)
		}
		if strings.TrimSpace(firstNonEmpty(envFn("GEMINI_API_KEY"), envFn("GOOGLE_API_KEY"))) != "" {
			return buildGeminiResolution(envFn, opts.PreferredModel, baseClient)
		}
	}

	// 5. Try local Ollama (:11434).
	if ollamaModel, ok := probeOllamaModel(ctx, probeClient, endpoints.Ollama); ok {
		return buildOllamaResolution(endpoints.Ollama, firstNonEmpty(opts.PreferredModel, ollamaModel, "llama3.2"), baseClient, true)
	}

	// Fallback default (unreachable until gateway/Ollama started or API key exported).
	return buildGatewayResolution(endpoints.Gateway, opts.PreferredModel, opts.RIDToken, baseClient, false, "default gateway (offline; set OPENAI_API_KEY/ANTHROPIC_API_KEY/GEMINI_API_KEY or start Ollama/gateway)")
}

func normalizeChatCompletionsURL(raw string) string {
	trimmed := strings.TrimRight(strings.TrimSpace(raw), "/")
	if strings.HasSuffix(trimmed, "/chat/completions") || strings.HasSuffix(trimmed, "/v1/messages") {
		return trimmed
	}
	return trimmed + "/v1/chat/completions"
}

func buildGatewayResolution(baseURL, model, ridToken string, client *http.Client, reachable bool, source string) ProviderResolution {
	return ProviderResolution{
		Provider:      ProviderGateway,
		CompletionURL: cleanBaseURL(baseURL) + "/v1/chat/completions",
		Model:         firstNonEmpty(model, "auto"),
		AuthToken:     strings.TrimSpace(ridToken),
		HTTPClient:    client,
		Reachable:     reachable,
		Source:        source,
	}
}

func buildOpenAIResolution(envFn func(string) string, model string, client *http.Client) ProviderResolution {
	baseURL := cleanBaseURL(firstNonEmpty(envFn("OPENAI_BASE_URL"), defaultOpenAIBaseURL))
	apiKey := strings.TrimSpace(envFn("OPENAI_API_KEY"))
	return ProviderResolution{
		Provider:      ProviderOpenAI,
		CompletionURL: baseURL + "/v1/chat/completions",
		Model:         firstNonEmpty(model, envFn("OPENAI_MODEL"), "gpt-4.1-mini"),
		AuthToken:     apiKey,
		HTTPClient:    client,
		Reachable:     apiKey != "",
		Source:        "OPENAI_API_KEY",
	}
}

func buildAnthropicResolution(envFn func(string) string, model string, baseClient *http.Client) ProviderResolution {
	baseURL := cleanBaseURL(firstNonEmpty(envFn("ANTHROPIC_BASE_URL"), defaultAnthropicBaseURL))
	apiKey := strings.TrimSpace(envFn("ANTHROPIC_API_KEY"))
	transport := &AnthropicAdapterTransport{
		Base:   baseClient.Transport,
		APIKey: apiKey,
	}
	adaptedClient := &http.Client{
		Timeout:   baseClient.Timeout,
		Transport: transport,
	}
	return ProviderResolution{
		Provider:      ProviderAnthropic,
		CompletionURL: baseURL + "/v1/messages",
		Model:         firstNonEmpty(model, envFn("ANTHROPIC_MODEL"), "claude-sonnet-4-20250514"),
		AuthToken:     "", // Sent via x-api-key by AnthropicAdapterTransport
		HTTPClient:    adaptedClient,
		Reachable:     apiKey != "",
		Source:        "ANTHROPIC_API_KEY",
	}
}

func buildGeminiResolution(envFn func(string) string, model string, client *http.Client) ProviderResolution {
	baseURL := cleanBaseURL(firstNonEmpty(envFn("GEMINI_OPENAI_BASE_URL"), defaultGeminiOpenAIURL))
	apiKey := strings.TrimSpace(firstNonEmpty(envFn("GEMINI_API_KEY"), envFn("GOOGLE_API_KEY")))
	return ProviderResolution{
		Provider:      ProviderGemini,
		CompletionURL: baseURL + "/chat/completions",
		Model:         firstNonEmpty(model, envFn("GEMINI_MODEL"), "gemini-2.5-flash"),
		AuthToken:     apiKey,
		HTTPClient:    client,
		Reachable:     apiKey != "",
		Source:        "GEMINI_API_KEY",
	}
}

func buildOllamaResolution(baseURL, model string, client *http.Client, reachable bool) ProviderResolution {
	return ProviderResolution{
		Provider:      ProviderOllama,
		CompletionURL: cleanBaseURL(baseURL) + "/v1/chat/completions",
		Model:         firstNonEmpty(model, "llama3.2"),
		HTTPClient:    client,
		Reachable:     reachable,
		Source:        "local Ollama (" + cleanBaseURL(baseURL) + ")",
	}
}

func probeHealthy(ctx context.Context, client *http.Client, healthURL string) bool {
	res := ProbeEndpoint(ctx, client, "probe", healthURL)
	return res.Healthy
}

func probeOllamaModel(ctx context.Context, client *http.Client, baseURL string) (string, bool) {
	tagsURL := cleanBaseURL(baseURL) + "/api/tags"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, tagsURL, nil)
	if err != nil {
		return "", false
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", false
	}
	var payload struct {
		Models []struct {
			Name string `json:"name"`
		} `json:"models"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 2*1024*1024)).Decode(&payload); err != nil {
		return "", true
	}
	if len(payload.Models) == 0 {
		return "", true
	}
	// Prefer coding-oriented local models if available.
	for _, m := range payload.Models {
		lower := strings.ToLower(m.Name)
		if strings.Contains(lower, "coder") || strings.Contains(lower, "qwen") || strings.Contains(lower, "deepseek") {
			return m.Name, true
		}
	}
	return payload.Models[0].Name, true
}

// AnthropicAdapterTransport translates OpenAI Chat Completions requests/responses to Anthropic /v1/messages wire format.
type AnthropicAdapterTransport struct {
	Base   http.RoundTripper
	APIKey string
}

func (t *AnthropicAdapterTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}
	rawReq, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	_ = req.Body.Close()

	var openaiReq struct {
		Model    string `json:"model"`
		Messages []struct {
			Role       string `json:"role"`
			Content    any    `json:"content"`
			ToolCallID string `json:"tool_call_id"`
			ToolCalls  []struct {
				ID       string `json:"id"`
				Type     string `json:"type"`
				Function struct {
					Name      string `json:"name"`
					Arguments string `json:"arguments"`
				} `json:"function"`
			} `json:"tool_calls"`
		} `json:"messages"`
		Tools []struct {
			Type     string `json:"type"`
			Function struct {
				Name        string         `json:"name"`
				Description string         `json:"description"`
				Parameters  map[string]any `json:"parameters"`
			} `json:"function"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(rawReq, &openaiReq); err != nil {
		return nil, fmt.Errorf("anthropic adapter decode openai request: %w", err)
	}

	var systemParts []string
	anthropicMsgs := make([]map[string]any, 0, len(openaiReq.Messages))
	for _, msg := range openaiReq.Messages {
		text := fmt.Sprint(msg.Content)
		if msg.Content == nil {
			text = ""
		}
		switch msg.Role {
		case "system":
			if strings.TrimSpace(text) != "" {
				systemParts = append(systemParts, text)
			}
		case "user":
			anthropicMsgs = append(anthropicMsgs, map[string]any{
				"role":    "user",
				"content": text,
			})
		case "assistant":
			if len(msg.ToolCalls) == 0 {
				anthropicMsgs = append(anthropicMsgs, map[string]any{
					"role":    "assistant",
					"content": text,
				})
				continue
			}
			blocks := make([]map[string]any, 0, len(msg.ToolCalls)+1)
			if strings.TrimSpace(text) != "" {
				blocks = append(blocks, map[string]any{"type": "text", "text": text})
			}
			for _, tc := range msg.ToolCalls {
				var inputObj map[string]any
				if err := json.Unmarshal([]byte(tc.Function.Arguments), &inputObj); err != nil || inputObj == nil {
					inputObj = map[string]any{}
				}
				blocks = append(blocks, map[string]any{
					"type":  "tool_use",
					"id":    tc.ID,
					"name":  tc.Function.Name,
					"input": inputObj,
				})
			}
			anthropicMsgs = append(anthropicMsgs, map[string]any{
				"role":    "assistant",
				"content": blocks,
			})
		case "tool":
			anthropicMsgs = append(anthropicMsgs, map[string]any{
				"role": "user",
				"content": []map[string]any{
					{
						"type":        "tool_result",
						"tool_use_id": msg.ToolCallID,
						"content":     text,
					},
				},
			})
		}
	}

	anthropicTools := make([]map[string]any, 0, len(openaiReq.Tools))
	for _, tool := range openaiReq.Tools {
		anthropicTools = append(anthropicTools, map[string]any{
			"name":         tool.Function.Name,
			"description":  tool.Function.Description,
			"input_schema": tool.Function.Parameters,
		})
	}

	anthropicReq := map[string]any{
		"model":      openaiReq.Model,
		"max_tokens": 4096,
		"messages":   anthropicMsgs,
	}
	if len(systemParts) > 0 {
		anthropicReq["system"] = strings.Join(systemParts, "\n\n")
	}
	if len(anthropicTools) > 0 {
		anthropicReq["tools"] = anthropicTools
	}
	encodedAnthropic, err := json.Marshal(anthropicReq)
	if err != nil {
		return nil, err
	}

	outReq := req.Clone(req.Context())
	outReq.Body = io.NopCloser(bytes.NewReader(encodedAnthropic))
	outReq.ContentLength = int64(len(encodedAnthropic))
	outReq.Header.Del("Authorization")
	outReq.Header.Set("Content-Type", "application/json")
	outReq.Header.Set("x-api-key", t.APIKey)
	outReq.Header.Set("anthropic-version", "2023-06-01")

	resp, err := base.RoundTrip(outReq)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp, nil
	}

	respRaw, err := io.ReadAll(io.LimitReader(resp.Body, 16*1024*1024))
	_ = resp.Body.Close()
	if err != nil {
		return nil, err
	}

	var anthropicResp struct {
		ID      string `json:"id"`
		Model   string `json:"model"`
		Content []struct {
			Type  string         `json:"type"`
			Text  string         `json:"text"`
			ID    string         `json:"id"`
			Name  string         `json:"name"`
			Input map[string]any `json:"input"`
		} `json:"content"`
		Usage struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(respRaw, &anthropicResp); err != nil {
		return nil, fmt.Errorf("anthropic adapter decode response: %w", err)
	}

	var textParts []string
	toolCalls := make([]map[string]any, 0)
	for _, block := range anthropicResp.Content {
		switch block.Type {
		case "text":
			if block.Text != "" {
				textParts = append(textParts, block.Text)
			}
		case "tool_use":
			argsJSON, _ := json.Marshal(block.Input)
			toolCalls = append(toolCalls, map[string]any{
				"id":   block.ID,
				"type": "function",
				"function": map[string]any{
					"name":      block.Name,
					"arguments": string(argsJSON),
				},
			})
		}
	}

	msgObj := map[string]any{
		"role":    "assistant",
		"content": strings.Join(textParts, "\n"),
	}
	if len(toolCalls) > 0 {
		msgObj["tool_calls"] = toolCalls
	}
	translated := map[string]any{
		"id":      anthropicResp.ID,
		"object":  "chat.completion",
		"model":   anthropicResp.Model,
		"choices": []map[string]any{{"index": 0, "message": msgObj, "finish_reason": "stop"}},
		"usage": map[string]int{
			"prompt_tokens":     anthropicResp.Usage.InputTokens,
			"completion_tokens": anthropicResp.Usage.OutputTokens,
			"total_tokens":      anthropicResp.Usage.InputTokens + anthropicResp.Usage.OutputTokens,
		},
	}
	encodedTranslated, err := json.Marshal(translated)
	if err != nil {
		return nil, err
	}

	resp.Body = io.NopCloser(bytes.NewReader(encodedTranslated))
	resp.ContentLength = int64(len(encodedTranslated))
	resp.Header.Set("Content-Type", "application/json")
	resp.Header.Set("X-Rocksoul-Provider", "anthropic")
	resp.Header.Set("X-Rocksoul-Model", anthropicResp.Model)
	return resp, nil
}
