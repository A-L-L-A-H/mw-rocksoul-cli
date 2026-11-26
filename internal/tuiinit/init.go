package tuiinit

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	TargetOpenCode = "opencode"
	TargetCrush    = "crush"
	TargetCodex    = "codex"
	TargetAll      = "all"

	DefaultGatewayV1URL = "http://127.0.0.1:4510/v1"
	DefaultMCPEndpoint  = "http://127.0.0.1:4530/mcp"
	DefaultCoreBaseURL  = "http://127.0.0.1:4520"
	DefaultModel        = "auto"
)

// Options configures zero-fork TUI config generation for OpenCode, Crush, or Codex.
type Options struct {
	Target     string
	Dir        string
	GatewayURL string
	MCPURL     string
	CoreURL    string
	Model      string
	Force      bool
}

// GeneratedFile describes a config artifact produced by Generate.
type GeneratedFile struct {
	Target  string `json:"target"`
	Path    string `json:"path"`
	Bytes   int    `json:"bytes"`
	Created bool   `json:"created"`
}

// NormalizeGatewayV1URL ensures the gateway URL ends with /v1 for OpenAI-compatible TUIs.
func NormalizeGatewayV1URL(raw string) string {
	trimmed := strings.TrimRight(strings.TrimSpace(raw), "/")
	if trimmed == "" {
		return DefaultGatewayV1URL
	}
	trimmed = strings.TrimSuffix(trimmed, "/chat/completions")
	if strings.HasSuffix(trimmed, "/v1") {
		return trimmed
	}
	return trimmed + "/v1"
}

// NormalizeMCPEndpoint ensures the MCP URL ends with /mcp.
func NormalizeMCPEndpoint(raw string) string {
	trimmed := strings.TrimRight(strings.TrimSpace(raw), "/")
	if trimmed == "" {
		return DefaultMCPEndpoint
	}
	if strings.HasSuffix(trimmed, "/mcp") {
		return trimmed
	}
	return trimmed + "/mcp"
}

// Generate writes zero-config TUI settings pre-wired to mw-rocksoul-gateway and mw-rocksoul-mcp.
func Generate(opts Options) ([]GeneratedFile, error) {
	target := strings.ToLower(strings.TrimSpace(opts.Target))
	if target == "" {
		target = TargetOpenCode
	}
	var targets []string
	switch target {
	case TargetOpenCode, TargetCrush, TargetCodex:
		targets = []string{target}
	case TargetAll:
		targets = []string{TargetOpenCode, TargetCrush, TargetCodex}
	default:
		return nil, fmt.Errorf("unsupported --target %q (expected opencode, crush, codex, or all)", opts.Target)
	}

	dir := strings.TrimSpace(opts.Dir)
	if dir == "" {
		dir = "."
	}
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("resolve target dir: %w", err)
	}

	gatewayV1 := NormalizeGatewayV1URL(opts.GatewayURL)
	mcpURL := NormalizeMCPEndpoint(opts.MCPURL)
	coreURL := strings.TrimRight(strings.TrimSpace(opts.CoreURL), "/")
	if coreURL == "" {
		coreURL = DefaultCoreBaseURL
	}
	model := strings.TrimSpace(opts.Model)
	if model == "" {
		model = DefaultModel
	}

	results := make([]GeneratedFile, 0, len(targets))
	for _, t := range targets {
		var relPath string
		var content []byte
		var buildErr error
		switch t {
		case TargetOpenCode:
			relPath = "opencode.json"
			content, buildErr = renderOpenCodeConfig(gatewayV1, mcpURL, coreURL, model)
		case TargetCrush:
			relPath = ".crush.json"
			content, buildErr = renderCrushConfig(gatewayV1, mcpURL, model)
		case TargetCodex:
			relPath = filepath.Join(".codex", "config.toml")
			content = renderCodexConfigTOML(gatewayV1, mcpURL, model)
		}
		if buildErr != nil {
			return nil, buildErr
		}

		fullPath := filepath.Join(absDir, relPath)
		if !opts.Force {
			if _, statErr := os.Stat(fullPath); statErr == nil {
				return nil, fmt.Errorf("file already exists: %s (pass --force to overwrite)", fullPath)
			}
		}
		if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
			return nil, fmt.Errorf("create parent dir for %s: %w", fullPath, err)
		}
		if err := os.WriteFile(fullPath, content, 0o644); err != nil {
			return nil, fmt.Errorf("write %s: %w", fullPath, err)
		}
		results = append(results, GeneratedFile{
			Target:  t,
			Path:    fullPath,
			Bytes:   len(content),
			Created: true,
		})
	}
	return results, nil
}

func renderOpenCodeConfig(gatewayV1, mcpURL, coreURL, model string) ([]byte, error) {
	if gatewayV1 == "" || mcpURL == "" {
		return nil, errors.New("gateway and mcp URLs are required")
	}
	doc := map[string]any{
		"$schema": "https://opencode.ai/config.json",
		"model":   "rocksoul/" + model,
		"plugin":  []string{"./plugins/opencode-rocksoul"},
		"provider": map[string]any{
			"rocksoul": map[string]any{
				"npm":  "@ai-sdk/openai-compatible",
				"name": "Rocksoul Gateway",
				"options": map[string]any{
					"baseURL": gatewayV1,
					"apiKey":  "{env:ROCKSOUL_TOKEN}",
					"headers": map[string]string{
						"X-MW-Agent":      "opencode-rocksoul",
						"X-Rocksoul-Core": coreURL,
					},
				},
				"models": map[string]any{
					model: map[string]any{
						"name": "Rocksoul (" + model + ")",
					},
				},
			},
		},
		"mcp": map[string]any{
			"rocksoul": map[string]any{
				"type":    "remote",
				"url":     mcpURL,
				"enabled": true,
			},
		},
	}
	encoded, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal opencode.json: %w", err)
	}
	return append(encoded, '\n'), nil
}

func renderCrushConfig(gatewayV1, mcpURL, model string) ([]byte, error) {
	doc := map[string]any{
		"$schema": "https://charm.land/crush.json",
		"providers": map[string]any{
			"rocksoul": map[string]any{
				"type":     "openai",
				"base_url": gatewayV1,
				"api_key":  "$ROCKSOUL_TOKEN",
				"models": []map[string]any{
					{
						"id":   model,
						"name": "Rocksoul (" + model + ")",
					},
				},
			},
		},
		"models": map[string]any{
			"large": map[string]any{
				"provider": "rocksoul",
				"model":    model,
			},
			"small": map[string]any{
				"provider": "rocksoul",
				"model":    model,
			},
		},
		"mcp": map[string]any{
			"rocksoul": map[string]any{
				"type": "http",
				"url":  mcpURL,
			},
		},
	}
	encoded, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal .crush.json: %w", err)
	}
	return append(encoded, '\n'), nil
}

func renderCodexConfigTOML(gatewayV1, mcpURL, model string) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "# Generated by rocksoul init-tui --target codex\n")
	fmt.Fprintf(&b, "model_provider = %q\n", "rocksoul")
	fmt.Fprintf(&b, "model = %q\n\n", model)
	fmt.Fprintf(&b, "[model_providers.rocksoul]\n")
	fmt.Fprintf(&b, "name = %q\n", "Rocksoul Gateway")
	fmt.Fprintf(&b, "base_url = %q\n", gatewayV1)
	fmt.Fprintf(&b, "env_key = %q\n", "ROCKSOUL_TOKEN")
	fmt.Fprintf(&b, "wire_api = %q\n\n", "chat")
	fmt.Fprintf(&b, "[mcp_servers.rocksoul]\n")
	fmt.Fprintf(&b, "url = %q\n", mcpURL)
	return []byte(b.String())
}
