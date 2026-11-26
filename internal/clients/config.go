package clients

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// UserConfig stores persistent user preferences under ~/.rocksoul/config.json.
type UserConfig struct {
	Provider           string `json:"provider,omitempty"`
	Model              string `json:"model,omitempty"`
	Mode               string `json:"mode,omitempty"`
	MaxAutoTier        string `json:"maxAutoTier,omitempty"`
	DataClassification string `json:"dataClassification,omitempty"`
	GatewayURL         string `json:"gatewayUrl,omitempty"`
	CoreURL            string `json:"coreUrl,omitempty"`
	MCPURL             string `json:"mcpUrl,omitempty"`
	SandboxURL         string `json:"sandboxUrl,omitempty"`
	RIDURL             string `json:"ridUrl,omitempty"`
	OllamaURL          string `json:"ollamaUrl,omitempty"`
}

// RocksoulHomeDir returns ~/.rocksoul (or ROCKSOUL_HOME if set).
func RocksoulHomeDir() string {
	if override := strings.TrimSpace(os.Getenv("ROCKSOUL_HOME")); override != "" {
		return override
	}
	homeDir, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(homeDir) == "" {
		return ".rocksoul"
	}
	return filepath.Join(homeDir, ".rocksoul")
}

// DefaultConfigPath returns ~/.rocksoul/config.json (or ROCKSOUL_CONFIG_PATH if set).
func DefaultConfigPath() string {
	if override := strings.TrimSpace(os.Getenv("ROCKSOUL_CONFIG_PATH")); override != "" {
		return override
	}
	return filepath.Join(RocksoulHomeDir(), "config.json")
}

// DefaultUserConfig returns sensible zero-config defaults for Rocksoul CLI.
func DefaultUserConfig() UserConfig {
	return UserConfig{
		Provider:    "auto",
		Mode:        "act",
		MaxAutoTier: "R0",
	}
}

// LoadUserConfig loads ~/.rocksoul/config.json if present, returning defaults when absent.
func LoadUserConfig(configPath string) (UserConfig, error) {
	cfg := DefaultUserConfig()
	if strings.TrimSpace(configPath) == "" {
		configPath = DefaultConfigPath()
	}
	raw, err := os.ReadFile(configPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return cfg, nil
		}
		return cfg, fmt.Errorf("read config %s: %w", configPath, err)
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return cfg, nil
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return DefaultUserConfig(), fmt.Errorf("decode config %s: %w", configPath, err)
	}
	if strings.TrimSpace(cfg.Provider) == "" {
		cfg.Provider = "auto"
	}
	if strings.TrimSpace(cfg.Mode) == "" {
		cfg.Mode = "act"
	}
	if strings.TrimSpace(cfg.MaxAutoTier) == "" {
		cfg.MaxAutoTier = "R0"
	}
	return cfg, nil
}

// SaveUserConfig persists UserConfig atomically to ~/.rocksoul/config.json.
func SaveUserConfig(configPath string, cfg UserConfig) error {
	if strings.TrimSpace(configPath) == "" {
		configPath = DefaultConfigPath()
	}
	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}
	encoded, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	tmpPath := configPath + ".tmp"
	if err := os.WriteFile(tmpPath, append(encoded, '\n'), 0o600); err != nil {
		return fmt.Errorf("write temp config: %w", err)
	}
	if err := os.Rename(tmpPath, configPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("replace config file: %w", err)
	}
	return nil
}
