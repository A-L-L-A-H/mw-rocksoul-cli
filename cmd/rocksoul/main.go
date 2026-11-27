package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/A-L-L-A-H/mw-rocksoul-cli/internal/agent"
	"github.com/A-L-L-A-H/mw-rocksoul-cli/internal/clients"
	"github.com/A-L-L-A-H/mw-rocksoul-cli/internal/risk"
	"github.com/A-L-L-A-H/mw-rocksoul-cli/internal/tuiinit"
)

var (
	Version = "0.1.0"
	Commit  = "dev"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(runCLI(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func runCLI(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	// Zero-friction UX: bare `rocksoul` launches interactive coding chat immediately.
	if len(args) == 0 {
		return cmdChat(ctx, nil, stdin, stdout, stderr)
	}

	first := strings.TrimSpace(args[0])
	switch first {
	case "version", "-v", "--version":
		return cmdVersion(args[1:], stdout, stderr)
	case "doctor":
		return cmdDoctor(ctx, args[1:], stdout, stderr)
	case "login":
		return cmdLogin(ctx, args[1:], stdout, stderr)
	case "mcp":
		return cmdMCP(ctx, args[1:], stdout, stderr)
	case "init-tui":
		return cmdInitTUI(args[1:], stdout, stderr)
	case "run":
		return cmdRun(ctx, args[1:], stdout, stderr)
	case "chat":
		return cmdChat(ctx, args[1:], stdin, stdout, stderr)
	case "plan":
		return cmdPlan(ctx, args[1:], stdout, stderr)
	case "help", "-h", "--help":
		printRootUsage(stdout)
		return 0
	default:
		// Support `rocksoul "<prompt>"` or `rocksoul --model ... "<prompt>"` / `rocksoul --model ...` (chat).
		if strings.HasPrefix(first, "-") {
			return cmdRunOrChatShortcut(ctx, args, stdin, stdout, stderr)
		}
		return cmdRun(ctx, args, stdout, stderr)
	}
}

func printRootUsage(w io.Writer) {
	fmt.Fprintf(w, `Rocksoul CLI (%s) â€” Zero-friction coding agent & MoonWitness AI client

Usage:
  rocksoul                        Launch interactive coding chat immediately
  rocksoul "<prompt>"             Run a direct one-shot coding task
  rocksoul run [flags] <prompt>   Run a one-shot coding agent turn
  rocksoul chat [flags]           Start interactive terminal chat
  rocksoul plan next|run|status   Execute or inspect TaskOS micro-task plan loop
  rocksoul doctor [--json]        Probe gateway/core/mcp/sandbox/rid/ollama/git
  rocksoul login [flags]          Inspect mw-rid token status or generate PKCE login URL
  rocksoul mcp list [--json]      List tools exposed by mw-rocksoul-mcp (:4530)
  rocksoul init-tui [flags]       Generate opencode.json / .crush.json / .codex/config.toml
  rocksoul version [--json]       Print binary version info

Chat Slash Commands:
  /model [name | provider <p>]    Show/switch model or provider (persists ~/.rocksoul/config.json)
  /diff                           Show workspace git status & diff
  /risk [tier <R0-R3>|approve ..] Inspect R0-R4 gate policy or issue single-use token
  /mcp                            List available MCP tools
  /clear                          Reset active chat session context
  /doctor                         Probe all ecosystem endpoints inline
  /plan | /act | /compact         Switch mode or compact conversation history
  /symbols [query]                Search workspace declarations
  /help | /exit                   Show help or exit chat
`, Version)
}

func cmdVersion(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("version", flag.ContinueOnError)
	fs.SetOutput(stderr)
	asJSON := fs.Bool("json", false, "output JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	info := map[string]string{
		"name":    "rocksoul",
		"version": Version,
		"commit":  Commit,
		"go":      runtime.Version(),
		"os":      runtime.GOOS,
		"arch":    runtime.GOARCH,
	}
	if *asJSON {
		_ = json.NewEncoder(stdout).Encode(info)
		return 0
	}
	fmt.Fprintf(stdout, "rocksoul %s (%s, %s/%s, %s)\n", Version, Commit, runtime.GOOS, runtime.GOARCH, runtime.Version())
	return 0
}

type doctorReport struct {
	Probes      []clients.ProbeResult      `json:"probes"`
	Git         map[string]any             `json:"git"`
	DiskSweeper map[string]any             `json:"diskSweeper,omitempty"`
	Provider    clients.ProviderResolution `json:"provider"`
	Config      string                     `json:"configPath"`
	AllOK       bool                       `json:"allOk"`
}

func collectDoctorReport(ctx context.Context, cfg clients.UserConfig, configPath string) doctorReport {
	endpoints := clients.ResolveEndpoints(cfg)
	probeClient := &http.Client{Timeout: 1500 * time.Millisecond}

	targets := []struct {
		name string
		url  string
	}{
		{name: "gateway", url: endpoints.Gateway + "/health"},
		{name: "core", url: endpoints.Core + "/health"},
		{name: "mcp", url: endpoints.MCP + "/health"},
		{name: "sandbox", url: endpoints.Sandbox + "/health"},
		{name: "rid", url: endpoints.RID + "/health"},
		{name: "ollama", url: endpoints.Ollama + "/api/tags"},
	}

	probes := make([]clients.ProbeResult, len(targets))
	var wg sync.WaitGroup
	for idx, target := range targets {
		wg.Add(1)
		go func(i int, name, probeURL string) {
			defer wg.Done()
			probes[i] = clients.ProbeEndpoint(ctx, probeClient, name, probeURL)
		}(idx, target.name, target.url)
	}
	wg.Wait()

	gitInfo := probeGit(ctx)
	diskInfo := probeDiskSweeper(ctx)
	allOK := gitInfo["available"] == true
	for _, p := range probes {
		if !p.Healthy {
			allOK = false
		}
	}

	ridToken := loadSavedAccessToken("")
	resolved := clients.ResolveProvider(ctx, clients.ProviderResolveOptions{
		PreferredProvider:  cfg.Provider,
		PreferredModel:     cfg.Model,
		Endpoints:          endpoints,
		RIDToken:           ridToken,
		DataClassification: cfg.DataClassification,
		ProbeClient:        probeClient,
	})

	return doctorReport{
		Probes:      probes,
		Git:         gitInfo,
		DiskSweeper: diskInfo,
		Provider:    resolved,
		Config:      configPath,
		AllOK:       allOK,
	}
}

func probeGit(ctx context.Context) map[string]any {
	cmdCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cmdCtx, "git", "--version").CombinedOutput()
	if err != nil {
		return map[string]any{"available": false, "error": err.Error()}
	}
	versionLine := strings.TrimSpace(string(out))
	inRepo := false
	if _, repoErr := exec.CommandContext(cmdCtx, "git", "rev-parse", "--is-inside-work-tree").CombinedOutput(); repoErr == nil {
		inRepo = true
	}
	return map[string]any{
		"available":  true,
		"version":    versionLine,
		"inWorkTree": inRepo,
	}
}

func renderDoctorReport(w io.Writer, report doctorReport) {
	fmt.Fprintf(w, "Rocksoul Doctor\n")
	fmt.Fprintf(w, "  Config   : %s\n", report.Config)
	fmt.Fprintf(w, "  Provider : %s (model=%s, source=%s, reachable=%v)\n",
		report.Provider.Provider, report.Provider.Model, report.Provider.Source, report.Provider.Reachable)
	for _, p := range report.Probes {
		badge := "DOWN"
		detail := p.Error
		if p.Healthy {
			badge = "OK  "
			detail = fmt.Sprintf("HTTP %d (%dms)", p.StatusCode, p.LatencyMS)
		}
		fmt.Fprintf(w, "  [%s] %-8s %-36s %s\n", badge, p.Name, p.URL, detail)
	}
	if report.Git["available"] == true {
		fmt.Fprintf(w, "  [OK  ] %-8s %s (inWorkTree=%v)\n", "git", report.Git["version"], report.Git["inWorkTree"])
	} else {
		fmt.Fprintf(w, "  [DOWN] %-8s %v\n", "git", report.Git["error"])
	}
	if report.DiskSweeper != nil {
		if report.DiskSweeper["available"] == true {
			status, _ := report.DiskSweeper["status"].(string)
			binPath, _ := report.DiskSweeper["binary"].(string)
			badge := "OK  "
			if status == "warn" || status == "critical" {
				badge = "WARN"
			}
			fmt.Fprintf(w, "  [%s] %-8s status=%s (%s)\n", badge, "mw-ww", status, binPath)
		} else {
			hint, _ := report.DiskSweeper["hint"].(string)
			fmt.Fprintf(w, "  [INFO] %-8s not installed (%s)\n", "mw-ww", hint)
		}
	}
}

func resolveDiskSweeperBinary() string {
	binName := "mw-ww-cli"
	if runtime.GOOS == "windows" {
		binName = "mw-ww-cli.exe"
	}
	if p, err := exec.LookPath(binName); err == nil {
		return p
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		candidate := filepath.Join(home, ".local", "bin", binName)
		if fi, statErr := os.Stat(candidate); statErr == nil && !fi.IsDir() {
			return candidate
		}
	}
	return ""
}

func probeDiskSweeper(ctx context.Context) map[string]any {
	binPath := resolveDiskSweeperBinary()
	if binPath == "" {
		return map[string]any{
			"available": false,
			"hint":      "install mw-ww-cli (A-L-L-A-H/mw-ww) for disk guard",
		}
	}
	cmdCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cmdCtx, binPath, "--drives", "--json").Output()
	if err != nil {
		return map[string]any{
			"available": true,
			"binary":    binPath,
			"status":    "error",
			"error":     err.Error(),
		}
	}
	var drives []struct {
		Drive   string `json:"drive"`
		Total   int64  `json:"total"`
		Free    int64  `json:"free"`
		UsedPct int    `json:"usedPct"`
		Status  string `json:"status"`
	}
	if err := json.Unmarshal(out, &drives); err != nil {
		return map[string]any{
			"available": true,
			"binary":    binPath,
			"status":    "error",
			"error":     err.Error(),
		}
	}
	worst := "ok"
	for _, d := range drives {
		if d.Status == "critical" {
			worst = "critical"
			break
		}
		if d.Status == "warn" {
			worst = "warn"
		}
	}
	return map[string]any{
		"available": true,
		"binary":    binPath,
		"status":    worst,
		"drives":    drives,
	}
}

func cmdDoctor(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(stderr)
	asJSON := fs.Bool("json", false, "output JSON")
	strict := fs.Bool("strict", false, "exit non-zero if any probe fails")
	configPathFlag := fs.String("config", "", "path to config.json")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	cfgPath := resolveConfigPath(*configPathFlag)
	cfg, err := clients.LoadUserConfig(cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "warning: load config: %v\n", err)
	}
	report := collectDoctorReport(ctx, cfg, cfgPath)
	if *asJSON {
		_ = json.NewEncoder(stdout).Encode(report)
	} else {
		renderDoctorReport(stdout, report)
	}
	if *strict && !report.AllOK {
		return 1
	}
	return 0
}

func cmdLogin(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("login", flag.ContinueOnError)
	fs.SetOutput(stderr)
	startFlow := fs.Bool("start", false, "generate PKCE S256 authorization URL for mw-rid")
	statusOnly := fs.Bool("status", false, "show PKCE config and token status")
	logout := fs.Bool("logout", false, "delete saved local token")
	clientID := fs.String("client-id", "rocksoul-cli", "OIDC client_id")
	redirectURI := fs.String("redirect-uri", "http://127.0.0.1:4599/callback", "OIDC redirect_uri")
	scope := fs.String("scope", "openid profile email", "OIDC scope")
	exchangeCode := fs.String("exchange-code", "", "authorization code to exchange at mw-rid /token")
	verifier := fs.String("verifier", "", "PKCE code_verifier matching --exchange-code")
	tokenFile := fs.String("token-file", "", "override token storage path")
	ridURLFlag := fs.String("rid-url", "", "override mw-rid base URL")
	asJSON := fs.Bool("json", false, "output JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	cfg, _ := clients.LoadUserConfig(clients.DefaultConfigPath())
	endpoints := clients.ResolveEndpoints(cfg)
	ridBase := endpoints.RID
	if strings.TrimSpace(*ridURLFlag) != "" {
		ridBase = strings.TrimRight(strings.TrimSpace(*ridURLFlag), "/")
	}
	tokPath := strings.TrimSpace(*tokenFile)
	if tokPath == "" {
		tokPath = clients.DefaultTokenPath()
	}

	ridClient := clients.NewRIDClient(ridBase, &http.Client{Timeout: 5 * time.Second})

	if *logout {
		if err := os.Remove(tokPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			fmt.Fprintf(stderr, "logout failed: %v\n", err)
			return 1
		}
		if *asJSON {
			_ = json.NewEncoder(stdout).Encode(map[string]any{"loggedOut": true, "tokenPath": tokPath})
		} else {
			fmt.Fprintf(stdout, "Removed local token at %s\n", tokPath)
		}
		return 0
	}

	if strings.TrimSpace(*exchangeCode) != "" {
		if strings.TrimSpace(*verifier) == "" {
			fmt.Fprintln(stderr, "error: --verifier is required with --exchange-code")
			return 2
		}
		tokenEndpoint := ridBase + "/token"
		if doc, err := ridClient.Discover(ctx); err == nil && doc.TokenEndpoint != "" {
			tokenEndpoint = doc.TokenEndpoint
		}
		tok, err := ridClient.ExchangeCode(ctx, tokenEndpoint, clients.TokenExchangeRequest{
			ClientID:     *clientID,
			Code:         *exchangeCode,
			RedirectURI:  *redirectURI,
			CodeVerifier: *verifier,
		})
		if err != nil {
			fmt.Fprintf(stderr, "token exchange failed: %v\n", err)
			return 1
		}
		if claims, claimErr := ridClient.UserInfo(ctx, tok.AccessToken); claimErr == nil {
			if sub, ok := claims["sub"].(string); ok {
				tok.Subject = sub
			}
		}
		if err := clients.SaveTokenSet(tokPath, tok); err != nil {
			fmt.Fprintf(stderr, "save token failed: %v\n", err)
			return 1
		}
		out := map[string]any{
			"authenticated": true,
			"issuer":        tok.Issuer,
			"subject":       tok.Subject,
			"tokenPreview":  clients.MaskToken(tok.AccessToken),
			"expiresAt":     tok.ExpiresAt,
			"tokenPath":     tokPath,
		}
		if *asJSON {
			_ = json.NewEncoder(stdout).Encode(out)
		} else {
			fmt.Fprintf(stdout, "Authenticated with %s (subject=%s, token=%s, saved=%s)\n",
				tok.Issuer, tok.Subject, clients.MaskToken(tok.AccessToken), tokPath)
		}
		return 0
	}

	if *startFlow {
		pkce, err := clients.GeneratePKCE()
		if err != nil {
			fmt.Fprintf(stderr, "generate PKCE: %v\n", err)
			return 1
		}
		authEndpoint := ridBase + "/auth"
		discoveryOK := false
		if doc, err := ridClient.Discover(ctx); err == nil && doc.AuthorizationEndpoint != "" {
			authEndpoint = doc.AuthorizationEndpoint
			discoveryOK = true
		}
		authURL, err := ridClient.BuildAuthorizationURL(authEndpoint, clients.PKCEAuthConfig{
			ClientID:    *clientID,
			RedirectURI: *redirectURI,
			Scope:       *scope,
		}, pkce)
		if err != nil {
			fmt.Fprintf(stderr, "build authorization URL: %v\n", err)
			return 1
		}
		payload := map[string]any{
			"ridUrl":           ridBase,
			"discoveryOnline":  discoveryOK,
			"clientId":         *clientID,
			"redirectUri":      *redirectURI,
			"scope":            *scope,
			"authorizationUrl": authURL,
			"pkceMethod":       pkce.Method,
			"codeChallenge":    pkce.CodeChallenge,
			"codeVerifier":     pkce.CodeVerifier,
			"state":            pkce.State,
		}
		if *asJSON {
			_ = json.NewEncoder(stdout).Encode(payload)
		} else {
			fmt.Fprintf(stdout, "mw-rid PKCE S256 Authorization Flow\n")
			fmt.Fprintf(stdout, "  Issuer       : %s (discovery=%v)\n", ridBase, discoveryOK)
			fmt.Fprintf(stdout, "  Authorize URL: %s\n", authURL)
			fmt.Fprintf(stdout, "  Code Verifier: %s\n", pkce.CodeVerifier)
			fmt.Fprintf(stdout, "  Next step    : rocksoul login --exchange-code <CODE> --verifier %s\n", pkce.CodeVerifier)
		}
		return 0
	}

	// Default / --status: inspect PKCE config + local token status without requiring mw-rid to be online.
	_ = statusOnly
	probe := clients.ProbeEndpoint(ctx, &http.Client{Timeout: 1200 * time.Millisecond}, "rid", ridBase+"/health")
	tok, tokErr := clients.LoadTokenSet(tokPath)
	authenticated := tokErr == nil && strings.TrimSpace(tok.AccessToken) != ""
	expired := authenticated && !tok.ExpiresAt.IsZero() && time.Now().UTC().After(tok.ExpiresAt)

	statusPayload := map[string]any{
		"ridUrl":        ridBase,
		"ridReachable":  probe.Healthy,
		"pkceMethod":    "S256",
		"clientId":      *clientID,
		"redirectUri":   *redirectURI,
		"tokenPath":     tokPath,
		"authenticated": authenticated && !expired,
		"expired":       expired,
		"tokenPreview":  clients.MaskToken(tok.AccessToken),
		"subject":       tok.Subject,
		"expiresAt":     tok.ExpiresAt,
	}
	if *asJSON {
		_ = json.NewEncoder(stdout).Encode(statusPayload)
	} else {
		fmt.Fprintf(stdout, "mw-rid Auth Status\n")
		fmt.Fprintf(stdout, "  RID Endpoint : %s (reachable=%v)\n", ridBase, probe.Healthy)
		fmt.Fprintf(stdout, "  PKCE Config  : method=S256 client_id=%s redirect_uri=%s\n", *clientID, *redirectURI)
		fmt.Fprintf(stdout, "  Token File   : %s\n", tokPath)
		if authenticated {
			state := "valid"
			if expired {
				state = "expired"
			}
			fmt.Fprintf(stdout, "  Token Status : %s (token=%s subject=%s)\n", state, clients.MaskToken(tok.AccessToken), tok.Subject)
		} else {
			fmt.Fprintf(stdout, "  Token Status : not logged in (optional â€” run `rocksoul login --start` for RID SSO)\n")
		}
	}
	return 0
}

func cmdMCP(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: rocksoul mcp <list|call> [flags]")
		return 2
	}
	sub := strings.ToLower(strings.TrimSpace(args[0]))
	cfg, _ := clients.LoadUserConfig(clients.DefaultConfigPath())
	endpoints := clients.ResolveEndpoints(cfg)
	ridToken := loadSavedAccessToken("")

	switch sub {
	case "list":
		fs := flag.NewFlagSet("mcp list", flag.ContinueOnError)
		fs.SetOutput(stderr)
		mcpURL := fs.String("url", endpoints.MCP, "mw-rocksoul-mcp base URL")
		asJSON := fs.Bool("json", false, "output JSON")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		mcpClient := clients.NewMCPClient(*mcpURL, ridToken, &http.Client{Timeout: 5 * time.Second})
		tools, err := mcpClient.ListTools(ctx)
		if err != nil {
			fmt.Fprintf(stderr, "mcp list failed (%s): %v\n", mcpClient.BaseURL, err)
			return 1
		}
		if *asJSON {
			_ = json.NewEncoder(stdout).Encode(map[string]any{"url": mcpClient.BaseURL, "count": len(tools), "tools": tools})
			return 0
		}
		renderMCPTools(stdout, mcpClient.BaseURL, tools)
		return 0

	case "call":
		fs := flag.NewFlagSet("mcp call", flag.ContinueOnError)
		fs.SetOutput(stderr)
		mcpURL := fs.String("url", endpoints.MCP, "mw-rocksoul-mcp base URL")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		rest := fs.Args()
		if len(rest) == 0 {
			fmt.Fprintln(stderr, "usage: rocksoul mcp call <tool-name> [json-arguments]")
			return 2
		}
		toolName := rest[0]
		toolArgs := map[string]any{}
		if len(rest) > 1 {
			if err := json.Unmarshal([]byte(rest[1]), &toolArgs); err != nil {
				fmt.Fprintf(stderr, "invalid JSON arguments: %v\n", err)
				return 2
			}
		}
		mcpClient := clients.NewMCPClient(*mcpURL, ridToken, &http.Client{Timeout: 15 * time.Second})
		result, err := mcpClient.CallTool(ctx, toolName, toolArgs)
		if err != nil {
			fmt.Fprintf(stderr, "mcp call %s failed: %v\n", toolName, err)
			return 1
		}
		fmt.Fprintln(stdout, result)
		return 0

	default:
		fmt.Fprintf(stderr, "unknown mcp subcommand %q (expected list or call)\n", sub)
		return 2
	}
}

func cmdInitTUI(args []string, stdout, stderr io.Writer) int {
	cfg, _ := clients.LoadUserConfig(clients.DefaultConfigPath())
	endpoints := clients.ResolveEndpoints(cfg)

	fs := flag.NewFlagSet("init-tui", flag.ContinueOnError)
	fs.SetOutput(stderr)
	target := fs.String("target", tuiinit.TargetOpenCode, "TUI target: opencode|crush|codex|all")
	dir := fs.String("dir", ".", "destination project directory")
	gatewayURL := fs.String("gateway", endpoints.Gateway+"/v1", "mw-rocksoul-gateway OpenAI base URL")
	mcpURL := fs.String("mcp", endpoints.MCP+"/mcp", "mw-rocksoul-mcp HTTP endpoint")
	coreURL := fs.String("core", endpoints.Core, "mw-rocksoul-core base URL")
	model := fs.String("model", firstOrDefault(cfg.Model, tuiinit.DefaultModel), "default model name")
	force := fs.Bool("force", false, "overwrite existing config files")
	asJSON := fs.Bool("json", false, "output JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	files, err := tuiinit.Generate(tuiinit.Options{
		Target:     *target,
		Dir:        *dir,
		GatewayURL: *gatewayURL,
		MCPURL:     *mcpURL,
		CoreURL:    *coreURL,
		Model:      *model,
		Force:      *force,
	})
	if err != nil {
		fmt.Fprintf(stderr, "init-tui failed: %v\n", err)
		return 1
	}

	if *asJSON {
		_ = json.NewEncoder(stdout).Encode(map[string]any{
			"target": *target,
			"files":  files,
		})
		return 0
	}
	for _, f := range files {
		fmt.Fprintf(stdout, "Generated %s config: %s (%d bytes)\n", f.Target, f.Path, f.Bytes)
	}
	return 0
}

func firstOrDefault(value, fallback string) string {
	if trimmed := strings.TrimSpace(value); trimmed != "" {
		return trimmed
	}
	return fallback
}

func renderMCPTools(w io.Writer, baseURL string, tools []clients.MCPTool) {
	fmt.Fprintf(w, "MCP Tools (%s) â€” %d available\n", baseURL, len(tools))
	if len(tools) == 0 {
		fmt.Fprintln(w, "  (no tools registered)")
		return
	}
	for _, tool := range tools {
		serverTag := ""
		if tool.Server != "" {
			serverTag = " [" + tool.Server + "]"
		}
		fmt.Fprintf(w, "  - %s%s: %s\n", tool.Name, serverTag, tool.Description)
	}
}

type runtimeFlags struct {
	dir                string
	model              string
	provider           string
	mode               string
	profile            string
	gatewayURL         string
	maxTier            string
	approveToken       string
	dataClassification string
	maxSteps           int
	configPath         string
	asJSON             bool
}

func registerRuntimeFlags(fs *flag.FlagSet, defaults clients.UserConfig) *runtimeFlags {
	rf := &runtimeFlags{}
	fs.StringVar(&rf.dir, "dir", ".", "workspace directory")
	fs.StringVar(&rf.model, "model", defaults.Model, "LLM model name (defaults to config/provider)")
	fs.StringVar(&rf.provider, "provider", defaults.Provider, "provider: auto|gateway|openai|anthropic|gemini|ollama")
	fs.StringVar(&rf.mode, "mode", defaults.Mode, "agent mode: act|plan")
	fs.StringVar(&rf.profile, "profile", agent.DefaultAgentProfile, "X-MW-Agent profile header")
	fs.StringVar(&rf.gatewayURL, "gateway", "", "explicit gateway chat completions URL override")
	fs.StringVar(&rf.maxTier, "max-tier", defaults.MaxAutoTier, "max auto-approved risk tier (R0-R3; R4 always blocked by default)")
	fs.StringVar(&rf.approveToken, "approve-token", "", "optional single-use risk gate approval token")
	fs.StringVar(&rf.dataClassification, "classification", defaults.DataClassification, "data classification: local_only|cloud_eligible")
	fs.IntVar(&rf.maxSteps, "max-steps", agent.DefaultMaxSteps, "maximum ReAct steps per turn")
	fs.StringVar(&rf.configPath, "config", "", "override ~/.rocksoul/config.json path")
	fs.BoolVar(&rf.asJSON, "json", false, "output JSON")
	return rf
}

func cmdRunOrChatShortcut(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	cfg, _ := clients.LoadUserConfig(clients.DefaultConfigPath())
	fs := flag.NewFlagSet("rocksoul", flag.ContinueOnError)
	fs.SetOutput(stderr)
	rf := registerRuntimeFlags(fs, cfg)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if len(fs.Args()) > 0 {
		return executeRunWithFlags(ctx, rf, strings.Join(fs.Args(), " "), stdout, stderr)
	}
	return executeChatWithFlags(ctx, rf, stdin, stdout, stderr)
}

func cmdRun(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	cfg, _ := clients.LoadUserConfig(clients.DefaultConfigPath())
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	rf := registerRuntimeFlags(fs, cfg)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	prompt := strings.TrimSpace(strings.Join(fs.Args(), " "))
	if prompt == "" {
		fmt.Fprintln(stderr, "usage: rocksoul run [flags] <prompt>")
		return 2
	}
	return executeRunWithFlags(ctx, rf, prompt, stdout, stderr)
}

func cmdChat(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	cfg, _ := clients.LoadUserConfig(clients.DefaultConfigPath())
	fs := flag.NewFlagSet("chat", flag.ContinueOnError)
	fs.SetOutput(stderr)
	rf := registerRuntimeFlags(fs, cfg)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	return executeChatWithFlags(ctx, rf, stdin, stdout, stderr)
}

type pendingTokenVault struct {
	mu          sync.Mutex
	byScopeHash map[string]string
	oneShotRaw  string
}

func newPendingTokenVault(initialRaw string) *pendingTokenVault {
	return &pendingTokenVault{
		byScopeHash: make(map[string]string),
		oneShotRaw:  strings.TrimSpace(initialRaw),
	}
}

func (v *pendingTokenVault) Put(scopeHash, token string) {
	v.mu.Lock()
	v.byScopeHash[scopeHash] = token
	v.mu.Unlock()
}

func (v *pendingTokenVault) Resolve(_ context.Context, _ risk.Action, decision risk.Decision) (string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if tok, ok := v.byScopeHash[decision.ScopeHash]; ok {
		delete(v.byScopeHash, decision.ScopeHash)
		return tok, nil
	}
	if v.oneShotRaw != "" {
		tok := v.oneShotRaw
		v.oneShotRaw = ""
		return tok, nil
	}
	return "", nil
}

func buildEngineBundle(
	ctx context.Context,
	rf *runtimeFlags,
	cfg clients.UserConfig,
	tokenVault *pendingTokenVault,
) (*agent.Engine, *risk.Gate, clients.ProviderResolution, clients.Endpoints, error) {
	maxTier := risk.TierR0
	if strings.TrimSpace(rf.maxTier) != "" {
		parsed, err := risk.ParseTier(rf.maxTier)
		if err != nil {
			return nil, nil, clients.ProviderResolution{}, clients.Endpoints{}, err
		}
		if parsed >= risk.TierR4 {
			return nil, nil, clients.ProviderResolution{}, clients.Endpoints{}, errors.New("R4 cannot be auto-approved; use R0-R3 and single-use approval tokens for R4")
		}
		maxTier = parsed
	}

	policy := risk.DefaultPolicy()
	policy.MaxAutoTier = maxTier
	gate := risk.NewGate(policy)

	endpoints := clients.ResolveEndpoints(cfg)
	ridToken := loadSavedAccessToken("")
	resolved := clients.ResolveProvider(ctx, clients.ProviderResolveOptions{
		PreferredProvider:  rf.provider,
		PreferredModel:     rf.model,
		GatewayOverrideURL: rf.gatewayURL,
		Endpoints:          endpoints,
		RIDToken:           ridToken,
		DataClassification: rf.dataClassification,
	})

	mcpClient := clients.NewMCPClient(endpoints.MCP, ridToken, &http.Client{Timeout: 10 * time.Second})

	engine, err := agent.NewEngine(agent.Options{
		DefaultGatewayURL:   resolved.CompletionURL,
		DefaultAgentProfile: rf.profile,
		AuthToken:           resolved.AuthToken,
		DataClassification:  rf.dataClassification,
		HTTPClient:          resolved.HTTPClient,
		MaxSteps:            rf.maxSteps,
		RiskGate:            gate,
		ApprovalResolver:    composeApprovalResolver(tokenVault, buildMobileApprovalBridgeFromEnv(gate)),
		MCPCaller:           mcpClient,
	})
	if err != nil {
		return nil, nil, resolved, endpoints, err
	}
	return engine, gate, resolved, endpoints, nil
}

func buildMobileApprovalBridgeFromEnv(gate *risk.Gate) *clients.MobileApprovalBridge {
	var transports []clients.ApprovalTransport
	if ntfy, err := clients.NewNtfyApprovalTransportFromEnv(); err == nil {
		transports = append(transports, ntfy)
	}
	if tg, err := clients.NewTelegramApprovalTransportFromEnv(); err == nil {
		transports = append(transports, tg)
	}
	if len(transports) == 0 {
		return nil
	}
	return clients.NewMobileApprovalBridge(clients.MobileApprovalOptions{
		Gate:                  gate,
		Transports:            transports,
		CallbackBaseURL:       strings.TrimSpace(os.Getenv("ROCKSOUL_APPROVAL_CALLBACK_URL")),
		Secret:                []byte(strings.TrimSpace(os.Getenv("ROCKSOUL_POCKET_APPROVAL_SECRET"))),
		CallbackToken:         strings.TrimSpace(os.Getenv("ROCKSOUL_APPROVAL_CALLBACK_TOKEN")),
		TelegramWebhookSecret: strings.TrimSpace(os.Getenv("TELEGRAM_WEBHOOK_SECRET")),
	})
}

func composeApprovalResolver(vault *pendingTokenVault, mobile *clients.MobileApprovalBridge) agent.ApprovalResolver {
	return func(ctx context.Context, action risk.Action, decision risk.Decision) (string, error) {
		if vault != nil {
			if tok, err := vault.Resolve(ctx, action, decision); err == nil && strings.TrimSpace(tok) != "" {
				return tok, nil
			}
		}
		if mobile != nil && decision.Tier >= risk.TierR3 {
			return mobile.Resolve(ctx, action, decision)
		}
		return "", nil
	}
}

func executeRunWithFlags(ctx context.Context, rf *runtimeFlags, prompt string, stdout, stderr io.Writer) int {
	cfgPath := resolveConfigPath(rf.configPath)
	cfg, _ := clients.LoadUserConfig(cfgPath)
	vault := newPendingTokenVault(rf.approveToken)

	engine, _, resolved, _, err := buildEngineBundle(ctx, rf, cfg, vault)
	if err != nil {
		fmt.Fprintf(stderr, "init error: %v\n", err)
		return 2
	}

	absDir, err := filepath.Abs(rf.dir)
	if err != nil {
		fmt.Fprintf(stderr, "resolve dir: %v\n", err)
		return 1
	}

	effectivePrompt, _, _ := agent.ResolveAtMentions(ctx, absDir, prompt)

	reply, runErr := engine.RunOneShot(ctx, absDir, rf.profile, resolved.Model, rf.mode, effectivePrompt, func(ev agent.AgentEvent) {
		if rf.asJSON {
			return
		}
		switch ev.Type {
		case "tool_call":
			fmt.Fprintf(stderr, "[step %d] tool -> %s %s\n", ev.Step, ev.ToolName, ev.Arguments)
		case "risk_blocked":
			fmt.Fprintf(stderr, "[risk %s] blocked %s: %s\n", ev.RiskTier, ev.ToolName, ev.Error)
		}
	})
	if runErr != nil {
		if rf.asJSON {
			_ = json.NewEncoder(stdout).Encode(map[string]any{
				"error":    runErr.Error(),
				"provider": resolved.Provider,
				"model":    resolved.Model,
			})
		} else {
			fmt.Fprintf(stderr, "run failed (%s/%s): %v\n", resolved.Provider, resolved.Model, runErr)
		}
		return 1
	}

	if rf.asJSON {
		_ = json.NewEncoder(stdout).Encode(map[string]any{
			"reply":    reply,
			"provider": resolved.Provider,
			"model":    resolved.Model,
			"workDir":  absDir,
		})
	} else {
		fmt.Fprintln(stdout, reply)
	}
	return 0
}

func executeChatWithFlags(ctx context.Context, rf *runtimeFlags, stdin io.Reader, stdout, stderr io.Writer) int {
	cfgPath := resolveConfigPath(rf.configPath)
	cfg, _ := clients.LoadUserConfig(cfgPath)
	vault := newPendingTokenVault(rf.approveToken)

	engine, gate, resolved, endpoints, err := buildEngineBundle(ctx, rf, cfg, vault)
	if err != nil {
		fmt.Fprintf(stderr, "init error: %v\n", err)
		return 2
	}

	absDir, err := filepath.Abs(rf.dir)
	if err != nil {
		fmt.Fprintf(stderr, "resolve dir: %v\n", err)
		return 1
	}

	session, err := engine.CreateSession(ctx, agent.SessionCreateInput{
		Title:        "Rocksoul Interactive Chat",
		WorkDir:      absDir,
		AgentProfile: rf.profile,
		Model:        resolved.Model,
		Mode:         rf.mode,
	})
	if err != nil {
		fmt.Fprintf(stderr, "create session: %v\n", err)
		return 1
	}

	fmt.Fprintf(stdout, "Rocksoul %s | dir=%s | provider=%s (%s) | mode=%s | risk=%s\n",
		Version, absDir, resolved.Provider, session.Model, session.Mode, gate.Policy().MaxAutoTier.String())
	if !resolved.Reachable {
		fmt.Fprintf(stdout, "Note: no live LLM endpoint detected yet (%s). Use /doctor or set OPENAI_API_KEY/ANTHROPIC_API_KEY/GEMINI_API_KEY or start Ollama.\n", resolved.Source)
	}
	fmt.Fprintln(stdout, "Commands: /model, /diff, /risk, /mcp, /clear, /doctor, /plan, /act, /compact, /symbols, /undo, /rewind, /help, /exit")

	scanner := bufio.NewScanner(stdin)
	scanner.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)

	for {
		fmt.Fprintf(stdout, "rocksoul[%s|%s]> ", session.Mode, gate.Policy().MaxAutoTier.String())
		if !scanner.Scan() {
			break
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "/") {
			fields := strings.Fields(line)
			cmd := strings.ToLower(fields[0])
			cmdArgs := fields[1:]

			switch cmd {
			case "/exit", "/quit":
				fmt.Fprintln(stdout, "Bye.")
				return 0

			case "/help":
				fmt.Fprintln(stdout, "Slash commands:")
				fmt.Fprintln(stdout, "  /model [name | provider <p>]     Show or set model/provider (saved to ~/.rocksoul/config.json)")
				fmt.Fprintln(stdout, "  /diff                            Show git status & diff in workspace")
				fmt.Fprintln(stdout, "  /risk [tier <R0-R3>|approve ...] Show risk gate policy, change auto tier, or mint single-use token")
				fmt.Fprintln(stdout, "  /mcp                             List MCP tools from mw-rocksoul-mcp (:4530)")
				fmt.Fprintln(stdout, "  /clear                           Start a fresh conversation session")
				fmt.Fprintln(stdout, "  /doctor                          Probe gateway/core/mcp/sandbox/rid/ollama/git")
				fmt.Fprintln(stdout, "  /plan | /act | /compact          Switch agent mode or compact conversation history")
				fmt.Fprintln(stdout, "  /symbols [query]                 Search workspace symbols")
				fmt.Fprintln(stdout, "  /undo | /rewind [id]             Revert last turn checkpoint or rewind to a listed one")
				fmt.Fprintln(stdout, "  /exit                            Exit interactive chat")
				continue

			case "/undo":
				restored, undoErr := agent.UndoLastCheckpoint(ctx, session.WorkDir)
				if undoErr != nil {
					fmt.Fprintf(stdout, "Undo failed: %v\n", undoErr)
					continue
				}
				fmt.Fprintf(stdout, "Reverted to checkpoint %s (%s)\n", restored.ID, restored.Label)
				continue

			case "/rewind":
				checkpoints, listErr := agent.ListCheckpoints(session.WorkDir)
				if listErr != nil {
					fmt.Fprintf(stdout, "Rewind failed: %v\n", listErr)
					continue
				}
				if len(cmdArgs) == 0 {
					for _, checkpoint := range checkpoints {
						fmt.Fprintf(stdout, "%s  %s  (%d files)\n", checkpoint.ID, checkpoint.Label, len(checkpoint.Files))
					}
					fmt.Fprintln(stdout, "Usage: /rewind <checkpoint-id>")
					continue
				}
				restored, rewindErr := agent.RestoreCheckpoint(ctx, session.WorkDir, cmdArgs[0])
				if rewindErr != nil {
					fmt.Fprintf(stdout, "Rewind failed: %v\n", rewindErr)
					continue
				}
				fmt.Fprintf(stdout, "Rewound to checkpoint %s (%s)\n", restored.ID, restored.Label)
				continue

			case "/diff":
				diffOut := runWorkspaceGitDiff(ctx, session.WorkDir)
				fmt.Fprintln(stdout, diffOut)
				continue

			case "/model":
				if len(cmdArgs) == 0 {
					fmt.Fprintf(stdout, "Active provider=%s model=%s endpoint=%s\n", resolved.Provider, session.Model, resolved.CompletionURL)
					continue
				}
				if strings.EqualFold(cmdArgs[0], "provider") && len(cmdArgs) >= 2 {
					newProvider := strings.ToLower(strings.TrimSpace(cmdArgs[1]))
					rf.provider = newProvider
					cfg.Provider = newProvider
					_ = clients.SaveUserConfig(cfgPath, cfg)
					newEngine, newGate, newResolved, newEndpoints, rebuildErr := buildEngineBundle(ctx, rf, cfg, vault)
					if rebuildErr != nil {
						fmt.Fprintf(stdout, "Switch provider failed: %v\n", rebuildErr)
						continue
					}
					engine, gate, resolved, endpoints = newEngine, newGate, newResolved, newEndpoints
					session, _ = engine.CreateSession(ctx, agent.SessionCreateInput{
						Title:        session.Title,
						WorkDir:      session.WorkDir,
						AgentProfile: session.AgentProfile,
						Model:        resolved.Model,
						Mode:         session.Mode,
					})
					fmt.Fprintf(stdout, "Switched provider=%s model=%s (%s) and saved to %s\n", resolved.Provider, session.Model, resolved.CompletionURL, cfgPath)
					continue
				}
				newModel := strings.TrimSpace(strings.Join(cmdArgs, " "))
				updated, err := engine.UpdateSession(ctx, session.ID, agent.SessionPatchInput{Model: &newModel})
				if err != nil {
					fmt.Fprintf(stdout, "Update model failed: %v\n", err)
					continue
				}
				session = updated
				resolved.Model = newModel
				rf.model = newModel
				cfg.Model = newModel
				if saveErr := clients.SaveUserConfig(cfgPath, cfg); saveErr != nil {
					fmt.Fprintf(stderr, "warning: save config: %v\n", saveErr)
				}
				fmt.Fprintf(stdout, "Model set to %q (saved to %s)\n", newModel, cfgPath)
				continue

			case "/risk":
				if len(cmdArgs) == 0 {
					fmt.Fprintln(stdout, gate.FormatPolicySummary())
					continue
				}
				sub := strings.ToLower(cmdArgs[0])
				switch sub {
				case "tier":
					if len(cmdArgs) < 2 {
						fmt.Fprintln(stdout, "Usage: /risk tier <R0|R1|R2|R3>")
						continue
					}
					parsedTier, err := risk.ParseTier(cmdArgs[1])
					if err != nil {
						fmt.Fprintf(stdout, "Error: %v\n", err)
						continue
					}
					if err := gate.SetMaxAutoTier(parsedTier); err != nil {
						fmt.Fprintf(stdout, "Error: %v\n", err)
						continue
					}
					cfg.MaxAutoTier = parsedTier.String()
					_ = clients.SaveUserConfig(cfgPath, cfg)
					fmt.Fprintf(stdout, "Risk gate auto-approval tier updated to %s (%s). R4 remains blocked by default.\n", parsedTier.String(), parsedTier.Description())
				case "approve":
					if len(cmdArgs) < 2 {
						fmt.Fprintln(stdout, "Usage: /risk approve <tool> [path-or-command]")
						continue
					}
					toolName := cmdArgs[1]
					target := strings.TrimSpace(strings.Join(cmdArgs[2:], " "))
					action := risk.Action{Tool: toolName, WorkDir: session.WorkDir}
					if toolName == "run_shell" || toolName == "sandbox_exec" {
						action.Command = target
					} else if toolName == "mcp_call" {
						action.RemoteTarget = target
					} else {
						action.Path = target
					}
					tok, err := gate.IssueApprovalToken(action, 5*time.Minute, "interactive-chat")
					if err != nil {
						fmt.Fprintf(stdout, "Failed to issue token: %v\n", err)
						continue
					}
					vault.Put(tok.ScopeHash, tok.Token)
					fmt.Fprintf(stdout, "Issued single-use approval token %s (tier=%s, expires=%s) for tool=%s target=%q\n",
						tok.ID, tok.TierLabel, tok.ExpiresAt.Format(time.RFC3339), toolName, target)
				default:
					fmt.Fprintln(stdout, gate.FormatPolicySummary())
				}
				continue

			case "/mcp":
				mcpClient := clients.NewMCPClient(endpoints.MCP, loadSavedAccessToken(""), &http.Client{Timeout: 4 * time.Second})
				tools, mcpErr := mcpClient.ListTools(ctx)
				if mcpErr != nil {
					fmt.Fprintf(stdout, "MCP unreachable (%s): %v\n", mcpClient.BaseURL, mcpErr)
					continue
				}
				renderMCPTools(stdout, mcpClient.BaseURL, tools)
				continue

			case "/clear":
				fresh, createErr := engine.CreateSession(ctx, agent.SessionCreateInput{
					Title:        "Rocksoul Interactive Chat",
					WorkDir:      session.WorkDir,
					AgentProfile: session.AgentProfile,
					Model:        session.Model,
					Mode:         session.Mode,
				})
				if createErr != nil {
					fmt.Fprintf(stdout, "Failed to clear session: %v\n", createErr)
					continue
				}
				session = fresh
				fmt.Fprintf(stdout, "Cleared conversation history (new session %s).\n", session.ID)
				continue

			case "/doctor":
				report := collectDoctorReport(ctx, cfg, cfgPath)
				renderDoctorReport(stdout, report)
				continue

			case "/symbols":
				query := strings.TrimSpace(strings.Join(cmdArgs, " "))
				symbols, symErr := agent.SearchWorkspaceSymbols(session.WorkDir, query, 30)
				if symErr != nil {
					fmt.Fprintf(stdout, "Symbol search error: %v\n", symErr)
					continue
				}
				if len(symbols) == 0 {
					fmt.Fprintln(stdout, "No matching workspace symbols.")
					continue
				}
				for _, sym := range symbols {
					fmt.Fprintf(stdout, "  %s:%d [%s/%s] %s\n", sym.FilePath, sym.Line, sym.Language, sym.Kind, sym.Name)
				}
				continue
			}
		}

		effectiveLine, _, _ := agent.ResolveAtMentions(ctx, session.WorkDir, line)

		outcome, runErr := engine.RunPromptWithCallback(ctx, session.ID, effectiveLine, func(ev agent.AgentEvent) {
			switch ev.Type {
			case "tool_call":
				fmt.Fprintf(stderr, "  [tool] %s %s\n", ev.ToolName, ev.Arguments)
			case "risk_blocked":
				fmt.Fprintf(stderr, "  [risk %s] blocked %s: %s (use /risk approve %s <target>)\n", ev.RiskTier, ev.ToolName, ev.Error, ev.ToolName)
			}
		})
		if runErr != nil {
			fmt.Fprintf(stdout, "Error: %v\n", runErr)
			continue
		}
		session = outcome.Session
		fmt.Fprintln(stdout, outcome.Reply)
	}
	return 0
}

func runWorkspaceGitDiff(ctx context.Context, workDir string) string {
	cmdCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	statusCmd := exec.CommandContext(cmdCtx, "git", "status", "--short")
	statusCmd.Dir = workDir
	statusOut, statusErr := statusCmd.CombinedOutput()
	if statusErr != nil {
		return fmt.Sprintf("git diff unavailable in %s: %s", workDir, strings.TrimSpace(string(statusOut)))
	}

	diffCmd := exec.CommandContext(cmdCtx, "git", "diff")
	diffCmd.Dir = workDir
	diffOut, _ := diffCmd.CombinedOutput()

	statusText := strings.TrimSpace(string(statusOut))
	diffText := strings.TrimSpace(string(diffOut))
	if statusText == "" && diffText == "" {
		return "Working tree clean (no diff)."
	}
	var b strings.Builder
	if statusText != "" {
		fmt.Fprintf(&b, "Status:\n%s\n", statusText)
	}
	if diffText != "" {
		if len(diffText) > 8192 {
			diffText = diffText[:8192] + "\n... (diff truncated)"
		}
		fmt.Fprintf(&b, "\nDiff:\n%s", diffText)
	}
	return strings.TrimRight(b.String(), "\n")
}

func resolveConfigPath(flagVal string) string {
	if strings.TrimSpace(flagVal) != "" {
		return strings.TrimSpace(flagVal)
	}
	return clients.DefaultConfigPath()
}

func loadSavedAccessToken(tokenPath string) string {
	tok, err := clients.LoadTokenSet(tokenPath)
	if err != nil {
		return ""
	}
	if !tok.ExpiresAt.IsZero() && time.Now().UTC().After(tok.ExpiresAt) {
		return ""
	}
	return strings.TrimSpace(tok.AccessToken)
}

func cmdPlan(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: rocksoul plan next|run|status [--dir <path>]")
		return 2
	}
	sub := strings.ToLower(strings.TrimSpace(args[0]))

	fs := flag.NewFlagSet("plan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfg, _ := clients.LoadUserConfig(clients.DefaultConfigPath())
	rf := registerRuntimeFlags(fs, cfg)
	loopFlag := fs.Bool("loop", false, "execute all ready tasks sequentially until done or blocked")
	commitFlag := fs.Bool("commit", false, "create path-scoped git commit after each verified task")
	verifyCmd := fs.String("verify", "", "verification command to run before committing each task")
	maxTasks := fs.Int("max-tasks", 0, "maximum number of tasks to execute in --loop mode (0 = unlimited)")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}

	absDir, err := filepath.Abs(rf.dir)
	if err != nil {
		fmt.Fprintf(stderr, "resolve dir: %v\n", err)
		return 1
	}

	plan, err := agent.LoadPlan(absDir)
	if err != nil {
		fmt.Fprintf(stderr, "load plan: %v\n", err)
		return 1
	}

	switch sub {
	case "status":
		if plan == nil {
			fmt.Fprintf(stdout, "No plan found at %s\n", agent.PlanFilePath(absDir))
			return 0
		}
		if rf.asJSON {
			enc := json.NewEncoder(stdout)
			enc.SetIndent("", "  ")
			_ = enc.Encode(plan)
			return 0
		}
		fmt.Fprintf(stdout, "Plan %s [%s] (%d tasks)\n", plan.ID, plan.Status, len(plan.Tasks))
		for _, t := range plan.Tasks {
			fmt.Fprintf(stdout, "  [%s] %s: %s\n", t.Status, t.ID, t.Title)
		}
		return 0

	case "next":
		if plan == nil {
			fmt.Fprintf(stdout, "No plan found at %s\n", agent.PlanFilePath(absDir))
			return 1
		}
		ready := plan.NextReadyTask()
		if ready == nil {
			fmt.Fprintln(stdout, "No tasks ready to execute.")
			return 0
		}
		if rf.asJSON {
			_ = json.NewEncoder(stdout).Encode(ready)
			return 0
		}
		fmt.Fprintf(stdout, "Next ready task: [%s] %s: %s\n", ready.Status, ready.ID, ready.Title)
		if len(ready.OwnerFiles) > 0 {
			fmt.Fprintf(stdout, "Owner files: %s\n", strings.Join(ready.OwnerFiles, ", "))
		}
		return 0

	case "run":
		if plan == nil {
			fmt.Fprintf(stdout, "No plan found at %s\n", agent.PlanFilePath(absDir))
			return 1
		}
		vault := newPendingTokenVault(rf.approveToken)
		engine, _, resolved, _, err := buildEngineBundle(ctx, rf, cfg, vault)
		if err != nil {
			fmt.Fprintf(stderr, "engine init error: %v\n", err)
			return 2
		}

		loopResult, runErr := agent.RunTaskOSLoopWithOptions(ctx, engine, absDir, agent.TaskOSLoopOptions{
			Model:         resolved.Model,
			Loop:          *loopFlag,
			Commit:        *commitFlag,
			VerifyCommand: *verifyCmd,
			MaxTasks:      *maxTasks,
			Callback: func(ev agent.AgentEvent) {
				if rf.asJSON {
					return
				}
				switch ev.Type {
				case "tool_call":
					fmt.Fprintf(stderr, "  [tool] %s %s\n", ev.ToolName, ev.Arguments)
				case "risk_blocked":
					fmt.Fprintf(stderr, "  [risk %s] blocked %s: %s\n", ev.RiskTier, ev.ToolName, ev.Error)
				}
			},
		})
		if runErr != nil {
			if rf.asJSON && loopResult != nil {
				_ = json.NewEncoder(stdout).Encode(map[string]any{
					"error":  runErr.Error(),
					"result": loopResult,
				})
			} else {
				fmt.Fprintf(stderr, "Task execution failed: %v\n", runErr)
			}
			return 1
		}
		if loopResult == nil || len(loopResult.ExecutedTasks) == 0 {
			if rf.asJSON {
				_ = json.NewEncoder(stdout).Encode(agent.TaskOSLoopResult{PlanStatus: plan.Status})
			} else {
				fmt.Fprintln(stdout, "No tasks ready to run.")
			}
			return 0
		}
		if rf.asJSON {
			_ = json.NewEncoder(stdout).Encode(loopResult)
			return 0
		}
		for _, executed := range loopResult.ExecutedTasks {
			if executed.CommitSHA != "" {
				fmt.Fprintf(stdout, "Executed task %s (%s) [commit %s]: %s\n", executed.ID, executed.Status, executed.CommitSHA[:7], executed.Title)
			} else {
				fmt.Fprintf(stdout, "Executed task %s (%s): %s\n", executed.ID, executed.Status, executed.Title)
			}
		}
		return 0

	default:
		fmt.Fprintf(stderr, "unknown plan subcommand: %s. Valid subcommands: next, run, status\n", sub)
		return 2
	}
}
