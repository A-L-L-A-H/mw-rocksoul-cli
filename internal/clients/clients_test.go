package clients

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
)

func TestGatewayCoreMCPSandboxClients(t *testing.T) {
	// 1. Gateway mock (:4510)
	gwSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok-gw" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/health":
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok", "service": "mw-rocksoul-gateway"})
		case "/v1/models":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]any{{"id": "local/qwen2.5-coder"}}})
		case "/v1/usage":
			_ = json.NewEncoder(w).Encode(map[string]any{"totalRequests": 3})
		case "/v1/local-providers":
			_ = json.NewEncoder(w).Encode(map[string]any{"providers": []map[string]any{{"name": "ollama", "baseUrl": "http://127.0.0.1:11434", "reachable": true}}})
		case "/v1/chat/completions":
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "cmpl_1", "model": "auto"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer gwSrv.Close()

	gw := NewGatewayClient(gwSrv.URL, "tok-gw", gwSrv.Client())
	if h, err := gw.Health(context.Background()); err != nil || h.Status != "ok" {
		t.Fatalf("Gateway.Health: %+v err=%v", h, err)
	}
	if models, err := gw.ListModels(context.Background()); err != nil || len(models) != 1 || models[0].ID != "local/qwen2.5-coder" {
		t.Fatalf("Gateway.ListModels: %+v err=%v", models, err)
	}
	if providers, err := gw.LocalProviders(context.Background()); err != nil || len(providers) != 1 || !providers[0].Reachable {
		t.Fatalf("Gateway.LocalProviders: %+v err=%v", providers, err)
	}
	if usage, err := gw.Usage(context.Background()); err != nil || usage["totalRequests"] == nil {
		t.Fatalf("Gateway.Usage: %+v err=%v", usage, err)
	}
	if comp, _, err := gw.ChatCompletions(context.Background(), map[string]any{"model": "auto"}); err != nil || comp["id"] != "cmpl_1" {
		t.Fatalf("Gateway.ChatCompletions: %+v err=%v", comp, err)
	}

	// 2. Core mock (:4520)
	coreSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/health":
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok"})
		case "/v1/plans/validate":
			_ = json.NewEncoder(w).Encode(map[string]any{"valid": true, "order": []string{"n1", "n2"}})
		case "/v1/risk/evaluate":
			_ = json.NewEncoder(w).Encode(map[string]any{"tier": "R1", "allowed": true})
		case "/v1/pcw/verify":
			_ = json.NewEncoder(w).Encode(map[string]any{"verified": true})
		case "/v1/swarm/check-overlap":
			_ = json.NewEncoder(w).Encode(map[string]any{"hasOverlap": false})
		case "/v1/evals/g0-g6":
			_ = json.NewEncoder(w).Encode(map[string]any{"passed": true})
		default:
			http.NotFound(w, r)
		}
	}))
	defer coreSrv.Close()

	core := NewCoreClient(coreSrv.URL, "", coreSrv.Client())
	if h, err := core.Health(context.Background()); err != nil || h.Status != "ok" {
		t.Fatalf("Core.Health: %+v err=%v", h, err)
	}
	if out, err := core.ValidatePlan(context.Background(), map[string]any{"nodes": []any{}}); err != nil || out["valid"] != true {
		t.Fatalf("Core.ValidatePlan: %+v err=%v", out, err)
	}
	if out, err := core.EvaluateRisk(context.Background(), map[string]any{"tool": "write_file"}); err != nil || out["tier"] != "R1" {
		t.Fatalf("Core.EvaluateRisk: %+v err=%v", out, err)
	}
	if out, err := core.VerifyPCW(context.Background(), map[string]any{"root": "abc"}); err != nil || out["verified"] != true {
		t.Fatalf("Core.VerifyPCW: %+v err=%v", out, err)
	}
	if out, err := core.CheckSwarmOverlap(context.Background(), map[string]any{}); err != nil || out["hasOverlap"] != false {
		t.Fatalf("Core.CheckSwarmOverlap: %+v err=%v", out, err)
	}
	if out, err := core.RunEvalsG0G6(context.Background(), map[string]any{}); err != nil || out["passed"] != true {
		t.Fatalf("Core.RunEvalsG0G6: %+v err=%v", out, err)
	}

	// 3. MCP mock (:4530)
	mcpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/health":
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok"})
		case "/mcp/tools":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"tools": []map[string]any{
					{"name": "mw_echo.health", "description": "Probe mw-echo", "server": "mw-echo"},
				},
			})
		case "/mcp/rpc":
			var rpcReq struct {
				ID     any            `json:"id"`
				Method string         `json:"method"`
				Params map[string]any `json:"params"`
			}
			_ = json.NewDecoder(r.Body).Decode(&rpcReq)
			if rpcReq.Params["name"] == "fail_tool" {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"jsonrpc": "2.0",
					"id":      rpcReq.ID,
					"error":   map[string]any{"code": -32602, "message": "invalid params"},
				})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      rpcReq.ID,
				"result":  map[string]any{"ok": true, "tool": rpcReq.Params["name"]},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer mcpSrv.Close()

	mcp := NewMCPClient(mcpSrv.URL, "", mcpSrv.Client())
	if tools, err := mcp.ListTools(context.Background()); err != nil || len(tools) != 1 || tools[0].Name != "mw_echo.health" {
		t.Fatalf("MCP.ListTools: %+v err=%v", tools, err)
	}
	if res, err := mcp.CallTool(context.Background(), "mw_echo.health", map[string]any{}); err != nil || !strings.Contains(res, `"ok":true`) {
		t.Fatalf("MCP.CallTool: %q err=%v", res, err)
	}
	if _, err := mcp.CallTool(context.Background(), "fail_tool", nil); err == nil || !strings.Contains(err.Error(), "-32602") {
		t.Fatalf("expected JSON-RPC error for fail_tool, got %v", err)
	}

	// 4. Sandbox mock (:4540)
	var releasedID string
	sbSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/health":
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok"})
		case r.Method == http.MethodPost && r.URL.Path == "/leases":
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "lease_42", "fencingToken": 7, "worktreePath": "/tmp/wt42"})
		case r.Method == http.MethodPost && r.URL.Path == "/exec":
			var req SandboxExecRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			if req.FencingToken != 7 {
				http.Error(w, "stale fencing token", http.StatusConflict)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"exitCode": 0, "stdout": "clean-output", "redacted": true})
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/leases/"):
			releasedID = strings.TrimPrefix(r.URL.Path, "/leases/")
			_ = json.NewEncoder(w).Encode(map[string]any{"released": true})
		default:
			http.NotFound(w, r)
		}
	}))
	defer sbSrv.Close()

	sb := NewSandboxClient(sbSrv.URL, "", sbSrv.Client())
	lease, err := sb.CreateLease(context.Background(), LeaseRequest{Owner: "rs-cli"})
	if err != nil || lease.ID != "lease_42" || lease.FencingToken != 7 {
		t.Fatalf("Sandbox.CreateLease: %+v err=%v", lease, err)
	}
	execRes, err := sb.Exec(context.Background(), SandboxExecRequest{LeaseID: lease.ID, FencingToken: lease.FencingToken, Command: "go", Args: []string{"version"}})
	if err != nil || execRes.ExitCode != 0 || execRes.Stdout != "clean-output" {
		t.Fatalf("Sandbox.Exec: %+v err=%v", execRes, err)
	}
	if err := sb.ReleaseLease(context.Background(), lease.ID); err != nil || releasedID != "lease_42" {
		t.Fatalf("Sandbox.ReleaseLease: released=%q err=%v", releasedID, err)
	}
}

func TestRIDClientPKCEAndTokenPersistence(t *testing.T) {
	pkce, err := GeneratePKCE()
	if err != nil {
		t.Fatalf("GeneratePKCE: %v", err)
	}
	if pkce.Method != "S256" || len(pkce.CodeVerifier) < 43 {
		t.Fatalf("unexpected PKCE pair: %+v", pkce)
	}
	// Independently verify RFC 7636 S256 digest.
	sum := sha256.Sum256([]byte(pkce.CodeVerifier))
	wantChallenge := base64.RawURLEncoding.EncodeToString(sum[:])
	if pkce.CodeChallenge != wantChallenge {
		t.Fatalf("PKCE S256 mismatch: got %q want %q", pkce.CodeChallenge, wantChallenge)
	}

	var ridURL string
	ridSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(OIDCDiscovery{
				Issuer:                ridURL,
				AuthorizationEndpoint: ridURL + "/auth",
				TokenEndpoint:         ridURL + "/token",
				UserinfoEndpoint:      ridURL + "/me",
				JWKSURI:               ridURL + "/jwks",
			})
		case "/token":
			_ = r.ParseForm()
			if r.FormValue("grant_type") != "authorization_code" || r.FormValue("code_verifier") != pkce.CodeVerifier {
				http.Error(w, "invalid pkce", http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token":  "eyJ_access_sample_token",
				"refresh_token": "rt_sample",
				"token_type":    "Bearer",
				"expires_in":    3600,
			})
		case "/me":
			if r.Header.Get("Authorization") != "Bearer eyJ_access_sample_token" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"sub": "rid_user_1", "email": "dev@moonwitness.local"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer ridSrv.Close()
	ridURL = ridSrv.URL

	rid := NewRIDClient(ridSrv.URL, ridSrv.Client())
	doc, err := rid.Discover(context.Background())
	if err != nil || doc.TokenEndpoint != ridSrv.URL+"/token" {
		t.Fatalf("RID.Discover: %+v err=%v", doc, err)
	}

	authURL, err := rid.BuildAuthorizationURL(doc.AuthorizationEndpoint, PKCEAuthConfig{
		ClientID:    "rocksoul-cli",
		RedirectURI: "http://127.0.0.1:4599/callback",
		Scope:       "openid profile",
	}, pkce)
	if err != nil {
		t.Fatalf("BuildAuthorizationURL: %v", err)
	}
	parsedURL, _ := url.Parse(authURL)
	if parsedURL.Query().Get("code_challenge_method") != "S256" || parsedURL.Query().Get("code_challenge") != pkce.CodeChallenge {
		t.Fatalf("auth URL missing PKCE parameters: %s", authURL)
	}

	tok, err := rid.ExchangeCode(context.Background(), doc.TokenEndpoint, TokenExchangeRequest{
		ClientID:     "rocksoul-cli",
		Code:         "auth-code-123",
		RedirectURI:  "http://127.0.0.1:4599/callback",
		CodeVerifier: pkce.CodeVerifier,
	})
	if err != nil || tok.AccessToken != "eyJ_access_sample_token" {
		t.Fatalf("RID.ExchangeCode: %+v err=%v", tok, err)
	}

	claims, err := rid.UserInfo(context.Background(), tok.AccessToken)
	if err != nil || claims["sub"] != "rid_user_1" {
		t.Fatalf("RID.UserInfo: %+v err=%v", claims, err)
	}
	tok.Subject = "rid_user_1"

	tokenPath := filepath.Join(t.TempDir(), "token.json")
	if err := SaveTokenSet(tokenPath, tok); err != nil {
		t.Fatalf("SaveTokenSet: %v", err)
	}
	loaded, err := LoadTokenSet(tokenPath)
	if err != nil || loaded.AccessToken != tok.AccessToken || loaded.Subject != "rid_user_1" {
		t.Fatalf("LoadTokenSet: %+v err=%v", loaded, err)
	}
}

func TestResolveProviderAutoFallbackCascade(t *testing.T) {
	// Mock healthy gateway -> wins over everything.
	gwSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer gwSrv.Close()

	// Mock healthy Ollama -> returns coding model.
	ollamaSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"models": []map[string]any{{"name": "qwen2.5-coder:7b"}},
		})
	}))
	defer ollamaSrv.Close()

	emptyEnv := func(string) string { return "" }

	// 1. Healthy gateway takes top priority.
	resGW := ResolveProvider(context.Background(), ProviderResolveOptions{
		Endpoints:   Endpoints{Gateway: gwSrv.URL, Ollama: ollamaSrv.URL},
		ProbeClient: gwSrv.Client(),
		EnvLookup: func(k string) string {
			if k == "OPENAI_API_KEY" {
				return "sk-test"
			}
			return ""
		},
	})
	if resGW.Provider != ProviderGateway || !resGW.Reachable {
		t.Fatalf("expected gateway priority, got %+v", resGW)
	}

	// 2. Offline gateway -> falls back to OPENAI_API_KEY.
	deadGW := "http://127.0.0.1:1"
	resOpenAI := ResolveProvider(context.Background(), ProviderResolveOptions{
		Endpoints: Endpoints{Gateway: deadGW, Ollama: ollamaSrv.URL},
		EnvLookup: func(k string) string {
			if k == "OPENAI_API_KEY" {
				return "sk-openai-123"
			}
			return ""
		},
	})
	if resOpenAI.Provider != ProviderOpenAI || resOpenAI.AuthToken != "sk-openai-123" || !resOpenAI.Reachable {
		t.Fatalf("expected OpenAI fallback, got %+v", resOpenAI)
	}

	// 3. Offline gateway + ANTHROPIC_API_KEY -> falls back to Anthropic with adapter transport.
	resAnthropic := ResolveProvider(context.Background(), ProviderResolveOptions{
		Endpoints: Endpoints{Gateway: deadGW, Ollama: ollamaSrv.URL},
		EnvLookup: func(k string) string {
			if k == "ANTHROPIC_API_KEY" {
				return "sk-ant-123"
			}
			return ""
		},
	})
	if resAnthropic.Provider != ProviderAnthropic || !strings.HasSuffix(resAnthropic.CompletionURL, "/v1/messages") {
		t.Fatalf("expected Anthropic fallback, got %+v", resAnthropic)
	}

	// 4. Offline gateway + GEMINI_API_KEY -> falls back to Gemini OpenAI-compatible endpoint.
	resGemini := ResolveProvider(context.Background(), ProviderResolveOptions{
		Endpoints: Endpoints{Gateway: deadGW, Ollama: ollamaSrv.URL},
		EnvLookup: func(k string) string {
			if k == "GEMINI_API_KEY" {
				return "AIza-test"
			}
			return ""
		},
	})
	if resGemini.Provider != ProviderGemini || resGemini.AuthToken != "AIza-test" {
		t.Fatalf("expected Gemini fallback, got %+v", resGemini)
	}

	// 5. Offline gateway + no API keys (or local_only) -> falls back to local Ollama and auto-picks qwen2.5-coder:7b!
	resOllama := ResolveProvider(context.Background(), ProviderResolveOptions{
		Endpoints:          Endpoints{Gateway: deadGW, Ollama: ollamaSrv.URL},
		ProbeClient:        ollamaSrv.Client(),
		DataClassification: "local_only",
		EnvLookup: func(k string) string {
			if k == "OPENAI_API_KEY" {
				return "sk-should-be-skipped-in-local-only"
			}
			return ""
		},
	})
	if resOllama.Provider != ProviderOllama || resOllama.Model != "qwen2.5-coder:7b" || !resOllama.Reachable {
		t.Fatalf("expected local Ollama fallback with qwen2.5-coder:7b, got %+v", resOllama)
	}

	// 6. Config persistence roundtrip.
	cfgPath := filepath.Join(t.TempDir(), "config.json")
	if err := SaveUserConfig(cfgPath, UserConfig{Provider: "ollama", Model: "qwen2.5-coder:7b", MaxAutoTier: "R1"}); err != nil {
		t.Fatalf("SaveUserConfig: %v", err)
	}
	loadedCfg, err := LoadUserConfig(cfgPath)
	if err != nil || loadedCfg.Model != "qwen2.5-coder:7b" || loadedCfg.MaxAutoTier != "R1" {
		t.Fatalf("LoadUserConfig: %+v err=%v", loadedCfg, err)
	}
	_ = emptyEnv
}

func TestAnthropicAdapterTransport(t *testing.T) {
	mockAnthropic := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-api-key") != "ant-key" || r.Header.Get("anthropic-version") != "2023-06-01" {
			http.Error(w, "missing anthropic headers", http.StatusUnauthorized)
			return
		}
		var req map[string]any
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req["system"] != "Be concise." {
			http.Error(w, "missing system prompt", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":    "msg_1",
			"model": "claude-sonnet-4-20250514",
			"content": []map[string]any{
				{"type": "text", "text": "Checking file."},
				{"type": "tool_use", "id": "toolu_1", "name": "read_file", "input": map[string]any{"path": "README.md"}},
			},
			"usage": map[string]int{"input_tokens": 25, "output_tokens": 12},
		})
	}))
	defer mockAnthropic.Close()

	client := &http.Client{
		Transport: &AnthropicAdapterTransport{
			Base:   mockAnthropic.Client().Transport,
			APIKey: "ant-key",
		},
	}
	openaiReq := `{"model":"claude-sonnet-4-20250514","messages":[{"role":"system","content":"Be concise."},{"role":"user","content":"read README"}]}`
	resp, err := client.Post(mockAnthropic.URL+"/v1/messages", "application/json", bytes.NewBufferString(openaiReq))
	if err != nil {
		t.Fatalf("AnthropicAdapter Post: %v", err)
	}
	defer resp.Body.Close()

	var decoded struct {
		Choices []struct {
			Message struct {
				Content   string `json:"content"`
				ToolCalls []struct {
					ID       string `json:"id"`
					Function struct {
						Name      string `json:"name"`
						Arguments string `json:"arguments"`
					} `json:"function"`
				} `json:"tool_calls"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		t.Fatalf("decode translated response: %v", err)
	}
	if len(decoded.Choices) != 1 || decoded.Choices[0].Message.Content != "Checking file." || len(decoded.Choices[0].Message.ToolCalls) != 1 {
		t.Fatalf("unexpected translated payload: %+v", decoded)
	}
	if decoded.Choices[0].Message.ToolCalls[0].Function.Name != "read_file" {
		t.Fatalf("unexpected tool name: %+v", decoded.Choices[0].Message.ToolCalls[0])
	}
}
