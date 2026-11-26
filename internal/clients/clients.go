package clients

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
)

const (
	DefaultGatewayBaseURL = "http://127.0.0.1:4510"
	DefaultCoreBaseURL    = "http://127.0.0.1:4520"
	DefaultMCPBaseURL     = "http://127.0.0.1:4530"
	DefaultSandboxBaseURL = "http://127.0.0.1:4540"
	DefaultRIDBaseURL     = "http://127.0.0.1:4480"
	DefaultOllamaBaseURL  = "http://127.0.0.1:11434"
)

// Endpoints holds resolved service base URLs for the Rocksoul & MoonWitness ecosystem.
type Endpoints struct {
	Gateway string `json:"gateway"`
	Core    string `json:"core"`
	MCP     string `json:"mcp"`
	Sandbox string `json:"sandbox"`
	RID     string `json:"rid"`
	Ollama  string `json:"ollama"`
}

// ResolveEndpoints resolves service base URLs using explicit overrides, config values, env vars, and defaults.
func ResolveEndpoints(cfg UserConfig) Endpoints {
	return Endpoints{
		Gateway: cleanBaseURL(firstNonEmpty(os.Getenv("ROCKSOUL_GATEWAY_URL"), cfg.GatewayURL, DefaultGatewayBaseURL)),
		Core:    cleanBaseURL(firstNonEmpty(os.Getenv("ROCKSOUL_CORE_URL"), cfg.CoreURL, DefaultCoreBaseURL)),
		MCP:     cleanBaseURL(firstNonEmpty(os.Getenv("ROCKSOUL_MCP_URL"), cfg.MCPURL, DefaultMCPBaseURL)),
		Sandbox: cleanBaseURL(firstNonEmpty(os.Getenv("ROCKSOUL_SANDBOX_URL"), cfg.SandboxURL, DefaultSandboxBaseURL)),
		RID:     cleanBaseURL(firstNonEmpty(os.Getenv("ROCKSOUL_RID_URL"), os.Getenv("MW_RID_URL"), cfg.RIDURL, DefaultRIDBaseURL)),
		Ollama:  cleanBaseURL(firstNonEmpty(os.Getenv("OLLAMA_HOST"), cfg.OllamaURL, DefaultOllamaBaseURL)),
	}
}

func cleanBaseURL(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	if !strings.Contains(trimmed, "://") {
		trimmed = "http://" + trimmed
	}
	return strings.TrimRight(trimmed, "/")
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

// HealthStatus captures a generic service health response payload.
type HealthStatus struct {
	Status  string         `json:"status"`
	Service string         `json:"service,omitempty"`
	Version string         `json:"version,omitempty"`
	Raw     map[string]any `json:"raw,omitempty"`
}

// ProbeResult captures latency and reachability for doctor diagnostics.
type ProbeResult struct {
	Name       string `json:"name"`
	URL        string `json:"url"`
	Healthy    bool   `json:"healthy"`
	StatusCode int    `json:"statusCode,omitempty"`
	LatencyMS  int64  `json:"latencyMs"`
	Detail     string `json:"detail,omitempty"`
	Error      string `json:"error,omitempty"`
}

// ProbeEndpoint executes a bounded HTTP GET probe against url.
func ProbeEndpoint(ctx context.Context, httpClient *http.Client, name, probeURL string) ProbeResult {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 2 * time.Second}
	}
	started := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
	if err != nil {
		return ProbeResult{Name: name, URL: probeURL, LatencyMS: time.Since(started).Milliseconds(), Error: err.Error()}
	}
	resp, err := httpClient.Do(req)
	latency := time.Since(started).Milliseconds()
	if err != nil {
		return ProbeResult{Name: name, URL: probeURL, LatencyMS: latency, Error: err.Error()}
	}
	defer resp.Body.Close()
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	healthy := resp.StatusCode >= 200 && resp.StatusCode < 300
	detail := strings.TrimSpace(string(bodyBytes))
	if len(detail) > 120 {
		detail = detail[:120] + "..."
	}
	result := ProbeResult{
		Name:       name,
		URL:        probeURL,
		Healthy:    healthy,
		StatusCode: resp.StatusCode,
		LatencyMS:  latency,
		Detail:     detail,
	}
	if !healthy {
		result.Error = fmt.Sprintf("HTTP %d", resp.StatusCode)
	}
	return result
}

func doJSONRequest(
	ctx context.Context,
	httpClient *http.Client,
	method, fullURL, bearerToken string,
	extraHeaders map[string]string,
	reqPayload any,
	respTarget any,
) (http.Header, error) {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	var bodyReader io.Reader
	if reqPayload != nil {
		encoded, err := json.Marshal(reqPayload)
		if err != nil {
			return nil, fmt.Errorf("marshal request: %w", err)
		}
		bodyReader = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, fullURL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("build request %s %s: %w", method, fullURL, err)
	}
	if reqPayload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	if strings.TrimSpace(bearerToken) != "" {
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(bearerToken))
	}
	for k, v := range extraHeaders {
		if strings.TrimSpace(v) != "" {
			req.Header.Set(k, v)
		}
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", method, fullURL, err)
	}
	defer resp.Body.Close()

	rawBody, err := io.ReadAll(io.LimitReader(resp.Body, 8*1024*1024))
	if err != nil {
		return resp.Header, fmt.Errorf("read response %s: %w", fullURL, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet := strings.TrimSpace(string(rawBody))
		if len(snippet) > 300 {
			snippet = snippet[:300] + "..."
		}
		return resp.Header, fmt.Errorf("%s %s returned HTTP %d: %s", method, fullURL, resp.StatusCode, snippet)
	}
	if respTarget != nil && len(bytes.TrimSpace(rawBody)) > 0 {
		if err := json.Unmarshal(rawBody, respTarget); err != nil {
			return resp.Header, fmt.Errorf("decode JSON from %s: %w", fullURL, err)
		}
	}
	return resp.Header, nil
}

// --- 1. mw-rocksoul-gateway (:4510) Wire Client ---

// GatewayModel represents a model exposed by GET /v1/models.
type GatewayModel struct {
	ID      string `json:"id"`
	Object  string `json:"object,omitempty"`
	OwnedBy string `json:"owned_by,omitempty"`
}

// LocalProviderInfo represents a discovered local inference provider from GET /v1/local-providers.
type LocalProviderInfo struct {
	Name      string   `json:"name"`
	BaseURL   string   `json:"baseUrl"`
	Reachable bool     `json:"reachable"`
	Models    []string `json:"models,omitempty"`
}

// GatewayClient communicates with mw-rocksoul-gateway (:4510).
type GatewayClient struct {
	BaseURL            string
	BearerToken        string
	DataClassification string
	HTTPClient         *http.Client
}

// NewGatewayClient constructs a GatewayClient defaulting to http://127.0.0.1:4510.
func NewGatewayClient(baseURL, bearerToken string, httpClient *http.Client) *GatewayClient {
	return &GatewayClient{
		BaseURL:     cleanBaseURL(firstNonEmpty(baseURL, DefaultGatewayBaseURL)),
		BearerToken: strings.TrimSpace(bearerToken),
		HTTPClient:  httpClient,
	}
}

func (c *GatewayClient) Health(ctx context.Context) (HealthStatus, error) {
	var raw map[string]any
	_, err := doJSONRequest(ctx, c.HTTPClient, http.MethodGet, c.BaseURL+"/health", c.BearerToken, nil, nil, &raw)
	if err != nil {
		return HealthStatus{}, err
	}
	status := HealthStatus{Raw: raw}
	if s, ok := raw["status"].(string); ok {
		status.Status = s
	}
	if svc, ok := raw["service"].(string); ok {
		status.Service = svc
	}
	return status, nil
}

func (c *GatewayClient) ListModels(ctx context.Context) ([]GatewayModel, error) {
	var envelope struct {
		Data   []GatewayModel `json:"data"`
		Models []GatewayModel `json:"models"`
	}
	_, err := doJSONRequest(ctx, c.HTTPClient, http.MethodGet, c.BaseURL+"/v1/models", c.BearerToken, nil, nil, &envelope)
	if err != nil {
		return nil, err
	}
	if len(envelope.Data) > 0 {
		return envelope.Data, nil
	}
	return envelope.Models, nil
}

func (c *GatewayClient) Usage(ctx context.Context) (map[string]any, error) {
	var usage map[string]any
	_, err := doJSONRequest(ctx, c.HTTPClient, http.MethodGet, c.BaseURL+"/v1/usage", c.BearerToken, nil, nil, &usage)
	return usage, err
}

func (c *GatewayClient) LocalProviders(ctx context.Context) ([]LocalProviderInfo, error) {
	var raw json.RawMessage
	_, err := doJSONRequest(ctx, c.HTTPClient, http.MethodGet, c.BaseURL+"/v1/local-providers", c.BearerToken, nil, nil, &raw)
	if err != nil {
		return nil, err
	}
	var list []LocalProviderInfo
	if err := json.Unmarshal(raw, &list); err == nil {
		return list, nil
	}
	var wrapped struct {
		Providers []LocalProviderInfo `json:"providers"`
	}
	if err := json.Unmarshal(raw, &wrapped); err != nil {
		return nil, err
	}
	return wrapped.Providers, nil
}

func (c *GatewayClient) ChatCompletions(ctx context.Context, payload map[string]any) (map[string]any, http.Header, error) {
	headers := map[string]string{
		"X-MW-Agent": "rocksoul",
	}
	if c.DataClassification != "" {
		headers["X-Rocksoul-Data-Classification"] = c.DataClassification
	}
	var resp map[string]any
	respHeaders, err := doJSONRequest(ctx, c.HTTPClient, http.MethodPost, c.BaseURL+"/v1/chat/completions", c.BearerToken, headers, payload, &resp)
	return resp, respHeaders, err
}

// --- 2. mw-rocksoul-core (:4520) Wire Client ---

// CoreClient communicates with mw-rocksoul-core (:4520).
type CoreClient struct {
	BaseURL     string
	BearerToken string
	HTTPClient  *http.Client
}

// NewCoreClient constructs a CoreClient defaulting to http://127.0.0.1:4520.
func NewCoreClient(baseURL, bearerToken string, httpClient *http.Client) *CoreClient {
	return &CoreClient{
		BaseURL:     cleanBaseURL(firstNonEmpty(baseURL, DefaultCoreBaseURL)),
		BearerToken: strings.TrimSpace(bearerToken),
		HTTPClient:  httpClient,
	}
}

func (c *CoreClient) Health(ctx context.Context) (HealthStatus, error) {
	var raw map[string]any
	_, err := doJSONRequest(ctx, c.HTTPClient, http.MethodGet, c.BaseURL+"/health", c.BearerToken, nil, nil, &raw)
	if err != nil {
		return HealthStatus{}, err
	}
	status := HealthStatus{Raw: raw}
	if s, ok := raw["status"].(string); ok {
		status.Status = s
	}
	return status, nil
}

func (c *CoreClient) ValidatePlan(ctx context.Context, plan map[string]any) (map[string]any, error) {
	var out map[string]any
	_, err := doJSONRequest(ctx, c.HTTPClient, http.MethodPost, c.BaseURL+"/v1/plans/validate", c.BearerToken, nil, plan, &out)
	return out, err
}

func (c *CoreClient) EvaluateRisk(ctx context.Context, req map[string]any) (map[string]any, error) {
	var out map[string]any
	_, err := doJSONRequest(ctx, c.HTTPClient, http.MethodPost, c.BaseURL+"/v1/risk/evaluate", c.BearerToken, nil, req, &out)
	return out, err
}

func (c *CoreClient) VerifyPCW(ctx context.Context, envelope map[string]any) (map[string]any, error) {
	var out map[string]any
	_, err := doJSONRequest(ctx, c.HTTPClient, http.MethodPost, c.BaseURL+"/v1/pcw/verify", c.BearerToken, nil, envelope, &out)
	return out, err
}

func (c *CoreClient) CheckSwarmOverlap(ctx context.Context, ownership map[string]any) (map[string]any, error) {
	var out map[string]any
	_, err := doJSONRequest(ctx, c.HTTPClient, http.MethodPost, c.BaseURL+"/v1/swarm/check-overlap", c.BearerToken, nil, ownership, &out)
	return out, err
}

func (c *CoreClient) RunEvalsG0G6(ctx context.Context, req map[string]any) (map[string]any, error) {
	var out map[string]any
	_, err := doJSONRequest(ctx, c.HTTPClient, http.MethodPost, c.BaseURL+"/v1/evals/g0-g6", c.BearerToken, nil, req, &out)
	return out, err
}

// --- 3. mw-rocksoul-mcp (:4530) HTTP & JSON-RPC 2.0 Wire Client ---

// MCPTool describes a tool published by mw-rocksoul-mcp.
type MCPTool struct {
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	Server      string         `json:"server,omitempty"`
	InputSchema map[string]any `json:"inputSchema,omitempty"`
}

// JSONRPCError models a standard JSON-RPC 2.0 error object.
type JSONRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

func (e *JSONRPCError) Error() string {
	return fmt.Sprintf("json-rpc error %d: %s", e.Code, e.Message)
}

// MCPClient communicates with mw-rocksoul-mcp (:4530) via REST and JSON-RPC 2.0.
type MCPClient struct {
	BaseURL     string
	BearerToken string
	HTTPClient  *http.Client
	rpcSeq      atomic.Int64
}

// NewMCPClient constructs an MCPClient defaulting to http://127.0.0.1:4530.
func NewMCPClient(baseURL, bearerToken string, httpClient *http.Client) *MCPClient {
	return &MCPClient{
		BaseURL:     cleanBaseURL(firstNonEmpty(baseURL, DefaultMCPBaseURL)),
		BearerToken: strings.TrimSpace(bearerToken),
		HTTPClient:  httpClient,
	}
}

func (c *MCPClient) Health(ctx context.Context) (HealthStatus, error) {
	var raw map[string]any
	_, err := doJSONRequest(ctx, c.HTTPClient, http.MethodGet, c.BaseURL+"/health", c.BearerToken, nil, nil, &raw)
	if err != nil {
		return HealthStatus{}, err
	}
	status := HealthStatus{Raw: raw}
	if s, ok := raw["status"].(string); ok {
		status.Status = s
	}
	return status, nil
}

// ListTools fetches tools from GET /mcp/tools, falling back to JSON-RPC tools/list on POST /mcp/rpc.
func (c *MCPClient) ListTools(ctx context.Context) ([]MCPTool, error) {
	var raw json.RawMessage
	_, err := doJSONRequest(ctx, c.HTTPClient, http.MethodGet, c.BaseURL+"/mcp/tools", c.BearerToken, nil, nil, &raw)
	if err == nil {
		if tools, parseErr := decodeMCPToolList(raw); parseErr == nil {
			return tools, nil
		}
	}
	// Fallback to JSON-RPC 2.0 tools/list.
	rpcRaw, rpcErr := c.CallRPC(ctx, "tools/list", map[string]any{})
	if rpcErr != nil {
		if err != nil {
			return nil, err
		}
		return nil, rpcErr
	}
	return decodeMCPToolList(rpcRaw)
}

func decodeMCPToolList(raw json.RawMessage) ([]MCPTool, error) {
	var direct []MCPTool
	if err := json.Unmarshal(raw, &direct); err == nil {
		return direct, nil
	}
	var wrapped struct {
		Tools []MCPTool `json:"tools"`
	}
	if err := json.Unmarshal(raw, &wrapped); err != nil {
		return nil, err
	}
	return wrapped.Tools, nil
}

// CallRPC invokes a JSON-RPC 2.0 method against POST /mcp/rpc.
func (c *MCPClient) CallRPC(ctx context.Context, method string, params any) (json.RawMessage, error) {
	id := c.rpcSeq.Add(1)
	reqBody := map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"method":  method,
		"params":  params,
	}
	var envelope struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      any             `json:"id"`
		Result  json.RawMessage `json:"result"`
		Error   *JSONRPCError   `json:"error"`
	}
	_, err := doJSONRequest(ctx, c.HTTPClient, http.MethodPost, c.BaseURL+"/mcp/rpc", c.BearerToken, nil, reqBody, &envelope)
	if err != nil {
		return nil, err
	}
	if envelope.Error != nil {
		return nil, envelope.Error
	}
	return envelope.Result, nil
}

// CallTool satisfies agent.MCPToolCaller by invoking JSON-RPC tools/call on mw-rocksoul-mcp.
func (c *MCPClient) CallTool(ctx context.Context, toolName string, arguments map[string]any) (string, error) {
	if arguments == nil {
		arguments = map[string]any{}
	}
	result, err := c.CallRPC(ctx, "tools/call", map[string]any{
		"name":      toolName,
		"arguments": arguments,
	})
	if err != nil {
		return "", err
	}
	return string(result), nil
}

// --- 4. mw-rocksoul-sandbox (:4540) Wire Client ---

// LeaseRequest specifies parameters to acquire an ephemeral worktree lease.
type LeaseRequest struct {
	RepoPath   string `json:"repoPath,omitempty"`
	Branch     string `json:"branch,omitempty"`
	TTLSeconds int    `json:"ttlSeconds,omitempty"`
	Owner      string `json:"owner,omitempty"`
}

// Lease represents an active ephemeral sandbox lease with a monotonic fencing token.
type Lease struct {
	ID           string `json:"id"`
	LeaseID      string `json:"leaseId,omitempty"`
	WorktreePath string `json:"worktreePath,omitempty"`
	Branch       string `json:"branch,omitempty"`
	FencingToken int64  `json:"fencingToken"`
	ExpiresAt    string `json:"expiresAt,omitempty"`
}

// SandboxExecRequest invokes an allowlisted command inside a leased sandbox worktree.
type SandboxExecRequest struct {
	LeaseID      string   `json:"leaseId"`
	FencingToken int64    `json:"fencingToken"`
	Command      string   `json:"command"`
	Args         []string `json:"args,omitempty"`
	TimeoutMS    int      `json:"timeoutMs,omitempty"`
}

// SandboxExecResult captures bounded, redacted command execution output.
type SandboxExecResult struct {
	ExitCode   int    `json:"exitCode"`
	Stdout     string `json:"stdout"`
	Stderr     string `json:"stderr"`
	DurationMS int64  `json:"durationMs,omitempty"`
	Redacted   bool   `json:"redacted,omitempty"`
}

// SandboxClient communicates with mw-rocksoul-sandbox (:4540).
type SandboxClient struct {
	BaseURL     string
	BearerToken string
	HTTPClient  *http.Client
}

// NewSandboxClient constructs a SandboxClient defaulting to http://127.0.0.1:4540.
func NewSandboxClient(baseURL, bearerToken string, httpClient *http.Client) *SandboxClient {
	return &SandboxClient{
		BaseURL:     cleanBaseURL(firstNonEmpty(baseURL, DefaultSandboxBaseURL)),
		BearerToken: strings.TrimSpace(bearerToken),
		HTTPClient:  httpClient,
	}
}

func (c *SandboxClient) Health(ctx context.Context) (HealthStatus, error) {
	var raw map[string]any
	_, err := doJSONRequest(ctx, c.HTTPClient, http.MethodGet, c.BaseURL+"/health", c.BearerToken, nil, nil, &raw)
	if err != nil {
		return HealthStatus{}, err
	}
	status := HealthStatus{Raw: raw}
	if s, ok := raw["status"].(string); ok {
		status.Status = s
	}
	return status, nil
}

func (c *SandboxClient) CreateLease(ctx context.Context, req LeaseRequest) (Lease, error) {
	var lease Lease
	_, err := doJSONRequest(ctx, c.HTTPClient, http.MethodPost, c.BaseURL+"/leases", c.BearerToken, nil, req, &lease)
	if err != nil {
		return Lease{}, err
	}
	if lease.ID == "" && lease.LeaseID != "" {
		lease.ID = lease.LeaseID
	}
	return lease, nil
}

func (c *SandboxClient) ReleaseLease(ctx context.Context, leaseID string) error {
	cleanID := url.PathEscape(strings.TrimSpace(leaseID))
	if cleanID == "" {
		return errors.New("leaseID is required")
	}
	_, err := doJSONRequest(ctx, c.HTTPClient, http.MethodDelete, c.BaseURL+"/leases/"+cleanID, c.BearerToken, nil, nil, nil)
	return err
}

func (c *SandboxClient) Exec(ctx context.Context, req SandboxExecRequest) (SandboxExecResult, error) {
	var out SandboxExecResult
	_, err := doJSONRequest(ctx, c.HTTPClient, http.MethodPost, c.BaseURL+"/exec", c.BearerToken, nil, req, &out)
	return out, err
}

// --- 5. mw-rid (:4480) OIDC PKCE Helper & Token Store ---

// OIDCDiscovery models standard /.well-known/openid-configuration fields from mw-rid.
type OIDCDiscovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	RevocationEndpoint    string `json:"revocation_endpoint,omitempty"`
}

// PKCEPair holds a generated RFC 7636 S256 verifier, challenge, and OAuth2 CSRF state token.
type PKCEPair struct {
	CodeVerifier  string `json:"codeVerifier"`
	CodeChallenge string `json:"codeChallenge"`
	Method        string `json:"method"`
	State         string `json:"state"`
}

// PKCEAuthConfig configures an authorization_code + PKCE login URL.
type PKCEAuthConfig struct {
	ClientID    string `json:"clientId"`
	RedirectURI string `json:"redirectUri"`
	Scope       string `json:"scope"`
	Audience    string `json:"audience,omitempty"`
}

// TokenExchangeRequest holds parameters for POST /token.
type TokenExchangeRequest struct {
	ClientID     string
	Code         string
	RedirectURI  string
	CodeVerifier string
}

// TokenSet persists an OAuth2/OIDC token bundle issued by mw-rid.
type TokenSet struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	IDToken      string    `json:"id_token,omitempty"`
	TokenType    string    `json:"token_type,omitempty"`
	Scope        string    `json:"scope,omitempty"`
	ExpiresIn    int       `json:"expires_in,omitempty"`
	ExpiresAt    time.Time `json:"expires_at,omitempty"`
	Issuer       string    `json:"issuer,omitempty"`
	Subject      string    `json:"subject,omitempty"`
}

// RIDClient communicates with mw-rid (:4480) for OIDC discovery, PKCE S256 authorization, and token exchange.
type RIDClient struct {
	BaseURL    string
	HTTPClient *http.Client
}

// NewRIDClient constructs a RIDClient defaulting to http://127.0.0.1:4480.
func NewRIDClient(baseURL string, httpClient *http.Client) *RIDClient {
	return &RIDClient{
		BaseURL:    cleanBaseURL(firstNonEmpty(baseURL, DefaultRIDBaseURL)),
		HTTPClient: httpClient,
	}
}

// GeneratePKCE produces a cryptographically random RFC 7636 S256 verifier/challenge pair and state nonce.
func GeneratePKCE() (PKCEPair, error) {
	verifierBytes := make([]byte, 32)
	if _, err := rand.Read(verifierBytes); err != nil {
		return PKCEPair{}, fmt.Errorf("generate PKCE verifier: %w", err)
	}
	stateBytes := make([]byte, 16)
	if _, err := rand.Read(stateBytes); err != nil {
		return PKCEPair{}, fmt.Errorf("generate OIDC state: %w", err)
	}
	verifier := base64.RawURLEncoding.EncodeToString(verifierBytes)
	challengeSum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(challengeSum[:])
	state := base64.RawURLEncoding.EncodeToString(stateBytes)

	return PKCEPair{
		CodeVerifier:  verifier,
		CodeChallenge: challenge,
		Method:        "S256",
		State:         state,
	}, nil
}

func (c *RIDClient) Health(ctx context.Context) (HealthStatus, error) {
	var raw map[string]any
	_, err := doJSONRequest(ctx, c.HTTPClient, http.MethodGet, c.BaseURL+"/health", "", nil, nil, &raw)
	if err != nil {
		return HealthStatus{}, err
	}
	status := HealthStatus{Raw: raw}
	if s, ok := raw["status"].(string); ok {
		status.Status = s
	}
	return status, nil
}

func (c *RIDClient) Discover(ctx context.Context) (OIDCDiscovery, error) {
	var doc OIDCDiscovery
	_, err := doJSONRequest(ctx, c.HTTPClient, http.MethodGet, c.BaseURL+"/.well-known/openid-configuration", "", nil, nil, &doc)
	return doc, err
}

// BuildAuthorizationURL constructs the PKCE S256 OIDC authorization URL for mw-rid.
func (c *RIDClient) BuildAuthorizationURL(authEndpoint string, cfg PKCEAuthConfig, pkce PKCEPair) (string, error) {
	endpoint := strings.TrimSpace(authEndpoint)
	if endpoint == "" {
		endpoint = c.BaseURL + "/auth"
	}
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("parse auth endpoint: %w", err)
	}
	clientID := strings.TrimSpace(cfg.ClientID)
	if clientID == "" {
		return "", errors.New("clientId is required")
	}
	redirectURI := strings.TrimSpace(cfg.RedirectURI)
	if redirectURI == "" {
		return "", errors.New("redirectUri is required")
	}
	scope := strings.TrimSpace(cfg.Scope)
	if scope == "" {
		scope = "openid profile email"
	}

	q := parsed.Query()
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", scope)
	q.Set("state", pkce.State)
	q.Set("code_challenge", pkce.CodeChallenge)
	q.Set("code_challenge_method", "S256")
	if strings.TrimSpace(cfg.Audience) != "" {
		q.Set("audience", strings.TrimSpace(cfg.Audience))
	}
	parsed.RawQuery = q.Encode()
	return parsed.String(), nil
}

// ExchangeCode exchanges an authorization code + PKCE verifier at mw-rid /token.
func (c *RIDClient) ExchangeCode(ctx context.Context, tokenEndpoint string, req TokenExchangeRequest) (TokenSet, error) {
	endpoint := strings.TrimSpace(tokenEndpoint)
	if endpoint == "" {
		endpoint = c.BaseURL + "/token"
	}
	httpClient := c.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 20 * time.Second}
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", strings.TrimSpace(req.ClientID))
	form.Set("code", strings.TrimSpace(req.Code))
	form.Set("redirect_uri", strings.TrimSpace(req.RedirectURI))
	form.Set("code_verifier", strings.TrimSpace(req.CodeVerifier))

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return TokenSet{}, fmt.Errorf("build token request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	httpReq.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return TokenSet{}, fmt.Errorf("token exchange failed: %w", err)
	}
	defer resp.Body.Close()

	rawBody, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return TokenSet{}, fmt.Errorf("read token response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return TokenSet{}, fmt.Errorf("token exchange HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(rawBody)))
	}

	var tok TokenSet
	if err := json.Unmarshal(rawBody, &tok); err != nil {
		return TokenSet{}, fmt.Errorf("decode token response: %w", err)
	}
	tok.Issuer = c.BaseURL
	if tok.ExpiresIn > 0 && tok.ExpiresAt.IsZero() {
		tok.ExpiresAt = time.Now().UTC().Add(time.Duration(tok.ExpiresIn) * time.Second)
	}
	return tok, nil
}

// UserInfo queries GET /me using an active Bearer access token.
func (c *RIDClient) UserInfo(ctx context.Context, accessToken string) (map[string]any, error) {
	var claims map[string]any
	_, err := doJSONRequest(ctx, c.HTTPClient, http.MethodGet, c.BaseURL+"/me", accessToken, nil, nil, &claims)
	return claims, err
}

// DefaultTokenPath returns ~/.rocksoul/token.json (or ROCKSOUL_TOKEN_PATH override).
func DefaultTokenPath() string {
	if override := strings.TrimSpace(os.Getenv("ROCKSOUL_TOKEN_PATH")); override != "" {
		return override
	}
	return filepath.Join(RocksoulHomeDir(), "token.json")
}

// SaveTokenSet writes TokenSet atomically with 0600 permissions.
func SaveTokenSet(tokenPath string, tok TokenSet) error {
	if strings.TrimSpace(tokenPath) == "" {
		tokenPath = DefaultTokenPath()
	}
	if err := os.MkdirAll(filepath.Dir(tokenPath), 0o700); err != nil {
		return fmt.Errorf("create token dir: %w", err)
	}
	encoded, err := json.MarshalIndent(tok, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal token set: %w", err)
	}
	tmpPath := tokenPath + ".tmp"
	if err := os.WriteFile(tmpPath, encoded, 0o600); err != nil {
		return fmt.Errorf("write temp token file: %w", err)
	}
	if err := os.Rename(tmpPath, tokenPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("commit token file: %w", err)
	}
	return nil
}

// LoadTokenSet loads TokenSet from tokenPath. Returns os.ErrNotExist if absent.
func LoadTokenSet(tokenPath string) (TokenSet, error) {
	if strings.TrimSpace(tokenPath) == "" {
		tokenPath = DefaultTokenPath()
	}
	raw, err := os.ReadFile(tokenPath)
	if err != nil {
		return TokenSet{}, err
	}
	var tok TokenSet
	if err := json.Unmarshal(raw, &tok); err != nil {
		return TokenSet{}, fmt.Errorf("decode token file: %w", err)
	}
	return tok, nil
}

// MaskToken redacts an access token for safe CLI display.
func MaskToken(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "(none)"
	}
	if len(trimmed) <= 10 {
		return trimmed[:2] + "..."
	}
	return trimmed[:6] + "..." + trimmed[len(trimmed)-4:]
}
