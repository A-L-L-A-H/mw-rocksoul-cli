package clients

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/A-L-L-A-H/mw-rocksoul-cli/internal/risk"
)

var (
	ErrChallengeNotFound    = errors.New("approval challenge not found")
	ErrChallengeExpired     = errors.New("approval challenge expired (fail-closed)")
	ErrChallengeAlreadyUsed = errors.New("approval nonce already consumed")
	ErrChallengeInvalidSig  = errors.New("approval signature or nonce invalid")
	ErrChallengeDenied      = errors.New("approval denied by operator")
	ErrChallengeUnauthorized = errors.New("approval callback token invalid")
)

type PocketApprovalRequest struct {
	ChallengeID   string    `json:"challengeId"`
	RiskTier      string    `json:"riskTier"`
	ActionSummary string    `json:"actionSummary"`
	DiffDigest    string    `json:"diffDigest"`
	ExpiresAt     time.Time `json:"expiresAt"`
	HMAC          string    `json:"hmac"`
}

type PocketApprovalResponse struct {
	Status string `json:"status"` // pending|approved|denied|expired
	Detail string `json:"detail,omitempty"`
}

// RequestPocketApproval sends a challenge to the pocket approval service.
func RequestPocketApproval(ctx context.Context, httpClient *http.Client, endpoint string, payload PocketApprovalRequest) (*PocketApprovalResponse, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal payload: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/request", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	var out PocketApprovalResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return &out, nil
}

// PollPocketApproval polls the approval status until final state or timeout.
func PollPocketApproval(ctx context.Context, httpClient *http.Client, endpoint, challengeID string, interval, timeout time.Duration) (*PocketApprovalResponse, error) {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		req, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/status/%s", strings.TrimRight(endpoint, "/"), challengeID), nil)
		if reqErr != nil {
			return nil, fmt.Errorf("poll build request: %w", reqErr)
		}
		resp, err := httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("poll request: %w", err)
		}
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("poll status %d", resp.StatusCode)
		}
		var status PocketApprovalResponse
		if err := json.Unmarshal(data, &status); err != nil {
			return nil, fmt.Errorf("decode poll: %w", err)
		}
		switch status.Status {
		case "approved", "denied", "expired":
			return &status, nil
		case "pending":
			// continue
		default:
			return nil, errors.New("unknown status: " + status.Status)
		}
		time.Sleep(interval)
	}
	return &PocketApprovalResponse{Status: "expired", Detail: "timeout"}, nil
}

// VerifyHMAC validates the HMAC of the request payload using a shared secret.
func VerifyHMAC(secret string, payload PocketApprovalRequest) bool {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload.ChallengeID))
	mac.Write([]byte(payload.RiskTier))
	mac.Write([]byte(payload.ActionSummary))
	mac.Write([]byte(payload.DiffDigest))
	mac.Write([]byte(payload.ExpiresAt.UTC().Format(time.RFC3339)))
	expected := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(expected), []byte(payload.HMAC))
}

// ApprovalPrompt is the human-facing approval request pushed to a phone.
type ApprovalPrompt struct {
	ChallengeID         string
	RiskTier            string
	Summary             string
	DiffDigest          string
	DiffPreview         string
	Nonce               string
	Signature           string
	ExpiresAt           time.Time
	ApproveURL          string
	DenyURL             string
	ApproveCallbackData string
	DenyCallbackData    string
}

// ApprovalTransport delivers an approval prompt to an out-of-band channel.
type ApprovalTransport interface {
	Send(ctx context.Context, prompt ApprovalPrompt) error
}

// NtfyApprovalTransport posts to an ntfy topic URL with Approve/Deny action headers.
type NtfyApprovalTransport struct {
	TopicURL   string
	HTTPClient *http.Client
}

// NewNtfyApprovalTransportFromEnv reads NTFY_TOPIC_URL.
func NewNtfyApprovalTransportFromEnv() (*NtfyApprovalTransport, error) {
	topic := strings.TrimSpace(os.Getenv("NTFY_TOPIC_URL"))
	if topic == "" {
		return nil, errors.New("NTFY_TOPIC_URL not set")
	}
	return &NtfyApprovalTransport{TopicURL: topic, HTTPClient: http.DefaultClient}, nil
}

func (n *NtfyApprovalTransport) Send(ctx context.Context, prompt ApprovalPrompt) error {
	bodyText := formatApprovalBody(prompt)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.TopicURL, strings.NewReader(bodyText))
	if err != nil {
		return fmt.Errorf("ntfy request: %w", err)
	}
	title := "Rocksoul approval " + prompt.ChallengeID
	if prompt.RiskTier != "" {
		title = fmt.Sprintf("Rocksoul [%s] approval %s", prompt.RiskTier, prompt.ChallengeID)
	}
	req.Header.Set("Title", title)
	req.Header.Set("Priority", "high")
	req.Header.Set("Actions", fmt.Sprintf("http, Approve, %s, method=POST, clear=true; http, Deny, %s, method=POST, clear=true", prompt.ApproveURL, prompt.DenyURL))
	client := n.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("ntfy send: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("ntfy status %d", resp.StatusCode)
	}
	return nil
}

// TelegramApprovalTransport sends a message with inline approve/deny buttons.
type TelegramApprovalTransport struct {
	BotToken   string
	ChatID     string
	APIBase    string
	HTTPClient *http.Client
}

// NewTelegramApprovalTransportFromEnv reads TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID.
func NewTelegramApprovalTransportFromEnv() (*TelegramApprovalTransport, error) {
	token := strings.TrimSpace(os.Getenv("TELEGRAM_BOT_TOKEN"))
	chat := strings.TrimSpace(os.Getenv("TELEGRAM_CHAT_ID"))
	if token == "" || chat == "" {
		return nil, errors.New("TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID required")
	}
	return &TelegramApprovalTransport{BotToken: token, ChatID: chat, APIBase: "https://api.telegram.org", HTTPClient: http.DefaultClient}, nil
}

func (t *TelegramApprovalTransport) Send(ctx context.Context, prompt ApprovalPrompt) error {
	base := t.APIBase
	if base == "" {
		base = "https://api.telegram.org"
	}
	type button struct {
		Text         string `json:"text"`
		CallbackData string `json:"callback_data,omitempty"`
		URL          string `json:"url,omitempty"`
	}
	approveData := prompt.ApproveCallbackData
	if approveData == "" {
		approveData = "approve:" + prompt.ChallengeID
	}
	denyData := prompt.DenyCallbackData
	if denyData == "" {
		denyData = "deny:" + prompt.ChallengeID
	}
	header := "Rocksoul approval " + prompt.ChallengeID
	if prompt.RiskTier != "" {
		header = fmt.Sprintf("Rocksoul [%s] approval %s", prompt.RiskTier, prompt.ChallengeID)
	}
	payload := map[string]any{
		"chat_id": t.ChatID,
		"text":    header + "\n" + formatApprovalBody(prompt),
		"reply_markup": map[string][][]button{"inline_keyboard": {{
			{Text: "Approve", CallbackData: approveData, URL: ""},
			{Text: "Deny", CallbackData: denyData, URL: ""},
		}}},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("telegram marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/bot"+t.BotToken+"/sendMessage", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("telegram request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	client := t.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("telegram send: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("telegram status %d", resp.StatusCode)
	}
	return nil
}

func formatApprovalBody(prompt ApprovalPrompt) string {
	var b strings.Builder
	b.WriteString(prompt.Summary)
	if prompt.DiffDigest != "" {
		fmt.Fprintf(&b, "\nDiff SHA-256: %s", prompt.DiffDigest)
	}
	if !prompt.ExpiresAt.IsZero() {
		fmt.Fprintf(&b, "\nExpires: %s", prompt.ExpiresAt.UTC().Format(time.RFC3339))
	}
	if prompt.DiffPreview != "" {
		preview := prompt.DiffPreview
		if len(preview) > 1200 {
			preview = preview[:1200] + "\n...(truncated)"
		}
		fmt.Fprintf(&b, "\n\n%s", preview)
	}
	return b.String()
}

// MobileApprovalOptions configures MobileApprovalBridge for interactive R3/R4 diff approvals.
type MobileApprovalOptions struct {
	Gate                  *risk.Gate
	Transports            []ApprovalTransport
	CallbackBaseURL       string
	Secret                []byte
	CallbackToken         string
	TelegramWebhookSecret string
	TTL                   time.Duration
	Clock                 func() time.Time
}

// MobileApprovalChallenge tracks a single-use cryptographic mobile approval request.
type MobileApprovalChallenge struct {
	ChallengeID         string      `json:"challengeId"`
	Nonce               string      `json:"nonce"`
	RiskTier            string      `json:"riskTier"`
	ScopeHash           string      `json:"scopeHash"`
	DiffDigest          string      `json:"diffDigest"`
	ActionSummary       string      `json:"actionSummary"`
	DiffPreview         string      `json:"diffPreview,omitempty"`
	Signature           string      `json:"signature"`
	ApproveURL          string      `json:"approveUrl"`
	DenyURL             string      `json:"denyUrl"`
	ApproveCallbackData string      `json:"approveCallbackData"`
	DenyCallbackData    string      `json:"denyCallbackData"`
	Status              string      `json:"status"` // pending|approved|denied|expired
	IssuedAt            time.Time   `json:"issuedAt"`
	ExpiresAt           time.Time   `json:"expiresAt"`
	Action              risk.Action `json:"action"`
}

// MobileApprovalCallback represents an inbound Ntfy/Telegram approval/denial callback.
type MobileApprovalCallback struct {
	ChallengeID   string `json:"challengeId"`
	Decision      string `json:"decision"` // approve|deny
	Nonce         string `json:"nonce"`
	Signature     string `json:"signature"`
	CallbackToken string `json:"callbackToken,omitempty"`
	Approver      string `json:"approver,omitempty"`
}

// MobileApprovalResult summarizes the verified outcome of a mobile approval callback.
type MobileApprovalResult struct {
	ChallengeID   string `json:"challengeId"`
	Status        string `json:"status"`
	ApprovalToken string `json:"approvalToken,omitempty"`
	Detail        string `json:"detail,omitempty"`
}

type bridgeChallengeState struct {
	challenge     MobileApprovalChallenge
	consumed      bool
	approvalToken string
	done          chan MobileApprovalResult
}

// MobileApprovalBridge implements interactive R3/R4 diff approvals over Ntfy/Telegram
// with single-use nonces, HMAC-SHA256 verification, and fail-closed expiry.
type MobileApprovalBridge struct {
	gate                  *risk.Gate
	transports            []ApprovalTransport
	callbackBaseURL       string
	secret                []byte
	callbackToken         string
	telegramWebhookSecret string
	ttl                   time.Duration
	clock                 func() time.Time

	mu         sync.Mutex
	challenges map[string]*bridgeChallengeState
}

// NewMobileApprovalBridge initializes a MobileApprovalBridge.
func NewMobileApprovalBridge(opts MobileApprovalOptions) *MobileApprovalBridge {
	secret := make([]byte, len(opts.Secret))
	copy(secret, opts.Secret)
	if len(secret) == 0 {
		secret = make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			sum := sha256.Sum256([]byte(fmt.Sprintf("rocksoul-mobile-%d", time.Now().UTC().UnixNano())))
			secret = sum[:]
		}
	}
	ttl := opts.TTL
	if ttl <= 0 {
		ttl = 3 * time.Minute
	}
	clockFn := opts.Clock
	if clockFn == nil {
		clockFn = func() time.Time { return time.Now().UTC() }
	}
	gate := opts.Gate
	if gate == nil {
		gate = risk.NewGate(risk.DefaultPolicy())
	}
	return &MobileApprovalBridge{
		gate:                  gate,
		transports:            append([]ApprovalTransport(nil), opts.Transports...),
		callbackBaseURL:       strings.TrimRight(strings.TrimSpace(opts.CallbackBaseURL), "/"),
		secret:                secret,
		callbackToken:         strings.TrimSpace(opts.CallbackToken),
		telegramWebhookSecret: strings.TrimSpace(opts.TelegramWebhookSecret),
		ttl:                   ttl,
		clock:                 clockFn,
		challenges:            make(map[string]*bridgeChallengeState),
	}
}

// ComputeDiffDigest returns the canonical lowercase SHA-256 hex digest of a diff or action payload.
func ComputeDiffDigest(diff string) string {
	sum := sha256.Sum256([]byte(diff))
	return hex.EncodeToString(sum[:])
}

// CreateChallenge mints a single-use nonce challenge for action+diff and dispatches prompts to configured transports.
func (b *MobileApprovalBridge) CreateChallenge(ctx context.Context, action risk.Action, diffText string) (MobileApprovalChallenge, error) {
	tier, reason := risk.Classify(action)
	scopeHash := risk.ScopeFingerprint(action, tier)

	idBytes := make([]byte, 8)
	if _, err := rand.Read(idBytes); err != nil {
		return MobileApprovalChallenge{}, fmt.Errorf("generate challenge id: %w", err)
	}
	nonceBytes := make([]byte, 12)
	if _, err := rand.Read(nonceBytes); err != nil {
		return MobileApprovalChallenge{}, fmt.Errorf("generate nonce: %w", err)
	}

	challengeID := hex.EncodeToString(idBytes)
	nonce := hex.EncodeToString(nonceBytes)
	now := b.clock()
	expiresAt := now.Add(b.ttl)

	target := action.Path
	if target == "" {
		target = action.Command
	}
	if target == "" {
		target = action.RemoteTarget
	}
	summary := fmt.Sprintf("Tool=%s Target=%s (%s)", action.Tool, target, reason)
	if strings.TrimSpace(diffText) == "" {
		diffText = summary
	}
	diffDigest := ComputeDiffDigest(diffText)
	sig := b.signChallenge(challengeID, nonce, scopeHash, diffDigest, expiresAt)

	approveSig := b.signDecision(challengeID, nonce, "approve", diffDigest, expiresAt)
	denySig := b.signDecision(challengeID, nonce, "deny", diffDigest, expiresAt)

	base := b.callbackBaseURL
	if base == "" {
		base = "http://127.0.0.1:4598"
	}
	approveQ := url.Values{
		"challenge": {challengeID},
		"decision":  {"approve"},
		"nonce":     {nonce},
		"sig":       {approveSig},
	}.Encode()
	denyQ := url.Values{
		"challenge": {challengeID},
		"decision":  {"deny"},
		"nonce":     {nonce},
		"sig":       {denySig},
	}.Encode()

	// Telegram callback_data has a 64-byte limit, so use a compact 16-hex prefix of decision HMAC.
	approveCompact := fmt.Sprintf("approve:%s:%s:%s", challengeID, nonce[:12], approveSig[:16])
	denyCompact := fmt.Sprintf("deny:%s:%s:%s", challengeID, nonce[:12], denySig[:16])

	ch := MobileApprovalChallenge{
		ChallengeID:         challengeID,
		Nonce:               nonce,
		RiskTier:            tier.String(),
		ScopeHash:           scopeHash,
		DiffDigest:          diffDigest,
		ActionSummary:       summary,
		DiffPreview:         diffText,
		Signature:           sig,
		ApproveURL:          base + "/callback?" + approveQ,
		DenyURL:             base + "/callback?" + denyQ,
		ApproveCallbackData: approveCompact,
		DenyCallbackData:    denyCompact,
		Status:              "pending",
		IssuedAt:            now,
		ExpiresAt:           expiresAt,
		Action:              action,
	}

	b.mu.Lock()
	b.challenges[challengeID] = &bridgeChallengeState{
		challenge: ch,
		done:      make(chan MobileApprovalResult, 1),
	}
	b.mu.Unlock()

	prompt := ApprovalPrompt{
		ChallengeID:         ch.ChallengeID,
		RiskTier:            ch.RiskTier,
		Summary:             ch.ActionSummary,
		DiffDigest:          ch.DiffDigest,
		DiffPreview:         ch.DiffPreview,
		Nonce:               ch.Nonce,
		Signature:           ch.Signature,
		ExpiresAt:           ch.ExpiresAt,
		ApproveURL:          ch.ApproveURL,
		DenyURL:             ch.DenyURL,
		ApproveCallbackData: ch.ApproveCallbackData,
		DenyCallbackData:    ch.DenyCallbackData,
	}
	for _, tr := range b.transports {
		if tr == nil {
			continue
		}
		if err := tr.Send(ctx, prompt); err != nil {
			return MobileApprovalChallenge{}, fmt.Errorf("send approval prompt: %w", err)
		}
	}

	return ch, nil
}

// VerifyAndResolveCallback validates a single-use nonce, signature/token, and expiry fail-closed.
func (b *MobileApprovalBridge) VerifyAndResolveCallback(_ context.Context, cb MobileApprovalCallback) (MobileApprovalResult, error) {
	if b.callbackToken != "" {
		if subtle.ConstantTimeCompare([]byte(b.callbackToken), []byte(strings.TrimSpace(cb.CallbackToken))) != 1 {
			return MobileApprovalResult{}, ErrChallengeUnauthorized
		}
	}

	decision := strings.ToLower(strings.TrimSpace(cb.Decision))
	if decision != "approve" && decision != "deny" {
		return MobileApprovalResult{}, fmt.Errorf("%w: invalid decision %q", ErrChallengeInvalidSig, cb.Decision)
	}

	b.mu.Lock()
	state, ok := b.challenges[strings.TrimSpace(cb.ChallengeID)]
	if !ok {
		b.mu.Unlock()
		return MobileApprovalResult{}, ErrChallengeNotFound
	}

	now := b.clock()
	if state.consumed {
		b.mu.Unlock()
		return MobileApprovalResult{}, ErrChallengeAlreadyUsed
	}
	if now.After(state.challenge.ExpiresAt) {
		state.challenge.Status = "expired"
		state.consumed = true
		res := MobileApprovalResult{ChallengeID: state.challenge.ChallengeID, Status: "expired", Detail: ErrChallengeExpired.Error()}
		select {
		case state.done <- res:
		default:
		}
		b.mu.Unlock()
		return res, ErrChallengeExpired
	}

	// Verify nonce (full or Telegram compact 12-char prefix) and HMAC signature (full or compact 16-char prefix).
	suppliedNonce := strings.TrimSpace(cb.Nonce)
	suppliedSig := strings.TrimSpace(cb.Signature)
	expectedDecisionSig := b.signDecision(state.challenge.ChallengeID, state.challenge.Nonce, decision, state.challenge.DiffDigest, state.challenge.ExpiresAt)

	fullMatch := hmac.Equal([]byte(state.challenge.Nonce), []byte(suppliedNonce)) &&
		(hmac.Equal([]byte(expectedDecisionSig), []byte(suppliedSig)) ||
			hmac.Equal([]byte(state.challenge.Signature), []byte(suppliedSig)))
	compactMatch := len(suppliedNonce) == 12 &&
		hmac.Equal([]byte(state.challenge.Nonce[:12]), []byte(suppliedNonce)) &&
		len(suppliedSig) == 16 &&
		hmac.Equal([]byte(expectedDecisionSig[:16]), []byte(suppliedSig))

	if !fullMatch && !compactMatch {
		b.mu.Unlock()
		return MobileApprovalResult{}, ErrChallengeInvalidSig
	}

	state.consumed = true
	if decision == "deny" {
		state.challenge.Status = "denied"
		res := MobileApprovalResult{ChallengeID: state.challenge.ChallengeID, Status: "denied", Detail: "denied"}
		select {
		case state.done <- res:
		default:
		}
		b.mu.Unlock()
		return res, nil
	}

	remainingTTL := state.challenge.ExpiresAt.Sub(now)
	if remainingTTL <= 0 {
		state.challenge.Status = "expired"
		b.mu.Unlock()
		return MobileApprovalResult{ChallengeID: state.challenge.ChallengeID, Status: "expired"}, ErrChallengeExpired
	}
	approver := strings.TrimSpace(cb.Approver)
	if approver == "" {
		approver = "mobile-bridge"
	}
	tok, err := b.gate.IssueApprovalToken(state.challenge.Action, remainingTTL, approver)
	if err != nil {
		b.mu.Unlock()
		return MobileApprovalResult{}, fmt.Errorf("issue risk gate token: %w", err)
	}

	state.challenge.Status = "approved"
	state.approvalToken = tok.Token
	res := MobileApprovalResult{
		ChallengeID:   state.challenge.ChallengeID,
		Status:        "approved",
		ApprovalToken: tok.Token,
	}
	select {
	case state.done <- res:
	default:
	}
	b.mu.Unlock()
	return res, nil
}

// GetChallengeStatus returns the current status of a challenge, failing closed to expired after ExpiresAt.
func (b *MobileApprovalBridge) GetChallengeStatus(challengeID string) (PocketApprovalResponse, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	state, ok := b.challenges[strings.TrimSpace(challengeID)]
	if !ok {
		return PocketApprovalResponse{}, ErrChallengeNotFound
	}
	if state.challenge.Status == "pending" && b.clock().After(state.challenge.ExpiresAt) {
		state.challenge.Status = "expired"
		state.consumed = true
	}
	return PocketApprovalResponse{Status: state.challenge.Status}, nil
}

// WaitForChallenge waits for an interactive approval outcome until expiry or ctx cancellation (fail-closed).
func (b *MobileApprovalBridge) WaitForChallenge(ctx context.Context, challengeID string) (MobileApprovalResult, error) {
	b.mu.Lock()
	state, ok := b.challenges[strings.TrimSpace(challengeID)]
	if !ok {
		b.mu.Unlock()
		return MobileApprovalResult{}, ErrChallengeNotFound
	}
	if state.challenge.Status == "approved" {
		tok := state.approvalToken
		b.mu.Unlock()
		return MobileApprovalResult{ChallengeID: challengeID, Status: "approved", ApprovalToken: tok}, nil
	}
	remaining := state.challenge.ExpiresAt.Sub(b.clock())
	b.mu.Unlock()

	if remaining <= 0 {
		_, _ = b.GetChallengeStatus(challengeID)
		return MobileApprovalResult{ChallengeID: challengeID, Status: "expired"}, ErrChallengeExpired
	}

	timer := time.NewTimer(remaining)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return MobileApprovalResult{ChallengeID: challengeID, Status: "expired"}, ctx.Err()
	case <-timer.C:
		_, _ = b.GetChallengeStatus(challengeID)
		return MobileApprovalResult{ChallengeID: challengeID, Status: "expired"}, ErrChallengeExpired
	case res := <-state.done:
		switch res.Status {
		case "approved":
			return res, nil
		case "denied":
			return res, ErrChallengeDenied
		default:
			return res, ErrChallengeExpired
		}
	}
}

// Resolve implements agent.ApprovalResolver for R3/R4 interactive mobile approval.
func (b *MobileApprovalBridge) Resolve(ctx context.Context, action risk.Action, decision risk.Decision) (string, error) {
	if decision.Tier < risk.TierR3 {
		return "", nil
	}
	diffSummary := fmt.Sprintf("Tier=%s Tool=%s Path=%s Command=%s Remote=%s",
		decision.TierLabel, action.Tool, action.Path, action.Command, action.RemoteTarget)
	ch, err := b.CreateChallenge(ctx, action, diffSummary)
	if err != nil {
		return "", err
	}
	res, waitErr := b.WaitForChallenge(ctx, ch.ChallengeID)
	if waitErr != nil {
		return "", waitErr
	}
	return res.ApprovalToken, nil
}

// ServeHTTP exposes /callback, /telegram/webhook, and /status/{id} for Ntfy and Telegram callbacks.
func (b *MobileApprovalBridge) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/callback" && (r.Method == http.MethodPost || r.Method == http.MethodGet):
		cb := MobileApprovalCallback{
			ChallengeID:   r.URL.Query().Get("challenge"),
			Decision:      r.URL.Query().Get("decision"),
			Nonce:         r.URL.Query().Get("nonce"),
			Signature:     r.URL.Query().Get("sig"),
			CallbackToken: r.Header.Get("X-Approval-Token"),
		}
		if cb.CallbackToken == "" {
			cb.CallbackToken = r.URL.Query().Get("token")
		}
		if r.Method == http.MethodPost && r.ContentLength != 0 && strings.Contains(r.Header.Get("Content-Type"), "application/json") {
			var bodyCB MobileApprovalCallback
			if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&bodyCB); err == nil {
				if bodyCB.ChallengeID != "" {
					cb = bodyCB
					if cb.CallbackToken == "" {
						cb.CallbackToken = r.Header.Get("X-Approval-Token")
					}
				}
			}
		}
		b.writeCallbackResult(w, cb)

	case r.URL.Path == "/telegram/webhook" && r.Method == http.MethodPost:
		if b.telegramWebhookSecret != "" {
			hdr := strings.TrimSpace(r.Header.Get("X-Telegram-Bot-Api-Secret-Token"))
			if subtle.ConstantTimeCompare([]byte(b.telegramWebhookSecret), []byte(hdr)) != 1 {
				writeBridgeJSON(w, http.StatusUnauthorized, map[string]string{"error": ErrChallengeUnauthorized.Error()})
				return
			}
		}
		var update struct {
			CallbackQuery *struct {
				ID   string `json:"id"`
				From struct {
					Username string `json:"username"`
					ID       int64  `json:"id"`
				} `json:"from"`
				Data string `json:"data"`
			} `json:"callback_query"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&update); err != nil || update.CallbackQuery == nil {
			writeBridgeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid telegram callback_query"})
			return
		}
		parts := strings.Split(strings.TrimSpace(update.CallbackQuery.Data), ":")
		if len(parts) != 4 {
			writeBridgeJSON(w, http.StatusForbidden, map[string]string{"error": ErrChallengeInvalidSig.Error()})
			return
		}
		approver := update.CallbackQuery.From.Username
		if approver == "" {
			approver = fmt.Sprintf("tg:%d", update.CallbackQuery.From.ID)
		}
		cb := MobileApprovalCallback{
			Decision:      parts[0],
			ChallengeID:   parts[1],
			Nonce:         parts[2],
			Signature:     parts[3],
			CallbackToken: b.callbackToken, // Telegram webhook already authenticated by webhook secret / callback HMAC
			Approver:      approver,
		}
		b.writeCallbackResult(w, cb)

	case strings.HasPrefix(r.URL.Path, "/status/") && r.Method == http.MethodGet:
		id := strings.TrimPrefix(r.URL.Path, "/status/")
		status, err := b.GetChallengeStatus(id)
		if err != nil {
			writeBridgeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
			return
		}
		writeBridgeJSON(w, http.StatusOK, status)

	default:
		writeBridgeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
	}
}

func (b *MobileApprovalBridge) writeCallbackResult(w http.ResponseWriter, cb MobileApprovalCallback) {
	res, err := b.VerifyAndResolveCallback(context.Background(), cb)
	if err != nil {
		status := http.StatusForbidden
		switch {
		case errors.Is(err, ErrChallengeUnauthorized):
			status = http.StatusUnauthorized
		case errors.Is(err, ErrChallengeNotFound):
			status = http.StatusNotFound
		case errors.Is(err, ErrChallengeAlreadyUsed):
			status = http.StatusConflict
		case errors.Is(err, ErrChallengeExpired):
			status = http.StatusGone
		}
		writeBridgeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}
	// Never expose raw ApprovalToken over public HTTP callback response.
	writeBridgeJSON(w, http.StatusOK, PocketApprovalResponse{
		Status: res.Status,
		Detail: res.ChallengeID,
	})
}

func writeBridgeJSON(w http.ResponseWriter, statusCode int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(payload)
}

func (b *MobileApprovalBridge) signChallenge(challengeID, nonce, scopeHash, diffDigest string, expiresAt time.Time) string {
	mac := hmac.New(sha256.New, b.secret)
	mac.Write([]byte(challengeID))
	mac.Write([]byte("|"))
	mac.Write([]byte(nonce))
	mac.Write([]byte("|"))
	mac.Write([]byte(scopeHash))
	mac.Write([]byte("|"))
	mac.Write([]byte(diffDigest))
	mac.Write([]byte("|"))
	mac.Write([]byte(strconv.FormatInt(expiresAt.UTC().UnixNano(), 10)))
	return hex.EncodeToString(mac.Sum(nil))
}

func (b *MobileApprovalBridge) signDecision(challengeID, nonce, decision, diffDigest string, expiresAt time.Time) string {
	mac := hmac.New(sha256.New, b.secret)
	mac.Write([]byte("decision|"))
	mac.Write([]byte(challengeID))
	mac.Write([]byte("|"))
	mac.Write([]byte(nonce))
	mac.Write([]byte("|"))
	mac.Write([]byte(decision))
	mac.Write([]byte("|"))
	mac.Write([]byte(diffDigest))
	mac.Write([]byte("|"))
	mac.Write([]byte(strconv.FormatInt(expiresAt.UTC().UnixNano(), 10)))
	return hex.EncodeToString(mac.Sum(nil))
}
