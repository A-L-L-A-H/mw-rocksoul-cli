package clients

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
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
	// compute HMAC of payload fields using secret key from env or config (placeholder)
	// For this implementation we assume HMAC already provided.
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
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		resp, err := httpClient.Get(fmt.Sprintf("%s/status/%s", endpoint, challengeID))
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
	ChallengeID string
	Summary     string
	ApproveURL  string
	DenyURL     string
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
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.TopicURL, strings.NewReader(prompt.Summary))
	if err != nil {
		return fmt.Errorf("ntfy request: %w", err)
	}
	req.Header.Set("Title", "Rocksoul approval "+prompt.ChallengeID)
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
	payload := map[string]any{
		"chat_id": t.ChatID,
		"text":    "Rocksoul approval " + prompt.ChallengeID + "\n" + prompt.Summary,
		"reply_markup": map[string][][]button{"inline_keyboard": {{
			{Text: "Approve", CallbackData: "approve:" + prompt.ChallengeID, URL: ""},
			{Text: "Deny", CallbackData: "deny:" + prompt.ChallengeID, URL: ""},
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
