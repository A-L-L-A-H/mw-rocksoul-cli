package clients

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestVerifyHMAC(t *testing.T) {
	secret := "s3cr3t"
	payload := PocketApprovalRequest{
		ChallengeID:   "cid",
		RiskTier:      "high",
		ActionSummary: "test",
		DiffDigest:    "abc123",
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	}
	// compute correct HMAC
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload.ChallengeID))
	mac.Write([]byte(payload.RiskTier))
	mac.Write([]byte(payload.ActionSummary))
	mac.Write([]byte(payload.DiffDigest))
	mac.Write([]byte(payload.ExpiresAt.UTC().Format(time.RFC3339)))
	payload.HMAC = base64.StdEncoding.EncodeToString(mac.Sum(nil))

	if !VerifyHMAC(secret, payload) {
		t.Fatalf("expected HMAC to verify")
	}
}

func TestRequestPocketApproval(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/request" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"pending"}`))
	}))
	defer srv.Close()

	ctx := context.Background()
	client := srv.Client()
	payload := PocketApprovalRequest{ChallengeID: "cid", HMAC: "dummy"}
	resp, err := RequestPocketApproval(ctx, client, srv.URL, payload)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if resp.Status != "pending" {
		t.Fatalf("expected pending, got %s", resp.Status)
	}
}

func TestPollPocketApproval(t *testing.T) {
	// simulate status progression: pending then approved
	call := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if call == 0 {
			w.Write([]byte(`{"status":"pending"}`))
		} else {
			w.Write([]byte(`{"status":"approved"}`))
		}
		call++
	}))
	defer srv.Close()

	ctx := context.Background()
	client := srv.Client()
	// replace http.DefaultClient in PollPocketApproval by passing custom client via http.Get? It uses http.Get directly; cannot inject client. We'll set default transport to srv's client Transport.
	http.DefaultClient = client
	resp, err := PollPocketApproval(ctx, client, srv.URL, "cid", 10*time.Millisecond, 200*time.Millisecond)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if resp.Status != "approved" {
		t.Fatalf("expected approved, got %s", resp.Status)
	}
}

func TestNtfyApprovalTransportSendsActionHeaders(t *testing.T) {
	var actions, body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		actions = r.Header.Get("Actions")
		raw, _ := io.ReadAll(r.Body)
		body = string(raw)
	}))
	defer srv.Close()
	transport := &NtfyApprovalTransport{TopicURL: srv.URL, HTTPClient: srv.Client()}
	err := transport.Send(context.Background(), ApprovalPrompt{ChallengeID: "c1", Summary: "write file", ApproveURL: "http://x/a", DenyURL: "http://x/d"})
	if err != nil || body != "write file" || !strings.Contains(actions, "Approve, http://x/a") || !strings.Contains(actions, "Deny, http://x/d") {
		t.Fatalf("err=%v body=%q actions=%q", err, body, actions)
	}
}

func TestTelegramApprovalTransportInlineButtons(t *testing.T) {
	var path, payload string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		raw, _ := io.ReadAll(r.Body)
		payload = string(raw)
	}))
	defer srv.Close()
	transport := &TelegramApprovalTransport{BotToken: "tok", ChatID: "42", APIBase: srv.URL, HTTPClient: srv.Client()}
	if err := transport.Send(context.Background(), ApprovalPrompt{ChallengeID: "c2", Summary: "rm"}); err != nil {
		t.Fatal(err)
	}
	if path != "/bottok/sendMessage" || !strings.Contains(payload, "approve:c2") || !strings.Contains(payload, "deny:c2") || !strings.Contains(payload, `"chat_id":"42"`) {
		t.Fatalf("path=%q payload=%q", path, payload)
	}
}

func TestApprovalTransportEnvRequired(t *testing.T) {
	t.Setenv("NTFY_TOPIC_URL", "")
	t.Setenv("TELEGRAM_BOT_TOKEN", "")
	if _, err := NewNtfyApprovalTransportFromEnv(); err == nil {
		t.Fatal("ntfy env should be required")
	}
	if _, err := NewTelegramApprovalTransportFromEnv(); err == nil {
		t.Fatal("telegram env should be required")
	}
}
