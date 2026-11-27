package clients

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/A-L-L-A-H/mw-rocksoul-cli/internal/risk"
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

type captureTransport struct {
	prompts []ApprovalPrompt
}

func (c *captureTransport) Send(_ context.Context, prompt ApprovalPrompt) error {
	c.prompts = append(c.prompts, prompt)
	return nil
}

func TestMobileApprovalBridgeNtfyAndTelegramSingleUseNonceAndExpiryFailClosed(t *testing.T) {
	now := time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC)
	gate := risk.NewGateWithOptions(risk.GateOptions{
		Policy: risk.DefaultPolicy(),
		Secret: []byte("gate-secret-v42"),
		Clock:  func() time.Time { return now },
	})
	capTr := &captureTransport{}

	bridge := NewMobileApprovalBridge(MobileApprovalOptions{
		Gate:                  gate,
		Transports:            []ApprovalTransport{capTr},
		CallbackBaseURL:       "http://127.0.0.1:4598",
		Secret:                []byte("bridge-secret-v42"),
		CallbackToken:         "cb-tok-123",
		TelegramWebhookSecret: "tg-secret-456",
		TTL:                   2 * time.Minute,
		Clock:                 func() time.Time { return now },
	})
	srv := httptest.NewServer(bridge)
	defer srv.Close()

	// 1. R4 diff approval challenge over Ntfy callback URL -> issues single-use risk token & rejects replay.
	r4Action := risk.Action{Tool: "edit_file", Path: ".env"}
	ch1, err := bridge.CreateChallenge(context.Background(), r4Action, "--- a/.env\n+++ b/.env\n+FOO=BAR\n")
	if err != nil {
		t.Fatalf("CreateChallenge: %v", err)
	}
	if ch1.RiskTier != "R4" || len(capTr.prompts) != 1 || capTr.prompts[0].DiffDigest == "" {
		t.Fatalf("unexpected R4 challenge: %+v", ch1)
	}

	// Missing callback token must fail closed with 401.
	unauthReq, _ := http.NewRequest(http.MethodPost, strings.Replace(ch1.ApproveURL, "http://127.0.0.1:4598", srv.URL, 1), nil)
	unauthResp, err := srv.Client().Do(unauthReq)
	if err != nil || unauthResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 without callback token, got err=%v code=%d", err, unauthResp.StatusCode)
	}
	unauthResp.Body.Close()

	// Tampered signature must fail closed with 403 and NOT consume the nonce.
	badSigURL := strings.Replace(ch1.ApproveURL, ch1.ApproveURL[len(ch1.ApproveURL)-6:], "000000", 1)
	badReq, _ := http.NewRequest(http.MethodPost, strings.Replace(badSigURL, "http://127.0.0.1:4598", srv.URL, 1), nil)
	badReq.Header.Set("X-Approval-Token", "cb-tok-123")
	badResp, err := srv.Client().Do(badReq)
	if err != nil || badResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 on bad signature, got err=%v code=%d", err, badResp.StatusCode)
	}
	badResp.Body.Close()

	// Valid callback approves once and mints a working single-use R4 RiskGate token.
	okReq, _ := http.NewRequest(http.MethodPost, strings.Replace(ch1.ApproveURL, "http://127.0.0.1:4598", srv.URL, 1), nil)
	okReq.Header.Set("X-Approval-Token", "cb-tok-123")
	okResp, err := srv.Client().Do(okReq)
	if err != nil || okResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on valid approval callback, got err=%v code=%d", err, okResp.StatusCode)
	}
	okResp.Body.Close()

	waitRes, err := bridge.WaitForChallenge(context.Background(), ch1.ChallengeID)
	if err != nil || waitRes.Status != "approved" || !strings.HasPrefix(waitRes.ApprovalToken, "rsk_") {
		t.Fatalf("expected approved challenge with rsk_ token, got res=%+v err=%v", waitRes, err)
	}
	evalDec := gate.Evaluate(r4Action, waitRes.ApprovalToken)
	if !evalDec.Allowed || !evalDec.TokenConsumed {
		t.Fatalf("expected minted R4 token to unlock gate once, got %+v", evalDec)
	}

	// Replay of the exact same Ntfy callback URL MUST fail closed with 409 Conflict (single-use nonce).
	replayReq, _ := http.NewRequest(http.MethodPost, strings.Replace(ch1.ApproveURL, "http://127.0.0.1:4598", srv.URL, 1), nil)
	replayReq.Header.Set("X-Approval-Token", "cb-tok-123")
	replayResp, err := srv.Client().Do(replayReq)
	if err != nil || replayResp.StatusCode != http.StatusConflict {
		t.Fatalf("expected 409 on replayed nonce, got err=%v code=%d", err, replayResp.StatusCode)
	}
	replayResp.Body.Close()

	// 2. R3 challenge over Telegram inline keyboard webhook callback_query.
	r3Action := risk.Action{Tool: "run_shell", Command: "git push origin feature"}
	ch2, err := bridge.CreateChallenge(context.Background(), r3Action, "git push origin feature")
	if err != nil {
		t.Fatalf("CreateChallenge R3: %v", err)
	}
	if ch2.RiskTier != "R3" {
		t.Fatalf("expected R3 tier, got %s", ch2.RiskTier)
	}
	tgBody, _ := json.Marshal(map[string]any{
		"callback_query": map[string]any{
			"id":   "cbq-1",
			"from": map[string]any{"username": "secops", "id": 77},
			"data": ch2.ApproveCallbackData,
		},
	})
	tgReq, _ := http.NewRequest(http.MethodPost, srv.URL+"/telegram/webhook", strings.NewReader(string(tgBody)))
	tgReq.Header.Set("Content-Type", "application/json")
	tgReq.Header.Set("X-Telegram-Bot-Api-Secret-Token", "tg-secret-456")
	tgResp, err := srv.Client().Do(tgReq)
	if err != nil || tgResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from telegram webhook, got err=%v code=%d", err, tgResp.StatusCode)
	}
	tgResp.Body.Close()

	res2, err := bridge.WaitForChallenge(context.Background(), ch2.ChallengeID)
	if err != nil || res2.Status != "approved" || res2.ApprovalToken == "" {
		t.Fatalf("expected telegram R3 approval token, got res=%+v err=%v", res2, err)
	}

	// 3. Expiry fail-closed: challenge past TTL rejects approval with 410 Gone and reports expired.
	ch3, err := bridge.CreateChallenge(context.Background(), r4Action, "expired diff")
	if err != nil {
		t.Fatalf("CreateChallenge ch3: %v", err)
	}
	now = now.Add(3 * time.Minute)
	expReq, _ := http.NewRequest(http.MethodPost, strings.Replace(ch3.ApproveURL, "http://127.0.0.1:4598", srv.URL, 1), nil)
	expReq.Header.Set("X-Approval-Token", "cb-tok-123")
	expResp, err := srv.Client().Do(expReq)
	if err != nil || expResp.StatusCode != http.StatusGone {
		t.Fatalf("expected 410 Gone on expired challenge callback, got err=%v code=%d", err, expResp.StatusCode)
	}
	expResp.Body.Close()

	_, waitExpErr := bridge.WaitForChallenge(context.Background(), ch3.ChallengeID)
	if !errors.Is(waitExpErr, ErrChallengeExpired) {
		t.Fatalf("expected ErrChallengeExpired on expired challenge, got %v", waitExpErr)
	}
}
