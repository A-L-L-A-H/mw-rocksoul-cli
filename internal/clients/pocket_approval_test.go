package clients

import (
    "context"
    "crypto/hmac"
    "crypto/sha256"
    "encoding/base64"
    "net/http"
    "net/http/httptest"
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
        ExpiresAt:    time.Now().Add(5 * time.Minute),
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
