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
    "time"
)

type PocketApprovalRequest struct {
    ChallengeID   string `json:"challengeId"`
    RiskTier      string `json:"riskTier"`
    ActionSummary string `json:"actionSummary"`
    DiffDigest    string `json:"diffDigest"`
    ExpiresAt    time.Time `json:"expiresAt"`
    HMAC          string `json:"hmac"`
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
