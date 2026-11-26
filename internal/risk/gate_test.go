package risk

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestClassifyDeterministicTiers(t *testing.T) {
	cases := []struct {
		name   string
		action Action
		want   Tier
	}{
		{
			name:   "R0 read_file regular source",
			action: Action{Tool: "read_file", Path: "cmd/rocksoul/main.go"},
			want:   TierR0,
		},
		{
			name:   "R0 list_dir workspace",
			action: Action{Tool: "list_dir", Path: "internal"},
			want:   TierR0,
		},
		{
			name:   "R0 search_symbols workspace",
			action: Action{Tool: "search_symbols", Path: "."},
			want:   TierR0,
		},
		{
			name:   "R1 write_file normal file",
			action: Action{Tool: "write_file", Path: "internal/foo.go"},
			want:   TierR1,
		},
		{
			name:   "R1 edit_file .env.example allowed as local write",
			action: Action{Tool: "edit_file", Path: ".env.example"},
			want:   TierR1,
		},
		{
			name:   "R2 local shell go test",
			action: Action{Tool: "run_shell", Command: "go test ./..."},
			want:   TierR2,
		},
		{
			name:   "R3 curl remote egress",
			action: Action{Tool: "run_shell", Command: "curl https://example.com/api"},
			want:   TierR3,
		},
		{
			name:   "R3 git push egress",
			action: Action{Tool: "run_shell", Command: "git push origin main"},
			want:   TierR3,
		},
		{
			name:   "R3 mcp_call tool",
			action: Action{Tool: "mcp_call", RemoteTarget: "mw-rocksoul-mcp"},
			want:   TierR3,
		},
		{
			name:   "R4 protected .githooks write",
			action: Action{Tool: "write_file", Path: ".githooks/pre-commit"},
			want:   TierR4,
		},
		{
			name:   "R4 protected .githooks windows slash",
			action: Action{Tool: "edit_file", Path: `sub\.githooks\pre-push`},
			want:   TierR4,
		},
		{
			name:   "R4 protected .env read",
			action: Action{Tool: "read_file", Path: ".env"},
			want:   TierR4,
		},
		{
			name:   "R4 protected .env.production write",
			action: Action{Tool: "write_file", Path: "config/.env.production"},
			want:   TierR4,
		},
		{
			name:   "R4 destructive rm -rf",
			action: Action{Tool: "run_shell", Command: "rm -rf ./build"},
			want:   TierR4,
		},
		{
			name:   "R4 destructive git reset --hard",
			action: Action{Tool: "run_shell", Command: "git reset --hard HEAD~1"},
			want:   TierR4,
		},
		{
			name:   "R4 shell reading .env",
			action: Action{Tool: "run_shell", Command: "cat .env"},
			want:   TierR4,
		},
		{
			name:   "R4 shell touching .githooks",
			action: Action{Tool: "run_shell", Command: "chmod +x .githooks/pre-commit"},
			want:   TierR4,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, reason := Classify(tc.action)
			if got != tc.want {
				t.Fatalf("Classify(%+v) = %s (%q), want %s", tc.action, got, reason, tc.want)
			}
		})
	}
}

func TestEvaluateDefaultPolicyAndR4NeverAutoApproved(t *testing.T) {
	gate := NewGate(DefaultPolicy())

	// R0 auto-approved.
	r0 := gate.Evaluate(Action{Tool: "read_file", Path: "README.md"}, "")
	if !r0.Allowed || !r0.AutoApproved || r0.Tier != TierR0 {
		t.Fatalf("expected R0 auto-approved, got %+v", r0)
	}

	// R1 blocked by default when MaxAutoTier=R0.
	r1 := gate.Evaluate(Action{Tool: "write_file", Path: "README.md"}, "")
	if r1.Allowed || !r1.RequiresApproval || r1.Tier != TierR1 {
		t.Fatalf("expected R1 blocked requiring approval, got %+v", r1)
	}

	// Even when elevating MaxAutoTier to R3, R4 MUST remain blocked by default.
	if err := gate.SetMaxAutoTier(TierR3); err != nil {
		t.Fatalf("SetMaxAutoTier(R3): %v", err)
	}
	if err := gate.SetMaxAutoTier(TierR4); err == nil {
		t.Fatalf("expected SetMaxAutoTier(R4) to fail")
	}

	r3 := gate.Evaluate(Action{Tool: "mcp_call", RemoteTarget: "mw-rocksoul-mcp"}, "")
	if !r3.Allowed || !r3.AutoApproved || r3.Tier != TierR3 {
		t.Fatalf("expected R3 auto-approved under MaxAutoTier=R3, got %+v", r3)
	}

	r4Hook := gate.Evaluate(Action{Tool: "write_file", Path: ".githooks/pre-commit"}, "")
	if r4Hook.Allowed || r4Hook.Tier != TierR4 || !strings.Contains(r4Hook.Reason, "blocked") {
		t.Fatalf("expected R4 .githooks blocked even when MaxAutoTier=R3, got %+v", r4Hook)
	}

	r4Env := gate.Evaluate(Action{Tool: "read_file", Path: ".env"}, "")
	if r4Env.Allowed || r4Env.Tier != TierR4 {
		t.Fatalf("expected R4 .env blocked by default, got %+v", r4Env)
	}
}

func TestSingleUseApprovalTokenLifecycle(t *testing.T) {
	now := time.Date(2026, 11, 27, 5, 30, 0, 0, time.UTC)
	gate := NewGateWithOptions(GateOptions{
		Policy: DefaultPolicy(),
		Clock:  func() time.Time { return now },
	})

	writeAction := Action{Tool: "write_file", Path: "internal/app.go"}
	otherAction := Action{Tool: "write_file", Path: "internal/other.go"}

	tok, err := gate.IssueApprovalToken(writeAction, 2*time.Minute, "lead-dev")
	if err != nil {
		t.Fatalf("IssueApprovalToken: %v", err)
	}
	if !strings.HasPrefix(tok.Token, "rsk_") || tok.Tier != TierR1 {
		t.Fatalf("unexpected token: %+v", tok)
	}

	// 1. Wrong scope MUST be rejected and MUST NOT consume the token.
	wrongScope := gate.Evaluate(otherAction, tok.Token)
	if wrongScope.Allowed || !errors.Is(wrongScope.Err, ErrTokenScopeMismatch) {
		t.Fatalf("expected ErrTokenScopeMismatch, got %+v", wrongScope)
	}

	// 2. Tampered signature MUST be rejected.
	tampered := gate.Evaluate(writeAction, tok.Token+"deadbeef")
	if tampered.Allowed || !errors.Is(tampered.Err, ErrTokenInvalid) {
		t.Fatalf("expected ErrTokenInvalid on tampered token, got %+v", tampered)
	}

	// 3. Matching action succeeds and consumes the token.
	firstUse := gate.Evaluate(writeAction, tok.Token)
	if !firstUse.Allowed || !firstUse.TokenConsumed || firstUse.Tier != TierR1 {
		t.Fatalf("expected first use to succeed and consume token, got %+v", firstUse)
	}

	// 4. Second use (replay) MUST fail with ErrTokenAlreadyUsed.
	replay := gate.Evaluate(writeAction, tok.Token)
	if replay.Allowed || !errors.Is(replay.Err, ErrTokenAlreadyUsed) {
		t.Fatalf("expected ErrTokenAlreadyUsed on replay, got %+v", replay)
	}

	// 5. Expired token MUST fail with ErrTokenExpired.
	r4Action := Action{Tool: "edit_file", Path: ".githooks/pre-commit"}
	expTok, err := gate.IssueApprovalToken(r4Action, 1*time.Minute, "owner")
	if err != nil {
		t.Fatalf("IssueApprovalToken(R4): %v", err)
	}
	now = now.Add(2 * time.Minute)
	expired := gate.Evaluate(r4Action, expTok.Token)
	if expired.Allowed || !errors.Is(expired.Err, ErrTokenExpired) {
		t.Fatalf("expected ErrTokenExpired, got %+v", expired)
	}

	// 6. Fresh R4 token unlocks exactly once when AllowR4OverrideToken=true.
	freshR4, err := gate.IssueApprovalToken(r4Action, 1*time.Minute, "owner")
	if err != nil {
		t.Fatalf("IssueApprovalToken fresh R4: %v", err)
	}
	okR4 := gate.Evaluate(r4Action, freshR4.Token)
	if !okR4.Allowed || !okR4.TokenConsumed || okR4.Tier != TierR4 {
		t.Fatalf("expected fresh R4 token to succeed once, got %+v", okR4)
	}
	if len(gate.AuditLog()) == 0 || !strings.Contains(gate.FormatPolicySummary(), "Risk Gate Policy") {
		t.Fatalf("expected non-empty audit log and formatted summary")
	}
}

func TestParseTier(t *testing.T) {
	if tier, err := ParseTier("r2"); err != nil || tier != TierR2 {
		t.Fatalf("ParseTier(r2) = %v, %v", tier, err)
	}
	if tier, err := ParseTier("0"); err != nil || tier != TierR0 {
		t.Fatalf("ParseTier(0) = %v, %v", tier, err)
	}
	if _, err := ParseTier("R9"); err == nil {
		t.Fatalf("expected ParseTier(R9) error")
	}
}
