package contracts

import (
	"encoding/json"
	"strings"
	"testing"
)

const (
	testSHA256A = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testSHA256B = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	testCommit  = "0123456789abcdef0123456789abcdef01234567"
)

func validExecutionPacket() ExecutionPacket {
	return ExecutionPacket{
		SchemaVersion:      SchemaVersionExecutionPacket,
		PacketID:           "pkt-001",
		TaskID:             "task-auth-race",
		SessionID:          "sess-101",
		PrincipalID:        "dev@mw.local",
		AgentProfile:       "rocksoul",
		DataClassification: ClassificationLocalOnly,
		RiskTier:           RiskTierR1,
		Action:             "fs.patch",
		Capability:         "workspace.write",
		OwnedPaths:         []string{"internal/contracts/common.go"},
		Command:            "go",
		Args:               []string{"test", "./internal/contracts/..."},
		LeaseID:            "lease-001",
		FencingToken:       42,
		ParentProofHashes:  []string{testSHA256A},
		IssuedAt:           "2026-11-27T09:00:00Z",
		ExpiresAt:          "2026-11-27T09:15:00Z",
		Metadata:           map[string]any{"wave": "RS-0"},
	}
}

func validRiskDecision() RiskDecision {
	return RiskDecision{
		SchemaVersion:                   SchemaVersionRiskDecision,
		DecisionID:                      "dec-001",
		Allowed:                         true,
		Decision:                        DecisionAllow,
		EffectiveRiskTier:               RiskTierR1,
		DataClassification:              ClassificationLocalOnly,
		TargetZone:                      TargetZoneLocal,
		ReasonCodes:                     []string{},
		Messages:                        []string{"allowed in isolated worktree"},
		RequiresIndependentVerification: true,
		RequiresHumanApproval:           false,
		VerifiedGrantID:                 "grant-1",
		ScopeHash:                       testSHA256A,
		EvaluatedAt:                     "2026-11-27T09:00:05Z",
		DecisionSHA256:                  testSHA256B,
	}
}

func validWorktreeLease() WorktreeLease {
	return WorktreeLease{
		SchemaVersion: SchemaVersionWorktreeLease,
		LeaseID:       "lease-001",
		OwnerID:       "rocksoul-cli",
		RepoPath:      "z:/repo/mw-rocksoul-cli",
		WorktreePath:  "z:/repo/.worktrees/lease-001",
		BaseRef:       "main",
		BaseCommit:    testCommit,
		FencingToken:  7,
		Exclusive:     true,
		Label:         "wave-rs0",
		Status:        LeaseStatusActive,
		CreatedAt:     "2026-11-27T09:00:00Z",
		UpdatedAt:     "2026-11-27T09:00:00Z",
		ExpiresAt:     "2026-11-27T09:30:00Z",
	}
}

func validPcwEnvelope() PcwEnvelope {
	size := int64(512)
	exitZero := 0
	return PcwEnvelope{
		SchemaVersion:     SchemaVersionPcwEnvelope,
		EnvelopeID:        "pcw-001",
		TaskID:            "task-auth-race",
		ProducerAgentID:   "w2b-rocksoul-contracts",
		ReviewerAgentID:   "verifier-1",
		RiskTier:          RiskTierR1,
		ParentProofHashes: []string{testSHA256A},
		Artifacts: []PcwArtifactRecord{
			{
				ID:        "art-diff",
				Kind:      ArtifactDiff,
				SHA256:    testSHA256A,
				SizeBytes: &size,
				Path:      "internal/contracts/common.go",
			},
		},
		Checks: []PcwCheckEvidence{
			{
				Code:      "go_test",
				Command:   "go test ./internal/contracts/...",
				Status:    CheckStatusPass,
				Mandatory: true,
				ExitCode:  &exitZero,
			},
		},
		ChangedFiles:   []string{"internal/contracts/common.go"},
		ProducedAt:     "2026-11-27T09:10:00Z",
		ExpiresAt:      "2026-11-28T09:10:00Z",
		MerkleRoot:     testSHA256A,
		EnvelopeSHA256: testSHA256B,
	}
}

func validGatewayUsageEvent() GatewayUsageEvent {
	return GatewayUsageEvent{
		SchemaVersion:    SchemaVersionGatewayUsageEvent,
		EventID:          "evt-001",
		AgentID:          "rocksoul",
		RequestedModel:   "auto",
		ResolvedProvider: "ollama",
		ResolvedModel:    "qwen2.5-coder:14b",
		Classification:   ClassificationLocalOnly,
		StatusCode:       200,
		LatencyMS:        145,
		PromptTokens:     1200,
		CompletionTokens: 320,
		RTKTokensSaved:   280,
		RedactionsCount:  2,
		EgressBlocked:    false,
		CacheHit:         false,
		CostUSDMicros:    0,
		CreatedAt:        "2026-11-27T09:05:00Z",
	}
}

func TestAllContractsRoundTripJSON(t *testing.T) {
	t.Run("ExecutionPacket", func(t *testing.T) {
		in := validExecutionPacket()
		raw, err := MarshalContract(in)
		if err != nil {
			t.Fatalf("MarshalContract: %v", err)
		}
		var wire map[string]any
		if err := json.Unmarshal(raw, &wire); err != nil {
			t.Fatalf("unmarshal map: %v", err)
		}
		if wire["schemaVersion"] != SchemaVersionExecutionPacket {
			t.Fatalf("unexpected schemaVersion: %v", wire["schemaVersion"])
		}
		var out ExecutionPacket
		if err := UnmarshalAndValidate(raw, &out); err != nil {
			t.Fatalf("UnmarshalAndValidate: %v", err)
		}
		if out.PacketID != in.PacketID || out.FencingToken != in.FencingToken {
			t.Fatalf("round-trip mismatch: got %+v want %+v", out, in)
		}
	})

	t.Run("RiskDecision", func(t *testing.T) {
		in := validRiskDecision()
		raw, err := MarshalContract(in)
		if err != nil {
			t.Fatalf("MarshalContract: %v", err)
		}
		var out RiskDecision
		if err := UnmarshalAndValidate(raw, &out); err != nil {
			t.Fatalf("UnmarshalAndValidate: %v", err)
		}
		if out.DecisionID != in.DecisionID || out.DecisionSHA256 != in.DecisionSHA256 {
			t.Fatalf("round-trip mismatch: got %+v want %+v", out, in)
		}
	})

	t.Run("WorktreeLease", func(t *testing.T) {
		in := validWorktreeLease()
		raw, err := MarshalContract(in)
		if err != nil {
			t.Fatalf("MarshalContract: %v", err)
		}
		var out WorktreeLease
		if err := UnmarshalAndValidate(raw, &out); err != nil {
			t.Fatalf("UnmarshalAndValidate: %v", err)
		}
		if out.LeaseID != in.LeaseID || out.BaseCommit != in.BaseCommit {
			t.Fatalf("round-trip mismatch: got %+v want %+v", out, in)
		}
	})

	t.Run("PcwEnvelope", func(t *testing.T) {
		in := validPcwEnvelope()
		raw, err := MarshalContract(in)
		if err != nil {
			t.Fatalf("MarshalContract: %v", err)
		}
		var out PcwEnvelope
		if err := UnmarshalAndValidate(raw, &out); err != nil {
			t.Fatalf("UnmarshalAndValidate: %v", err)
		}
		if out.EnvelopeID != in.EnvelopeID || out.MerkleRoot != in.MerkleRoot {
			t.Fatalf("round-trip mismatch: got %+v want %+v", out, in)
		}
	})

	t.Run("GatewayUsageEvent", func(t *testing.T) {
		in := validGatewayUsageEvent()
		raw, err := MarshalContract(in)
		if err != nil {
			t.Fatalf("MarshalContract: %v", err)
		}
		var out GatewayUsageEvent
		if err := UnmarshalAndValidate(raw, &out); err != nil {
			t.Fatalf("UnmarshalAndValidate: %v", err)
		}
		if out.EventID != in.EventID || out.RTKTokensSaved != in.RTKTokensSaved {
			t.Fatalf("round-trip mismatch: got %+v want %+v", out, in)
		}
	})
}

func TestExecutionPacketValidationErrors(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*ExecutionPacket)
		want   string
	}{
		{"wrong schemaVersion", func(p *ExecutionPacket) { p.SchemaVersion = "v0" }, "schemaVersion"},
		{"invalid riskTier", func(p *ExecutionPacket) { p.RiskTier = "R9" }, "riskTier"},
		{"invalid classification", func(p *ExecutionPacket) { p.DataClassification = "public" }, "dataClassification"},
		{"lease without fencing token", func(p *ExecutionPacket) { p.LeaseID = "l1"; p.FencingToken = 0 }, "fencingToken"},
		{"bad parent proof hash", func(p *ExecutionPacket) { p.ParentProofHashes = []string{"not-sha"} }, "parentProofHashes[0]"},
		{"expired window", func(p *ExecutionPacket) { p.ExpiresAt = p.IssuedAt }, "expiresAt"},
		{"empty owned path", func(p *ExecutionPacket) { p.OwnedPaths = []string{"  "} }, "ownedPaths[0]"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := validExecutionPacket()
			tc.mutate(&p)
			err := p.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestRiskDecisionValidationErrors(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*RiskDecision)
		want   string
	}{
		{"wrong schemaVersion", func(d *RiskDecision) { d.SchemaVersion = "bad" }, "schemaVersion"},
		{"r4 cannot be allowed", func(d *RiskDecision) { d.EffectiveRiskTier = RiskTierR4 }, "effectiveRiskTier"},
		{"local_only cannot allow cloud", func(d *RiskDecision) { d.TargetZone = TargetZoneCloud }, "targetZone"},
		{"allowed mismatch", func(d *RiskDecision) { d.Decision = DecisionDeny; d.ReasonCodes = []string{"DENIED"} }, "allowed"},
		{"deny without reasonCodes", func(d *RiskDecision) { d.Allowed = false; d.Decision = DecisionDeny; d.ReasonCodes = nil }, "reasonCodes"},
		{"bad decisionSha256", func(d *RiskDecision) { d.DecisionSHA256 = "xyz" }, "decisionSha256"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := validRiskDecision()
			tc.mutate(&d)
			err := d.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestWorktreeLeaseValidationErrors(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*WorktreeLease)
		want   string
	}{
		{"wrong schemaVersion", func(l *WorktreeLease) { l.SchemaVersion = "v2" }, "schemaVersion"},
		{"invalid baseCommit", func(l *WorktreeLease) { l.BaseCommit = "abc" }, "baseCommit"},
		{"non-positive fencingToken", func(l *WorktreeLease) { l.FencingToken = 0 }, "fencingToken"},
		{"released without releasedAt", func(l *WorktreeLease) { l.Status = LeaseStatusReleased }, "releasedAt"},
		{"active with releasedAt", func(l *WorktreeLease) { l.ReleasedAt = "2026-11-27T09:01:00Z" }, "releasedAt"},
		{"updatedAt before createdAt", func(l *WorktreeLease) { l.UpdatedAt = "2026-11-27T08:59:00Z" }, "updatedAt"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := validWorktreeLease()
			tc.mutate(&l)
			err := l.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestPcwEnvelopeValidationErrors(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*PcwEnvelope)
		want   string
	}{
		{"wrong schemaVersion", func(e *PcwEnvelope) { e.SchemaVersion = "pcw/v2" }, "schemaVersion"},
		{"self approval", func(e *PcwEnvelope) { e.ReviewerAgentID = e.ProducerAgentID }, "reviewerAgentId"},
		{"empty artifacts", func(e *PcwEnvelope) { e.Artifacts = nil }, "artifacts"},
		{"duplicate artifact id", func(e *PcwEnvelope) { e.Artifacts = append(e.Artifacts, e.Artifacts[0]) }, "duplicate artifact id"},
		{"invalid artifact kind", func(e *PcwEnvelope) { e.Artifacts[0].Kind = "unknown" }, "artifacts[0].kind"},
		{"skipped check without reason", func(e *PcwEnvelope) { e.Checks = []PcwCheckEvidence{{Code: "lint", Status: CheckStatusSkipped}} }, "checks[0].reason"},
		{"bad merkleRoot", func(e *PcwEnvelope) { e.MerkleRoot = "1234" }, "merkleRoot"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := validPcwEnvelope()
			tc.mutate(&e)
			err := e.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestGatewayUsageEventValidationErrors(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*GatewayUsageEvent)
		want   string
	}{
		{"wrong schemaVersion", func(e *GatewayUsageEvent) { e.SchemaVersion = "v0" }, "schemaVersion"},
		{"bad statusCode", func(e *GatewayUsageEvent) { e.StatusCode = 99 }, "statusCode"},
		{"negative tokens", func(e *GatewayUsageEvent) { e.PromptTokens = -1 }, "promptTokens"},
		{"negative rtk saved", func(e *GatewayUsageEvent) { e.RTKTokensSaved = -5 }, "rtkTokensSaved"},
		{"negative cost", func(e *GatewayUsageEvent) { e.CostUSDMicros = -10 }, "costUsdMicros"},
		{"bad timestamp", func(e *GatewayUsageEvent) { e.CreatedAt = "not-a-time" }, "createdAt"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := validGatewayUsageEvent()
			tc.mutate(&e)
			err := e.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestUnmarshalAndValidateRejectsCorruptJSON(t *testing.T) {
	var pkt ExecutionPacket
	if err := UnmarshalAndValidate([]byte(`{broken`), &pkt); err == nil {
		t.Fatal("expected JSON decode error")
	}
	if _, err := MarshalContract(nil); err == nil {
		t.Fatal("expected nil contract error")
	}
}
