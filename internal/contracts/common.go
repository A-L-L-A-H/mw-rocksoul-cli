// Package contracts defines versioned wire contracts exchanged across the
// five mw-rocksoul-* repositories (cli, gateway, core, mcp, sandbox).
package contracts

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

const (
	SchemaVersionExecutionPacket   = "rocksoul.execution_packet/v1"
	SchemaVersionRiskDecision      = "rocksoul.risk_decision/v1"
	SchemaVersionWorktreeLease     = "rocksoul.worktree_lease/v1"
	SchemaVersionPcwEnvelope       = "pcw/v1"
	SchemaVersionGatewayUsageEvent = "rocksoul.gateway_usage_event/v1"
)

// RiskTier classifies operational risk from R0 (read-only) to R4 (prohibited/protected).
type RiskTier string

const (
	RiskTierR0 RiskTier = "R0"
	RiskTierR1 RiskTier = "R1"
	RiskTierR2 RiskTier = "R2"
	RiskTierR3 RiskTier = "R3"
	RiskTierR4 RiskTier = "R4"
)

// DataClassification controls egress privacy and air-gap enforcement.
type DataClassification string

const (
	ClassificationLocalOnly     DataClassification = "local_only"
	ClassificationCloudEligible DataClassification = "cloud_eligible"
)

// TargetZone identifies where an evaluated operation executes.
type TargetZone string

const (
	TargetZoneLocal TargetZone = "local"
	TargetZoneCloud TargetZone = "cloud"
)

// DecisionKind represents the policy verdict returned by RiskDecision.
type DecisionKind string

const (
	DecisionAllow                DecisionKind = "allow"
	DecisionRequireHumanApproval DecisionKind = "require_human_approval"
	DecisionDeny                 DecisionKind = "deny"
)

// LeaseStatus represents the lifecycle state of a WorktreeLease.
type LeaseStatus string

const (
	LeaseStatusActive   LeaseStatus = "active"
	LeaseStatusReleased LeaseStatus = "released"
	LeaseStatusExpired  LeaseStatus = "expired"
)

// ArtifactKind categorizes evidence artifacts carried inside a PcwEnvelope.
type ArtifactKind string

const (
	ArtifactDiff           ArtifactKind = "diff"
	ArtifactTestLog        ArtifactKind = "test_log"
	ArtifactReport         ArtifactKind = "report"
	ArtifactTranscript     ArtifactKind = "transcript"
	ArtifactToolOutput     ArtifactKind = "tool_output"
	ArtifactEvidenceBundle ArtifactKind = "evidence_bundle"
	ArtifactEvalResult     ArtifactKind = "eval_result"
)

// CheckStatus captures verification check outcomes inside a PcwEnvelope.
type CheckStatus string

const (
	CheckStatusPass          CheckStatus = "pass"
	CheckStatusFail          CheckStatus = "fail"
	CheckStatusSkipped       CheckStatus = "skipped"
	CheckStatusNotApplicable CheckStatus = "not_applicable"
	CheckStatusNotRun        CheckStatus = "not_run"
)

var (
	sha256HexPattern    = regexp.MustCompile(`^[a-f0-9]{64}$`)
	commitSHAHexPattern = regexp.MustCompile(`^[a-f0-9]{40,64}$`)
)

// ContractValidator is implemented by all versioned wire contracts.
type ContractValidator interface {
	Validate() error
}

// ValidationError describes one contract invariant violation.
type ValidationError struct {
	Field   string
	Message string
}

func (e ValidationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Field, e.Message)
}

// ValidationErrors aggregates multiple contract validation failures.
type ValidationErrors []ValidationError

func (e ValidationErrors) Error() string {
	if len(e) == 0 {
		return ""
	}
	parts := make([]string, len(e))
	for i, item := range e {
		parts[i] = item.Error()
	}
	return strings.Join(parts, "; ")
}

func (e ValidationErrors) asErr() error {
	if len(e) == 0 {
		return nil
	}
	return e
}

func addErr(errs *ValidationErrors, field, message string) {
	*errs = append(*errs, ValidationError{Field: field, Message: message})
}

func requireSchemaVersion(errs *ValidationErrors, actual, expected string) {
	if actual != expected {
		addErr(errs, "schemaVersion", fmt.Sprintf("must equal %q (got %q)", expected, actual))
	}
}

func requireNonEmpty(errs *ValidationErrors, field, value string) {
	if strings.TrimSpace(value) == "" {
		addErr(errs, field, "must not be empty")
	}
}

func validateRiskTierField(errs *ValidationErrors, field string, tier RiskTier) {
	switch tier {
	case RiskTierR0, RiskTierR1, RiskTierR2, RiskTierR3, RiskTierR4:
	default:
		addErr(errs, field, fmt.Sprintf("invalid risk tier %q (expected R0-R4)", tier))
	}
}

func validateClassificationField(errs *ValidationErrors, field string, c DataClassification) {
	switch c {
	case ClassificationLocalOnly, ClassificationCloudEligible:
	default:
		addErr(errs, field, fmt.Sprintf("invalid data classification %q", c))
	}
}

func validateTargetZoneField(errs *ValidationErrors, field string, z TargetZone) {
	switch z {
	case TargetZoneLocal, TargetZoneCloud:
	default:
		addErr(errs, field, fmt.Sprintf("invalid target zone %q", z))
	}
}

func isValidSHA256Hex(v string) bool {
	return sha256HexPattern.MatchString(v)
}

func parseRFC3339(errs *ValidationErrors, field, raw string) (time.Time, bool) {
	if strings.TrimSpace(raw) == "" {
		addErr(errs, field, "must be a non-empty RFC3339 timestamp")
		return time.Time{}, false
	}
	parsed, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		addErr(errs, field, fmt.Sprintf("must be valid RFC3339 timestamp: %v", err))
		return time.Time{}, false
	}
	return parsed, true
}

func validateSHA256List(errs *ValidationErrors, field string, hashes []string) {
	for i, h := range hashes {
		if !isValidSHA256Hex(h) {
			addErr(errs, fmt.Sprintf("%s[%d]", field, i), "must be 64 lowercase hex characters")
		}
	}
}

// MarshalContract validates and serializes a contract to JSON.
func MarshalContract(c ContractValidator) ([]byte, error) {
	if c == nil {
		return nil, errors.New("contract must not be nil")
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(c)
}

// UnmarshalAndValidate decodes JSON into target and enforces contract validation.
func UnmarshalAndValidate[T ContractValidator](data []byte, target T) error {
	if err := json.Unmarshal(data, target); err != nil {
		return fmt.Errorf("decode contract JSON: %w", err)
	}
	return target.Validate()
}
