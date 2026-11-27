package contracts

import "strings"

// RiskDecision is the versioned policy verdict returned by mw-rocksoul-core
// (/v1/risk/evaluate) and enforced by mw-rocksoul-cli and mw-rocksoul-sandbox.
type RiskDecision struct {
	SchemaVersion                   string             `json:"schemaVersion"`
	DecisionID                      string             `json:"decisionId"`
	Allowed                         bool               `json:"allowed"`
	Decision                        DecisionKind       `json:"decision"`
	EffectiveRiskTier               RiskTier           `json:"effectiveRiskTier"`
	DataClassification              DataClassification `json:"dataClassification"`
	TargetZone                      TargetZone         `json:"targetZone"`
	ReasonCodes                     []string           `json:"reasonCodes"`
	Messages                        []string           `json:"messages"`
	RequiresIndependentVerification bool               `json:"requiresIndependentVerification"`
	RequiresHumanApproval           bool               `json:"requiresHumanApproval"`
	VerifiedGrantID                 string             `json:"verifiedGrantId,omitempty"`
	VerifiedApprovalTokenID         string             `json:"verifiedApprovalTokenId,omitempty"`
	ScopeHash                       string             `json:"scopeHash,omitempty"`
	EvaluatedAt                     string             `json:"evaluatedAt"`
	DecisionSHA256                  string             `json:"decisionSha256"`
}

// Validate enforces RiskDecision v1 schema and non-negotiable R0-R4 / air-gap invariants.
func (d RiskDecision) Validate() error {
	var errs ValidationErrors

	requireSchemaVersion(&errs, d.SchemaVersion, SchemaVersionRiskDecision)
	requireNonEmpty(&errs, "decisionId", d.DecisionID)

	switch d.Decision {
	case DecisionAllow, DecisionRequireHumanApproval, DecisionDeny:
	default:
		addErr(&errs, "decision", "must be one of allow, require_human_approval, deny")
	}

	if d.Allowed && d.Decision != DecisionAllow {
		addErr(&errs, "allowed", "cannot be true unless decision is allow")
	}
	if !d.Allowed && d.Decision == DecisionAllow {
		addErr(&errs, "allowed", "must be true when decision is allow")
	}

	validateRiskTierField(&errs, "effectiveRiskTier", d.EffectiveRiskTier)
	validateClassificationField(&errs, "dataClassification", d.DataClassification)
	validateTargetZoneField(&errs, "targetZone", d.TargetZone)

	if d.EffectiveRiskTier == RiskTierR4 && d.Allowed {
		addErr(&errs, "effectiveRiskTier", "R4 operations cannot be allowed")
	}
	if d.DataClassification == ClassificationLocalOnly && d.TargetZone == TargetZoneCloud && d.Allowed {
		addErr(&errs, "targetZone", "local_only classification cannot allow cloud targetZone")
	}
	if d.Decision == DecisionDeny && len(d.ReasonCodes) == 0 {
		addErr(&errs, "reasonCodes", "must contain at least one reason code when decision is deny")
	}

	if strings.TrimSpace(d.ScopeHash) != "" && !isValidSHA256Hex(d.ScopeHash) {
		addErr(&errs, "scopeHash", "must be 64 lowercase hex characters when present")
	}
	parseRFC3339(&errs, "evaluatedAt", d.EvaluatedAt)
	if !isValidSHA256Hex(d.DecisionSHA256) {
		addErr(&errs, "decisionSha256", "must be 64 lowercase hex characters")
	}

	return errs.asErr()
}
