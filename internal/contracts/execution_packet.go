package contracts

import (
	"fmt"
	"strings"
)

// ExecutionPacket is the versioned work-dispatch envelope exchanged between
// mw-rocksoul-cli, mw-rocksoul-core, and mw-rocksoul-sandbox.
type ExecutionPacket struct {
	SchemaVersion      string             `json:"schemaVersion"`
	PacketID           string             `json:"packetId"`
	TaskID             string             `json:"taskId"`
	SessionID          string             `json:"sessionId"`
	PrincipalID        string             `json:"principalId"`
	AgentProfile       string             `json:"agentProfile"`
	DataClassification DataClassification `json:"dataClassification"`
	RiskTier           RiskTier           `json:"riskTier"`
	Action             string             `json:"action"`
	Capability         string             `json:"capability"`
	OwnedPaths         []string           `json:"ownedPaths,omitempty"`
	Command            string             `json:"command,omitempty"`
	Args               []string           `json:"args,omitempty"`
	LeaseID            string             `json:"leaseId,omitempty"`
	FencingToken       int64              `json:"fencingToken,omitempty"`
	ParentProofHashes  []string           `json:"parentProofHashes,omitempty"`
	IssuedAt           string             `json:"issuedAt"`
	ExpiresAt          string             `json:"expiresAt"`
	Metadata           map[string]any     `json:"metadata,omitempty"`
}

// Validate verifies all ExecutionPacket v1 structural and safety invariants.
func (p ExecutionPacket) Validate() error {
	var errs ValidationErrors

	requireSchemaVersion(&errs, p.SchemaVersion, SchemaVersionExecutionPacket)
	requireNonEmpty(&errs, "packetId", p.PacketID)
	requireNonEmpty(&errs, "taskId", p.TaskID)
	requireNonEmpty(&errs, "sessionId", p.SessionID)
	requireNonEmpty(&errs, "principalId", p.PrincipalID)
	requireNonEmpty(&errs, "agentProfile", p.AgentProfile)
	validateClassificationField(&errs, "dataClassification", p.DataClassification)
	validateRiskTierField(&errs, "riskTier", p.RiskTier)
	requireNonEmpty(&errs, "action", p.Action)
	requireNonEmpty(&errs, "capability", p.Capability)

	for i, path := range p.OwnedPaths {
		if strings.TrimSpace(path) == "" {
			addErr(&errs, fmt.Sprintf("ownedPaths[%d]", i), "must not be empty")
		}
	}

	if p.FencingToken < 0 {
		addErr(&errs, "fencingToken", "must not be negative")
	}
	if strings.TrimSpace(p.LeaseID) != "" && p.FencingToken <= 0 {
		addErr(&errs, "fencingToken", "must be a positive integer when leaseId is set")
	}

	validateSHA256List(&errs, "parentProofHashes", p.ParentProofHashes)

	issuedAt, okIssued := parseRFC3339(&errs, "issuedAt", p.IssuedAt)
	expiresAt, okExpires := parseRFC3339(&errs, "expiresAt", p.ExpiresAt)
	if okIssued && okExpires && !expiresAt.After(issuedAt) {
		addErr(&errs, "expiresAt", "must be strictly after issuedAt")
	}

	return errs.asErr()
}
