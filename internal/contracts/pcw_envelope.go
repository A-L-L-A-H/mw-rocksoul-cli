package contracts

import (
	"fmt"
	"strings"
)

// PcwArtifactRecord describes one hashed evidence artifact in a PcwEnvelope.
type PcwArtifactRecord struct {
	ID        string       `json:"id"`
	Kind      ArtifactKind `json:"kind"`
	SHA256    string       `json:"sha256"`
	Content   string       `json:"content,omitempty"`
	SizeBytes *int64       `json:"sizeBytes,omitempty"`
	Path      string       `json:"path,omitempty"`
}

// PcwCheckEvidence records a verification command or invariant check outcome.
type PcwCheckEvidence struct {
	Code      string      `json:"code"`
	Command   string      `json:"command,omitempty"`
	Status    CheckStatus `json:"status"`
	Mandatory bool        `json:"mandatory,omitempty"`
	ExitCode  *int        `json:"exitCode,omitempty"`
	Reason    string      `json:"reason,omitempty"`
}

// PcwEnvelope is the Proof-Carrying Work (pcw/v1) attestation envelope verified
// by mw-rocksoul-core (/v1/pcw/verify).
type PcwEnvelope struct {
	SchemaVersion     string             `json:"schemaVersion"`
	EnvelopeID        string             `json:"envelopeId"`
	TaskID            string             `json:"taskId"`
	ProducerAgentID   string             `json:"producerAgentId"`
	ReviewerAgentID   string             `json:"reviewerAgentId,omitempty"`
	RiskTier          RiskTier           `json:"riskTier"`
	ParentProofHashes []string           `json:"parentProofHashes"`
	Artifacts         []PcwArtifactRecord `json:"artifacts"`
	Checks            []PcwCheckEvidence `json:"checks"`
	ChangedFiles      []string           `json:"changedFiles,omitempty"`
	ProducedAt        string             `json:"producedAt"`
	ExpiresAt         string             `json:"expiresAt,omitempty"`
	Metadata          map[string]any     `json:"metadata,omitempty"`
	MerkleRoot        string             `json:"merkleRoot"`
	EnvelopeSHA256    string             `json:"envelopeSha256"`
}

// Validate verifies pcw/v1 structure, digests, artifact uniqueness, and check/reviewer rules.
func (e PcwEnvelope) Validate() error {
	var errs ValidationErrors

	requireSchemaVersion(&errs, e.SchemaVersion, SchemaVersionPcwEnvelope)
	requireNonEmpty(&errs, "envelopeId", e.EnvelopeID)
	requireNonEmpty(&errs, "taskId", e.TaskID)
	requireNonEmpty(&errs, "producerAgentId", e.ProducerAgentID)
	if strings.TrimSpace(e.ReviewerAgentID) != "" && e.ReviewerAgentID == e.ProducerAgentID {
		addErr(&errs, "reviewerAgentId", "must differ from producerAgentId (self-approval prohibited)")
	}

	validateRiskTierField(&errs, "riskTier", e.RiskTier)
	validateSHA256List(&errs, "parentProofHashes", e.ParentProofHashes)

	if len(e.Artifacts) == 0 {
		addErr(&errs, "artifacts", "must contain at least one artifact")
	}
	seenArtifacts := make(map[string]struct{}, len(e.Artifacts))
	for i, art := range e.Artifacts {
		prefix := fmt.Sprintf("artifacts[%d]", i)
		requireNonEmpty(&errs, prefix+".id", art.ID)
		if art.ID != "" {
			if _, exists := seenArtifacts[art.ID]; exists {
				addErr(&errs, prefix+".id", fmt.Sprintf("duplicate artifact id %q", art.ID))
			}
			seenArtifacts[art.ID] = struct{}{}
		}
		switch art.Kind {
		case ArtifactDiff, ArtifactTestLog, ArtifactReport, ArtifactTranscript,
			ArtifactToolOutput, ArtifactEvidenceBundle, ArtifactEvalResult:
		default:
			addErr(&errs, prefix+".kind", fmt.Sprintf("invalid artifact kind %q", art.Kind))
		}
		if !isValidSHA256Hex(art.SHA256) {
			addErr(&errs, prefix+".sha256", "must be 64 lowercase hex characters")
		}
		if art.SizeBytes != nil && *art.SizeBytes < 0 {
			addErr(&errs, prefix+".sizeBytes", "must not be negative")
		}
	}

	for i, chk := range e.Checks {
		prefix := fmt.Sprintf("checks[%d]", i)
		requireNonEmpty(&errs, prefix+".code", chk.Code)
		switch chk.Status {
		case CheckStatusPass, CheckStatusFail, CheckStatusSkipped, CheckStatusNotApplicable, CheckStatusNotRun:
		default:
			addErr(&errs, prefix+".status", fmt.Sprintf("invalid check status %q", chk.Status))
		}
		if chk.Status == CheckStatusSkipped && strings.TrimSpace(chk.Reason) == "" {
			addErr(&errs, prefix+".reason", "is required when check status is skipped")
		}
	}

	producedAt, okProduced := parseRFC3339(&errs, "producedAt", e.ProducedAt)
	if strings.TrimSpace(e.ExpiresAt) != "" {
		expiresAt, okExpires := parseRFC3339(&errs, "expiresAt", e.ExpiresAt)
		if okProduced && okExpires && !expiresAt.After(producedAt) {
			addErr(&errs, "expiresAt", "must be strictly after producedAt")
		}
	}

	if !isValidSHA256Hex(e.MerkleRoot) {
		addErr(&errs, "merkleRoot", "must be 64 lowercase hex characters")
	}
	if !isValidSHA256Hex(e.EnvelopeSHA256) {
		addErr(&errs, "envelopeSha256", "must be 64 lowercase hex characters")
	}

	return errs.asErr()
}
