package contracts

import "strings"

// WorktreeLease models an isolated ephemeral git worktree lease issued by
// mw-rocksoul-sandbox (:4540) with a monotonic fencing token.
type WorktreeLease struct {
	SchemaVersion string      `json:"schemaVersion"`
	LeaseID       string      `json:"leaseId"`
	OwnerID       string      `json:"ownerId"`
	RepoPath      string      `json:"repoPath"`
	WorktreePath  string      `json:"worktreePath"`
	BaseRef       string      `json:"baseRef"`
	BaseCommit    string      `json:"baseCommit"`
	FencingToken  int64       `json:"fencingToken"`
	Exclusive     bool        `json:"exclusive"`
	Label         string      `json:"label,omitempty"`
	Status        LeaseStatus `json:"status"`
	CreatedAt     string      `json:"createdAt"`
	UpdatedAt     string      `json:"updatedAt"`
	ExpiresAt     string      `json:"expiresAt"`
	ReleasedAt    string      `json:"releasedAt,omitempty"`
}

// Validate checks WorktreeLease v1 fields, fencing token, commit SHA, and lifecycle timestamps.
func (l WorktreeLease) Validate() error {
	var errs ValidationErrors

	requireSchemaVersion(&errs, l.SchemaVersion, SchemaVersionWorktreeLease)
	requireNonEmpty(&errs, "leaseId", l.LeaseID)
	requireNonEmpty(&errs, "ownerId", l.OwnerID)
	requireNonEmpty(&errs, "repoPath", l.RepoPath)
	requireNonEmpty(&errs, "worktreePath", l.WorktreePath)
	requireNonEmpty(&errs, "baseRef", l.BaseRef)

	if !commitSHAHexPattern.MatchString(l.BaseCommit) {
		addErr(&errs, "baseCommit", "must be 40-64 lowercase hex characters")
	}
	if l.FencingToken <= 0 {
		addErr(&errs, "fencingToken", "must be a positive integer")
	}

	switch l.Status {
	case LeaseStatusActive, LeaseStatusReleased, LeaseStatusExpired:
	default:
		addErr(&errs, "status", "must be one of active, released, expired")
	}

	createdAt, okCreated := parseRFC3339(&errs, "createdAt", l.CreatedAt)
	updatedAt, okUpdated := parseRFC3339(&errs, "updatedAt", l.UpdatedAt)
	expiresAt, okExpires := parseRFC3339(&errs, "expiresAt", l.ExpiresAt)

	if okCreated && okUpdated && updatedAt.Before(createdAt) {
		addErr(&errs, "updatedAt", "must not precede createdAt")
	}
	if okCreated && okExpires && !expiresAt.After(createdAt) {
		addErr(&errs, "expiresAt", "must be strictly after createdAt")
	}

	hasReleasedAt := strings.TrimSpace(l.ReleasedAt) != ""
	if l.Status == LeaseStatusReleased {
		if !hasReleasedAt {
			addErr(&errs, "releasedAt", "is required when status is released")
		} else {
			releasedAt, okRel := parseRFC3339(&errs, "releasedAt", l.ReleasedAt)
			if okCreated && okRel && releasedAt.Before(createdAt) {
				addErr(&errs, "releasedAt", "must not precede createdAt")
			}
		}
	} else if hasReleasedAt {
		addErr(&errs, "releasedAt", "must only be set when status is released")
	}

	return errs.asErr()
}
