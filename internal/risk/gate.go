package risk

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Tier represents a deterministic operational risk tier from R0 (read-only) to R4 (destructive/protected).
type Tier int

const (
	TierR0 Tier = 0 // Auto-read: workspace inspection, read-only queries
	TierR1 Tier = 1 // Local write: create/edit files inside workspace
	TierR2 Tier = 2 // Local exec: non-destructive local shell/sandbox commands
	TierR3 Tier = 3 // Remote/egress: network calls, MCP remote connectors, git push/fetch
	TierR4 Tier = 4 // Destructive or protected surfaces (.githooks/*, .env, rm -rf, git reset --hard)
)

// String returns the canonical R0-R4 label.
func (t Tier) String() string {
	switch t {
	case TierR0:
		return "R0"
	case TierR1:
		return "R1"
	case TierR2:
		return "R2"
	case TierR3:
		return "R3"
	case TierR4:
		return "R4"
	default:
		return fmt.Sprintf("R%d", int(t))
	}
}

// Description returns a short human-readable description of the risk tier.
func (t Tier) Description() string {
	switch t {
	case TierR0:
		return "auto-read"
	case TierR1:
		return "local-write"
	case TierR2:
		return "local-exec"
	case TierR3:
		return "remote-egress"
	case TierR4:
		return "destructive-or-protected"
	default:
		return "unknown"
	}
}

// ParseTier parses strings like "R0".."R4" or "0".."4".
func ParseTier(raw string) (Tier, error) {
	cleaned := strings.ToUpper(strings.TrimSpace(raw))
	cleaned = strings.TrimPrefix(cleaned, "R")
	val, err := strconv.Atoi(cleaned)
	if err != nil || val < int(TierR0) || val > int(TierR4) {
		return TierR4, fmt.Errorf("invalid risk tier %q (expected R0-R4)", raw)
	}
	return Tier(val), nil
}

var (
	ErrTokenInvalid       = errors.New("approval token is invalid or malformed")
	ErrTokenAlreadyUsed   = errors.New("approval token has already been consumed")
	ErrTokenExpired       = errors.New("approval token has expired")
	ErrTokenScopeMismatch = errors.New("approval token does not match action scope")
)

const (
	defaultTokenTTL = 5 * time.Minute
	maxTokenTTL     = 30 * time.Minute
	maxAuditEntries = 200
)

// Action describes an operation evaluated by the R0-R4 Risk Gate.
type Action struct {
	Tool         string `json:"tool"`
	Path         string `json:"path,omitempty"`
	Command      string `json:"command,omitempty"`
	RemoteTarget string `json:"remoteTarget,omitempty"`
	WorkDir      string `json:"workDir,omitempty"`
}

// Policy controls automatic execution thresholds and protected-surface enforcement.
type Policy struct {
	// MaxAutoTier is the highest tier allowed without an explicit single-use approval token.
	// TierR4 is NEVER auto-approved even if MaxAutoTier >= TierR4.
	MaxAutoTier Tier `json:"maxAutoTier"`
	// BlockR4WithoutToken enforces that R4 actions are always blocked unless a matching single-use token is presented.
	BlockR4WithoutToken bool `json:"blockR4WithoutToken"`
	// AllowR4OverrideToken controls whether a single-use approval token can unlock an R4 action.
	// When false, R4 is hard-blocked unconditionally.
	AllowR4OverrideToken bool `json:"allowR4OverrideToken"`
}

// DefaultPolicy allows R0 (auto-read) automatically, requires approval for R1-R3,
// and blocks R4 by default unless explicitly unlocked with a single-use approval token.
func DefaultPolicy() Policy {
	return Policy{
		MaxAutoTier:          TierR0,
		BlockR4WithoutToken:  true,
		AllowR4OverrideToken: true,
	}
}

// Decision captures the deterministic policy evaluation result for an Action.
type Decision struct {
	Allowed          bool   `json:"allowed"`
	Tier             Tier   `json:"tier"`
	TierLabel        string `json:"tierLabel"`
	Reason           string `json:"reason"`
	AutoApproved     bool   `json:"autoApproved,omitempty"`
	RequiresApproval bool   `json:"requiresApproval,omitempty"`
	TokenConsumed    bool   `json:"tokenConsumed,omitempty"`
	ScopeHash        string `json:"scopeHash"`
	Err              error  `json:"-"`
}

// ApprovalToken represents an issued single-use HMAC-signed approval token bound to one action scope.
type ApprovalToken struct {
	Token     string    `json:"token"`
	ID        string    `json:"id"`
	Tier      Tier      `json:"tier"`
	TierLabel string    `json:"tierLabel"`
	ScopeHash string    `json:"scopeHash"`
	Approver  string    `json:"approver"`
	IssuedAt  time.Time `json:"issuedAt"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// AuditEntry logs a policy decision made by the Gate.
type AuditEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Action    Action    `json:"action"`
	Decision  Decision  `json:"decision"`
}

type approvalRecord struct {
	id        string
	tier      Tier
	scopeHash string
	approver  string
	issuedAt  time.Time
	expiresAt time.Time
	used      bool
	usedAt    time.Time
}

// GateOptions customizes Gate construction (primarily for deterministic testing).
type GateOptions struct {
	Policy Policy
	Secret []byte
	Clock  func() time.Time
}

// Gate enforces deterministic R0-R4 classification and single-use approval token verification.
type Gate struct {
	mu     sync.Mutex
	policy Policy
	secret []byte
	clock  func() time.Time
	tokens map[string]*approvalRecord
	audit  []AuditEntry
}

// NewGate initializes a Risk Gate with the provided Policy and a fresh cryptographic HMAC secret.
func NewGate(policy Policy) *Gate {
	return NewGateWithOptions(GateOptions{Policy: policy})
}

// NewGateWithOptions initializes a Risk Gate with optional custom secret and clock.
func NewGateWithOptions(opts GateOptions) *Gate {
	secret := make([]byte, len(opts.Secret))
	copy(secret, opts.Secret)
	if len(secret) == 0 {
		secret = make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			sum := sha256.Sum256([]byte(fmt.Sprintf("rocksoul-risk-%d", time.Now().UTC().UnixNano())))
			secret = sum[:]
		}
	}
	clockFn := opts.Clock
	if clockFn == nil {
		clockFn = func() time.Time { return time.Now().UTC() }
	}
	resolvedPolicy := opts.Policy
	if resolvedPolicy.MaxAutoTier < TierR0 {
		resolvedPolicy.MaxAutoTier = TierR0
	}
	if resolvedPolicy.MaxAutoTier >= TierR4 {
		// R4 can never be auto-approved.
		resolvedPolicy.MaxAutoTier = TierR3
	}
	resolvedPolicy.BlockR4WithoutToken = true

	return &Gate{
		policy: resolvedPolicy,
		secret: secret,
		clock:  clockFn,
		tokens: make(map[string]*approvalRecord),
		audit:  make([]AuditEntry, 0, 32),
	}
}

// Policy returns a copy of the Gate's active Policy.
func (g *Gate) Policy() Policy {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.policy
}

// SetMaxAutoTier updates the highest auto-approved tier (capped at R3; R4 is never auto-approved).
func (g *Gate) SetMaxAutoTier(tier Tier) error {
	if tier < TierR0 || tier > TierR3 {
		return fmt.Errorf("max auto tier must be between R0 and R3 (R4 cannot be auto-approved)")
	}
	g.mu.Lock()
	g.policy.MaxAutoTier = tier
	g.mu.Unlock()
	return nil
}

// AuditLog returns a snapshot of recent Gate decisions.
func (g *Gate) AuditLog() []AuditEntry {
	g.mu.Lock()
	defer g.mu.Unlock()
	snapshot := make([]AuditEntry, len(g.audit))
	copy(snapshot, g.audit)
	return snapshot
}

// FormatPolicySummary renders a human-readable summary of the R0-R4 policy and audit stats.
func (g *Gate) FormatPolicySummary() string {
	g.mu.Lock()
	policy := g.policy
	auditCount := len(g.audit)
	activeTokens := 0
	now := g.clock()
	for _, rec := range g.tokens {
		if !rec.used && !now.After(rec.expiresAt) {
			activeTokens++
		}
	}
	var recent []AuditEntry
	if len(g.audit) > 5 {
		recent = append(recent, g.audit[len(g.audit)-5:]...)
	} else {
		recent = append(recent, g.audit...)
	}
	g.mu.Unlock()

	var out strings.Builder
	fmt.Fprintf(&out, "Risk Gate Policy:\n")
	fmt.Fprintf(&out, "  Auto-approved up to : %s (%s)\n", policy.MaxAutoTier.String(), policy.MaxAutoTier.Description())
	fmt.Fprintf(&out, "  R4 protected/destruct: blocked by default (single-use token override=%v)\n", policy.AllowR4OverrideToken)
	fmt.Fprintf(&out, "  Protected surfaces  : .githooks/*, .git/hooks/*, .env, .env.*, *.pem, *.key, id_rsa, CODEOWNERS\n")
	fmt.Fprintf(&out, "  Active unused tokens: %d | Decisions audited: %d\n", activeTokens, auditCount)
	if len(recent) > 0 {
		out.WriteString("  Recent decisions:\n")
		for _, entry := range recent {
			verdict := "DENY"
			if entry.Decision.Allowed {
				verdict = "ALLOW"
			}
			target := entry.Action.Path
			if target == "" {
				target = entry.Action.Command
			}
			if target == "" {
				target = entry.Action.RemoteTarget
			}
			fmt.Fprintf(&out, "    - [%s %s] tool=%s target=%q (%s)\n",
				verdict, entry.Decision.TierLabel, entry.Action.Tool, target, entry.Decision.Reason)
		}
	}
	return strings.TrimRight(out.String(), "\n")
}

// Classify deterministically assigns a Risk Tier (R0-R4) and explanation to an Action.
func Classify(action Action) (Tier, string) {
	tool := strings.ToLower(strings.TrimSpace(action.Tool))
	normalizedPath := normalizeActionPath(action.WorkDir, action.Path)
	trimmedCmd := strings.TrimSpace(action.Command)
	trimmedRemote := strings.TrimSpace(action.RemoteTarget)

	// 1. Protected file paths always escalate to R4 regardless of tool.
	if normalizedPath != "" {
		if protectedReason, isProtected := matchProtectedPath(normalizedPath); isProtected {
			return TierR4, protectedReason
		}
	}

	// 2. Shell / command inspection for R4 destructive or protected-path references, then R3 egress.
	if trimmedCmd != "" {
		if reason, isR4 := matchDestructiveOrProtectedCommand(trimmedCmd); isR4 {
			return TierR4, reason
		}
		if reason, isR3 := matchEgressCommand(trimmedCmd); isR3 {
			return TierR3, reason
		}
	}

	// 3. Explicit remote target implies R3 egress.
	if trimmedRemote != "" {
		return TierR3, fmt.Sprintf("remote egress target %q", trimmedRemote)
	}

	// 4. Deterministic tool-level tier mapping.
	switch tool {
	case "read_file", "list_dir", "grep_search", "search_symbols", "git_status", "git_diff", "git_log":
		return TierR0, "read-only workspace inspection"
	case "write_file", "edit_file", "apply_patch", "mkdir", "delete_file":
		return TierR1, "local workspace file mutation"
	case "run_shell", "sandbox_exec", "exec":
		return TierR2, "local command execution"
	case "mcp_call", "http_request", "web_fetch", "remote_exec", "git_push":
		return TierR3, "remote/egress tool invocation"
	default:
		if strings.HasPrefix(tool, "mcp_") || strings.HasPrefix(tool, "remote_") {
			return TierR3, fmt.Sprintf("remote tool %q", tool)
		}
		// Fail closed for unrecognized tools.
		return TierR3, fmt.Sprintf("unclassified tool %q defaults to R3", tool)
	}
}

// ScopeFingerprint computes a deterministic SHA-256 hex digest binding a token to a single Action and Tier.
func ScopeFingerprint(action Action, tier Tier) string {
	canonical := strings.Join([]string{
		tier.String(),
		strings.ToLower(strings.TrimSpace(action.Tool)),
		normalizeActionPath(action.WorkDir, action.Path),
		strings.TrimSpace(action.Command),
		strings.TrimSpace(action.RemoteTarget),
	}, "\x00")
	digest := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(digest[:])
}

// IssueApprovalToken mints a single-use HMAC-signed approval token bound to the exact Action scope.
func (g *Gate) IssueApprovalToken(action Action, ttl time.Duration, approver string) (ApprovalToken, error) {
	if strings.TrimSpace(action.Tool) == "" {
		return ApprovalToken{}, errors.New("action tool is required to issue approval token")
	}
	tier, _ := Classify(action)
	g.mu.Lock()
	defer g.mu.Unlock()

	if tier == TierR4 && !g.policy.AllowR4OverrideToken {
		return ApprovalToken{}, errors.New("policy forbids issuing override tokens for R4 actions")
	}

	if ttl <= 0 {
		ttl = defaultTokenTTL
	}
	if ttl > maxTokenTTL {
		ttl = maxTokenTTL
	}

	cleanApprover := strings.TrimSpace(approver)
	if cleanApprover == "" {
		cleanApprover = "operator"
	}

	idBytes := make([]byte, 12)
	if _, err := rand.Read(idBytes); err != nil {
		return ApprovalToken{}, fmt.Errorf("generate token id: %w", err)
	}
	tokenID := hex.EncodeToString(idBytes)

	now := g.clock()
	expiresAt := now.Add(ttl)
	scopeHash := ScopeFingerprint(action, tier)
	signature := g.signToken(tokenID, scopeHash, expiresAt)

	g.tokens[tokenID] = &approvalRecord{
		id:        tokenID,
		tier:      tier,
		scopeHash: scopeHash,
		approver:  cleanApprover,
		issuedAt:  now,
		expiresAt: expiresAt,
	}

	return ApprovalToken{
		Token:     "rsk_" + tokenID + "." + signature,
		ID:        tokenID,
		Tier:      tier,
		TierLabel: tier.String(),
		ScopeHash: scopeHash,
		Approver:  cleanApprover,
		IssuedAt:  now,
		ExpiresAt: expiresAt,
	}, nil
}

// VerifyAndConsumeToken validates a single-use approval token against action and atomically consumes it.
func (g *Gate) VerifyAndConsumeToken(rawToken string, action Action) error {
	tier, _ := Classify(action)
	scopeHash := ScopeFingerprint(action, tier)

	g.mu.Lock()
	defer g.mu.Unlock()
	return g.verifyAndConsumeLocked(rawToken, tier, scopeHash)
}

func (g *Gate) verifyAndConsumeLocked(rawToken string, tier Tier, scopeHash string) error {
	trimmed := strings.TrimSpace(rawToken)
	if !strings.HasPrefix(trimmed, "rsk_") {
		return ErrTokenInvalid
	}
	body := strings.TrimPrefix(trimmed, "rsk_")
	parts := strings.Split(body, ".")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return ErrTokenInvalid
	}
	tokenID, suppliedSig := parts[0], parts[1]

	record, exists := g.tokens[tokenID]
	if !exists {
		return ErrTokenInvalid
	}
	expectedSig := g.signToken(record.id, record.scopeHash, record.expiresAt)
	if !hmac.Equal([]byte(expectedSig), []byte(suppliedSig)) {
		return ErrTokenInvalid
	}
	if record.used {
		return ErrTokenAlreadyUsed
	}
	now := g.clock()
	if now.After(record.expiresAt) {
		return ErrTokenExpired
	}
	if record.tier != tier || record.scopeHash != scopeHash {
		return ErrTokenScopeMismatch
	}
	if tier == TierR4 && !g.policy.AllowR4OverrideToken {
		return errors.New("R4 override tokens are disabled by policy")
	}

	record.used = true
	record.usedAt = now
	return nil
}

// Evaluate determines whether action is allowed under the active policy and optional single-use approval token.
func (g *Gate) Evaluate(action Action, approvalToken string) Decision {
	tier, reason := Classify(action)
	scopeHash := ScopeFingerprint(action, tier)

	g.mu.Lock()
	defer g.mu.Unlock()

	decision := Decision{
		Tier:      tier,
		TierLabel: tier.String(),
		Reason:    reason,
		ScopeHash: scopeHash,
	}

	// Auto-approve only when tier <= MaxAutoTier and strictly below TierR4.
	if tier < TierR4 && tier <= g.policy.MaxAutoTier {
		decision.Allowed = true
		decision.AutoApproved = true
		g.recordAuditLocked(action, decision)
		return decision
	}

	trimmedToken := strings.TrimSpace(approvalToken)
	if trimmedToken != "" {
		if err := g.verifyAndConsumeLocked(trimmedToken, tier, scopeHash); err != nil {
			decision.Allowed = false
			decision.RequiresApproval = true
			decision.Reason = fmt.Sprintf("%s; %s", reason, err.Error())
			decision.Err = err
			g.recordAuditLocked(action, decision)
			return decision
		}
		decision.Allowed = true
		decision.TokenConsumed = true
		decision.Reason = fmt.Sprintf("%s (approved via single-use token)", reason)
		g.recordAuditLocked(action, decision)
		return decision
	}

	decision.Allowed = false
	decision.RequiresApproval = true
	if tier == TierR4 {
		decision.Reason = fmt.Sprintf("R4 blocked by default: %s", reason)
	} else {
		decision.Reason = fmt.Sprintf("%s requires approval above auto tier %s: %s", tier.String(), g.policy.MaxAutoTier.String(), reason)
	}
	g.recordAuditLocked(action, decision)
	return decision
}

func (g *Gate) signToken(tokenID, scopeHash string, expiresAt time.Time) string {
	mac := hmac.New(sha256.New, g.secret)
	mac.Write([]byte(tokenID))
	mac.Write([]byte("|"))
	mac.Write([]byte(scopeHash))
	mac.Write([]byte("|"))
	mac.Write([]byte(strconv.FormatInt(expiresAt.UnixNano(), 10)))
	return hex.EncodeToString(mac.Sum(nil))
}

func (g *Gate) recordAuditLocked(action Action, decision Decision) {
	if len(g.audit) >= maxAuditEntries {
		g.audit = g.audit[1:]
	}
	g.audit = append(g.audit, AuditEntry{
		Timestamp: g.clock(),
		Action:    action,
		Decision:  decision,
	})
}

func normalizeActionPath(workDir, rawPath string) string {
	trimmed := strings.TrimSpace(rawPath)
	if trimmed == "" {
		return ""
	}
	if workDir != "" && filepath.IsAbs(trimmed) {
		if absRoot, err := filepath.Abs(workDir); err == nil {
			if rel, relErr := filepath.Rel(absRoot, trimmed); relErr == nil && !strings.HasPrefix(rel, "..") {
				trimmed = rel
			}
		}
	}
	slashed := strings.ReplaceAll(trimmed, "\\", "/")
	cleaned := path.Clean(slashed)
	cleaned = strings.TrimPrefix(cleaned, "./")
	return cleaned
}

func matchProtectedPath(normalizedPath string) (string, bool) {
	lowerFull := strings.ToLower(normalizedPath)
	base := path.Base(lowerFull)
	segments := strings.Split(lowerFull, "/")

	// Protected git hook directories (.githooks/*, .git/hooks/*).
	for idx, seg := range segments {
		if seg == ".githooks" {
			return fmt.Sprintf("protected git hooks surface (%s)", normalizedPath), true
		}
		if seg == ".git" && idx+1 < len(segments) && (segments[idx+1] == "hooks" || segments[idx+1] == "config") {
			return fmt.Sprintf("protected git metadata surface (%s)", normalizedPath), true
		}
		if seg == ".ssh" {
			return fmt.Sprintf("protected SSH key directory (%s)", normalizedPath), true
		}
	}

	// Protected environment secret files (.env, .env.* except templates/examples).
	if base == ".env" || strings.HasPrefix(base, ".env.") {
		if base != ".env.example" && base != ".env.sample" && base != ".env.template" {
			return fmt.Sprintf("protected environment secret file (%s)", normalizedPath), true
		}
	}

	// Protected private key & credential artifacts.
	switch base {
	case "id_rsa", "id_ed25519", "id_ecdsa", ".npmrc", ".netrc", "codeowners":
		return fmt.Sprintf("protected credential or governance file (%s)", normalizedPath), true
	}
	for _, ext := range []string{".pem", ".key", ".p12", ".pfx", ".kdbx"} {
		if strings.HasSuffix(base, ext) {
			return fmt.Sprintf("protected private key artifact (%s)", normalizedPath), true
		}
	}

	// Autonomous Git & release governance lock surfaces.
	if strings.HasSuffix(lowerFull, ".agents/rules/autonomous-git-release-lock.md") ||
		strings.HasSuffix(lowerFull, ".github/workflows/promote.yml") ||
		strings.HasSuffix(lowerFull, ".github/workflows/sync-main-to-dev.yml") ||
		strings.HasSuffix(lowerFull, ".github/workflows/promotion-policy.yml") ||
		strings.HasSuffix(lowerFull, ".github/workflows/release-orchestrate.yml") ||
		strings.HasSuffix(lowerFull, ".github/workflows/release-prepare.yml") ||
		strings.HasSuffix(lowerFull, ".github/workflows/release.yml") {
		return fmt.Sprintf("protected release governance surface (%s)", normalizedPath), true
	}

	return "", false
}

var (
	destructiveCommandPatterns = []struct {
		reason string
		regex  *regexp.Regexp
	}{
		{reason: "destructive recursive delete (rm -rf)", regex: regexp.MustCompile(`(?i)\brm\s+[^\n]*(-[a-z]*r[a-z]*f|-[a-z]*f[a-z]*r|--recursive\s+--force|--force\s+--recursive)`)},
		{reason: "destructive PowerShell recursive delete", regex: regexp.MustCompile(`(?i)\bremove-item\b[^\n]*(-recurse[^\n]*-force|-force[^\n]*-recurse)`)},
		{reason: "destructive git reset --hard", regex: regexp.MustCompile(`(?i)\bgit\s+reset\s+--hard\b`)},
		{reason: "destructive git force push", regex: regexp.MustCompile(`(?i)\bgit\s+push\b[^\n]*(\s--force\b|\s-f\b|\s--force-with-lease\b)`)},
		{reason: "destructive git clean", regex: regexp.MustCompile(`(?i)\bgit\s+clean\s+-[a-z]*f`)},
		{reason: "destructive git checkout discard", regex: regexp.MustCompile(`(?i)\bgit\s+checkout\s+--\s+\.`)},
		{reason: "destructive disk or system command", regex: regexp.MustCompile(`(?i)\b(mkfs(\.[a-z0-9]+)?|fdisk|diskpart|shutdown|reboot|poweroff|dd\s+if=)\b`)},
		{reason: "destructive SQL drop/truncate", regex: regexp.MustCompile(`(?i)\b(drop\s+(database|table|schema)|truncate\s+table)\b`)},
		{reason: "destructive chmod 777", regex: regexp.MustCompile(`(?i)\bchmod\s+-r\s+777\b`)},
		{reason: "protected git hooks referenced in shell command", regex: regexp.MustCompile(`(?i)(^|[\s"'/\\])\.githooks([/\\]|$|\s|"|')|(^|[\s"'/\\])\.git[/\\]hooks([/\\]|$|\s|"|')`)},
		{reason: "protected .env file referenced in shell command", regex: regexp.MustCompile(`(?i)(^|[\s"'/\\])\.env(\.[a-z0-9_-]+)?($|[\s"'|;&>])`)},
	}

	egressCommandPatterns = []struct {
		reason string
		regex  *regexp.Regexp
	}{
		{reason: "network HTTP/transfer command", regex: regexp.MustCompile(`(?i)\b(curl|wget|invoke-webrequest|invoke-restmethod|iwr|irm|ssh|scp|sftp|rsync|nc|netcat|telnet)\b`)},
		{reason: "remote git network command", regex: regexp.MustCompile(`(?i)\bgit\s+(push|pull|fetch|clone)\b`)},
		{reason: "package or container registry publish/pull", regex: regexp.MustCompile(`(?i)\b((npm|pnpm|bun|yarn)\s+publish|docker\s+(push|pull|login)|gh\s+(pr|release|api|repo))\b`)},
		{reason: "external URL egress in shell command", regex: regexp.MustCompile(`(?i)https?://`)},
	}

	loopbackURLPattern = regexp.MustCompile(`(?i)^https?://(127\.0\.0\.1|localhost|\[::1\])([:/]|$)`)
)

func matchDestructiveOrProtectedCommand(cmd string) (string, bool) {
	// Permit benign mentions of .env.example while catching real .env references.
	sanitizedForEnv := strings.ReplaceAll(strings.ToLower(cmd), ".env.example", "__env_example__")
	sanitizedForEnv = strings.ReplaceAll(sanitizedForEnv, ".env.sample", "__env_sample__")
	sanitizedForEnv = strings.ReplaceAll(sanitizedForEnv, ".env.template", "__env_template__")

	for _, rule := range destructiveCommandPatterns {
		if rule.regex.MatchString(sanitizedForEnv) {
			return rule.reason, true
		}
	}
	return "", false
}

func matchEgressCommand(cmd string) (string, bool) {
	for _, rule := range egressCommandPatterns {
		if !rule.regex.MatchString(cmd) {
			continue
		}
		if rule.reason == "external URL egress in shell command" {
			urls := regexp.MustCompile(`(?i)https?://[^\s"']+`).FindAllString(cmd, -1)
			hasNonLoopback := false
			for _, u := range urls {
				if !loopbackURLPattern.MatchString(u) {
					hasNonLoopback = true
					break
				}
			}
			if !hasNonLoopback {
				continue
			}
		}
		return rule.reason, true
	}
	return "", false
}
