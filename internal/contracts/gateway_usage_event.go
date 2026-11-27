package contracts

// GatewayUsageEvent is the versioned telemetry record emitted by
// mw-rocksoul-gateway (:4510) for per-agent token, RTK savings, redaction, and cost tracking.
type GatewayUsageEvent struct {
	SchemaVersion    string             `json:"schemaVersion"`
	EventID          string             `json:"eventId"`
	AgentID          string             `json:"agentId"`
	RequestedModel   string             `json:"requestedModel"`
	ResolvedProvider string             `json:"resolvedProvider"`
	ResolvedModel    string             `json:"resolvedModel"`
	Classification   DataClassification `json:"classification"`
	StatusCode       int                `json:"statusCode"`
	LatencyMS        int64              `json:"latencyMs"`
	PromptTokens     int64              `json:"promptTokens"`
	CompletionTokens int64              `json:"completionTokens"`
	RTKTokensSaved   int64              `json:"rtkTokensSaved"`
	RedactionsCount  int64              `json:"redactionsCount"`
	EgressBlocked    bool               `json:"egressBlocked"`
	CacheHit         bool               `json:"cacheHit"`
	CostUSDMicros    int64              `json:"costUsdMicros"`
	CreatedAt        string             `json:"createdAt"`
}

// Validate enforces GatewayUsageEvent v1 fields, HTTP status bounds, and non-negative counters.
func (e GatewayUsageEvent) Validate() error {
	var errs ValidationErrors

	requireSchemaVersion(&errs, e.SchemaVersion, SchemaVersionGatewayUsageEvent)
	requireNonEmpty(&errs, "eventId", e.EventID)
	requireNonEmpty(&errs, "agentId", e.AgentID)
	requireNonEmpty(&errs, "requestedModel", e.RequestedModel)
	requireNonEmpty(&errs, "resolvedProvider", e.ResolvedProvider)
	requireNonEmpty(&errs, "resolvedModel", e.ResolvedModel)
	validateClassificationField(&errs, "classification", e.Classification)

	if e.StatusCode < 100 || e.StatusCode > 599 {
		addErr(&errs, "statusCode", "must be a valid HTTP status code (100-599)")
	}
	if e.LatencyMS < 0 {
		addErr(&errs, "latencyMs", "must not be negative")
	}
	if e.PromptTokens < 0 {
		addErr(&errs, "promptTokens", "must not be negative")
	}
	if e.CompletionTokens < 0 {
		addErr(&errs, "completionTokens", "must not be negative")
	}
	if e.RTKTokensSaved < 0 {
		addErr(&errs, "rtkTokensSaved", "must not be negative")
	}
	if e.RedactionsCount < 0 {
		addErr(&errs, "redactionsCount", "must not be negative")
	}
	if e.CostUSDMicros < 0 {
		addErr(&errs, "costUsdMicros", "must not be negative")
	}

	parseRFC3339(&errs, "createdAt", e.CreatedAt)

	return errs.asErr()
}
