package audit

import "time"

// EventType identifies the kind of audit record.
type EventType string

const (
	EventPolicyDecision  EventType = "policy_decision"
	EventOperationResult EventType = "operation_result"
	EventApprovalGranted EventType = "approval_granted"
	EventApprovalDenied  EventType = "approval_denied"
)

// Event is a structured audit record emitted after every authorization
// check and operation result. secret_exposed must always be false; any
// implementation that sets it true has a bug.
type Event struct {
	Event        EventType      `json:"event"`
	RequestID    string         `json:"request_id"`
	Timestamp    time.Time      `json:"timestamp"`
	Actor        string         `json:"actor"`
	Consumer     string         `json:"consumer"`
	Tool         string         `json:"tool"`
	Resource     string         `json:"resource"`
	Purpose      string         `json:"purpose,omitempty"`
	Decision     string         `json:"decision,omitempty"`
	MatchedRule  string         `json:"matched_rule,omitempty"`
	Risk         string         `json:"risk,omitempty"`
	ApprovalID   string         `json:"approval_id,omitempty"`
	Result       string         `json:"result,omitempty"`
	Backend      string         `json:"backend,omitempty"`
	SecretExposed bool          `json:"secret_exposed"` // must always be false
	Extra        map[string]any `json:"extra,omitempty"`
}

// Sink receives audit events. Implementations must be non-blocking and
// best-effort — a failed write must not abort the operation.
type Sink interface {
	Send(event Event)
}

// NoopSink discards all events. Useful in tests and during bootstrapping.
type NoopSink struct{}

func (NoopSink) Send(Event) {}
