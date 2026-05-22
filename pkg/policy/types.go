package policy

import (
	"context"
	"time"
)

// Decision is the outcome of a policy authorization check.
type Decision string

const (
	Allow           Decision = "allow"
	Deny            Decision = "deny"
	RequireApproval Decision = "require_approval"
)

// Actor represents the human or service account initiating the request.
type Actor struct {
	ID     string
	Email  string
	Roles  []string
	Groups []string
}

// Consumer represents the MCP client (ad-mcp, entra-mcp, etc.) making the call.
type Consumer struct {
	ID   string
	Name string
}

// Resource identifies the target object being acted upon.
type Resource struct {
	Type string            // e.g. "ad:user", "ad:group"
	ID   string            // e.g. "alice", "domain-admins"
	Path string            // e.g. "ou:staff/alice"
	Tags map[string]string
}

// ApprovalRequirement describes what is needed when Decision == RequireApproval.
type ApprovalRequirement struct {
	Mode       string // "required"
	Risk       string // "low", "medium", "high"
	TTLSeconds int
	Approvers  []string
}

// PolicyRequest is the input to every authorization check.
// All tool handlers must build one of these before calling Engine.Authorize.
type PolicyRequest struct {
	RequestID string
	Actor     Actor
	Consumer  Consumer
	Tool      string // fully-qualified, e.g. "ad.unlock_user"
	Resource  Resource
	Purpose   string
	Context   map[string]any
}

// PolicyDecision is the output of Engine.Authorize.
type PolicyDecision struct {
	Decision       Decision
	Reason         string
	MatchedRuleID  string
	Risk           string // inherited from tool catalog
	TTL            time.Duration
	Approval       *ApprovalRequirement
	Obligations    []string
	AuditFields    map[string]any
}

// Engine is the single authorization entry point for all operation MCPs.
// Implementations must be safe for concurrent use.
type Engine interface {
	Authorize(ctx context.Context, req PolicyRequest) (PolicyDecision, error)
}
