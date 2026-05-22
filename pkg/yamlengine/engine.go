package yamlengine

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/raychao-oao/mcp-policy/pkg/policy"
)

// Engine is a policy.Engine backed by a YAML config file.
// Decision order (first match wins after explicit deny):
//  1. explicit deny
//  2. require_approval
//  3. allow
//  4. default deny
type Engine struct {
	cfg Config
}

// LoadFile reads and parses a YAML policy file, returning a ready Engine.
// Returns an error if the file is missing or malformed (fail-closed).
func LoadFile(path string) (*Engine, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("yamlengine: read policy file: %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("yamlengine: parse policy file: %w", err)
	}
	if cfg.Version != 1 {
		return nil, fmt.Errorf("yamlengine: unsupported policy version %d", cfg.Version)
	}
	return &Engine{cfg: cfg}, nil
}

// Authorize implements policy.Engine. It is safe for concurrent use.
func (e *Engine) Authorize(_ context.Context, req policy.PolicyRequest) (policy.PolicyDecision, error) {
	roles := e.rolesFor(req.Actor.ID)
	if len(roles) == 0 {
		return deny("unknown actor", ""), nil
	}

	toolMeta, ok := e.cfg.Tools[req.Tool]
	if !ok {
		return deny(fmt.Sprintf("tool %q not registered", req.Tool), ""), nil
	}

	// 1. Explicit deny (checked across all roles first)
	for _, role := range roles {
		rc, ok := e.cfg.Roles[role]
		if !ok {
			continue
		}
		for _, rule := range rc.Deny {
			if matchRule(rule, req) {
				return deny(fmt.Sprintf("denied by rule %s", rule.ID), rule.ID), nil
			}
		}
	}

	// 2. require_approval
	for _, role := range roles {
		rc, ok := e.cfg.Roles[role]
		if !ok {
			continue
		}
		for _, rule := range rc.RequireApproval {
			if matchRule(rule, req) {
				ap := &policy.ApprovalRequirement{
					Mode: "required",
					Risk: toolMeta.Risk,
				}
				if rule.Approval != nil {
					ap.Risk = rule.Approval.Risk
					ap.TTLSeconds = rule.Approval.TTLSeconds
					ap.Mode = rule.Approval.Mode
				}
				return policy.PolicyDecision{
					Decision:      policy.RequireApproval,
					Reason:        fmt.Sprintf("approval required by rule %s", rule.ID),
					MatchedRuleID: rule.ID,
					Risk:          toolMeta.Risk,
					Approval:      ap,
				}, nil
			}
		}
	}

	// 3. allow
	for _, role := range roles {
		rc, ok := e.cfg.Roles[role]
		if !ok {
			continue
		}
		for _, rule := range rc.Allow {
			if matchRule(rule, req) {
				return policy.PolicyDecision{
					Decision:      policy.Allow,
					Reason:        fmt.Sprintf("allowed by rule %s", rule.ID),
					MatchedRuleID: rule.ID,
					Risk:          toolMeta.Risk,
					TTL:           30 * time.Minute,
				}, nil
			}
		}
	}

	// 4. default deny
	return deny("no matching allow rule (default deny)", ""), nil
}

func (e *Engine) rolesFor(actorID string) []string {
	ac, ok := e.cfg.Actors[actorID]
	if !ok {
		return nil
	}
	return ac.Roles
}

func deny(reason, ruleID string) policy.PolicyDecision {
	return policy.PolicyDecision{
		Decision:      policy.Deny,
		Reason:        reason,
		MatchedRuleID: ruleID,
	}
}

// matchRule returns true if the rule applies to the request.
// Tool must match exactly. Resource is prefix-wildcard matched.
// Purpose is exact-matched if the rule specifies any.
func matchRule(rule Rule, req policy.PolicyRequest) bool {
	if rule.Tool != req.Tool {
		return false
	}
	if !matchResource(rule.Resources, req.Resource.Path) {
		return false
	}
	if len(rule.Purposes) > 0 && !matchPurpose(rule.Purposes, req.Purpose) {
		return false
	}
	return true
}

// matchResource checks whether path matches any of the resource patterns.
// Patterns ending in "/*" are prefix-matched; others are exact.
func matchResource(patterns []string, path string) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, p := range patterns {
		if strings.HasSuffix(p, "/*") {
			prefix := strings.TrimSuffix(p, "*")
			if strings.HasPrefix(path, prefix) {
				return true
			}
		} else if p == path {
			return true
		}
	}
	return false
}

func matchPurpose(patterns []string, purpose string) bool {
	for _, p := range patterns {
		if p == purpose {
			return true
		}
	}
	return false
}
