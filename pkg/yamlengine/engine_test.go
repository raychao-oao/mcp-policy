package yamlengine_test

import (
	"context"
	"os"
	"testing"

	"github.com/raychao-oao/mcp-policy/pkg/policy"
	"github.com/raychao-oao/mcp-policy/pkg/yamlengine"
)

const testPolicy = `
version: 1

defaults:
  decision: deny

tools:
  ad.search_user:
    risk: low
    access: read
  ad.get_user:
    risk: low
    access: read
  ad.unlock_user:
    risk: medium
    access: write
  ad.disable_user:
    risk: high
    access: write
  ad.add_user_to_group:
    risk: high
    access: privileged_write

actors:
  ray:
    roles: [it_admin]

roles:
  it_admin:
    allow:
      - id: allow-read-staff
        tool: ad.search_user
        resources: ["ou:staff/*"]
      - id: allow-get-staff
        tool: ad.get_user
        resources: ["ou:staff/*"]
    require_approval:
      - id: approval-unlock-staff
        tool: ad.unlock_user
        resources: ["ou:staff/*"]
        approval:
          mode: required
          risk: medium
          ttl_seconds: 300
      - id: approval-disable-staff
        tool: ad.disable_user
        resources: ["ou:staff/*"]
        approval:
          mode: required
          risk: high
          ttl_seconds: 300
    deny:
      - id: deny-domain-admins
        tool: ad.add_user_to_group
        resources: ["group:domain-admins"]
`

func loadTestEngine(t *testing.T) *yamlengine.Engine {
	t.Helper()
	f, err := os.CreateTemp("", "policy-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(testPolicy); err != nil {
		t.Fatal(err)
	}
	e, err := yamlengine.LoadFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func req(actor, tool, resource string) policy.PolicyRequest {
	return policy.PolicyRequest{
		Actor:    policy.Actor{ID: actor},
		Consumer: policy.Consumer{ID: "ad-mcp"},
		Tool:     tool,
		Resource: policy.Resource{Path: resource},
	}
}

func TestAuthorize(t *testing.T) {
	e := loadTestEngine(t)
	ctx := context.Background()

	cases := []struct {
		name     string
		req      policy.PolicyRequest
		want     policy.Decision
	}{
		// allow cases
		{"read staff user", req("ray", "ad.search_user", "ou:staff/alice"), policy.Allow},
		{"get staff user", req("ray", "ad.get_user", "ou:staff/alice"), policy.Allow},

		// require_approval cases
		{"unlock staff", req("ray", "ad.unlock_user", "ou:staff/alice"), policy.RequireApproval},
		{"disable staff", req("ray", "ad.disable_user", "ou:staff/alice"), policy.RequireApproval},

		// explicit deny
		{"add to domain-admins", req("ray", "ad.add_user_to_group", "group:domain-admins"), policy.Deny},

		// out-of-scope resource → default deny
		{"read finance user", req("ray", "ad.search_user", "ou:finance/bob"), policy.Deny},

		// unknown actor → default deny
		{"unknown actor", req("unknown", "ad.search_user", "ou:staff/alice"), policy.Deny},

		// unknown tool → default deny
		{"unknown tool", req("ray", "ad.nonexistent", "ou:staff/alice"), policy.Deny},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := e.Authorize(ctx, tc.req)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.Decision != tc.want {
				t.Errorf("decision = %q, want %q (reason: %s)", got.Decision, tc.want, got.Reason)
			}
		})
	}
}

func TestLoadFile_MissingFile(t *testing.T) {
	_, err := yamlengine.LoadFile("/nonexistent/policy.yaml")
	if err == nil {
		t.Error("expected error for missing file, got nil")
	}
}

func TestLoadFile_BadVersion(t *testing.T) {
	f, err := os.CreateTemp("", "policy-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	f.WriteString("version: 99\ndefaults:\n  decision: deny\n")
	_, err = yamlengine.LoadFile(f.Name())
	if err == nil {
		t.Error("expected error for unsupported version, got nil")
	}
}
