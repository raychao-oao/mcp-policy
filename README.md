# mcp-policy

Shared policy engine for Enterprise AI operation MCPs.

Provides the authorization contract and built-in YAML engine used by `ad-mcp`, `entra-mcp`, `firewall-mcp`, `proxmox-mcp`, and any other operation MCP in the ecosystem.

## Packages

| Package | Role |
|---------|------|
| `pkg/policy` | Stable contract: types, `Engine` interface, `PolicyRequest`, `PolicyDecision` |
| `pkg/audit` | Structured audit event schema and `Sink` interface |
| `pkg/yamlengine` | v1 YAML-backed engine (replaceable with OPA/Cedar without changing importers) |

## Decision model

Every tool call produces exactly one of three outcomes:

```
allow            → execute operation
deny             → return structured error, do not execute
require_approval → obtain approval token from cred-mcp, then re-authorize
```

Default is `deny`. Explicit deny rules always win.

## Quick start

```go
import (
    "github.com/raychao-oao/mcp-policy/pkg/policy"
    "github.com/raychao-oao/mcp-policy/pkg/yamlengine"
)

engine, err := yamlengine.LoadFile("/etc/mcp/policy.yaml")
if err != nil {
    log.Fatal(err)
}

dec, err := engine.Authorize(ctx, policy.PolicyRequest{
    Actor:    policy.Actor{ID: "ray", Roles: []string{"it_admin"}},
    Consumer: policy.Consumer{ID: "ad-mcp"},
    Tool:     "ad.unlock_user",
    Resource: policy.Resource{Path: "ou:staff/alice"},
    Purpose:  "helpdesk_unlock",
})
```

## Policy YAML format

```yaml
version: 1

defaults:
  decision: deny

tools:
  ad.search_user:
    risk: low
    access: read
  ad.unlock_user:
    risk: medium
    access: write

actors:
  ray:
    roles: [it_admin]

roles:
  it_admin:
    allow:
      - id: allow-read-staff
        tool: ad.search_user
        resources: ["ou:staff/*"]
    require_approval:
      - id: approval-unlock-staff
        tool: ad.unlock_user
        resources: ["ou:staff/*"]
        approval:
          mode: required
          risk: medium
          ttl_seconds: 300
    deny:
      - id: deny-domain-admins
        tool: ad.add_user_to_group
        resources: ["group:domain-admins"]
```

## Replacing the engine backend

`policy.Engine` is an interface. To switch to OPA:

```go
// opaengine implements policy.Engine using OPA Rego
var _ policy.Engine = (*opaengine.Engine)(nil)
```

Operation MCPs never import `yamlengine` directly — they depend only on `policy.Engine` — so swapping the backend requires zero changes to tool handlers.

## License

MIT
