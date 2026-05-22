package yamlengine

// Config is the top-level structure of a policy YAML file.
type Config struct {
	Version  int             `yaml:"version"`
	Defaults DefaultConfig   `yaml:"defaults"`
	Tools    map[string]ToolMeta `yaml:"tools"`
	Actors   map[string]ActorConfig `yaml:"actors"`
	Roles    map[string]RoleConfig  `yaml:"roles"`
}

type DefaultConfig struct {
	Decision string `yaml:"decision"` // "deny"
}

// ToolMeta is static metadata for a registered tool.
type ToolMeta struct {
	Risk    string `yaml:"risk"`   // "low", "medium", "high"
	Access  string `yaml:"access"` // "read", "write", "privileged_write"
}

type ActorConfig struct {
	Roles []string `yaml:"roles"`
}

type RoleConfig struct {
	Allow           []Rule `yaml:"allow"`
	RequireApproval []Rule `yaml:"require_approval"`
	Deny            []Rule `yaml:"deny"`
}

type Rule struct {
	ID        string           `yaml:"id"`
	Tool      string           `yaml:"tool"`
	Resources []string         `yaml:"resources"`
	Purposes  []string         `yaml:"purposes,omitempty"`
	Approval  *ApprovalConfig  `yaml:"approval,omitempty"`
}

type ApprovalConfig struct {
	Mode       string `yaml:"mode"`
	Risk       string `yaml:"risk"`
	TTLSeconds int    `yaml:"ttl_seconds"`
}
