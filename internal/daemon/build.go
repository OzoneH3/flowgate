package daemon

type BuildIdentity struct {
	HolderIteratorSHA256 string `json:"holder_iterator_sha256,omitempty"`
	MaxRuleSchema        int    `json:"max_rule_schema,omitempty"`
	Source               string `json:"source"`
	ExecutableSHA256     string `json:"executable_sha256"`
	Modified             bool   `json:"modified"`
}
