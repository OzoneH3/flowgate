package daemon

type BuildIdentity struct {
	HolderIteratorSHA256 string `json:"holder_iterator_sha256,omitempty"`
	UDPCollectorSHA256   string `json:"udp_collector_sha256,omitempty"`
	MaxRuleSchema        int    `json:"max_rule_schema,omitempty"`
	Source               string `json:"source"`
	Version              string `json:"version,omitempty"`
	ExecutableSHA256     string `json:"executable_sha256"`
	Modified             bool   `json:"modified"`
}
