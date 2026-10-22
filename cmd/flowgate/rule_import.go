package main

import (
	"bytes"
	"encoding/json"
	"flowgate/internal/policy"
)

// Ignore only the known read-only projection property. Other unknown fields
// remain errors, and this metadata is never added to the persisted rule.
func decodeImportedRules(data []byte) ([]policy.Rule, error) {
	var imported []struct {
		policy.Rule
		FollowsUpdates *bool `json:"follows_updates,omitempty"`
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&imported); err != nil {
		return nil, err
	}
	rules := make([]policy.Rule, len(imported))
	for i := range imported {
		rules[i] = imported[i].Rule
	}
	return rules, nil
}
