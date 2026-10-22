package main

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestRuleImportDiscardsReadOnlyScopeMetadata(t *testing.T) {
	for _, value := range []string{"true", "false"} {
		r, err := decodeImportedRules([]byte(`[{"id":"saved","follows_updates":` + value + `,"filter":{"application":"app","revision":"old"}}]`))
		if err != nil || len(r) != 1 {
			t.Fatal(r, err)
		}
		b, _ := json.Marshal(r)
		if bytes.Contains(b, []byte("follows_updates")) {
			t.Fatal(string(b))
		}
		if r[0].FollowsUpdates() {
			t.Fatal("client granted update scope")
		}
	}
	if _, err := decodeImportedRules([]byte(`[{"arbitrary_unknown":true}]`)); err == nil {
		t.Fatal("unknown field accepted")
	}
}
