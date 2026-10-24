package store

import (
	"encoding/json"
	"flowgate/internal/policy"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNetworkEndpointDurableAndDowngradeRefusal(t *testing.T) {
	dir, err := os.MkdirTemp("../../.workspace/tmp", "endpoint-store-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "rules.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	r := policy.Rule{Schema: 7, NetworkEndpoint: true, ID: "endpoint:synthetic", Version: 1, Created: time.Now().UTC(), Action: "allow", Priority: 100, Filter: policy.Filter{AllPrograms: true, AllUIDs: true, Direction: "outgoing", Protocol: "tcp", RemoteAddress: "192.0.2.40", RemotePort: 8445}}
	if err = s.Replace([]policy.Rule{r}); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	rs, err := s.Load()
	if err != nil || len(rs) != 1 || !rs[0].NetworkEndpoint || rs[0].Schema != 7 {
		t.Fatal(rs, err)
	}
	// Older Store.Load uses DisallowUnknownFields. Its Rule did not contain
	// network_endpoint, so it refuses this document rather than loading an allow
	// with the new authority silently erased. Schema7 is also unsupported there.
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var old struct {
		ShareWithRoot bool `json:"share_with_root,omitempty"`
	}
	d := json.NewDecoder(strings.NewReader(string(raw)))
	d.DisallowUnknownFields()
	if err := d.Decode(&old); err == nil || !strings.Contains(err.Error(), `unknown field "network_endpoint"`) {
		t.Fatal("legacy strict decoder did not refuse new authority", err)
	}
	bad := r
	bad.Schema = 4
	if err = s.Replace([]policy.Rule{bad}); err == nil {
		t.Fatal("partial network schema saved")
	}
	rs, err = s.Load()
	if err != nil || len(rs) != 1 || rs[0].Schema != 7 {
		t.Fatal("failed save corrupted persisted permission", rs, err)
	}
}
