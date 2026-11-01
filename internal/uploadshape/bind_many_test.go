package uploadshape

import (
	"encoding/json"
	"flowgate/internal/identity"
	"testing"
)

type batchTransport struct {
	calls   []map[string]any
	corrupt bool
}

func (b *batchTransport) Close() error { return nil }
func (b *batchTransport) Call(q map[string]any) (json.RawMessage, error) {
	b.calls = append(b.calls, q)
	rows := q["bindings"].([]map[string]any)
	out := []map[string]any{}
	for _, r := range rows {
		cookie := r["expected_cookie"]
		if b.corrupt {
			cookie = "foreign"
		}
		out = append(out, map[string]any{"cookie": cookie})
	}
	v, e := json.Marshal(map[string]any{"bindings": out})
	return v, e
}
func TestBindingBatchKeepsCurrentIdentityDirectionsAndVersion(t *testing.T) {
	m := newManager(Options{})
	m.cfg = Config{Enabled: true, Caps: []Cap{{Application: "alpha", BitsPerSecond: 4_000_000, DownloadBitsPerSecond: 8_000_000}, {Application: "beta", BitsPerSecond: 2_000_000}}}
	rows := censusRows(3)
	hs := []hint{}
	for i, app := range []string{"0:alpha", "0:beta", "0:unconfigured"} {
		r := rows[i]
		hs = append(hs, hint{flow: identity.Flow{Protocol: r.Protocol, Local: r.Local, Remote: r.Remote}, app: app, cookie: r.Cookie})
	}
	tr := &batchTransport{}
	if n := m.bindMany(tr, hs, 1); n != 2 || len(tr.calls) != 1 {
		t.Fatal(n, tr.calls)
	}
	qs := tr.calls[0]["bindings"].([]map[string]any)
	if qs[0]["rate"] != uint64(4_000_000) || qs[0]["download_rate"] != uint64(8_000_000) || qs[1]["download_rate"] != uint64(0) || qs[0]["expected_cookie"] != rows[0].Cookie || qs[1]["expected_app"] != "0:beta" {
		t.Fatal(qs)
	}
	if m.bindMany(tr, hs, 2) != 0 || len(tr.calls) != 1 {
		t.Fatal("stale configuration issued batch")
	}
	if m.bindMany(tr, make([]hint, identity.MaxResolveBatch+1), 1) != 0 {
		t.Fatal("unbounded batch")
	}
	tr.corrupt = true
	m.bindMany(tr, hs, 1)
	if m.Snapshot().LastError != "binding batch cookie mismatch" {
		t.Fatal(m.Snapshot().LastError)
	}
}
