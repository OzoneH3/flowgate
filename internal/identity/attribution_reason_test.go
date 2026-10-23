package identity

import (
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAttributionReasonNoSocketLegacyRevalidation(t *testing.T) {
	before := Attribution{Sockets: []Socket{{Inode: 9, Cookie: "original"}}}
	for _, tc := range []struct {
		code, reason string
		ended        bool
	}{
		{ReasonNoSocketObserved, "new wording independent of classification", true},
		{"", "no visible matching socket", true},
		{"", "socket diagnostics unavailable", false},
		{"future_reason", "no visible matching socket", false},
		{ReasonSocketCensusUnavailable, "no visible matching socket", false},
	} {
		after := Attribution{ReasonCode: tc.code, Reason: tc.reason}
		got := ComparePendingBinding(before, after, time.Now()).Code == "connection_ended"
		if got != tc.ended {
			t.Fatalf("code=%q reason=%q ended=%v", tc.code, tc.reason, got)
		}
	}
	if ComparePendingBinding(Attribution{}, Attribution{ReasonCode: ReasonNoSocketObserved}, time.Now()).Code == "connection_ended" {
		t.Fatal("no original socket must not become an ended connection")
	}
}

func TestAttributionReasonRuntimeOverride(t *testing.T) {
	original := Attribution{Status: "directly-associated", ReasonCode: ReasonNativeOwnerObserved, Reason: "native evidence", Application: &Application{Key: "native"}, Fingerprint: "original"}
	w := WineTable{broker: filepath.Join(t.TempDir(), "missing-broker")}
	got := w.resolveAttributionLocked(Flow{}, original)
	if got.ReasonCode != ReasonRuntimeBrokerUnavailable || got.Application != nil || got.Fingerprint != original.Fingerprint || got.Reason != "configured census broker unavailable" {
		t.Fatalf("runtime refusal retained stale reason/changed binding: %+v", got)
	}
	// This retired fixture has no helper process to stop.
	w.dead = true
	w.session = &RuntimeSession{}
	got = w.resolveAttributionLocked(Flow{}, original)
	if got.ReasonCode != ReasonRuntimeSessionChanged || got.Application != nil {
		t.Fatalf("session override: %+v", got)
	}
}

func TestAttributionReasonJSONCompatibility(t *testing.T) {
	for _, code := range []string{"", ReasonMultipleCandidates, "future_reason"} {
		a := Attribution{Status: "unidentified", Reason: "detailed original evidence", ReasonCode: code}
		b, err := json.Marshal(a)
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(b, &fields); err != nil {
			t.Fatal(err)
		}
		if _, present := fields["reason_code"]; present != (code != "") {
			t.Fatalf("omitempty: %s", b)
		}
		var decoded Attribution
		if err := json.Unmarshal(b, &decoded); err != nil {
			t.Fatal(err)
		}
		if decoded.ReasonCode != code || decoded.Reason != a.Reason {
			t.Fatalf("evidence lost: %s", b)
		}
	}
}

// Real sockets in the existing private lab only. This observes ownership; it
// does not send a packet or claim delivery, short-close cause, or host coverage.
func TestAttributionReasonNativePrivateCensus(t *testing.T) {
	if os.Getenv("FLOWGATE_PARENT_NETNS") == "" || os.Getenv("FLOWGATE_PARENT_NETNS") == NetNS() {
		t.Skip("private lab namespace required")
	}
	for _, address := range []string{"127.0.0.1:0", "[::1]:0"} {
		t.Run(address, func(t *testing.T) {
			c, err := net.ListenPacket("udp", address)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			local := netip.MustParseAddrPort(c.LocalAddr().String())
			remote := netip.AddrPortFrom(local.Addr(), 9)
			f := Flow{NetNS: NetNS(), Protocol: "udp", Direction: "outgoing", Local: local, Remote: remote}
			a := Resolve(f)
			if a.ReasonCode != ReasonNativeOwnerObserved || a.Application == nil || len(a.Owners) != 1 || a.Owners[0].PID != os.Getpid() {
				t.Fatalf("bound owner: %+v", a)
			}
			f.NetNS = "foreign"
			if got := Resolve(f); got.ReasonCode != ReasonNamespaceMismatch || got.Application != nil {
				t.Fatalf("namespace: %+v", got)
			}
			f.NetNS = NetNS()
			if err := c.Close(); err != nil {
				t.Fatal(err)
			}
			a = Resolve(f)
			if a.ReasonCode != ReasonNoSocketObserved || len(a.Sockets) != 0 || a.Application != nil {
				t.Fatalf("no socket observed: %+v", a)
			}
		})
	}
}
