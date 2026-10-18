package main

import "testing"

func TestHostPeerCommandBounds(t *testing.T) {
	for _, q := range []peerRequest{{Op: "quit"}, {Op: "send", Protocol: "udp", Port: 24680}, {Op: "send", Protocol: "tcp", Port: 24709, V6: true}} {
		if e := validatePeerRequest(q); e != nil {
			t.Fatal(e)
		}
	}
	for _, q := range []peerRequest{{Op: "setup"}, {Op: "send", Protocol: "udp", Port: 53}, {Op: "send", Protocol: "udp", Port: 24710}, {Op: "send", Protocol: "raw", Port: 24680}, {Op: "quit", Port: 24680}} {
		if validatePeerRequest(q) == nil {
			t.Fatal("accepted", q)
		}
	}
}
