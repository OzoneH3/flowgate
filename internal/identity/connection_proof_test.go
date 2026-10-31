package identity

import (
	"encoding/json"
	"testing"
)

func TestFreshConnectionProofIsNotSerializedOrRoutedAsHint(t *testing.T) {
	a := Attribution{freshConnectionProof: true}
	data, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	var copy Attribution
	if err = json.Unmarshal(data, &copy); err != nil {
		t.Fatal(err)
	}
	if copy.FreshConnectionProof() || copyWineInitial(a).FreshConnectionProof() {
		t.Fatal("fresh proof escaped its observation")
	}
}
func TestNativeReuseDoesNotDonateFreshConnectionProof(t *testing.T) {
	x, r := newReuseFixture()
	x.nativeAlpha()
	x.resolveHook = func(a *Attribution) { a.freshConnectionProof = true }
	f := udpFlow("outgoing", "172.30.42.123:34429", "198.51.100.1:7770")
	if !r.Resolve(f).FreshConnectionProof() {
		t.Fatal("full observation lost proof")
	}
	if r.Resolve(f).FreshConnectionProof() {
		t.Fatal("native cache donated full discovery proof")
	}
}
