package identity

import (
	"crypto/sha256"
	"fmt"
	"os"
	"testing"
)

// This is descriptor/identity evidence, not packet-delivery evidence. The
// existing fixtures exercise additional holders, file-table splits, surviving
// threads, transfers, generation changes and ambiguity through shared code.
func TestFDIteratorRealHolderMatrix(t *testing.T) {
	helper := os.Getenv("FLOWGATE_ITERATOR_TEST_HELPER")
	if helper == "" {
		t.Skip("explicit isolated iterator test helper required")
	}
	if os.Getenv("FLOWGATE_PARENT_NETNS") == "" || os.Getenv("FLOWGATE_PARENT_NETNS") == NetNS() {
		t.Fatal("separate network namespace required")
	}
	if os.Getenv("FLOWGATE_PARENT_PIDNS_ID") == "" || link("/proc/self/ns/pid") == os.Getenv("FLOWGATE_PARENT_PIDNS_ID") {
		t.Fatal("separate PID namespace required")
	}
	image, err := os.ReadFile(helper)
	if err != nil {
		t.Fatal(err)
	}
	close, err := EnableHolderIterator(helper, fmt.Sprintf("%x", sha256.Sum256(image)))
	if err != nil {
		t.Fatal(err)
	}
	defer close()
	if holderIterator.Load() == nil {
		t.Fatal("iterator not enabled")
	}
	r := holderIterator.Load()
	before, _ := r.Stats()
	for _, tc := range []struct {
		name string
		run  func(*testing.T)
	}{
		{"topology", TestHolderCensusRealTopologies},
		{"identity", TestHolderIdentityRealTopologies},
		{"transfers-and-churn", TestHolderChurnRealTopologies},
	} {
		t.Run(tc.name, tc.run)
	}
	after, failures := r.Stats()
	if after <= before {
		t.Fatal("no successful kernel enumeration during matrix")
	}
	fmt.Printf("Iterator matrix fresh tables=%d fallback requests=%d\n", after-before, failures)
	if failures != 0 {
		t.Fatalf("matrix used %d fallback requests; cannot claim iterator-only coverage", failures)
	}
}
