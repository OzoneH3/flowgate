package queue

import "testing"

func TestQueueHandoffSequenceField(t *testing.T) {
	for _, s := range []string{"101 22 8 2 65535 0 0 4294967295 1\n", "100 22 0 2 0 0 0 9 1\n101 22 8 2 65535 0 0 4294967295 1\n"} {
		n, ok := parseQueueSequence(s, 101)
		if !ok || n != 4294967295 {
			t.Fatal(n, ok)
		}
	}
	for _, s := range []string{"", "101 bad", "101 22 8 2 65535 0 0 x 1", "100 22 8 2 65535 0 0 5 1"} {
		if _, ok := parseQueueSequence(s, 101); ok {
			t.Fatal("invalid fence", s)
		}
	}
}
