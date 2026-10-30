package identity

import (
	"encoding/json"
	"testing"
)

func TestQueueOutputWitnessCannotComeFromSerializedFlow(t *testing.T) {
	f := WithQueueOutputInterface(Flow{Direction: "outgoing"}, 7)
	if n, ok := f.QueueOutputInterface(); !ok || n != 7 {
		t.Fatal("queue witness lost")
	}
	data, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Flow
	if err = json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if _, ok := decoded.QueueOutputInterface(); ok {
		t.Fatal("JSON forged queue evidence")
	}
	changed := f
	changed.Interface = 8
	if _, ok := changed.QueueOutputInterface(); ok {
		t.Fatal("mutated interface accepted")
	}
	for _, v := range []Flow{WithQueueOutputInterface(Flow{Direction: "incoming"}, 7), WithQueueOutputInterface(Flow{Direction: "outgoing"}, 0)} {
		if _, ok := v.QueueOutputInterface(); ok {
			t.Fatal("non-egress witness")
		}
	}
}
