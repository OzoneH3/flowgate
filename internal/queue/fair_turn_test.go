package queue

import (
	"sync"
	"testing"
)

func TestHotEndpointCannotRepeatedlyOvertakeOlderColdTurn(t *testing.T) {
	started := make(chan uint32, 5)
	release := map[uint32]chan struct{}{1: make(chan struct{}), 3: make(chan struct{}), 4: make(chan struct{})}
	var once sync.Once
	unblock := func() {
		once.Do(func() {
			for _, ch := range release {
				select {
				case <-ch:
				default:
					close(ch)
				}
			}
		})
	}
	w := newPacketWorkers(1, func(p packetJob, _ bool) {
		started <- p.id
		if ch := release[p.id]; ch != nil {
			<-ch
		}
	})
	defer func() { unblock(); w.stop() }()
	if !w.submit(job(1, 8000)) {
		t.Fatal("hot head")
	}
	if receiveID(t, started) != 1 {
		t.Fatal("wrong head")
	}
	if !w.submit(job(2, 8001)) || !w.submit(job(3, 8000)) {
		t.Fatal("followers")
	}
	close(release[1])
	if got := receiveID(t, started); got != 3 {
		t.Fatal("short burst lost priority", got)
	}
	if !w.submit(job(4, 8000)) {
		t.Fatal("next hot follower")
	}
	close(release[3])
	if got := receiveID(t, started); got != 4 {
		t.Fatal("second preferred turn", got)
	}
	if !w.submit(job(5, 8000)) {
		t.Fatal("third hot follower")
	}
	close(release[4])
	if got := receiveID(t, started); got != 2 {
		t.Fatalf("hot endpoint exceeded preferred-turn bound: %d", got)
	}
	if got := receiveID(t, started); got != 5 {
		t.Fatal(got)
	}
}
