package govpn

import (
	"sync"
	"testing"
)

func TestKnownPeersConcurrent(t *testing.T) {
	kp := NewKnownPeers()
	var wg sync.WaitGroup
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 10000; i++ {
				kp.Set("peer", &Peer{})
				kp.Snapshot()
				kp.Delete("peer")
			}
		}()
	}
	wg.Wait()
	if got := len(kp.Snapshot()); got != 0 {
		t.Fatalf("Snapshot len = %d, want 0", got)
	}
}
