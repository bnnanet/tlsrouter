package tlsrouter

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestWithTLSALPNManageSerializesCalls(t *testing.T) {
	var lc ListenConfig
	var active atomic.Int32
	var maxActive atomic.Int32
	var wg sync.WaitGroup

	for range 32 {
		wg.Go(func() {
			_ = lc.withTLSALPNManage(func() error {
				current := active.Add(1)
				for {
					old := maxActive.Load()
					if current <= old || maxActive.CompareAndSwap(old, current) {
						break
					}
				}
				time.Sleep(time.Millisecond)
				active.Add(-1)
				return nil
			})
		})
	}
	wg.Wait()

	if got := maxActive.Load(); got != 1 {
		t.Fatalf("maximum concurrent ManageSync calls = %d, want 1", got)
	}
}
