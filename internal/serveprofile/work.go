package serveprofile

import (
	"context"
	"runtime/pprof"
)

// Work labels only explicit diagnostic windows. It neither requests discovery nor
// changes its scope/freshness. Existing kernel/per-flow authority is unaffected.
func Work(ctx context.Context, name string, fn func()) {
	if active.Load() == nil {
		fn()
		return
	}
	pprof.Do(ctx, pprof.Labels("flowgate_work", name), func(context.Context) { fn() })
}
