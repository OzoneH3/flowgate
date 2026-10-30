package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flowgate/internal/daemon"
	"flowgate/internal/policy"
	"io"
	"os"
	"runtime/debug"
)

var sourceRevision string

// Set by the matched build after compiling the optional iterator loader.
// Empty disables loading even if a helper path is supplied.
var holderIteratorSHA256 string

func buildIdentity() daemon.BuildIdentity {
	b := daemon.BuildIdentity{Source: sourceRevision, MaxRuleSchema: policy.NetworkEndpointSchema}
	if v, ok := debug.ReadBuildInfo(); ok {
		for _, s := range v.Settings {
			switch s.Key {
			case "vcs.revision":
				if b.Source == "" {
					b.Source = s.Value
				}
			case "vcs.modified":
				b.Modified = s.Value == "true"
			}
		}
	}
	if f, err := os.Open("/proc/self/exe"); err == nil {
		defer f.Close()
		h := sha256.New()
		if _, err = io.Copy(h, f); err == nil {
			b.ExecutableSHA256 = hex.EncodeToString(h.Sum(nil))
		}
	}
	return b
}
