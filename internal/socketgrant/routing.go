package socketgrant

import "flowgate/internal/identity"

// KeyForQueuedOutput requires the packet's kernel-reported egress interface in
// addition to full verified ownership. The kernel gate must independently match
// actual meta oif; this function alone does not enforce routing.
func KeyForQueuedOutput(f identity.Flow, a identity.Attribution) (Key, bool) {
	outdev, ok := f.QueueOutputInterface()
	if !ok {
		return Key{}, false
	}
	k, ok := KeyFor(f, a)
	if !ok {
		return Key{}, false
	}
	k.Interface = outdev
	return k, true
}
