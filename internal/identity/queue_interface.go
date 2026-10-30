package identity

// WithQueueOutputInterface is called by the trusted NFQUEUE adapter with
// NFQA_IFINDEX_OUTDEV. A route lookup or an activity display value is not a
// substitute. The private witness is lost on JSON round trips.
func WithQueueOutputInterface(f Flow, outdev uint32) Flow {
	f.Interface = outdev
	f.queueOutputInterface = 0
	if f.Direction == "outgoing" && outdev != 0 {
		f.queueOutputInterface = outdev
	}
	return f
}
func (f Flow) QueueOutputInterface() (uint32, bool) {
	return f.queueOutputInterface, f.Direction == "outgoing" && f.queueOutputInterface != 0 && f.Interface == f.queueOutputInterface
}
