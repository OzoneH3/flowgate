package queue

import (
	"os"
	"strconv"
	"strings"
)

func queueSequence(number uint16) (uint32, bool) {
	b, err := os.ReadFile("/proc/net/netfilter/nfnetlink_queue")
	if err != nil {
		return 0, false
	}
	return parseQueueSequence(string(b), number)
}
func parseQueueSequence(text string, number uint16) (uint32, bool) {
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) < 8 {
			continue
		}
		q, err := strconv.ParseUint(f[0], 10, 16)
		if err != nil || uint16(q) != number {
			continue
		}
		seq, err := strconv.ParseUint(f[7], 10, 32)
		return uint32(seq), err == nil
	}
	return 0, false
}
