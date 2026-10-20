package identity

import (
	"fmt"
	"os"
	"strings"
)

func activityLeaderExited(base string) bool {
	stat := string(readBound(base+"/stat", 8192))
	i := strings.LastIndex(stat, ") ")
	return i >= 0 && strings.HasPrefix(stat[i+2:], "Z ")
}
func activityDescriptorMatches(path string, inode uint32) bool {
	target, err := os.Readlink(path)
	return err == nil && target == fmt.Sprintf("socket:[%d]", inode)
}

// Categories describe evidence, not speculative causes for an unknown socket.
func activityOwnershipCategory(row ActivityRow) string {
	switch row.Ownership {
	case "Visible descriptor holder":
		return "visible-holder"
	case "Shared socket":
		return "shared"
	case "No userspace socket inode":
		return "no-userspace-inode"
	case "Owner changed during inspection":
		return "holder-changed"
	case "Owner inaccessible":
		return "holder-inaccessible"
	case "Owner metadata unavailable":
		return "holder-metadata-unavailable"
	default:
		if strings.Contains(row.Evidence, "truncated") {
			return "holders-truncated"
		}
		return "unknown"
	}
}

// This never removes owners or changes Resolve's conservative enforcement model.
func activityDisplayApplication(row ActivityRow, processes map[string]ActivityProcess) *Application {
	if len(row.Owners) == 0 || (row.Ownership != "Visible descriptor holder" && row.Ownership != "Shared socket") {
		return nil
	}
	var first *ActivityProcess
	for _, id := range row.Owners {
		p, ok := processes[id]
		if !ok || !LiveRuleable(p.Application) {
			return nil
		}
		if first != nil && (p.UID != first.UID || p.Application.Key != first.Application.Key || p.Application.Revision != first.Application.Revision) {
			return nil
		}
		copy := p
		first = &copy
	}
	a := first.Application
	return &a
}
