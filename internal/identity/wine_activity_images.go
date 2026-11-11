package identity

import (
	diagnostics "flowgate/internal/serveprofile"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type wineImageKey struct{ path, revision string }

// This is candidate discovery, never application authority. annotateCensus still
// checks both tables, both owner sets, each socket, and the resulting image key.
func (w *WineTable) activityImageKeys(s *ActivitySnapshot, indices []int, second map[activityTableKey]tableSnapshot, proceed func() bool) []wineImageKey {
	seen := map[wineImageKey]bool{}
	names := map[string]bool{}
	var keys []wineImageKey
	for _, i := range indices {
		if !proceed() {
			return nil
		}
		r := s.Rows[i]
		f := Flow{NetNS: r.Socket.NetNS, Protocol: r.Socket.Protocol, Direction: "outgoing", Local: r.Socket.Local, Remote: r.Socket.Remote}
		t, ok := second[activityTable(r.Socket)]
		if !ok {
			continue
		}
		rows, err := selectTableRows(t, f)
		if err != nil || len(rows) != 1 {
			continue
		}
		if names[rows[0].Image] {
			continue
		}
		names[rows[0].Image] = true
		win := strings.ReplaceAll(rows[0].Image, "\\", "/")
		if len(win) < 3 || win[1] != ':' || win[2] != '/' {
			continue
		}
		path, err := filepath.EvalSymlinks(filepath.Join(w.prefix, "dosdevices", strings.ToLower(win[:1])+":", win[3:]))
		if err != nil {
			continue
		}
		key := wineImageKey{path, stamp(path)}
		if key.revision != "" && !seen[key] {
			seen[key] = true
			keys = append(keys, key)
		}
	}
	return keys
}

type wineImageDiscovery struct {
	processes func() ([]int, error)
	candidate func(int, *Process) bool
	inspect   func(int) (Process, error)
	maps      func(int) string
	fds       func(int) (map[uint32]bool, error)
	peers     func() (map[uint32]uint32, error)
	visible   func(Process, wineImageKey, string) bool
}

func (w *WineTable) activityImagesVisible(broker *Process, keys []wineImageKey, proceed func() bool) map[wineImageKey]bool {
	defer diagnostics.Begin(diagnostics.WineImageValidation).End()
	diagnostics.Count(diagnostics.ActivityImageRequests, uint64(len(keys)))
	ops := wineImageDiscovery{
		processes: func() ([]int, error) {
			diagnostics.Count(diagnostics.ActivityImageProcessPasses, 1)
			entries, err := os.ReadDir("/proc")
			var pids []int
			for _, e := range entries {
				if pid, err := strconv.Atoi(e.Name()); err == nil {
					pids = append(pids, pid)
				}
			}
			return pids, err
		},
		// Image validation intentionally allows a different mount namespace.
		// The helper's stricter mount filter is not a complete image candidate set.
		candidate: func(pid int, b *Process) bool {
			return mayHaveWinePrefix(pid, w.prefix) && mayShareWineScope(pid, b, false) && mayShareWinePrefix(pid, w.prefix) && mayBeWineProcess(pid)
		},
		inspect: func(pid int) (Process, error) {
			diagnostics.Count(diagnostics.ActivityImageInspections, 1)
			return Inspect(pid)
		},
		maps: func(pid int) string {
			return readWineImageMaps(pid, true)
		},
		fds: func(pid int) (map[uint32]bool, error) {
			diagnostics.Count(diagnostics.ActivityImageFDs, 1)
			return socketFDs(pid)
		},
		peers: func() (map[uint32]uint32, error) {
			diagnostics.Count(diagnostics.ActivityImagePeers, 1)
			return unixPeers()
		},
		visible: func(p Process, key wineImageKey, maps string) bool {
			return wineTableImageVisible(p, key.path, key.revision, maps)
		},
	}
	return discoverWineImages(broker, w.prefix, keys, proceed, ops)
}

// One fresh image pass shares candidate discovery across distinct images only.
// Before and after inspections/maps are separate observations. No state escapes
// this call or crosses any of Activity's three independent sameServer barriers.
func discoverWineImages(broker *Process, prefix string, keys []wineImageKey, proceed func() bool, ops wineImageDiscovery) map[wineImageKey]bool {
	found, deleted := map[wineImageKey]bool{}, map[wineImageKey]bool{}
	if len(keys) == 0 || !proceed() {
		return found
	}
	pids, err := ops.processes()
	if err != nil {
		return found
	}
	for _, pid := range pids {
		if !proceed() {
			return nil
		}
		if !ops.candidate(pid, broker) {
			continue
		}
		p, err := ops.inspect(pid)
		if err != nil || p.Application.Prefix != prefix || p.UID != broker.UID || p.NetNS != broker.NetNS {
			continue
		}
		before := ops.maps(pid)
		var matching []wineImageKey
		for _, key := range keys {
			if !proceed() {
				return nil
			}
			if strings.Contains(before, key.path+" (deleted)") {
				deleted[key] = true
				continue
			}
			if ops.visible(p, key, before) {
				matching = append(matching, key)
			}
		}
		if len(matching) == 0 {
			continue
		}
		cf, err := ops.fds(p.PID)
		if err != nil {
			continue
		}
		bf, err := ops.fds(broker.PID)
		if err != nil {
			continue
		}
		peers, err := ops.peers()
		if err != nil {
			continue
		}
		related := false
		for fd := range cf {
			if bf[peers[fd]] && peers[peers[fd]] == fd {
				related = true
				break
			}
		}
		current, err := ops.inspect(p.PID)
		if err != nil || !related || current.Start != p.Start || current.UID != p.UID || current.NetNS != p.NetNS || current.MountNS != p.MountNS || current.Application.Prefix != prefix {
			continue
		}
		after := ops.maps(p.PID)
		for _, key := range matching {
			if !proceed() {
				return nil
			}
			if ops.visible(current, key, after) {
				found[key] = true
			}
		}
	}
	// Do not stop after finding a witness: a later deleted mapping vetoes only
	// that exact image, independently of process order and other applications.
	for key := range deleted {
		delete(found, key)
	}
	if !proceed() {
		return nil
	}
	return found
}
