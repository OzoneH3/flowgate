package identity

// Experimental, explicitly configured Wine owner-table snapshot adapter. The
// helper is a separate PE process in the selected test prefix, never injected.
import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type WindowsOwner struct {
	PID     uint32 `json:"pid"`
	Created uint64 `json:"created"`
	Image   string `json:"image"`
	Address string `json:"address"`
	Port    uint16 `json:"port"`
	State   uint32 `json:"state"`
}
type TableEvidence struct {
	Runtime   string         `json:"runtime"`
	BrokerPID int            `json:"broker_pid"`
	UID       uint32         `json:"uid"`
	Owners    []WindowsOwner `json:"windows_handle_holders"`
	Method    string         `json:"method"`
}
type tableSnapshot struct {
	Version  string         `json:"version"`
	Rows     []WindowsOwner `json:"rows"`
	Complete bool           `json:"complete"`
	Error    uint32         `json:"error"`
}
type WineTable struct {
	mu                      sync.Mutex
	cmd                     *exec.Cmd
	input                   io.WriteCloser
	output                  chan []byte
	dead                    bool
	lost                    atomic.Bool
	broker, prefix, version string
	helper                  string
	generation              string
}

// NewWineTable is lab-only. runner and helper are explicitly trusted executable
// paths; runtime version and broker image are pinned by the operator.
func NewWineTable(runner, helper, broker, prefix, version string) (*WineTable, error) {
	if version != "11.19" && version != "11.0" {
		return nil, fmt.Errorf("unsupported experimental runtime version")
	}
	prefix, err := filepath.EvalSymlinks(prefix)
	if err != nil {
		return nil, err
	}
	helper, err = filepath.EvalSymlinks(helper)
	if err != nil {
		return nil, err
	}
	if _, err = os.Stat(broker); err != nil {
		return nil, err
	}
	cmd := exec.Command(runner, helper)
	cmd.Env = append(os.Environ(), "WINEPREFIX="+prefix)
	in, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stderr = os.Stderr
	if err = cmd.Start(); err != nil {
		return nil, err
	}
	w := &WineTable{helper: helper, cmd: cmd, input: in, output: make(chan []byte, 1), broker: broker, prefix: prefix, version: version, generation: fmt.Sprint(time.Now().UnixNano())}
	go func() {
		s := bufio.NewScanner(out)
		s.Buffer(make([]byte, 4096), 1<<20)
		for s.Scan() {
			b := append([]byte(nil), s.Bytes()...)
			select {
			case w.output <- b:
			default:
				w.lost.Store(true)
				out.Close()
				close(w.output)
				return
			}
		}
		w.lost.Store(true)
		close(w.output)
	}()
	return w, nil
}
func (w *WineTable) Close() { w.mu.Lock(); defer w.mu.Unlock(); w.stop() }
func (w *WineTable) stop() {
	if !w.dead {
		w.dead = true
		w.input.Close()
		w.cmd.Process.Kill()
		w.cmd.Wait()
	}
}
func (w *WineTable) snapshot(proto string) (tableSnapshot, error) {
	var s tableSnapshot
	if proto != "tcp" && proto != "udp" {
		return s, fmt.Errorf("unsupported census protocol")
	}
	if w.dead {
		return s, fmt.Errorf("observer stopped; explicit restart required")
	}
	if _, err := io.WriteString(w.input, proto[:1]+"\n"); err != nil {
		w.stop()
		return s, err
	}
	select {
	case b, ok := <-w.output:
		if w.lost.Load() || !ok || json.Unmarshal(b, &s) != nil || !s.Complete || s.Error != 0 || s.Version != w.version || len(s.Rows) > 4096 {
			w.stop()
			return s, fmt.Errorf("incomplete or unsupported runtime census")
		}
	case <-time.After(2 * time.Second):
		w.stop()
		return s, fmt.Errorf("runtime census deadline")
	}
	return s, nil
}
func selectTableRows(s tableSnapshot, f Flow) ([]WindowsOwner, error) {
	var rows []WindowsOwner
	for _, r := range s.Rows {
		if r.Port != f.Local.Port() || (r.Address != f.Local.Addr().String() && r.Address != "0.0.0.0") {
			continue
		}
		if (f.Protocol == "tcp" && r.State != 2) || r.PID == 0 || r.Created == 0 || r.Image == "" {
			return nil, fmt.Errorf("missing Windows process identity")
		}
		rows = append(rows, r)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].PID != rows[j].PID {
			return rows[i].PID < rows[j].PID
		}
		return rows[i].Created < rows[j].Created
	})
	// Multiple handles in one process are not multiple recipients.
	unique := rows[:0]
	for _, r := range rows {
		if len(unique) == 0 || unique[len(unique)-1] != r {
			unique = append(unique, r)
		}
	}
	return unique, nil
}
func (w *WineTable) Resolve(f Flow) Attribution {
	w.mu.Lock()
	defer w.mu.Unlock()
	a := Resolve(f)
	// This adapter must never fall back to the weaker broker/client assumption.
	trusted, err := os.Stat(w.broker)
	if err != nil {
		a.Application = nil
		a.Reason = "configured census broker unavailable"
		return a
	}
	var broker *Process
	for i := range a.Owners {
		p := &a.Owners[i]
		st, e := os.Stat(fmt.Sprintf("/proc/%d/exe", p.PID))
		if e == nil && os.SameFile(trusted, st) {
			broker = p
		}
	}
	if broker == nil {
		for _, p := range a.Owners {
			if strings.HasPrefix(p.Application.Kind, "wine") && p.Application.Prefix == w.prefix {
				a.Application = nil
				a.Association = nil
				a.Reason = "selected runtime lacks pinned broker evidence"
				return a
			}
		}
		return a // Native traffic retains its original behavior.
	}
	a.Application = nil
	a.Association = nil
	a.Status = "unidentified"
	a.Reason = "Wine census relationship incomplete"
	if !a.VisibilityComplete || len(a.Sockets) != 1 || broker.Application.Prefix != w.prefix || f.Direction != "incoming" || !f.Local.Addr().Is4() {
		return a
	}
	for _, p := range a.Owners {
		if p.PID != broker.PID && (p.Application.Kind != "wine" || p.Application.Prefix != w.prefix || p.UID != broker.UID) {
			return a
		}
	}
	first, err := w.snapshot(f.Protocol)
	if err != nil {
		a.Reason = err.Error()
		return a
	}
	if !w.sameServer(broker) {
		a.Reason = "helper/broker Unix peer relationship missing"
		return a
	}
	rows, err := selectTableRows(first, f)
	if err != nil {
		a.Reason = err.Error()
		return a
	}
	// Bookend with fresh kernel cookies and FD-holder identities, then another
	// runtime census. This detects observed changes, not adversarial ABA races.
	again := Resolve(f)
	second, err := w.snapshot(f.Protocol)
	if err != nil {
		a.Reason = err.Error()
		return a
	}
	rows2, err := selectTableRows(second, f)
	if err != nil {
		return a
	}
	b, _ := json.Marshal(rows)
	c, _ := json.Marshal(rows2)
	if a.Fingerprint != again.Fingerprint || !again.VisibilityComplete || string(b) != string(c) {
		a.Reason = "ownership changed during runtime census"
		return a
	}
	a.Table = &TableEvidence{Runtime: first.Version, BrokerPID: broker.PID, UID: broker.UID, Owners: rows, Method: "two IPv4 runtime owner-table snapshots bookending kernel cookie/FD census; ordinary same-user non-adversarial snapshot model"}
	a.Fingerprint = digest(a.Fingerprint + w.generation + string(b))
	if len(rows) != 1 {
		a.Status = "multiple-candidates"
		a.Reason = "runtime census has zero or multiple Windows handle holders"
		return a
	}
	win := strings.ReplaceAll(rows[0].Image, "\\", "/")
	if len(win) < 3 || win[1] != ':' || win[2] != '/' {
		return a
	}
	path, err := filepath.EvalSymlinks(filepath.Join(w.prefix, "dosdevices", strings.ToLower(win[:1])+":", win[3:]))
	if err != nil {
		return a
	}
	revision := stamp(path)
	if revision == "" || !w.imageRevisionVisible(broker, path, revision) {
		return a
	}
	app := Application{Kind: "wine", Name: filepath.Base(path), Executable: path, Revision: revision, Prefix: w.prefix, Runtime: w.broker, Evidence: []string{"runtime Windows handle-table owner PID plus process creation time and full image path", "one kernel socket cookie and pinned broker image", "snapshot model; not protection against hostile same-user handle transfer"}}
	app.Key = digest(fmt.Sprintf("%d|%s|%s|%s", broker.UID, app.Kind, app.Prefix, app.Executable))
	a.Fingerprint = digest(a.Fingerprint + revision)
	a.Application = &app
	a.Status = "corroborated-runtime-table"
	a.Reason = "one Windows handle holder in runtime census; snapshot synchronization limits apply"
	return a
}

// Prove that the observer's mapped PE image uses this broker, not another
// server with a coincident endpoint. A name or prefix alone is insufficient.
func (w *WineTable) sameServer(broker *Process) bool {
	bf, err := socketFDs(broker.PID)
	if err != nil {
		return false
	}
	peers, err := unixPeers()
	if err != nil {
		return false
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return false
	}
	matches := 0
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		p, err := Inspect(pid)
		if err != nil || p.Application.Executable != w.helper || p.Application.Prefix != w.prefix || p.UID != broker.UID || p.NetNS != broker.NetNS || p.MountNS != broker.MountNS {
			continue
		}
		fds, err := socketFDs(pid)
		if err != nil {
			continue
		}
		for fd := range fds {
			peer := peers[fd]
			if bf[peer] && peers[peer] == fd {
				matches++
				break
			}
		}
	}
	return matches == 1
}

// Public Windows process paths identify the application, but filesystem paths
// alone cannot establish its loaded revision. Retain the existing mapped-image
// corroboration and reject deleted mappings even if the path has been reused.
func (w *WineTable) imageRevisionVisible(broker *Process, path, revision string) bool {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return false
	}
	found := false
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		p, err := Inspect(pid)
		if err != nil || p.Application.Prefix != w.prefix || p.UID != broker.UID || p.NetNS != broker.NetNS {
			continue
		}
		maps := string(readBound("/proc/"+e.Name()+"/maps", 2<<20))
		if strings.Contains(maps, path+" (deleted)") {
			return false
		}
		if p.Application.Executable == path && p.Application.Revision == revision && p.Application.Key != "" {
			found = true
		}
	}
	return found
}
