package identity

// Experimental, explicitly configured Wine owner-table snapshot adapter. The
// helper is a separate PE process in the selected test prefix, never injected.
import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type WindowsOwner struct {
	Family        int    `json:"family"`
	Scope         uint32 `json:"scope_id"`
	PID           uint32 `json:"pid"`
	Created       uint64 `json:"created"`
	CreationTime  string `json:"creation_time,omitempty"`
	Image         string `json:"image"`
	Address       string `json:"address"`
	Port          uint16 `json:"port"`
	State         uint32 `json:"state"`
	RemoteAddress string `json:"remote_address,omitempty"`
	RemotePort    uint16 `json:"remote_port,omitempty"`
}
type TableEvidence struct {
	Runtime      string         `json:"runtime"`
	Prefix       string         `json:"prefix,omitempty"`
	BrokerStart  string         `json:"broker_start_ticks,omitempty"`
	SocketCookie string         `json:"socket_cookie,omitempty"`
	BrokerPID    int            `json:"broker_pid"`
	UID          uint32         `json:"uid"`
	Owners       []WindowsOwner `json:"windows_handle_holders"`
	Method       string         `json:"method"`
}
type tableSnapshot struct {
	Family   int            `json:"family"`
	Schema   int            `json:"schema"`
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
	requiredSchema          int
	session                 *RuntimeSession
	startupDeadline         time.Time
}

// supportedCensusVersion describes the validated Wine 11 owner-table family,
// not a vendor, executable hash, prefix or application allowlist. Unknown
// families are attempted and reported explicitly, never silently skipped.
func supportedCensusVersion(version string) bool {
	parts := strings.Split(version, ".")
	if len(parts) != 2 || parts[0] != "11" || len(parts[1]) == 0 || len(parts[1]) > 3 {
		return false
	}
	for _, ch := range parts[1] {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return true
}

// NewWineTable is lab-only. Paths are explicitly trusted; an empty version
// requests negotiation from the live census rather than an operator pin.
func NewWineTable(runner, helper, broker, prefix, version string) (*WineTable, error) {
	return newWineTable(runner, helper, broker, prefix, version, nil)
}
func newWineTable(runner, helper, broker, prefix, version string, env []string) (*WineTable, error) {
	return newWineTableAs(runner, helper, broker, prefix, version, env, nil)
}
func newWineTableAs(runner, helper, broker, prefix, version string, env []string, credential *syscall.Credential) (*WineTable, error) {
	return newWineTableConfigured(runner, helper, broker, prefix, version, env, credential, nil)
}
func newWineTableConfigured(runner, helper, broker, prefix, version string, env []string, credential *syscall.Credential, namespace *wineNamespace) (*WineTable, error) {
	if version != "" && !supportedCensusVersion(version) {
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
	if namespace != nil {
		cmd = namespace.command()
		credential = nil
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: credential, Pdeathsig: syscall.SIGKILL}
	if env == nil {
		cmd.Env = append(os.Environ(), "WINEPREFIX="+prefix)
	} else {
		cmd.Env = env
	}
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
	return w.snapshotFamily(proto, 4)
}
func (w *WineTable) snapshotFamily(proto string, family int) (tableSnapshot, error) {
	var s tableSnapshot
	if proto != "tcp" && proto != "udp" {
		return s, fmt.Errorf("unsupported census protocol")
	}
	if w.dead {
		return s, fmt.Errorf("observer stopped; explicit restart required")
	}
	if _, err := io.WriteString(w.input, fmt.Sprintf("%s%d\n", proto[:1], family)); err != nil {
		w.stop()
		return s, err
	}
	select {
	case b, ok := <-w.output:
		if w.lost.Load() || !ok || json.Unmarshal(b, &s) != nil || !s.Complete || s.Family != family || (s.Schema != 1 && s.Schema != 2) || (w.requiredSchema != 0 && s.Schema != w.requiredSchema) || s.Error != 0 || (w.version != "" && s.Version != w.version) || len(s.Rows) > 4096 {
			w.stop()
			return s, fmt.Errorf("incomplete or unsupported runtime census")
		}
		if w.version == "" {
			if s.Schema != 2 || !supportedCensusVersion(s.Version) {
				w.stop()
				return s, fmt.Errorf("runtime owner census %q schema %d is not validated; no application identity inferred", s.Version, s.Schema)
			}
			w.requiredSchema = s.Schema
			w.version = s.Version // Pin the negotiated contract for this generation.
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
		addr, err := netip.ParseAddr(r.Address)
		if err != nil {
			return nil, fmt.Errorf("malformed runtime address")
		}
		if r.Port != f.Local.Port() || (addr.Unmap() != f.Local.Addr().Unmap() && !addr.IsUnspecified()) {
			continue
		}
		if addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || f.Local.Addr().IsLinkLocalUnicast() || (addr.Is4() && r.Scope != 0) {
			return nil, fmt.Errorf("scoped runtime endpoint requires a proven Windows-to-Linux interface mapping")
		}
		if addr.Is6() && f.Local.Addr().Is4() && !addr.IsUnspecified() && !addr.Is4In6() {
			continue
		}
		if addr.Is4() && f.Local.Addr().Is6() && !f.Local.Addr().Is4In6() {
			continue
		}
		if f.Direction == "outgoing" {
			if f.Remote.Addr().IsLinkLocalUnicast() {
				return nil, fmt.Errorf("runtime remote interface mapping unavailable")
			}
			if f.Protocol != "tcp" || s.Schema != 2 {
				return nil, fmt.Errorf("outgoing attribution needs protocol2 TCP owner table")
			}
			remote, e := netip.ParseAddr(r.RemoteAddress)
			if e != nil {
				return nil, fmt.Errorf("missing runtime remote endpoint")
			}
			if remote.Unmap() != f.Remote.Addr().Unmap() || r.RemotePort != f.Remote.Port() {
				continue
			}
			if r.State != 3 && r.State != 5 {
				return nil, fmt.Errorf("outgoing runtime socket is neither SYN_SENT nor ESTABLISHED")
			}
		} else if f.Protocol == "tcp" && r.State != 2 {
			continue
		}
		if r.PID == 0 || r.Created == 0 || r.Image == "" {
			return nil, fmt.Errorf("missing Windows process identity")
		}
		r.CreationTime = strconv.FormatUint(r.Created, 10)
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
	if w.session != nil && !w.session.current() {
		a.Application = nil
		a.Association = nil
		a.Reason = "attached runtime session replaced; explicit reattachment required"
		w.stop()
		return a
	}
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
	if !a.VisibilityComplete || len(a.Sockets) != 1 || broker.Application.Prefix != w.prefix || (f.Direction != "incoming" && f.Direction != "outgoing") {
		return a
	}
	for _, p := range a.Owners {
		if p.PID != broker.PID && (p.Application.Kind != "wine" || p.Application.Prefix != w.prefix || p.UID != broker.UID) {
			return a
		}
	}
	family := 4
	if a.Sockets[0].Family == 10 {
		family = 6
	}
	if family == 6 && f.Local.Addr().Is4() && (a.Sockets[0].V6Only == nil || *a.Sockets[0].V6Only) {
		a.Reason = "IPv4 delivery to IPv6 socket requires observed dual-stack mode"
		return a
	}
	first, rows, err := w.snapshotRows(f, family)
	if err != nil {
		a.Reason = err.Error()
		return a
	}
	if !w.sameServer(broker) {
		a.Reason = "helper/broker Unix peer relationship missing"
		return a
	}
	// Bookend with fresh kernel cookies and FD-holder identities, then another
	// runtime census. This detects observed changes, not adversarial ABA races.
	again := Resolve(f)
	second, err := w.snapshotFamily(f.Protocol, family)
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
	if fingerprint(nil, a.Sockets) != fingerprint(nil, again.Sockets) || !again.VisibilityComplete || string(b) != string(c) || !sameBrokerGeneration(*broker, again.Owners) {
		a.Reason = "ownership changed during runtime census"
		return a
	}
	a.Table = &TableEvidence{Runtime: first.Version, Prefix: w.prefix, BrokerPID: broker.PID, BrokerStart: broker.Start, SocketCookie: a.Sockets[0].Cookie, UID: broker.UID, Owners: rows, Method: "two family-specific runtime owner-table snapshots bookending kernel cookie/FD census; ordinary same-user non-adversarial snapshot model"}
	a.Fingerprint = digest(fingerprint([]Process{*broker}, a.Sockets) + w.generation + string(b))
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
	if !consistentWineHolders(a.Owners, *broker, app) || !consistentWineHolders(again.Owners, *broker, app) {
		a.Status = "multiple-candidates"
		a.Reason = "visible non-broker holder disagrees with Windows owner table"
		return a
	}
	app.DisplayName = strings.TrimSuffix(app.Name, filepath.Ext(app.Name)) + " · via wineserver"
	if broker.Provenance != nil && broker.Provenance.Evidence == "verified" && broker.Provenance.Launch != nil && broker.Provenance.Launch.Game != nil {
		g := broker.Provenance.Launch.Game
		if g.Status == "verified-file" && g.Executable == path && g.Revision == revision && g.Title != "" {
			app.DisplayName = g.Title + " · via wineserver"
		}
	}
	a.Fingerprint = digest(a.Fingerprint + revision)
	a.Application = &app
	a.Status = "corroborated-runtime-table"
	a.Reason = "one verified Windows handle holder, exact socket endpoint and kernel cookie; broker FD is transport evidence, not the permission target"
	return a
}

// Prove that the observer's mapped PE image uses this broker, not another
// server with a coincident endpoint. A name or prefix alone is insufficient.
func (w *WineTable) sameServer(broker *Process) bool { return w.helperPeers(broker) == 1 }
func (w *WineTable) helperPeers(broker *Process) int {
	bf, err := socketFDs(broker.PID)
	if err != nil {
		return -1
	}
	peers, err := unixPeers()
	if err != nil {
		return -1
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return -1
	}
	matches := 0
	for _, e := range entries {
		if !w.startupDeadline.IsZero() && time.Now().After(w.startupDeadline) {
			return -1
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		p, err := Inspect(pid)
		if err != nil || p.Application.Prefix != w.prefix || p.UID != broker.UID || p.NetNS != broker.NetNS || p.MountNS != broker.MountNS {
			continue
		}
		if p.Application.Executable != w.helper && !w.mappedObserver(p) {
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
	return matches
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
			cf, err := socketFDs(p.PID)
			if err != nil {
				continue
			}
			bf, err := socketFDs(broker.PID)
			if err != nil {
				continue
			}
			peers, err := unixPeers()
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
			current, err := Inspect(p.PID)
			if err == nil && related && current.Start == p.Start && current.Application.Revision == revision && current.Application.Executable == path {
				found = true
			}
		}
	}
	return found
}

// Broker-only and broker+same-client snapshots have the same authority when
// cookie, Windows handle owner/generation and mapped PE revision are unchanged.
func sameBrokerGeneration(b Process, owners []Process) bool {
	for _, p := range owners {
		if p.PID == b.PID {
			return p.Start == b.Start && p.ExecutableRevision == b.ExecutableRevision && p.UID == b.UID && p.NetNS == b.NetNS && p.MountNS == b.MountNS
		}
	}
	return false
}
func consistentWineHolders(owners []Process, b Process, app Application) bool {
	for _, p := range owners {
		if p.PID == b.PID {
			continue
		}
		if p.UID != b.UID || p.NetNS != b.NetNS || p.MountNS != b.MountNS || p.Application.Key != app.Key || p.Application.Revision != app.Revision {
			return false
		}
	}
	return true
}

// Bounded retries only bridge publication timing while connect is still held.
// Empty evidence never becomes authority and cannot wait for successful connect.
func (w *WineTable) snapshotRows(f Flow, family int) (tableSnapshot, []WindowsOwner, error) {
	var s tableSnapshot
	var rows []WindowsOwner
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(20 * time.Millisecond)
		}
		s, err = w.snapshotFamily(f.Protocol, family)
		if err != nil {
			return s, nil, err
		}
		rows, err = selectTableRows(s, f)
		if err != nil || len(rows) > 0 || f.Direction != "outgoing" {
			return s, rows, err
		}
	}
	return s, rows, nil
}
