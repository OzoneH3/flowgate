package identity

import (
	"encoding/binary"
	"fmt"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// WineBrokerExecutable is explicitly configured by the caller. Empty disables
// the non-sharing Wine-client assumption. Never classify a broker by basename.
var WineBrokerExecutable string

type Association struct {
	ClientPID     int      `json:"client_pid"`
	BrokerPID     int      `json:"broker_pid"`
	ClientChannel uint32   `json:"client_channel_inode"`
	BrokerChannel uint32   `json:"broker_channel_inode"`
	Evidence      []string `json:"evidence"`
	Assumptions   []string `json:"assumptions"`
}

func socketFDs(pid int) (map[uint32]bool, error) {
	base := fmt.Sprintf("/proc/%d/fd", pid)
	entries, err := os.ReadDir(base)
	if err != nil {
		return nil, err
	}
	out := map[uint32]bool{}
	for _, fd := range entries {
		s := link(base + "/" + fd.Name())
		if strings.HasPrefix(s, "socket:[") {
			v, e := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(s, "socket:["), "]"), 10, 32)
			if e == nil {
				out[uint32(v)] = true
			}
		}
	}
	return out, nil
}
func unixPeers() (map[uint32]uint32, error) {
	c, err := netlink.Dial(unix.NETLINK_SOCK_DIAG, nil)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(time.Second))
	req := make([]byte, 24)
	req[0] = unix.AF_UNIX
	binary.NativeEndian.PutUint32(req[4:8], 0xffffffff)
	binary.NativeEndian.PutUint32(req[12:16], 4)
	for i := 16; i < 24; i++ {
		req[i] = 255
	}
	msgs, err := c.Execute(netlink.Message{Header: netlink.Header{Type: 20, Flags: netlink.Request | netlink.Dump}, Data: req})
	if err != nil {
		return nil, err
	}
	out := map[uint32]uint32{}
	for _, m := range msgs {
		if len(m.Data) < 16 {
			return nil, fmt.Errorf("short unix_diag")
		}
		attrs, err := netlink.UnmarshalAttributes(m.Data[16:])
		if err != nil {
			return nil, err
		}
		for _, a := range attrs {
			if a.Type == 2 && len(a.Data) == 4 {
				out[binary.NativeEndian.Uint32(m.Data[4:8])] = binary.NativeEndian.Uint32(a.Data)
			}
		}
	}
	return out, nil
}
func brokerAssociation(owners []Process) (*Association, *Process) {
	if WineBrokerExecutable == "" || len(owners) != 2 {
		return nil, nil
	}
	trusted, err := os.Stat(WineBrokerExecutable)
	if err != nil {
		return nil, nil
	}
	var client, broker *Process
	for i := range owners {
		p := &owners[i]
		actual, err := os.Stat(fmt.Sprintf("/proc/%d/exe", p.PID))
		if err == nil && os.SameFile(trusted, actual) {
			broker = p
		} else if p.Application.Kind == "wine" && p.Application.Key != "" {
			client = p
		}
	}
	if client == nil || broker == nil || client.UID != broker.UID || client.NetNS != broker.NetNS || client.MountNS != broker.MountNS || client.Application.Prefix == "" || client.Application.Prefix != broker.Application.Prefix {
		return nil, nil
	}
	cf, err := socketFDs(client.PID)
	if err != nil {
		return nil, nil
	}
	bf, err := socketFDs(broker.PID)
	if err != nil {
		return nil, nil
	}
	peers, err := unixPeers()
	if err != nil {
		return nil, nil
	}
	ids := make([]int, 0, len(cf))
	for inode := range cf {
		ids = append(ids, int(inode))
	}
	sort.Ints(ids)
	for _, id := range ids {
		inode := uint32(id)
		peer := peers[inode]
		if bf[peer] && peers[peer] == inode {
			return &Association{ClientPID: client.PID, BrokerPID: broker.PID, ClientChannel: inode, BrokerChannel: peer, Evidence: []string{"configured broker executable device/inode matches /proc/exe", "bidirectional UNIX_DIAG_PEER channel connects client and broker", "same UID, namespaces and canonical explicit prefix", "one mapped Windows image client holds this network socket"}, Assumptions: []string{"Wine 11.19 ordinary sockets without cross-process Windows handle duplication/inheritance", "visible holders are not a complete Windows handle table", "not a guarantee against hostile same-user FD manipulation or external relays"}}, client
		}
	}
	return nil, nil
}

// Principal returns the logical client for authorization, preserving all holders.
func (a Attribution) Principal() *Process {
	if a.Application == nil {
		return nil
	}
	if a.Association != nil {
		for i := range a.Owners {
			if a.Owners[i].PID == a.Association.ClientPID {
				return &a.Owners[i]
			}
		}
		return nil
	}
	if len(a.Owners) == 1 {
		return &a.Owners[0]
	}
	return nil
}
