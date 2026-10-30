package identity

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// NetworkSnapshot contains configuration, never traffic counters or geolocation.
// It is scoped to the daemon's network namespace, just like socket attribution.
type NetworkLink struct {
	Index            uint32 `json:"index"`
	Name             string `json:"name"`
	Kind             string `json:"kind"`
	Flags            uint32 `json:"flags"`
	Address          string `json:"address"`
	PermanentAddress string `json:"permanent_address,omitempty"`
}
type NetworkAddress struct {
	Interface uint32 `json:"interface"`
	Prefix    string `json:"prefix"`
	Flags     uint32 `json:"flags"`
}
type NetworkRoute struct {
	Prefix    string `json:"prefix"`
	Gateway   string `json:"gateway,omitempty"`
	Interface uint32 `json:"interface"`
	Table     uint32 `json:"table"`
	Priority  uint32 `json:"priority"`
	Scope     uint8  `json:"scope"`
	Type      uint8  `json:"type"`
	Options   string `json:"options,omitempty"`
	Config    string `json:"config,omitempty"`
}
type NetworkSnapshot struct {
	State     string           `json:"state"`
	Revision  string           `json:"revision"`
	NetNS     string           `json:"netns"`
	Reason    string           `json:"reason"`
	Links     []NetworkLink    `json:"links"`
	Addresses []NetworkAddress `json:"addresses"`
	Routes    []NetworkRoute   `json:"routes"`
	Rules     []string         `json:"rules"`
}

func (s *NetworkSnapshot) seal() {
	sort.Slice(s.Links, func(i, j int) bool { return s.Links[i].Index < s.Links[j].Index })
	sort.Slice(s.Addresses, func(i, j int) bool {
		a, _ := json.Marshal(s.Addresses[i])
		b, _ := json.Marshal(s.Addresses[j])
		return string(a) < string(b)
	})
	sort.Slice(s.Routes, func(i, j int) bool {
		a, _ := json.Marshal(s.Routes[i])
		b, _ := json.Marshal(s.Routes[j])
		return string(a) < string(b)
	})
	sort.Strings(s.Rules)
	s.Revision = ""
	b, _ := json.Marshal(s)
	h := sha256.Sum256(b)
	s.Revision = hex.EncodeToString(h[:])
}
func netAddr(b []byte) string {
	if len(b) == 4 {
		return netip.AddrFrom4([4]byte(b)).String()
	}
	if len(b) == 16 {
		return netip.AddrFrom16([16]byte(b)).String()
	}
	return ""
}
func dumpNetwork(kind uint16, size int) ([]netlink.Message, error) {
	c, err := netlink.Dial(unix.NETLINK_ROUTE, nil)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(time.Second))
	data := make([]byte, size)
	data[0] = unix.AF_UNSPEC
	rows, err := c.Execute(netlink.Message{Header: netlink.Header{Type: netlink.HeaderType(kind), Flags: netlink.Request | netlink.Dump}, Data: data})
	if len(rows) > 8192 {
		return nil, fmt.Errorf("network configuration exceeds 8192 records")
	}
	return rows, err
}
func collectNetwork() (NetworkSnapshot, error) {
	s := NetworkSnapshot{State: "ready", NetNS: NetNS(), Reason: "Kernel link/address/route/policy-rule snapshot", Links: []NetworkLink{}, Addresses: []NetworkAddress{}, Routes: []NetworkRoute{}, Rules: []string{}}
	for _, kind := range []uint16{unix.RTM_GETLINK, unix.RTM_GETADDR, unix.RTM_GETROUTE, unix.RTM_GETRULE} {
		size := 12
		if kind == unix.RTM_GETLINK {
			size = 16
		}
		if kind == unix.RTM_GETADDR {
			size = 8
		}
		rows, err := dumpNetwork(kind, size)
		if err != nil {
			return s, err
		}
		for _, m := range rows {
			b := m.Data
			if len(b) < size {
				return s, fmt.Errorf("short network dump")
			}
			attrs, err := netlink.UnmarshalAttributes(b[size:])
			if err != nil {
				return s, err
			}
			switch kind {
			case unix.RTM_GETLINK:
				v := NetworkLink{Index: binary.NativeEndian.Uint32(b[4:8]), Flags: binary.NativeEndian.Uint32(b[8:12])}
				for _, a := range attrs {
					switch a.Type & 0x3fff {
					case unix.IFLA_IFNAME:
						v.Name = strings.TrimRight(string(a.Data), "\x00")
					case unix.IFLA_ADDRESS:
						v.Address = hex.EncodeToString(a.Data)
					case unix.IFLA_PERM_ADDRESS:
						v.PermanentAddress = hex.EncodeToString(a.Data)
					case unix.IFLA_LINKINFO:
						nested, e := netlink.UnmarshalAttributes(a.Data)
						if e != nil {
							return s, e
						}
						for _, n := range nested {
							if n.Type&0x3fff == unix.IFLA_INFO_KIND {
								v.Kind = strings.TrimRight(string(n.Data), "\x00")
							}
						}
					}
				}
				s.Links = append(s.Links, v)
			case unix.RTM_GETADDR:
				if b[0] != unix.AF_INET && b[0] != unix.AF_INET6 {
					continue
				}
				v := NetworkAddress{Interface: binary.NativeEndian.Uint32(b[4:8]), Flags: uint32(b[2])}
				addr := ""
				for _, a := range attrs {
					switch a.Type & 0x3fff {
					case unix.IFA_LOCAL:
						addr = netAddr(a.Data)
					case unix.IFA_ADDRESS:
						if addr == "" {
							addr = netAddr(a.Data)
						}
					case unix.IFA_FLAGS:
						if len(a.Data) == 4 {
							v.Flags = binary.NativeEndian.Uint32(a.Data)
						}
					}
				}
				ip, e := netip.ParseAddr(addr)
				if e != nil {
					return s, e
				}
				v.Prefix = netip.PrefixFrom(ip, int(b[1])).String()
				s.Addresses = append(s.Addresses, v)
			case unix.RTM_GETROUTE:
				// Cached per-destination lookups are traffic state, not topology.
				if binary.NativeEndian.Uint32(b[8:12])&unix.RTM_F_CLONED != 0 {
					continue
				}
				if b[0] != unix.AF_INET && b[0] != unix.AF_INET6 {
					continue
				}
				v := NetworkRoute{Table: uint32(b[4]), Scope: b[6], Type: b[7]}
				// Include stable route attributes (preferred source, metrics,
				// encap, selectors) in revision fences, not expiry countdowns.
				parts := []string{hex.EncodeToString(b[:12])}
				for _, attr := range attrs {
					typ := attr.Type & 0x3fff
					if typ != unix.RTA_CACHEINFO && typ != 23 /* RTA_EXPIRES */ {
						parts = append(parts, fmt.Sprintf("%d:%x", typ, attr.Data))
					}
					if typ == unix.RTA_SRC {
						v.Options = "source-specific"
					}
				}
				if b[2] != 0 || b[3] != 0 {
					v.Options = "source/tos-specific"
				}
				sort.Strings(parts)
				config := sha256.Sum256([]byte(strings.Join(parts, ";")))
				v.Config = hex.EncodeToString(config[:])
				addr := "0.0.0.0"
				if b[0] == unix.AF_INET6 {
					addr = "::"
				}
				for _, a := range attrs {
					switch a.Type & 0x3fff {
					case unix.RTA_DST:
						addr = netAddr(a.Data)
					case unix.RTA_GATEWAY:
						v.Gateway = netAddr(a.Data)
					case unix.RTA_OIF:
						if len(a.Data) == 4 {
							v.Interface = binary.NativeEndian.Uint32(a.Data)
						}
					case unix.RTA_PRIORITY:
						if len(a.Data) == 4 {
							v.Priority = binary.NativeEndian.Uint32(a.Data)
						}
					case unix.RTA_TABLE:
						if len(a.Data) == 4 {
							v.Table = binary.NativeEndian.Uint32(a.Data)
						}
					case unix.RTA_MULTIPATH, 30 /* RTA_NH_ID */ :
						h := sha256.Sum256(a.Data)
						v.Options = hex.EncodeToString(h[:])
					}
				}
				ip, e := netip.ParseAddr(addr)
				if e != nil {
					return s, e
				}
				v.Prefix = netip.PrefixFrom(ip, int(b[1])).Masked().String()
				s.Routes = append(s.Routes, v)
			case unix.RTM_GETRULE:
				if b[0] != unix.AF_INET && b[0] != unix.AF_INET6 {
					continue
				}
				s.Rules = append(s.Rules, hex.EncodeToString(b))
			}
		}
	}
	s.seal()
	return s, nil
}
func CollectNetwork() NetworkSnapshot {
	// Two identical complete dumps avoid publishing a torn link/address/route set.
	a, err := collectNetwork()
	if err == nil {
		var b NetworkSnapshot
		b, err = collectNetwork()
		if err == nil && a.Revision == b.Revision {
			return b
		}
		if err == nil {
			err = fmt.Errorf("network changed during collection; awaiting stable snapshot")
		}
	}
	a = NetworkSnapshot{State: "unavailable", NetNS: NetNS(), Reason: err.Error()}
	a.seal()
	return a
}

// ZoneManager owns immutable generations shared by enforcement and Activity.
// Route notifications trigger a refresh; a one-second census also recovers
// from lost netlink events and refreshes failed collections automatically.
type ZoneManager struct {
	publication      sync.Mutex // lock order: publication -> Engine -> snapshot mu
	publisher        func(NetworkZones, func()) error
	publicationError error
	mu               sync.RWMutex
	legacy           NetworkZones
	current          NetworkZones
}

func NewZoneManager(legacy NetworkZones) *ZoneManager {
	return NewZoneManagerWithPublisher(legacy, nil)
}

// The publisher runs outside the snapshot lock. It must commit the snapshot
// even when accelerator revocation fails; errors describe degraded enforcement.
// Configure it at construction, before any Run or Refresh calls.
func NewZoneManagerWithPublisher(legacy NetworkZones, publisher func(NetworkZones, func()) error) *ZoneManager {
	m := &ZoneManager{legacy: legacy, publisher: publisher}
	m.Refresh()
	return m
}
func (m *ZoneManager) Refresh() {
	m.publication.Lock()
	defer m.publication.Unlock()
	z := AutomaticNetworkZones(m.legacy, CollectNetwork())
	m.publish(z)
}

// Caller holds publication. No Engine path may call Refresh under Engine.mu.
func (m *ZoneManager) publish(z NetworkZones) {
	commit := func() { m.mu.Lock(); m.current = z; m.mu.Unlock() }
	var err error
	if m.publisher == nil {
		commit()
	} else {
		err = m.publisher(z, commit)
	}
	m.mu.Lock()
	m.publicationError = err
	m.mu.Unlock()
}
func (m *ZoneManager) PublicationError() error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.publicationError
}
func (m *ZoneManager) Snapshot() NetworkZones { m.mu.RLock(); defer m.mu.RUnlock(); return m.current }
func (m *ZoneManager) Run(ctx context.Context) {
	changed := make(chan struct{}, 1)
	c, err := netlink.Dial(unix.NETLINK_ROUTE, &netlink.Config{Groups: unix.RTMGRP_LINK | unix.RTMGRP_IPV4_IFADDR | unix.RTMGRP_IPV6_IFADDR | unix.RTMGRP_IPV4_ROUTE | unix.RTMGRP_IPV6_ROUTE | unix.RTMGRP_IPV4_RULE | (1 << 18) /* RTNLGRP_IPV6_RULE */})
	if err == nil {
		defer c.Close()
		go func() {
			for {
				c.SetReadDeadline(time.Now().Add(time.Second))
				_, e := c.Receive()
				if ctx.Err() != nil {
					return
				}
				if e != nil {
					// Failed watchers fall back to the census instead of spinning.
					select {
					case <-ctx.Done():
						return
					case <-time.After(100 * time.Millisecond):
					}
				}
				if e == nil {
					select {
					case changed <- struct{}{}:
					default:
					}
				}
			}
		}()
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.Refresh()
		case <-changed:
			m.Refresh()
		}
	}
}
