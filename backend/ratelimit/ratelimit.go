// Package ratelimit caps how fast an individual VPN client may move traffic.
//
// The panel gives a user a throughput ceiling in kbit/s; this package turns
// that into Linux traffic-control state on the node. It works for the tunnel
// backends — openvpn, wireguard and ikev2 — because each of those hands every
// client its own address inside the tunnel, which is what a shaper needs to
// tell clients apart. Xray users all share the proxy's own egress and cannot be
// separated at the packet level, so they are out of scope.
//
// How it is wired:
//
//   - One HTB qdisc on the egress interface holds a class per (user,
//     direction). The class rate is the user's ceiling.
//   - Packets are classified by firewall mark rather than by address, so a
//     single tc filter serves every backend. Marks are set in mangle FORWARD,
//     where the client's tunnel address is still visible — including for IPsec,
//     whose packets are encrypted by the time they reach the egress qdisc.
//   - Download and upload get separate classes, so an "8 Mbit" user gets 8
//     Mbit each way rather than 8 shared.
//
// Everything installed here is tagged and removed again on Close, so a node
// restart never leaves stale shaping behind.
package ratelimit

import (
	"fmt"
	"sort"
	"sync"
)

// Direction distinguishes the two classes a user gets.
type Direction int

const (
	// Download is traffic heading to the client (matched on destination).
	Download Direction = iota
	// Upload is traffic coming from the client (matched on source).
	Upload
)

func (d Direction) String() string {
	if d == Upload {
		return "up"
	}
	return "down"
}

// Client is one shaped tunnel address.
type Client struct {
	// User identifies the account the address belongs to, for logging.
	User string
	// Address is the client's address inside the tunnel (host address, no mask).
	Address string
	// LimitKbps is the ceiling per direction. Zero means unshaped.
	LimitKbps uint32
}

// Manager owns the tc and mark state for one node.
type Manager struct {
	mu sync.Mutex
	// iface is the egress interface the shaping hangs off.
	iface string
	// applied is the state currently installed, keyed by tunnel address.
	applied map[string]Client
	// marks maps an address to the firewall mark handed to it.
	marks map[string]uint32
	// freed holds marks whose client went away, for reuse.
	freed []uint32
	// nextMark is the next never-used mark.
	nextMark uint32
	runner   commandRunner
	// nft runs an nft command; swappable so tests observe marking without a
	// live nftables. Defaults to the real nft on Linux, a no-op elsewhere.
	nft     func(args ...string) error
	started bool
}

// commandRunner exists so tests can observe the commands without a live kernel.
type commandRunner interface {
	run(name string, args ...string) error
	output(name string, args ...string) (string, error)
}

const (
	// firstMark starts our marks high enough to stay clear of the low values
	// other tools on the host tend to use, and markMask means we only ever read
	// or write our own bits.
	firstMark uint32 = 0x00100000
	markMask  uint32 = 0x00ff0000
	// maxClients bounds the mark range so a runaway user list cannot walk past
	// markMask into somebody else's bits.
	maxClients = 0xfe
)

// New returns a Manager shaping traffic on iface.
func New(iface string) *Manager {
	return &Manager{
		iface:    iface,
		applied:  map[string]Client{},
		marks:    map[string]uint32{},
		nextMark: firstMark,
		runner:   execRunner{},
		nft:      defaultNFT,
	}
}

// Apply makes the installed shaping match clients exactly: new addresses are
// shaped, changed ceilings are updated, and addresses no longer present are
// unshaped. Clients with a zero limit are treated as absent.
func (m *Manager) Apply(clients []Client) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	wanted := make(map[string]Client, len(clients))
	for _, c := range clients {
		if c.Address == "" || c.LimitKbps == 0 {
			continue
		}
		wanted[c.Address] = c
	}

	if len(wanted) > 0 && !m.started {
		if err := m.setupRoot(); err != nil {
			return err
		}
		m.started = true
	}

	// Remove first, so a shrinking set frees its marks before new ones allocate.
	for addr := range m.applied {
		if _, keep := wanted[addr]; !keep {
			m.removeLocked(addr)
		}
	}

	// Deterministic order keeps class ids stable across runs, which makes the
	// installed state easy to compare in tests and in `tc class show`.
	addrs := make([]string, 0, len(wanted))
	for addr := range wanted {
		addrs = append(addrs, addr)
	}
	sort.Strings(addrs)

	var firstErr error
	for _, addr := range addrs {
		c := wanted[addr]
		if existing, ok := m.applied[addr]; ok {
			if existing.LimitKbps == c.LimitKbps {
				continue
			}
			if err := m.updateLocked(c); err != nil && firstErr == nil {
				firstErr = err
			}
			continue
		}
		if err := m.addLocked(c); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// Close removes every rule and qdisc this manager installed.
func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for addr := range m.applied {
		m.removeLocked(addr)
	}
	if m.started {
		m.teardownRoot()
		m.started = false
	}
}

func (m *Manager) String() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return fmt.Sprintf("ratelimit(iface=%s, clients=%d)", m.iface, len(m.applied))
}
