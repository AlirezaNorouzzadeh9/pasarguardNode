//go:build linux

package hostroute

// TCP MSS clamping for tunnel client subnets.
//
// Why this exists: a client sizes its TCP segments from the MTU it sees on its
// own link, which says nothing about the path this node's traffic actually
// takes. When the node sits behind a relay/backhaul tunnel, or hands traffic to
// an egress tunnel, the usable MTU is far smaller. Small packets (DNS, pings,
// short HTTP replies) get through, while multi-kilobyte TLS handshakes are
// silently dropped — the tunnel looks connected and no site loads.
//
// Path MTU discovery cannot rescue this: the ICMP "fragmentation needed"
// replies are routinely dropped on these paths, so the client never learns.
// Clamping the MSS advertised in both directions of the handshake is the only
// reliable fix, and it has to be derived from the real interface MTUs rather
// than a hardcoded number so it keeps working when the tunnel MTU changes.
//
// The rules live in their own table and base chain at an earlier hook priority
// than the forward-accept rules: those start with accept verdicts, and an
// accept terminates evaluation of its chain, so anything appended after them
// would never run.

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// MSSTable is exported so other packages that install their own forward rules
// can skip it: an accept landing in this chain would shadow the clamp.
const MSSTable = mssTable

const (
	mssTable         = "pg_node_mss"
	mssChain         = "clamp"
	mssCommentPrefix = "pg_node_mss "

	// mssHeadroom is what the largest safe segment gives up against the
	// smallest MTU on the box. Measured against a relay tunnel of MTU 1320,
	// AES-CBC-256/HMAC-SHA256 over UDP 4500 leaves 1228 bytes for the inner
	// packet, i.e. ~92 bytes of encapsulation; add the inner IPv4 (20) and TCP
	// (20) headers and room for TCP options (timestamps and SACK push the
	// header to 52-60 bytes) and round up for cipher/padding variation.
	mssHeadroom = 160

	// mssFloor is the smallest MSS worth advertising (RFC 1122 minimum MTU of
	// 576 less the IPv4 and TCP headers).
	mssFloor = 536

	// mtuCeiling bounds the result when every interface is jumbo-framed; beyond
	// a normal ethernet MTU there is nothing worth clamping to.
	mtuCeiling = 1500
)

// MSSRefreshInterval is how often a refresher re-reads the interface MTUs.
const MSSRefreshInterval = time.Minute

var (
	appliedMu  sync.Mutex
	appliedMSS = map[string]int{}
)

// EnsureMSSClampForSubnet installs (or refreshes) MSS clamping for subnet,
// replacing any rules previously installed under the same ownerID. It returns
// the MSS it settled on so the caller can log it and detect changes. Calling it
// again with an unchanged path MTU is a no-op, so it is cheap to poll.
func EnsureMSSClampForSubnet(subnet, ownerID string) (int, error) {
	subnet = strings.TrimSpace(subnet)
	if subnet == "" {
		return 0, fmt.Errorf("empty subnet")
	}
	mss, err := PathMSS()
	if err != nil {
		return 0, err
	}

	appliedMu.Lock()
	defer appliedMu.Unlock()
	if appliedMSS[ownerID] == mss && mssChainExists() {
		return mss, nil
	}

	if err := ensureMSSChain(); err != nil {
		return 0, err
	}
	if err := removeMSSRules(ownerID); err != nil {
		return 0, err
	}
	for _, saddr := range []bool{true, false} {
		if err := addMSSRule(subnet, ownerID, mss, saddr); err != nil {
			return 0, err
		}
	}
	appliedMSS[ownerID] = mss
	return mss, nil
}

// EnsureMSSClampForInterface is the WireGuard-shaped variant: its clients are
// identified by the tunnel interface rather than a subnet, and its peer pool is
// usually a wide range that would overlap the other backends' subnets.
func EnsureMSSClampForInterface(iface, ownerID string) (int, error) {
	iface = strings.TrimSpace(iface)
	if iface == "" {
		return 0, fmt.Errorf("empty interface")
	}
	mss, err := PathMSS()
	if err != nil {
		return 0, err
	}

	appliedMu.Lock()
	defer appliedMu.Unlock()
	if appliedMSS[ownerID] == mss && mssChainExists() {
		return mss, nil
	}

	if err := ensureMSSChain(); err != nil {
		return 0, err
	}
	if err := removeMSSRules(ownerID); err != nil {
		return 0, err
	}
	for _, inbound := range []bool{true, false} {
		if err := addMSSIfaceRule(iface, ownerID, mss, inbound); err != nil {
			return 0, err
		}
	}
	appliedMSS[ownerID] = mss
	return mss, nil
}

// StartMSSRefresher keeps the clamp in step with the live interface MTUs: a
// relay tunnel can come back up with a different MTU long after the backend
// started, and a stale clamp is exactly as broken as no clamp. logf is called
// only when the value actually changes. The returned func stops the refresher.
func StartMSSRefresher(subnet, ownerID string, logf func(format string, args ...any)) func() {
	return startRefresher(ownerID, logf, func() (int, error) {
		return EnsureMSSClampForSubnet(subnet, ownerID)
	}, subnet)
}

// StartMSSRefresherForInterface is the interface-matched counterpart.
func StartMSSRefresherForInterface(iface, ownerID string, logf func(format string, args ...any)) func() {
	return startRefresher(ownerID, logf, func() (int, error) {
		return EnsureMSSClampForInterface(iface, ownerID)
	}, iface)
}

func startRefresher(ownerID string, logf func(format string, args ...any), apply func() (int, error), target string) func() {
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(MSSRefreshInterval)
		defer ticker.Stop()
		last := 0
		appliedMu.Lock()
		last = appliedMSS[ownerID]
		appliedMu.Unlock()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				mss, err := apply()
				if err != nil {
					continue
				}
				if mss != last && logf != nil {
					logf("MSS clamp for %s updated %d -> %d (path MTU changed)", target, last, mss)
				}
				last = mss
			}
		}
	}()
	return func() { close(done) }
}

// RemoveMSSClamp deletes every clamp rule tagged with ownerID.
func RemoveMSSClamp(ownerID string) error {
	appliedMu.Lock()
	delete(appliedMSS, ownerID)
	appliedMu.Unlock()
	if !mssChainExists() {
		return nil
	}
	return removeMSSRules(ownerID)
}

// PathMSS is the MSS to advertise given the smallest MTU currently configured
// on any interface that forwarded client traffic could cross.
func PathMSS() (int, error) {
	mtu, err := smallestForwardingMTU()
	if err != nil {
		return 0, err
	}
	return mssForMTU(mtu), nil
}

func mssForMTU(mtu int) int {
	if mtu > mtuCeiling {
		mtu = mtuCeiling
	}
	mss := mtu - mssHeadroom
	if mss < mssFloor {
		return mssFloor
	}
	return mss
}

// smallestForwardingMTU returns the lowest MTU among the interfaces that can
// carry forwarded client traffic. Loopback, down interfaces and Docker's
// bridge/veth plumbing are skipped: they never sit on the client path and a
// container bridge would otherwise drag the clamp down for no reason.
func smallestForwardingMTU() (int, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return 0, fmt.Errorf("list interfaces: %w", err)
	}
	smallest := 0
	for _, iface := range ifaces {
		if !eligibleForMTU(iface.Name, iface.Flags) || iface.MTU <= 0 {
			continue
		}
		if smallest == 0 || iface.MTU < smallest {
			smallest = iface.MTU
		}
	}
	if smallest == 0 {
		return 0, fmt.Errorf("no usable interface found")
	}
	return smallest, nil
}

func eligibleForMTU(name string, flags net.Flags) bool {
	if flags&net.FlagUp == 0 || flags&net.FlagLoopback != 0 {
		return false
	}
	for _, skip := range []string{"docker", "br-", "veth", "virbr", "cni", "flannel", "kube"} {
		if strings.HasPrefix(name, skip) {
			return false
		}
	}
	return true
}

func ensureMSSChain() error {
	if err := runNFT("add", "table", "ip", mssTable); err != nil {
		return err
	}
	// Run ahead of the forward-accept rules, whose accept verdict would
	// otherwise end the chain before a clamp appended there could match.
	return runNFT("add", "chain", "ip", mssTable, mssChain,
		"{ type filter hook forward priority mangle - 10 ; policy accept ; }")
}

func mssChainExists() bool {
	return exec.Command("nft", "list", "chain", "ip", mssTable, mssChain).Run() == nil
}

func addMSSRule(subnet, ownerID string, mss int, saddr bool) error {
	match := "daddr"
	dir := "to-client"
	if saddr {
		match, dir = "saddr", "from-client"
	}
	return runNFT(
		"add", "rule", "ip", mssTable, mssChain,
		"ip", match, subnet,
		"tcp", "flags", "syn", "/", "syn,rst",
		"tcp", "option", "maxseg", "size", "set", fmt.Sprint(mss),
		"comment", quote(fmt.Sprintf("%sowner=%s subnet=%s direction=%s mss=%d", mssCommentPrefix, ownerID, subnet, dir, mss)),
	)
}

func addMSSIfaceRule(iface, ownerID string, mss int, inbound bool) error {
	match := "oifname"
	dir := "to-client"
	if inbound {
		match, dir = "iifname", "from-client"
	}
	return runNFT(
		"add", "rule", "ip", mssTable, mssChain,
		match, quote(iface),
		"tcp", "flags", "syn", "/", "syn,rst",
		"tcp", "option", "maxseg", "size", "set", fmt.Sprint(mss),
		"comment", quote(fmt.Sprintf("%sowner=%s iface=%s direction=%s mss=%d", mssCommentPrefix, ownerID, iface, dir, mss)),
	)
}

func removeMSSRules(ownerID string) error {
	chain := baseChain{family: "ip", table: mssTable, name: mssChain}
	return removeRulesWithComment(chain, mssOwnerComment(ownerID))
}

func mssOwnerComment(ownerID string) string {
	return fmt.Sprintf("%sowner=%s ", mssCommentPrefix, ownerID)
}
