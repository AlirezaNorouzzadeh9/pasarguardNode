//go:build linux

package hostroute

import (
	"net"
	"testing"
)

func TestMSSForMTU(t *testing.T) {
	cases := []struct {
		name string
		mtu  int
		want int
	}{
		{"relay tunnel 1320", 1320, 1160},
		{"wireguard egress 1420", 1420, 1260},
		{"plain ethernet", 1500, 1340},
		{"jumbo frames are capped at ethernet", 9000, 1340},
		{"tiny link falls back to the floor", 600, mssFloor},
		{"floor is never crossed", 100, mssFloor},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := mssForMTU(tc.mtu); got != tc.want {
				t.Fatalf("mssForMTU(%d) = %d, want %d", tc.mtu, got, tc.want)
			}
		})
	}
}

func TestEligibleForMTU(t *testing.T) {
	up := net.FlagUp
	cases := []struct {
		name  string
		iface string
		flags net.Flags
		want  bool
	}{
		{"relay tunnel counts", "back412", up, true},
		{"egress wireguard counts", "uk", up, true},
		{"uplink counts", "eth0", up, true},
		{"loopback is skipped", "lo", up | net.FlagLoopback, false},
		{"down interfaces are skipped", "eth1", 0, false},
		{"docker bridge is skipped", "docker0", up, false},
		{"compose bridge is skipped", "br-9f2c1a", up, false},
		{"veth pair is skipped", "vethabc123", up, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := eligibleForMTU(tc.iface, tc.flags); got != tc.want {
				t.Fatalf("eligibleForMTU(%q, %v) = %v, want %v", tc.iface, tc.flags, got, tc.want)
			}
		})
	}
}

// The clamp has to be reachable: the forward-accept rules this package installs
// begin with accept verdicts, and an accept ends evaluation of its chain, so a
// clamp sharing that chain would never run.
func TestMSSChainRunsBeforeForwardAccepts(t *testing.T) {
	if mssTable == "filter" || mssTable == "mangle" {
		t.Fatalf("clamp must live in its own table, got %q", mssTable)
	}
	if mssOwnerComment("x") == ownerComment("x") {
		t.Fatal("clamp and forward rules must use distinct owner comments")
	}
}
